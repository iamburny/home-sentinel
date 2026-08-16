const fs = require("fs");
const { promisify } = require("util");
const { execFile } = require("child_process");
const Docker = require("dockerode");
const config = require("../config");
const state = require("../state");

const execFileAsync = promisify(execFile);

const docker = new Docker({ host: config.dockerHostName, port: config.dockerHostPort, protocol: "http" });

// --- CPU: sustained-usage detection -----------------------------------------

function cpuPercentFromStats(stats) {
    const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
    const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
    const numCpus =
        stats.cpu_stats.online_cpus || (stats.cpu_stats.cpu_usage.percpu_usage || []).length || 1;
    if (systemDelta <= 0 || cpuDelta < 0) return 0;
    return (cpuDelta / systemDelta) * numCpus * 100;
}

async function checkCpu() {
    const alerts = [];
    const containers = await docker.listContainers();

    await Promise.all(
        containers.map(async (c) => {
            const name = (c.Names[0] || "").replace(/^\//, "");
            try {
                const stats = await docker.getContainer(c.Id).stats({ stream: false });
                const cpuPercent = cpuPercentFromStats(stats);
                state.recordCpuSample(name, cpuPercent);

                const threshold = config.anomaly.cpuThresholdOverrides[name] ?? config.anomaly.defaultCpuThreshold;
                const samples = state.recentCpuSamples(name, config.anomaly.sustainedSamples);
                const sustained =
                    samples.length >= config.anomaly.sustainedSamples &&
                    samples.every((s) => s.cpu_percent > threshold);

                if (sustained) {
                    alerts.push({
                        severity: "HIGH",
                        title: `[${name}] sustained high CPU`,
                        detail: `${Math.round(cpuPercent)}% CPU sustained across the last ${samples.length} checks (threshold: ${threshold}%). This is the exact signature the cryptominer incident showed.`,
                    });
                }
            } catch (err) {
                console.error(`[anomalyScanner] cpu check failed for ${name}:`, err.message);
            }
        })
    );

    return alerts;
}

// --- Process paths: binaries executing from ephemeral/world-writable dirs --

async function containerNameForPid(pid) {
    try {
        const cgroup = await fs.promises.readFile(`/proc/${pid}/cgroup`, "utf8");
        const match = cgroup.match(/[a-f0-9]{64}/);
        if (!match) return null;
        const containers = await docker.listContainers();
        const found = containers.find((c) => c.Id === match[0]);
        return found ? (found.Names[0] || "").replace(/^\//, "") : null;
    } catch {
        return null;
    }
}

async function checkProcessPaths() {
    const alerts = [];
    let pids;
    try {
        pids = (await fs.promises.readdir("/proc")).filter((p) => /^\d+$/.test(p));
    } catch (err) {
        console.error("[anomalyScanner] cannot read /proc:", err.message);
        return alerts;
    }

    for (const pid of pids) {
        let cmdline;
        try {
            cmdline = await fs.promises.readFile(`/proc/${pid}/cmdline`, "utf8");
        } catch {
            continue; // process exited between readdir and read, or unreadable - not actionable
        }
        const argv0 = cmdline.split("\0")[0];
        if (!argv0) continue;

        const isSuspicious = config.anomaly.suspiciousExecPathPatterns.some((re) => re.test(argv0));
        if (!isSuspicious) continue;

        const containerName = await containerNameForPid(pid);
        alerts.push({
            severity: "CRITICAL",
            title: `[${containerName || "host"}] process executing from ephemeral path`,
            detail: `PID ${pid}: "${argv0}" - no legitimate long-running process runs from /tmp, /var/tmp, or /dev/shm. This matches the exact pattern used in the cryptominer incident (/tmp/.ICEi-unix/javae).`,
        });
    }

    return alerts;
}

// --- Exposed ports: new 0.0.0.0-bound listeners not on the approved list ---

async function checkPorts() {
    const alerts = [];
    let stdout;
    try {
        ({ stdout } = await execFileAsync("ss", ["-tln"]));
    } catch (err) {
        console.error("[anomalyScanner] failed to run ss:", err.message);
        return alerts;
    }

    const lines = stdout.split("\n").slice(1); // drop header
    const seenPorts = new Set();
    for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 4) continue;
        const localAddr = cols[3];
        const lastColon = localAddr.lastIndexOf(":");
        if (lastColon === -1) continue;
        const addr = localAddr.slice(0, lastColon);
        const port = Number(localAddr.slice(lastColon + 1));
        const isPublic = addr === "0.0.0.0" || addr === "*" || addr === "[::]";
        if (!isPublic || !port || seenPorts.has(port)) continue;
        seenPorts.add(port);

        if (!config.anomaly.approvedPublicPorts.includes(port)) {
            alerts.push({
                severity: "HIGH",
                title: `unapproved public port ${port}`,
                detail: `Port ${port} is now listening on 0.0.0.0 and isn't in the approved baseline. This is the exact pattern that left Redis/MariaDB unauthenticated and reachable before this incident's hardening - verify this is intentional, then add it to approvedPublicPorts in config.js if so.`,
            });
        }
    }
    return alerts;
}

// --- SSH: successful logins from outside the LAN ---------------------------

function ipInCidr(ip, cidr) {
    const [range, bitsStr] = cidr.split("/");
    const bits = Number(bitsStr);
    const toInt = (a) => a.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false; // IPv6 or malformed - treat as non-LAN
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (toInt(ip) & mask) === (toInt(range) & mask);
}

async function checkSshLogins() {
    const alerts = [];
    let content;
    try {
        content = await fs.promises.readFile(config.authLogPath, "utf8");
    } catch (err) {
        console.error("[anomalyScanner] cannot read auth log:", err.message);
        return alerts;
    }

    const lines = content.split("\n");
    const lastLineCount = Number(state.getKv("authLogLinesProcessed", 0));
    const newLines = lines.slice(lastLineCount);
    state.setKv("authLogLinesProcessed", lines.length);

    const acceptedRe = /Accepted \S+ for (\S+) from (\S+) port \d+/;
    for (const line of newLines) {
        const match = line.match(acceptedRe);
        if (!match) continue;
        const [, user, ip] = match;
        if (!ipInCidr(ip, config.lanCidr)) {
            alerts.push({
                severity: "CRITICAL",
                title: "SSH login from outside the LAN",
                detail: `User "${user}" logged in via SSH from ${ip}, outside ${config.lanCidr}. Every successful login this server has ever had came from the local network - verify this was you.`,
            });
        }
    }
    return alerts;
}

async function run() {
    const [cpuAlerts, pathAlerts, portAlerts, sshAlerts] = await Promise.all([
        checkCpu(),
        checkProcessPaths(),
        checkPorts(),
        checkSshLogins(),
    ]);
    state.pruneOldCpuSamples();
    return [...cpuAlerts, ...pathAlerts, ...portAlerts, ...sshAlerts];
}

module.exports = { run, ipInCidr, cpuPercentFromStats };
