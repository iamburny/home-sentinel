const { execFile } = require("child_process");
const { promisify } = require("util");
const Docker = require("dockerode");
const config = require("../config");
const state = require("../state");

const execFileAsync = promisify(execFile);

const docker = new Docker({ host: config.dockerHostName, port: config.dockerHostPort, protocol: "http" });

async function runTrivyJson(args) {
    const { stdout } = await execFileAsync("trivy", args, { maxBuffer: 1024 * 1024 * 64 });
    return JSON.parse(stdout);
}

/** Flattens a Trivy JSON report into a simple, uniform findings list. */
function extractFindings(trivyReport) {
    const findings = [];
    for (const result of trivyReport.Results || []) {
        for (const vuln of result.Vulnerabilities || []) {
            findings.push({
                id: vuln.VulnerabilityID,
                severity: vuln.Severity,
                title: vuln.Title || vuln.VulnerabilityID,
                pkg: vuln.PkgName,
                installed: vuln.InstalledVersion,
                fixed: vuln.FixedVersion,
            });
        }
        for (const secret of result.Secrets || []) {
            findings.push({
                id: `secret:${result.Target}:${secret.RuleID}:${secret.StartLine}`,
                severity: secret.Severity,
                title: `Leaked secret: ${secret.Title}`,
                file: result.Target,
                line: secret.StartLine,
            });
        }
    }
    return findings;
}

function toAlert(scopeLabel, finding) {
    return {
        severity: finding.severity,
        title: `[${scopeLabel}] ${finding.id}`,
        detail: finding.pkg
            ? `${finding.title}\n${finding.pkg} ${finding.installed} → fix: ${finding.fixed || "none available"}`
            : `${finding.title}${finding.file ? ` (${finding.file}:${finding.line})` : ""}`,
    };
}

/** Filesystem-scans every project with source on disk for vulnerable deps and leaked secrets. */
async function scanProjectSources() {
    const alerts = [];
    for (const project of config.fsScanProjects) {
        try {
            const report = await runTrivyJson([
                "fs",
                "--scanners", "vuln,secret",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--format", "json",
                "--quiet",
                project.path,
            ]);
            const findings = extractFindings(report);
            const newFindings = state.recordFindings(project.name, findings);
            state.pruneStaleFindings(project.name, findings.map((f) => f.id));
            alerts.push(...newFindings.map((f) => toAlert(project.name, f)));
        } catch (err) {
            console.error(`[vulnScanner] fs scan failed for ${project.name}:`, err.message);
        }
    }
    return alerts;
}

/** Scans every running container's actual image - covers vendor images with no source on disk too. */
async function scanRunningImages() {
    const alerts = [];
    const containers = await docker.listContainers();
    const seenImages = new Set();

    for (const c of containers) {
        const image = c.Image;
        const containerName = (c.Names[0] || "").replace(/^\//, "");
        if (seenImages.has(image)) continue;
        seenImages.add(image);

        try {
            const inspect = await docker.getImage(image).inspect();
            const createdAt = new Date(inspect.Created);
            const ageDays = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);
            if (ageDays > config.staleImageDays) {
                alerts.push({
                    severity: "MEDIUM",
                    title: `[${containerName}] stale image`,
                    detail: `Image "${image}" was built ${Math.round(ageDays)} days ago (${createdAt
                        .toISOString()
                        .slice(0, 10)}) - likely carrying unpatched CVEs. Consider rebuilding.`,
                });
            }
        } catch (err) {
            console.error(`[vulnScanner] image inspect failed for ${image}:`, err.message);
        }

        try {
            const report = await runTrivyJson([
                "image",
                "--severity", "CRITICAL,HIGH",
                "--format", "json",
                "--quiet",
                image,
            ]);
            const findings = extractFindings(report);
            const target = `image:${image}`;
            const newFindings = state.recordFindings(target, findings);
            state.pruneStaleFindings(target, findings.map((f) => f.id));
            alerts.push(...newFindings.map((f) => toAlert(containerName, f)));
        } catch (err) {
            console.error(`[vulnScanner] image scan failed for ${image}:`, err.message);
        }
    }
    return alerts;
}

async function run() {
    const [sourceAlerts, imageAlerts] = await Promise.all([scanProjectSources(), scanRunningImages()]);
    return [...sourceAlerts, ...imageAlerts];
}

module.exports = { run, extractFindings, toAlert };
