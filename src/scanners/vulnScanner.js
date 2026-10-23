const { execFile } = require("child_process");
const { promisify } = require("util");
const Docker = require("dockerode");
const config = require("../config");
const state = require("../state");

const execFileAsync = promisify(execFile);

const docker = new Docker({ host: config.dockerHostName, port: config.dockerHostPort, protocol: "http" });

// Scans never update Trivy's DBs themselves - prepareTrivyDbs does that once up front.
const SKIP_DB_UPDATE = ["--skip-db-update", "--skip-java-db-update"];
const DB_DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000;

async function runTrivyJson(args) {
    const { stdout } = await execFileAsync("trivy", args, { maxBuffer: 1024 * 1024 * 64 });
    return JSON.parse(stdout);
}

/**
 * Downloads or refreshes Trivy's vulnerability and Java DBs before any scan
 * starts. Source and image scans run concurrently, and a scan left to update a
 * DB itself replaces the file while other scans have it memory-mapped, which
 * kills them with SIGBUS. A failed refresh doesn't stop the run - scans carry
 * on against whatever DB is already cached - but is returned as a problem so
 * the run isn't recorded as clean.
 */
async function prepareTrivyDbs() {
    const problems = [];
    for (const flag of ["--download-db-only", "--download-java-db-only"]) {
        try {
            await execFileAsync("trivy", ["image", flag, "--quiet"], { timeout: DB_DOWNLOAD_TIMEOUT_MS });
        } catch (err) {
            console.error(`[vulnScanner] trivy ${flag} failed, scanning with the cached DB:`, err.message);
            problems.push(`trivy ${flag} failed`);
        }
    }
    return problems;
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
                detail: `${vuln.Title || vuln.VulnerabilityID}\n${vuln.PkgName} ${vuln.InstalledVersion} → fix: ${vuln.FixedVersion || "none available"}`,
            });
        }
        for (const secret of result.Secrets || []) {
            findings.push({
                id: `secret:${result.Target}:${secret.RuleID}:${secret.StartLine}`,
                severity: secret.Severity,
                title: `Leaked secret: ${secret.Title}`,
                detail: `${secret.Title} (${result.Target}:${secret.StartLine})`,
            });
        }
    }
    return findings;
}

/**
 * `target` is the real key findings are stored/looked-up under in state.js
 * (e.g. "api.collecterly.com", or "image:sha256:..." for a vendor image) -
 * `scopeLabel` is the human-readable name shown in the alert text, which for
 * image/stale findings is the container name rather than that raw key. Both
 * are threaded through so alert.js can build a dashboard deep link using the
 * real target while still showing a friendly label.
 */
function toAlert(target, scopeLabel, finding) {
    return {
        target,
        vulnId: finding.id,
        severity: finding.severity,
        title: `[${scopeLabel}] ${finding.id}`,
        detail: finding.detail,
    };
}

/** Filesystem-scans every project with source on disk for vulnerable deps and leaked secrets. */
async function scanProjectSources() {
    const alerts = [];
    const targets = [];
    const failed = [];
    for (const project of config.fsScanProjects) {
        targets.push(project.name);
        try {
            const report = await runTrivyJson([
                "fs",
                ...SKIP_DB_UPDATE,
                "--scanners", "vuln,secret",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--ignore-unfixed",
                "--format", "json",
                "--quiet",
                project.path,
            ]);
            const findings = extractFindings(report);
            const newFindings = state.recordFindings(project.name, findings);
            state.pruneStaleFindings(project.name, findings.map((f) => f.id));
            alerts.push(...newFindings.map((f) => toAlert(project.name, project.name, f)));
        } catch (err) {
            console.error(`[vulnScanner] fs scan failed for ${project.name}:`, err.message);
            failed.push(project.name);
        }
    }
    return { alerts, targets, failed };
}

/** Scans every running container's actual image - covers vendor images with no source on disk too. */
async function scanRunningImages() {
    const alerts = [];
    const targets = [];
    const failed = [];
    const containers = await docker.listContainers();
    const seenImages = new Set();

    for (const c of containers) {
        const image = c.Image;
        const containerName = (c.Names[0] || "").replace(/^\//, "");
        if (seenImages.has(image)) continue;
        seenImages.add(image);

        const staleTarget = `stale:${containerName}`;
        const imageTarget = `image:${image}`;
        targets.push(staleTarget, imageTarget);

        try {
            const inspect = await docker.getImage(image).inspect();
            const createdAt = new Date(inspect.Created);
            const ageDays = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);
            // Routed through recordFindings/pruneStaleFindings like everything
            // else, rather than a raw one-off push - otherwise this would
            // re-alert every single day forever instead of once, and would
            // never show up in the dashboard's findings list.
            if (ageDays > config.staleImageDays) {
                const staleFinding = {
                    id: "stale-image",
                    severity: "MEDIUM",
                    title: "stale image",
                    detail: `Image "${image}" was built ${Math.round(ageDays)} days ago (${createdAt
                        .toISOString()
                        .slice(0, 10)}) - likely carrying unpatched CVEs. Consider rebuilding.`,
                };
                const newFindings = state.recordFindings(staleTarget, [staleFinding]);
                alerts.push(...newFindings.map((f) => toAlert(staleTarget, containerName, f)));
            } else {
                state.pruneStaleFindings(staleTarget, []);
            }
        } catch (err) {
            console.error(`[vulnScanner] image inspect failed for ${image}:`, err.message);
        }

        try {
            const report = await runTrivyJson([
                "image",
                ...SKIP_DB_UPDATE,
                "--severity", "CRITICAL,HIGH",
                "--ignore-unfixed",
                "--format", "json",
                "--quiet",
                image,
            ]);
            const findings = extractFindings(report);
            const newFindings = state.recordFindings(imageTarget, findings);
            state.pruneStaleFindings(imageTarget, findings.map((f) => f.id));
            alerts.push(...newFindings.map((f) => toAlert(imageTarget, containerName, f)));
        } catch (err) {
            console.error(`[vulnScanner] image scan failed for ${image}:`, err.message);
            failed.push(containerName);
        }
    }
    return { alerts, targets, failed };
}

/**
 * Returns the new alerts plus `problems`: DB refreshes that failed and targets
 * that couldn't be scanned. A target that fails keeps its previous findings
 * open rather than resolving them, so problems are the only sign it was missed.
 */
async function run() {
    const problems = await prepareTrivyDbs();
    const [sources, images] = await Promise.all([scanProjectSources(), scanRunningImages()]);
    const failed = [...sources.failed, ...images.failed];
    if (failed.length > 0) {
        problems.push(`${failed.length} target(s) not scanned: ${failed.join(", ")}`);
    }
    // Resolves findings for any target that vanished entirely this cycle
    // (a container retagged or renamed, not just an individual finding
    // within a target going away) - see resolveOrphanedTargets's own doc
    // comment for why pruneStaleFindings alone can't catch this case.
    state.resolveOrphanedTargets([...sources.targets, ...images.targets]);
    return { alerts: [...sources.alerts, ...images.alerts], problems };
}

module.exports = { run, extractFindings, toAlert };
