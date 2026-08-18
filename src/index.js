const cron = require("node-cron");
const config = require("./config");
const alert = require("./alert");
const state = require("./state");
const vulnScanner = require("./scanners/vulnScanner");
const anomalyScanner = require("./scanners/anomalyScanner");
const fixTrigger = require("./fixTrigger");

// How often to check for a manual "run scan now" request from the dashboard
// (src/dashboard/server.js writes it into the shared SQLite state - sentinel
// has no listener of its own, so it polls instead).
const SCAN_REQUEST_POLL_MS = 10_000;

let vulnScanInProgress = false;
let anomalyScanInProgress = false;

async function runVulnScan() {
    if (vulnScanInProgress) {
        console.log("[sentinel] vulnerability scan already in progress, skipping");
        return;
    }
    vulnScanInProgress = true;
    console.log("[sentinel] starting vulnerability scan...");
    const runId = state.startScanRun("vuln");
    try {
        const findings = await vulnScanner.run();
        await alert.sendDigest("Vulnerability scan", findings);
        console.log(`[sentinel] vulnerability scan complete: ${findings.length} new finding(s)`);
        state.finishScanRun(runId, { findingsCount: findings.length });
    } catch (err) {
        console.error("[sentinel] vulnerability scan failed:", err);
        state.finishScanRun(runId, { error: err.message });
    } finally {
        vulnScanInProgress = false;
    }
}

async function runAnomalyScan() {
    if (anomalyScanInProgress) {
        console.log("[sentinel] anomaly scan already in progress, skipping");
        return;
    }
    anomalyScanInProgress = true;
    const runId = state.startScanRun("anomaly");
    try {
        const findings = await anomalyScanner.run();
        await alert.sendDigest("Compromise indicators", findings);
        if (findings.length > 0) {
            console.log(`[sentinel] anomaly scan: ${findings.length} finding(s)`);
        }
        state.finishScanRun(runId, { findingsCount: findings.length });
    } catch (err) {
        console.error("[sentinel] anomaly scan failed:", err);
        state.finishScanRun(runId, { error: err.message });
    } finally {
        anomalyScanInProgress = false;
    }
}

function pollForManualScanRequests() {
    for (const [scanType, run] of [
        ["vuln", runVulnScan],
        ["anomaly", runAnomalyScan],
    ]) {
        if (state.getScanRequestStatus(scanType).pending) {
            state.consumeScanRequest(scanType);
            console.log(`[sentinel] manual ${scanType} scan requested via dashboard`);
            run();
        }
    }
}

/**
 * Fires any "Fix with Claude" requests the dashboard has queued. Each
 * project's routine id/token live in config.fsScanProjects - a request for a
 * project that hasn't been wired up yet (or isn't a project at all, e.g. an
 * image/stale-image target) is left pending rather than erroring, since it
 * may just not have a "Fix with Claude" button surfaced for it yet.
 */
async function pollForFixRequests() {
    for (const req of state.getPendingFixRequests()) {
        const project = config.fsScanProjects.find((p) => p.name === req.target);
        if (!project?.fixRoutineId || !project?.fixRoutineToken) continue;

        const text = [
            "Security finding from home-sentinel.",
            `Repo: ${project.githubRepo}`,
            `Severity: ${req.severity}`,
            `Title: ${req.title}`,
            `Detail: ${req.detail}`,
        ].join("\n");

        try {
            const { sessionId, sessionUrl } = await fixTrigger.fireRoutine(
                project.fixRoutineId,
                project.fixRoutineToken,
                text
            );
            console.log(`[sentinel] fired fix routine for ${req.target}/${req.vuln_id}: ${sessionUrl}`);
            state.markFixStarted(req.id, { sessionId, sessionUrl });
            await alert.sendFixStarted({ target: req.target, title: req.title || req.vuln_id, sessionUrl });
        } catch (err) {
            console.error(`[sentinel] failed to fire fix routine for ${req.target}/${req.vuln_id}:`, err.message);
            state.markFixError(req.id, err.message);
        }
    }
}

async function main() {
    console.log("[sentinel] starting up");
    console.log(`[sentinel] vuln scan schedule: ${config.vulnScanCron}`);
    console.log(`[sentinel] anomaly scan schedule: ${config.anomalyScanCron}`);

    if (!config.slackWebhookUrl) {
        console.warn("[sentinel] SLACK_WEBHOOK_URL is not set - alerts will only be logged, not sent");
    }

    cron.schedule(config.vulnScanCron, runVulnScan);
    cron.schedule(config.anomalyScanCron, runAnomalyScan);
    setInterval(pollForManualScanRequests, SCAN_REQUEST_POLL_MS);
    setInterval(pollForFixRequests, SCAN_REQUEST_POLL_MS);

    // Run once immediately on startup so we don't wait for the first cron tick.
    await runAnomalyScan();
    await runVulnScan();
}

main().catch((err) => {
    console.error("[sentinel] fatal error:", err);
    process.exit(1);
});
