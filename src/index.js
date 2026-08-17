const cron = require("node-cron");
const config = require("./config");
const alert = require("./alert");
const state = require("./state");
const vulnScanner = require("./scanners/vulnScanner");
const anomalyScanner = require("./scanners/anomalyScanner");

async function runVulnScan() {
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
    }
}

async function runAnomalyScan() {
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

    // Run once immediately on startup so we don't wait for the first cron tick.
    await runAnomalyScan();
    await runVulnScan();
}

main().catch((err) => {
    console.error("[sentinel] fatal error:", err);
    process.exit(1);
});
