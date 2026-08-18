const config = require("./config");

const SEVERITY_EMOJI = {
    CRITICAL: "🔴",
    HIGH: "🟠",
    MODERATE: "🟡",
    MEDIUM: "🟡",
    LOW: "⚪",
    INFO: "ℹ️",
};

/**
 * Sends a batched digest of findings to Slack. `findings` is an array of
 * { severity, title, detail } objects. No-ops (just logs) if no webhook is
 * configured, so the service still runs and prints locally in dev.
 */
async function sendDigest(heading, findings) {
    if (findings.length === 0) return;

    const lines = findings.map((f) => {
        const emoji = SEVERITY_EMOJI[f.severity?.toUpperCase()] || "•";
        const link =
            config.dashboardBaseUrl && f.target && f.vulnId
                ? `\n<${config.dashboardBaseUrl}/findings/view?target=${encodeURIComponent(f.target)}&vuln=${encodeURIComponent(f.vulnId)}|View & fix →>`
                : "";
        return `${emoji} *${f.title}*\n${f.detail}${link}`;
    });
    const text = `*${heading}* (${findings.length} finding${findings.length === 1 ? "" : "s"})\n\n${lines.join("\n\n")}`;

    console.log(`[alert] ${heading}: ${findings.length} finding(s)`);
    for (const f of findings) console.log(`  - [${f.severity}] ${f.title}`);

    if (!config.slackWebhookUrl) {
        console.warn("[alert] SLACK_WEBHOOK_URL not set - alert logged locally only");
        return;
    }

    try {
        const res = await fetch(config.slackWebhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
        });
        if (!res.ok) {
            console.error(`[alert] Slack webhook returned ${res.status}: ${await res.text()}`);
        }
    } catch (err) {
        console.error("[alert] failed to post to Slack:", err.message);
    }
}

module.exports = { sendDigest };
