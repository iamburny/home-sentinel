const path = require("path");
const express = require("express");
const { basicAuth } = require("./auth");
const { timeAgo } = require("./format");
const state = require("../state");

const PORT = Number(process.env.DASHBOARD_PORT || 3099);
const DASHBOARD_USER = process.env.DASHBOARD_USER || "admin";
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_TYPES = ["vuln", "anomaly"];

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(basicAuth(DASHBOARD_USER, DASHBOARD_PASSWORD));
app.locals.timeAgo = timeAgo;

function severityCounts(findings) {
    const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
    for (const f of findings) {
        const sev = (f.severity || "").toUpperCase();
        counts[sev] = (counts[sev] || 0) + 1;
    }
    return counts;
}

function latestRunByType(runs, scanType) {
    return runs.find((r) => r.scan_type === scanType) || null;
}

app.get("/", (req, res) => {
    const activeFindings = state.getActiveFindings();
    const recentRuns = state.getRecentScanRuns(20);
    const latestCpu = state.getLatestCpuByContainer();

    res.render("overview", {
        activePage: "overview",
        severityCounts: severityCounts(activeFindings),
        totalActive: activeFindings.length,
        lastVulnRun: latestRunByType(recentRuns, "vuln"),
        lastAnomalyRun: latestRunByType(recentRuns, "anomaly"),
        latestCpu,
        vulnScanPending: state.getScanRequestStatus("vuln").pending,
        anomalyScanPending: state.getScanRequestStatus("anomaly").pending,
    });
});

// The one state-changing route the dashboard exposes: queues a manual scan
// request for sentinel's poll loop to pick up (see requestScan in
// src/state.js). Never touches findings/anomaly data directly.
app.post("/scan/:type", (req, res) => {
    const { type } = req.params;
    if (SCAN_TYPES.includes(type)) {
        state.requestScan(type);
    }
    res.redirect("/");
});

app.get("/findings", (req, res) => {
    const showResolved = req.query.resolved === "1";
    const severityFilter = (req.query.severity || "").toUpperCase();
    const targetFilter = req.query.target || "";

    let findings = showResolved ? state.getResolvedFindings(200) : state.getActiveFindings();
    if (severityFilter) findings = findings.filter((f) => f.severity?.toUpperCase() === severityFilter);
    if (targetFilter) findings = findings.filter((f) => f.target === targetFilter);

    const allTargets = [...new Set(state.getActiveFindings().map((f) => f.target))].sort();

    res.render("findings", {
        activePage: "findings",
        findings,
        showResolved,
        severityFilter,
        targetFilter,
        allTargets,
        severityOrder: SEVERITY_ORDER,
    });
});

app.get("/events", (req, res) => {
    res.render("events", {
        activePage: "events",
        events: state.getRecentAnomalyEvents(200),
    });
});

app.listen(PORT, () => {
    console.log(`[dashboard] listening on :${PORT}`);
});
