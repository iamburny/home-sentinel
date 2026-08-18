const path = require("path");
const express = require("express");
const { basicAuth } = require("./auth");
const { timeAgo } = require("./format");
const state = require("../state");
const config = require("../config");

const PORT = Number(process.env.DASHBOARD_PORT || 3099);
const DASHBOARD_USER = process.env.DASHBOARD_USER || "admin";
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_TYPES = ["vuln", "anomaly"];

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(basicAuth(DASHBOARD_USER, DASHBOARD_PASSWORD));
app.locals.timeAgo = timeAgo;

/** Whether a target has a "Fix with Claude" routine configured (id + token both set). */
function fixEnabledFor(target) {
    const project = config.fsScanProjects.find((p) => p.name === target);
    return Boolean(project?.fixRoutineId && project?.fixRoutineToken);
}

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

/** Collapses a batch of fix_requests rows sharing a batch_id into one summary row for the overview panel. */
function groupFixes(rows) {
    const byBatch = new Map();
    for (const r of rows) {
        const key = r.batch_id || `solo:${r.id}`;
        if (!byBatch.has(key)) byBatch.set(key, []);
        byBatch.get(key).push(r);
    }
    return [...byBatch.values()].map((group) => ({
        target: group[0].target,
        vulnId: group.length === 1 ? group[0].vuln_id : null,
        title: group.length === 1 ? group[0].title || group[0].vuln_id : `${group.length} findings`,
        status: group[0].status,
        requested_at: group[0].requested_at,
        started_at: group[0].started_at,
        session_url: group[0].session_url,
    }));
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
        activeFixes: groupFixes(state.getActiveFixRequests()),
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
        fixEnabledFor,
    });
});

// Single-finding review page - the safe, unfurl-friendly GET that Slack
// alerts and findings-list rows link to. Firing a fix only ever happens via
// the POST /fix form below, never from loading this page.
app.get("/findings/view", (req, res) => {
    const { target, vuln } = req.query;
    const finding = [...state.getActiveFindings(), ...state.getResolvedFindings(500)].find(
        (f) => f.target === target && f.vuln_id === vuln
    );
    if (!finding) {
        res.status(404).render("finding", { activePage: "findings", finding: null, fixRequest: null, fixEnabled: false });
        return;
    }

    res.render("finding", {
        activePage: "findings",
        finding,
        fixRequest: state.getFixRequestForFinding(target, vuln),
        fixEnabled: fixEnabledFor(target),
    });
});

// The dashboard's second deliberate write (alongside POST /scan/:type):
// queues a "fix this finding with Claude" request for sentinel's poll loop
// to fire (see requestFix in src/state.js). Never calls the routine API
// directly - see src/fixTrigger.js and src/index.js.
app.post("/fix", (req, res) => {
    const { target, vuln } = req.body;
    const finding = state.getActiveFindings().find((f) => f.target === target && f.vuln_id === vuln);
    if (finding && fixEnabledFor(target)) {
        state.requestFix(target, vuln, {
            severity: finding.severity,
            title: finding.title,
            detail: finding.detail,
        });
    }
    res.redirect(`/findings/view?target=${encodeURIComponent(target)}&vuln=${encodeURIComponent(vuln)}`);
});

// Bulk version of POST /fix: queues one batch covering every checked finding
// for a single target, so sentinel fires them in one routine call instead of
// one per finding. Same deliberate write exception as POST /fix - see
// requestFixBatch in src/state.js.
app.post("/fix/batch", (req, res) => {
    const { target } = req.body;
    const vulnIds = [].concat(req.body.vuln || []);

    if (vulnIds.length > 0 && fixEnabledFor(target)) {
        const activeFindings = state.getActiveFindings();
        const findings = vulnIds
            .map((v) => activeFindings.find((f) => f.target === target && f.vuln_id === v))
            .filter(Boolean)
            .map((f) => ({ vulnId: f.vuln_id, severity: f.severity, title: f.title, detail: f.detail }));
        state.requestFixBatch(target, findings);
    }
    res.redirect(`/findings?target=${encodeURIComponent(target)}`);
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
