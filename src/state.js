const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const os = require("os");

// STATE_DIR is always set explicitly in production (see docker-compose.yml).
// When it isn't - local/test runs - default to a directory unique to this
// process, so concurrent test-runner processes never race on the same file.
const DATA_DIR = process.env.STATE_DIR || path.join(os.tmpdir(), `sentinel-${process.pid}`);
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new DatabaseSync(path.join(DATA_DIR, "sentinel.sqlite"));
db.exec("PRAGMA journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS vuln_findings (
        target TEXT NOT NULL,
        vuln_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT,
        detail TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        resolved_at TEXT,
        PRIMARY KEY (target, vuln_id)
    );

    CREATE TABLE IF NOT EXISTS cpu_samples (
        container TEXT NOT NULL,
        cpu_percent REAL NOT NULL,
        sampled_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_cpu_samples_container
        ON cpu_samples (container, sampled_at);

    CREATE TABLE IF NOT EXISTS anomaly_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT,
        occurred_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_anomaly_events_occurred
        ON anomaly_events (occurred_at);

    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        findings_count INTEGER,
        error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_scan_runs_type_started
        ON scan_runs (scan_type, started_at);

    CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

// CREATE TABLE IF NOT EXISTS above doesn't retroactively add columns to a
// table that already existed (production had vuln_findings before title/
// detail/resolved_at existed) - migrate those in explicitly.
const existingColumns = new Set(
    db.prepare("PRAGMA table_info(vuln_findings)").all().map((c) => c.name)
);
for (const [name, ddl] of [
    ["title", "ALTER TABLE vuln_findings ADD COLUMN title TEXT"],
    ["detail", "ALTER TABLE vuln_findings ADD COLUMN detail TEXT"],
    ["resolved_at", "ALTER TABLE vuln_findings ADD COLUMN resolved_at TEXT"],
]) {
    if (!existingColumns.has(name)) db.exec(ddl);
}

function getKv(key, fallback) {
    const row = db.prepare("SELECT value FROM kv WHERE key = ?").get(key);
    return row ? row.value : fallback;
}

function setKv(key, value) {
    db.prepare(
        "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).run(key, String(value));
}

/**
 * Records findings for a target, returning only the ones not seen before
 * (so the caller only alerts on genuinely new vulnerabilities). A finding
 * that was previously resolved and has now reappeared counts as new too -
 * a regression is exactly the kind of thing that should alert.
 */
function recordFindings(target, findings) {
    const now = new Date().toISOString();
    const isFirstScan =
        db.prepare("SELECT 1 FROM vuln_findings WHERE target = ? LIMIT 1").get(target) === undefined;

    const getExisting = db.prepare(
        "SELECT resolved_at FROM vuln_findings WHERE target = ? AND vuln_id = ?"
    );
    const upsert = db.prepare(`
        INSERT INTO vuln_findings (target, vuln_id, severity, title, detail, first_seen, last_seen, resolved_at)
        VALUES (@target, @vuln_id, @severity, @title, @detail, @first_seen, @last_seen, NULL)
        ON CONFLICT(target, vuln_id) DO UPDATE SET
            severity = excluded.severity,
            title = excluded.title,
            detail = excluded.detail,
            last_seen = excluded.last_seen,
            resolved_at = NULL
    `);

    // A target's very first scan establishes a silent baseline rather than
    // alerting on everything at once - only genuinely new findings from the
    // second scan onward should page anyone.
    const newFindings = [];
    db.exec("BEGIN");
    try {
        for (const f of findings) {
            const existing = getExisting.get(target, f.id);
            const isNew = !existing || existing.resolved_at !== null;
            if (isNew && !isFirstScan) newFindings.push(f);
            upsert.run({
                target,
                vuln_id: f.id,
                severity: f.severity,
                title: f.title ?? null,
                detail: f.detail ?? null,
                first_seen: now,
                last_seen: now,
            });
        }
        db.exec("COMMIT");
    } catch (err) {
        db.exec("ROLLBACK");
        throw err;
    }
    return newFindings;
}

/** Marks findings for a target that weren't present in the latest scan as resolved (fixed) - keeps history instead of deleting it. */
function pruneStaleFindings(target, currentVulnIds) {
    const rows = db
        .prepare("SELECT vuln_id FROM vuln_findings WHERE target = ? AND resolved_at IS NULL")
        .all(target);
    const resolve = db.prepare(
        "UPDATE vuln_findings SET resolved_at = ? WHERE target = ? AND vuln_id = ?"
    );
    const now = new Date().toISOString();
    const currentSet = new Set(currentVulnIds);
    for (const row of rows) {
        if (!currentSet.has(row.vuln_id)) resolve.run(now, target, row.vuln_id);
    }
}

function recordCpuSample(container, cpuPercent) {
    db.prepare("INSERT INTO cpu_samples (container, cpu_percent, sampled_at) VALUES (?, ?, ?)").run(
        container,
        cpuPercent,
        new Date().toISOString()
    );
}

/** Returns the most recent `n` CPU samples for a container, newest first. */
function recentCpuSamples(container, n) {
    return db
        .prepare(
            "SELECT cpu_percent, sampled_at FROM cpu_samples WHERE container = ? ORDER BY sampled_at DESC LIMIT ?"
        )
        .all(container, n);
}

/** Keeps the cpu_samples table from growing forever. */
function pruneOldCpuSamples(olderThanHours = 6) {
    const cutoff = new Date(Date.now() - olderThanHours * 3600 * 1000).toISOString();
    db.prepare("DELETE FROM cpu_samples WHERE sampled_at < ?").run(cutoff);
}

/** Persists an anomaly-scan finding (severity/title/detail) for dashboard history. */
function recordAnomalyEvent(finding) {
    db.prepare(
        "INSERT INTO anomaly_events (severity, title, detail, occurred_at) VALUES (?, ?, ?, ?)"
    ).run(finding.severity, finding.title, finding.detail ?? null, new Date().toISOString());
}

/** Starts tracking a scan run, returning its id for finishScanRun(). */
function startScanRun(scanType) {
    const result = db
        .prepare("INSERT INTO scan_runs (scan_type, started_at) VALUES (?, ?)")
        .run(scanType, new Date().toISOString());
    return result.lastInsertRowid;
}

/** Marks a scan run complete - call with the id returned by startScanRun(). */
function finishScanRun(id, { findingsCount = null, error = null } = {}) {
    db.prepare(
        "UPDATE scan_runs SET finished_at = ?, findings_count = ?, error = ? WHERE id = ?"
    ).run(new Date().toISOString(), findingsCount, error, id);
}

// --- Read-only queries - safe for the dashboard to call. Never call the
// write functions above from dashboard code; see src/dashboard/server.js. ---

/** All currently-unresolved vulnerability findings, newest first. */
function getActiveFindings() {
    return db
        .prepare(
            "SELECT target, vuln_id, severity, title, detail, first_seen, last_seen FROM vuln_findings WHERE resolved_at IS NULL ORDER BY last_seen DESC"
        )
        .all();
}

/** Recently resolved vulnerability findings, most recently resolved first. */
function getResolvedFindings(limit = 50) {
    return db
        .prepare(
            "SELECT target, vuln_id, severity, title, detail, first_seen, resolved_at FROM vuln_findings WHERE resolved_at IS NOT NULL ORDER BY resolved_at DESC LIMIT ?"
        )
        .all(limit);
}

/** Recent anomaly-scan findings, newest first. */
function getRecentAnomalyEvents(limit = 100) {
    return db
        .prepare(
            "SELECT severity, title, detail, occurred_at FROM anomaly_events ORDER BY occurred_at DESC LIMIT ?"
        )
        .all(limit);
}

/** Recent scan runs (both vuln and anomaly), newest first. */
function getRecentScanRuns(limit = 20) {
    return db
        .prepare(
            "SELECT scan_type, started_at, finished_at, findings_count, error FROM scan_runs ORDER BY started_at DESC LIMIT ?"
        )
        .all(limit);
}

/** The single most recent CPU sample for every container that has one. */
function getLatestCpuByContainer() {
    return db
        .prepare(
            `SELECT container, cpu_percent, sampled_at FROM cpu_samples c1
             WHERE sampled_at = (SELECT MAX(sampled_at) FROM cpu_samples c2 WHERE c2.container = c1.container)
             ORDER BY container`
        )
        .all();
}

module.exports = {
    recordFindings,
    pruneStaleFindings,
    recordCpuSample,
    recentCpuSamples,
    pruneOldCpuSamples,
    recordAnomalyEvent,
    startScanRun,
    finishScanRun,
    getActiveFindings,
    getResolvedFindings,
    getRecentAnomalyEvents,
    getRecentScanRuns,
    getLatestCpuByContainer,
    getKv,
    setKv,
};
