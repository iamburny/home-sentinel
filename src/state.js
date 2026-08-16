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
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (target, vuln_id)
    );

    CREATE TABLE IF NOT EXISTS cpu_samples (
        container TEXT NOT NULL,
        cpu_percent REAL NOT NULL,
        sampled_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_cpu_samples_container
        ON cpu_samples (container, sampled_at);

    CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

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
 * (so the caller only alerts on genuinely new vulnerabilities).
 */
function recordFindings(target, findings) {
    const now = new Date().toISOString();
    const isFirstScan =
        db.prepare("SELECT 1 FROM vuln_findings WHERE target = ? LIMIT 1").get(target) === undefined;

    const getExisting = db.prepare(
        "SELECT vuln_id FROM vuln_findings WHERE target = ? AND vuln_id = ?"
    );
    const upsert = db.prepare(`
        INSERT INTO vuln_findings (target, vuln_id, severity, first_seen, last_seen)
        VALUES (@target, @vuln_id, @severity, @first_seen, @last_seen)
        ON CONFLICT(target, vuln_id) DO UPDATE SET last_seen = excluded.last_seen
    `);

    // A target's very first scan establishes a silent baseline rather than
    // alerting on everything at once - only genuinely new findings from the
    // second scan onward should page anyone.
    const newFindings = [];
    db.exec("BEGIN");
    try {
        for (const f of findings) {
            const existing = getExisting.get(target, f.id);
            if (!existing && !isFirstScan) newFindings.push(f);
            upsert.run({
                target,
                vuln_id: f.id,
                severity: f.severity,
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

/** Drops findings for a target that weren't present in the latest scan (fixed). */
function pruneStaleFindings(target, currentVulnIds) {
    const rows = db.prepare("SELECT vuln_id FROM vuln_findings WHERE target = ?").all(target);
    const del = db.prepare("DELETE FROM vuln_findings WHERE target = ? AND vuln_id = ?");
    const currentSet = new Set(currentVulnIds);
    for (const row of rows) {
        if (!currentSet.has(row.vuln_id)) del.run(target, row.vuln_id);
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

module.exports = {
    recordFindings,
    pruneStaleFindings,
    recordCpuSample,
    recentCpuSamples,
    pruneOldCpuSamples,
    getKv,
    setKv,
};
