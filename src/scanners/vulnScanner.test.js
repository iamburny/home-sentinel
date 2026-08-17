const test = require("node:test");
const assert = require("node:assert/strict");
const { extractFindings, toAlert } = require("./vulnScanner");

test("extractFindings: pulls vulnerabilities out of a Trivy report", () => {
    const report = {
        Results: [
            {
                Target: "package-lock.json",
                Vulnerabilities: [
                    {
                        VulnerabilityID: "GHSA-9qr9-h5gf-34mp",
                        Severity: "CRITICAL",
                        Title: "Next.js RCE in React Flight protocol",
                        PkgName: "next",
                        InstalledVersion: "15.5.4",
                        FixedVersion: "15.5.7",
                    },
                ],
            },
        ],
    };
    const findings = extractFindings(report);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].id, "GHSA-9qr9-h5gf-34mp");
    assert.equal(findings[0].severity, "CRITICAL");
    assert.match(findings[0].detail, /next 15\.5\.4/);
    assert.match(findings[0].detail, /15\.5\.7/);
});

test("extractFindings: pulls leaked secrets out of a Trivy report", () => {
    const report = {
        Results: [
            {
                Target: "docker-compose.yml",
                Secrets: [{ RuleID: "generic-password", Title: "Hardcoded password", Severity: "HIGH", StartLine: 50 }],
            },
        ],
    };
    const findings = extractFindings(report);
    assert.equal(findings.length, 1);
    assert.match(findings[0].id, /^secret:docker-compose\.yml:generic-password:50$/);
    assert.equal(findings[0].severity, "HIGH");
    assert.match(findings[0].detail, /docker-compose\.yml:50/);
});

test("extractFindings: returns an empty list for a clean report", () => {
    assert.deepEqual(extractFindings({ Results: [{ Target: "x" }] }), []);
    assert.deepEqual(extractFindings({}), []);
});

test("toAlert: prefixes the finding id with the scope label and passes detail through", () => {
    const alert = toAlert("www.collecterly.com", {
        id: "GHSA-9qr9-h5gf-34mp",
        severity: "CRITICAL",
        title: "Next.js RCE",
        detail: "Next.js RCE\nnext 15.5.4 → fix: 15.5.7",
    });
    assert.equal(alert.severity, "CRITICAL");
    assert.equal(alert.title, "[www.collecterly.com] GHSA-9qr9-h5gf-34mp");
    assert.match(alert.detail, /next 15\.5\.4/);
    assert.match(alert.detail, /15\.5\.7/);
});

test("toAlert: formats a secret finding the same way", () => {
    const alert = toAlert("api.collecterly.com", {
        id: "secret:docker-compose.yml:generic-password:50",
        severity: "HIGH",
        title: "Leaked secret: Hardcoded password",
        detail: "Leaked secret: Hardcoded password (docker-compose.yml:50)",
    });
    assert.match(alert.detail, /docker-compose\.yml:50/);
});
