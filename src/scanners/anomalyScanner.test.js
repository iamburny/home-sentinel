const test = require("node:test");
const assert = require("node:assert/strict");
const { ipInCidr, cpuPercentFromStats } = require("./anomalyScanner");

test("ipInCidr: matches addresses inside the range", () => {
    assert.equal(ipInCidr("192.168.1.196", "192.168.1.0/24"), true);
    assert.equal(ipInCidr("192.168.1.1", "192.168.1.0/24"), true);
    assert.equal(ipInCidr("192.168.1.255", "192.168.1.0/24"), true);
});

test("ipInCidr: rejects addresses outside the range", () => {
    assert.equal(ipInCidr("192.168.2.1", "192.168.1.0/24"), false);
    assert.equal(ipInCidr("154.57.209.199", "192.168.1.0/24"), false);
    assert.equal(ipInCidr("10.0.0.1", "192.168.1.0/24"), false);
});

test("ipInCidr: handles non-IPv4 input safely (treated as non-LAN)", () => {
    assert.equal(ipInCidr("not-an-ip", "192.168.1.0/24"), false);
    assert.equal(ipInCidr("::1", "192.168.1.0/24"), false);
});

test("ipInCidr: /32 matches only the exact address", () => {
    assert.equal(ipInCidr("192.168.1.5", "192.168.1.5/32"), true);
    assert.equal(ipInCidr("192.168.1.6", "192.168.1.5/32"), false);
});

test("cpuPercentFromStats: computes sustained-high-CPU-like percentage correctly", () => {
    // Mirrors the real incident's signature: one container eating ~6.5 cores.
    const stats = {
        cpu_stats: {
            cpu_usage: { total_usage: 1_000_000_000 },
            system_cpu_usage: 10_000_000_000,
            online_cpus: 8,
        },
        precpu_stats: {
            cpu_usage: { total_usage: 0 },
            system_cpu_usage: 9_000_000_000,
        },
    };
    // cpuDelta=1e9, systemDelta=1e9, cpus=8 -> 100% * 8 = 800%
    assert.equal(cpuPercentFromStats(stats), 800);
});

test("cpuPercentFromStats: returns 0 for a bogus/first sample (no system delta)", () => {
    const stats = {
        cpu_stats: { cpu_usage: { total_usage: 100 }, system_cpu_usage: 100, online_cpus: 4 },
        precpu_stats: { cpu_usage: { total_usage: 100 }, system_cpu_usage: 100 },
    };
    assert.equal(cpuPercentFromStats(stats), 0);
});
