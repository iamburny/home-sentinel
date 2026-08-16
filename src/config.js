const dockerHostUrl = new URL(process.env.DOCKER_HOST || "tcp://docker-socket-proxy:2375");

module.exports = {
    slackWebhookUrl: process.env.SLACK_WEBHOOK_URL,
    lanCidr: process.env.LAN_CIDR || "192.168.1.0/24",
    authLogPath: process.env.AUTH_LOG_PATH || "/var/log/auth.log",
    // DOCKER_HOST itself (tcp://host:port) is read directly by Trivy via the
    // process environment. These are pre-parsed for our own dockerode client.
    dockerHostName: dockerHostUrl.hostname,
    dockerHostPort: Number(dockerHostUrl.port),

    // Projects with source on disk to filesystem-scan for dependency CVEs and
    // leaked secrets. `path` is where each is bind-mounted read-only inside
    // this container - see docker-compose.yml.
    fsScanProjects: [
        { name: "api.collecterly.com", path: "/projects/api.collecterly.com" },
        { name: "www.collecterly.com", path: "/projects/www.collecterly.com" },
        { name: "fuel-web", path: "/projects/fuel-web" },
        { name: "fuel-admin", path: "/projects/fuel-admin" },
        { name: "fuel-api", path: "/projects/fuel-api" },
        { name: "unleash", path: "/projects/unleash" },
        { name: "simple-proxy", path: "/projects/simple-proxy" },
        { name: "www.burny.uk", path: "/projects/www.burny.uk" },
        { name: "joplin-server", path: "/projects/joplin-server" },
    ],

    // Image age past which we flag "stale - likely carrying unpatched CVEs".
    // The collecterly image was 11 months old when it was compromised.
    staleImageDays: 90,

    vulnScanCron: process.env.VULN_SCAN_CRON || "0 4 * * *", // daily 04:00
    anomalyScanCron: process.env.ANOMALY_SCAN_CRON || "*/5 * * * *", // every 5 min

    anomaly: {
        // Sustained CPU % (100% = 1 full core) above which we alert, once
        // `sustainedSamples` consecutive 5-minute samples all exceed it.
        // The collecterly miner ran at 600%+ continuously for hours - a
        // single momentary spike should never page anyone.
        defaultCpuThreshold: 200,
        sustainedSamples: 3,
        cpuThresholdOverrides: {
            jellyfin: 600, // transcoding
            hytale: 400,
            "minecraft-docker-2-mc-1": 400,
        },

        // No legitimate long-running server process executes its binary from
        // an ephemeral/world-writable location. This is the exact pattern
        // the incident's miner used (/tmp/.ICEi-unix/javae) - a directory
        // named to *look* like a real X11 socket dir at a glance, but actual
        // socket dirs never contain executables, so path-based detection
        // isn't fooled by the disguise the way a human skimming `ls` is.
        suspiciousExecPathPatterns: [/^\/tmp\//, /^\/var\/tmp\//, /^\/dev\/shm\//],

        // 0.0.0.0-bound ports considered expected. Anything not in this list
        // showing up as publicly bound triggers an alert. Seeded from the
        // server's state as of 2026-08-16, post-hardening (db/redis/postgres
        // now loopback-only - if any of those reappear here, that's a real
        // regression and should alert).
        approvedPublicPorts: [
            22, 80, 443, 8080, // ssh, traefik http/https, traefik dashboard
            3001, // uptime-kuma
            8096, 1900, 7359, // jellyfin (http, dlna)
            8123, 8124, // collecterlyapp, collecterly
            8130, 8131, // burny, joplin
            8200, 8201, 8202, 8203, // fuel-api, fuel-web, fuel-admin, unleash
            8030, // simple-proxy
            25566, 5520, // minecraft, hytale
        ],
    },
};
