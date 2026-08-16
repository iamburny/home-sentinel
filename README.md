# home-sentinel

Vulnerability and runtime compromise monitoring for everything running on
the home server. Built after a cryptominer sat undetected on `collecterly`
for weeks, exploiting a critical, 11-month-unpatched Next.js RCE. Nothing on
the server was watching for either of those things - this closes that gap.

## What it does

Two scans, on independent schedules:

- **Vulnerability scan** (daily, `VULN_SCAN_CRON`): runs [Trivy](https://trivy.dev)
  against every project's source (dependency CVEs + leaked secrets) and
  against every running container's actual image (catches vendor images with
  no source on disk, like Joplin or Jellyfin, and catches drift between
  source and what's actually deployed). Also flags any image older than
  `staleImageDays` (default 90) as likely carrying unpatched CVEs.
- **Anomaly scan** (every 5 min, `ANOMALY_SCAN_CRON`): checks for the specific
  signals that would have caught the actual incident - sustained absurd CPU
  per container, a process executing from `/tmp`/`/var/tmp`/`/dev/shm`, a
  newly-exposed `0.0.0.0` port not on the approved list, or a successful SSH
  login from outside the LAN.

Findings are batched and posted to Slack. Only *new* findings trigger an
alert (state is tracked in SQLite) - you won't get paged for the same known
issue every cycle. This is alert-only: it never takes automatic action.

## Setup

1. Copy `.env.example` to `.env` and fill in `SLACK_WEBHOOK_URL` (Slack ->
   Apps -> Incoming Webhooks - use a dedicated one for infra alerts, separate
   from any app's own logging webhook).
2. Adjust `LAN_CIDR` if your local network isn't `192.168.1.0/24`.
3. `./deploy.sh`

## Adding a new project

Edit `src/config.js`:
- If it has source on disk, add it to `fsScanProjects` and add a matching
  read-only volume mount in `docker-compose.yml` under `/projects/<name>`.
  It'll then get both a filesystem scan (dependencies/secrets) *and* an
  image scan automatically, once it's running as a container.
- If it's a vendor image only (no source you control), it's picked up
  automatically for image scanning and staleness checks - nothing to add.
- If it legitimately runs hot on CPU, add an entry to
  `anomaly.cpuThresholdOverrides`.
- If it needs a new public port, add it to `anomaly.approvedPublicPorts`
  *after* confirming that's actually intentional - that's exactly the check
  that would have caught Redis being exposed unauthenticated.

## Why a docker-socket-proxy instead of mounting `/var/run/docker.sock` directly

Direct socket access is root-equivalent host control - if this container were
ever compromised, that access would undo every other hardening step in this
project. `docker-socket-proxy` sits in front of the real socket and only
allows the specific read-only endpoints this service actually needs
(container/image listing, image inspect, stats) - no create, no exec, no
delete. See `docker-compose.yml` for the exact permission set.

## Known limitations

- Anomaly detection is heuristic, not exhaustive. It catches the *pattern*
  of this specific incident well; it isn't a substitute for keeping
  dependencies patched, which the vulnerability scanner half addresses.
- The approved-ports and CPU-override lists need occasional manual upkeep
  as new services are added - see above.
