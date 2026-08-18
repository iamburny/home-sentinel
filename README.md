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
issue every cycle. Detection is automatic; fixing is not - nothing here ever
changes a repo or a running container on its own. The one opt-in exception
is the dashboard's "Fix with Claude" button (see below), and even that only
starts a Claude Code session that opens a PR for you to review - it never
merges anything itself.

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

## Dashboard and "Fix with Claude"

A LAN-only dashboard (`http://<server-lan-ip>:3099`, HTTP Basic Auth) shows
open/resolved findings, anomaly history, and scan status, and can trigger a
scan on demand. Each `vuln_findings` entry can also show a "Fix with Claude"
button that starts a real [Claude Code
routine](https://code.claude.com/docs/en/routines) scoped to that one
finding's project - the same link is included in the Slack alert.

To wire up a project (one at a time, whenever convenient - projects without
this configured just don't show the button):

1. At [claude.ai/code/routines](https://claude.ai/code/routines), create a
   routine for the project. Attach only that project's GitHub repo. Write a
   prompt telling Claude to treat the routine-fire payload as the finding to
   act on, apply the minimal fix, push to a `claude/`-prefixed branch, and
   open a **draft** PR - not merge it.
2. Strip the routine's connectors down to none needed - it includes all your
   connected MCP connectors by default.
3. Add an API trigger, generate its token, and copy the routine id (from the
   URL) and the token.
4. Add both to this server's `.env` as `FIX_ROUTINE_<PROJECT>_ID` /
   `FIX_ROUTINE_<PROJECT>_TOKEN` (see `.env.example` for the exact names)
   **directly over your own SSH session** - the token is a system credential
   (write access to that repo via an automated session), not something to
   paste into a chat.
5. `docker compose up -d --build sentinel dashboard` to pick it up.

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
