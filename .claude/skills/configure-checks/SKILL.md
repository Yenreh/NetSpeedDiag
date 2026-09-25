---
name: configure-checks
description: Configure what NetSpeedDiag measures - add or disable download/upload targets, TCP/HTTPS/SSH/DNS service checks (e.g. the user's own servers or droplets), ping and route targets, profiles, plan speeds and analysis thresholds, or adapt the catalog to another ISP or city. Use when the user wants to test a specific server, protocol or port, add their cloud hosts, or tune what counts as a problem.
---

# Configure checks

Work from the repository root. Read the "Configuration" section of `AGENTS.md` first.

## Where changes go

| Change | File |
|---|---|
| Generic targets, checks, profiles, thresholds | `config/tests.json` (versioned) |
| Private hosts, user names, personal overrides | `config/tests.local.json` (gitignored; start from `config/tests.local.example.json`) |
| Plan speeds, port, default profile | `.env` (`NSD_PLAN_DOWNLOAD_MBPS`, `NSD_PLAN_UPLOAD_MBPS`, ...) |

Never put private IPs, user names or key paths in `config/tests.json`.

`tests.local.json` merges on top by `id`: an entry with an existing id overrides only the
fields it sets (`{"id": "ovh-europe", "enabled": false}`); a new id is appended. Plain lists
(e.g. `route.targets`, `names`) replace the base list entirely, so copy the base values.

## Service check recipes (`services.checks`)

```json
{"id": "droplet-ssh", "type": "ssh", "name": "Droplet NYC (SSH)", "host": "203.0.113.10",
 "user": "root", "identity_file": "~/.ssh/id_ed25519", "auth": true, "throughput_mb": 50,
 "category": "cloud"}
{"id": "app-https", "type": "https", "name": "My app", "host": "app.example.com", "path": "/health", "category": "cloud"}
{"id": "db-tcp", "type": "tcp", "name": "Postgres", "host": "203.0.113.10", "port": 5432, "category": "cloud"}
{"id": "dns", "type": "dns", "servers": ["@system", "@gateway", "1.1.1.1", {"name": "ISP DNS", "address": "200.x.x.x"}],
 "names": ["google.com", "github.com"]}
```

- `ssh` without `auth` only reads the server banner (no login). With `auth: true` it runs
  `ssh -o BatchMode=yes` using the user's keys/agent and never prompts. Before enabling it,
  confirm with the user and make sure the host key is already known (the user logs in once
  manually), otherwise the check reports "Host key verification failed".
- `category: "cloud"` feeds the cloud latency metric and the dashboard Cloud column.
- Optional per check: `count`, `interval_seconds`, `timeout_seconds`, `enabled`.

## Throughput targets (`download.targets` / `upload.targets`)

- `static`: `url` of a large file (the stream re-requests it until the test ends).
- `ookla`: `host` (`name:port`) or `search` (`@city`, `@country` or text) + `index`.
- `fastcom`: `server_index` (0 = nearest), `category: "auto"`.
- Categories: `isp-cache`, `local`, `national`, `international`, `cdn` (anycast, nearest edge), `cloud`.
  The default catalog is written from a Latin America point of view: fixed US/EU servers are
  `international`; override categories by id in `config/tests.local.json` if that does not fit.
- Add route/ping targets for new hosts too (`route.targets`, `ping.targets`) when latency
  per hop matters.

Verify a new URL before adding it: `curl -s -o /dev/null -w "%{http_code} %{size_download}\n"
--max-time 5 -r 0-1000000 <url>` should return 200/206 with data. Some servers rate limit
large parallel downloads (HTTP 403/429); prefer files of 25-100 MB.

## Thresholds (`analysis`)

All finding thresholds are in `config/tests.json` -> `analysis` (defaults in
`netspeeddiag/analyzer.py` `DEFAULT_THRESHOLDS`). After changing them or the plan, apply to
stored runs: `.venv/bin/python main.py reanalyze`.

## Validate

```bash
.venv/bin/python -c "from netspeeddiag.settings import load_settings as l; s=l(); [s.resolve_profile(p) for p in s.profile_names()]; print('catalog ok')"
.venv/bin/python -m unittest discover -s tests
.venv/bin/python main.py run -p quick -l config-check --brief     # only if the user agrees to run traffic
```
