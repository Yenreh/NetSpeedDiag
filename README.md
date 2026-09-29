# NetSpeedDiag

Repeatable diagnostics for a home internet line. Each run measures latency, packet loss,
routes and throughput (single vs parallel connections, ISP cache vs same city vs
international), stores everything as JSON and produces automatic findings. Runs can be
compared, for example before and after connecting directly to the ISP modem.

## Setup

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.template .env        # set NSD_PLAN_DOWNLOAD_MBPS / NSD_PLAN_UPLOAD_MBPS
```

System tools used: `ping`, `mtr` (optional, for routes and double-NAT detection).
No root needed.

## Usage

```bash
.venv/bin/python main.py                    # dashboard at http://127.0.0.1:7072/
.venv/bin/python main.py run -p quick -l via-router -n "evening"
.venv/bin/python main.py repeat -e 30 -c 24 -l day-profile   # quick run every 30 min, 12 h
.venv/bin/python main.py list [-n 10] [--json]
.venv/bin/python main.py show latest [--brief | --json]      # also "previous" or a run id
.venv/bin/python main.py compare previous latest [--json]
.venv/bin/python main.py reanalyze          # recompute findings (e.g. after setting the plan)
.venv/bin/python -m unittest discover -s tests
```

Profiles (`config/tests.json`): `quick` (~2 min), `standard` (~6 min), `full` (~10 min,
adds 8 streams). Only one run executes at a time, also across processes (dashboard and
terminal share a lock file).

## What is measured

| Step | Detail |
|---|---|
| System context | Interface (wired/Wi-Fi, link speed, errors), TCP congestion control, DNS, public IP / ASN, first hops (double NAT) |
| Idle latency | `ping` to gateway, 1.1.1.1, 8.8.8.8, fast.com: loss, avg, p95, jitter |
| Routes | `mtr` per-hop loss and latency with ASN |
| Download | Each target with 1 and N parallel TCP connections: steady rate (after warm-up), peak, per stream, TTFB, out-of-order packet share |
| Upload | Same, rate taken from interface counters (send buffers would inflate app-level counts) |
| Services | Optional protocol checks: `tcp`, `https` (TCP/TLS/TTFB), `ssh` (banner; login and throughput with your keys), `dns` (per resolver) |
| Latency under load | Ping while saturating download and upload (bufferbloat, loss under load) |

Target categories: `isp-cache` (Netflix cache embedded in your own ISP), `local` (same city,
other ISPs), `national`, `international`, `cdn` (anycast edges such as Cloudflare), `cloud`.
The default catalog treats the fixed US/EU servers as `international`; override by id if you
are in those regions.
Target types: `static` URL, `ookla` (fixed host or search), `fastcom` (scraped token + API).

## Configuring for another setup

Everything setup-specific lives in `config/tests.json`; nothing about the ISP is hardcoded.

- Placeholders: `@gateway` (default router), `@system` (first resolver in `/etc/resolv.conf`),
  and in Ookla searches `@city` / `@country` (location of the public IP), e.g.
  `{"id": "ookla-local", "type": "ookla", "search": "@city", "index": 0, "category": "local"}`.
- `"category": "auto"` on fast.com targets: `isp-cache` when the Netflix cache belongs to your
  own ISP (matched against the public IP reverse DNS / ASN), else `national` / `international`.
- `analysis`: every finding threshold (loss, bufferbloat, plan ratios, per-flow ratio, DNS...).
- `labels`: suggestions shown in the dashboard label field.
- `config/tests.local.json` (not versioned, see `config/tests.local.example.json`): merged on
  top of the catalog. Lists of objects with an `id` merge by id: same id overrides fields
  (e.g. `{"id": "cloudflare", "enabled": false}`), a new id is added. Put private hosts here.

## Service checks

```json
{"id": "droplet-ssh", "type": "ssh", "host": "203.0.113.10", "user": "root",
 "identity_file": "~/.ssh/id_ed25519", "auth": true, "throughput_mb": 50, "category": "cloud"}
```

- `tcp`: `host`, `port`. Repeated handshakes (works where ICMP is blocked).
- `https`: `host`, optional `port`, `path`. Connect, TLS and time to first byte.
- `ssh`: `host`, optional `port`. Without `auth` only the server banner is read (no login).
  With `auth: true` it logs in with `ssh -o BatchMode=yes` (keys/agent, never prompts; log in
  once manually to accept the host key); `throughput_mb` streams that many MB down and up.
- `dns`: `servers` (IPs, `@system`, `@gateway`, or `{"name", "address"}`), `names`.

Common keys: `id`, `name`, `category` (`cloud` feeds the cloud latency metric), `count`,
`interval_seconds`, `timeout_seconds`, `enabled`. DigitalOcean's public speed-test hosts no
longer exist; the default catalog checks the Spaces endpoint of several DO regions (inside
each datacenter) for latency and TLS. Real DO throughput needs your own droplet (SSH check).

## Using it with an AI agent

`AGENTS.md` describes the tool, the rules for running measurements and how to interpret
findings (`CLAUDE.md` imports it). Claude Code project skills live in `.claude/skills/`:
`diagnose-line` (run, interpret, compare, write evidence for the ISP) and
`configure-checks` (targets, service checks, thresholds). `--brief` / `--json` outputs are
clean JSON on stdout for agents.

## Data

- `data/results/<run-id>.json`: full run document, saved after every step.
- `GET /api/runs.csv`: one row per run with the headline metrics.
- `logs/netspeeddiag.log`: application log.

## Layout

```
main.py                     CLI (argparse)
config/tests.json           targets, durations, profiles
netspeeddiag/settings.py    .env loading, profile merge, logging
netspeeddiag/system_probe.py  interface / TCP stack / public IP / kernel counters
netspeeddiag/latency_probe.py ping, background ping, mtr
netspeeddiag/targets.py     static / Ookla / fast.com target resolution
netspeeddiag/throughput.py  multi-stream HTTP download/upload engine
netspeeddiag/service_probe.py  tcp / https / ssh / dns checks
netspeeddiag/analyzer.py    headline metrics and findings (pure functions)
netspeeddiag/runner.py      run orchestration and progress
netspeeddiag/store.py       JSON result store and CSV export
netspeeddiag/web.py         Flask API
netspeeddiag/templates/index.html  dashboard (vanilla JS, inline SVG charts)
```

## License

MIT, see `LICENSE`.
