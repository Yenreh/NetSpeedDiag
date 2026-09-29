# AGENTS.md - NetSpeedDiag

Guidance for AI agents (and humans) working with this repository, either to
diagnose an internet line or to change the code.

## What this is

A local tool that measures a home internet line in a repeatable way and keeps
every run as JSON: system context, idle latency/loss, `mtr` routes, protocol
checks (TCP/HTTPS/SSH/DNS), download/upload with 1 vs N parallel TCP
connections against targets in different network locations (cache inside the
ISP, same city, national, international, cloud), and latency under load. An
analyzer turns each run into headline metrics and findings. A Flask dashboard
and a CLI sit on top.

## Setup

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.template .env                                  # plan speeds, port, paths
cp config/tests.local.example.json config/tests.local.json   # optional, private hosts
```

Always run with `.venv/bin/python` (Python 3.13). Needs `ping`; `mtr` is optional
(routes, NAT detection). No root.

## CLI (agent-friendly)

Logs go to stderr, so stdout of `--json` / `--brief` is clean JSON.

```bash
.venv/bin/python main.py run -p quick -l <label> -n "<notes>" --brief   # ~2 min, prints summary + problems
.venv/bin/python main.py run -p standard -l <label>                     # ~6 min, full report
.venv/bin/python main.py list [-n 10] [--json]
.venv/bin/python main.py show latest [--brief | --json]                 # also "previous" or a run id
.venv/bin/python main.py compare previous latest [--json]               # A = baseline
.venv/bin/python main.py repeat -e 15 [-c 8] -l monitor                 # runs every 15 min
.venv/bin/python main.py reanalyze [RUN_ID ...]                         # after changing thresholds / plan
.venv/bin/python main.py serve                                          # dashboard, http://127.0.0.1:7072/
.venv/bin/python -m unittest discover -s tests
```

Dashboard API: `POST /api/runs {"profile","label","notes"}`, `GET /api/progress`,
`GET /api/runs`, `GET /api/runs/<id>`, `GET /api/runs.csv`, `POST /api/cancel`.

## Rules when running measurements

* A run moves real traffic: a `quick` run on a healthy gigabit line downloads a few GB.
  Do not loop runs without the user asking; prefer `quick` for monitoring.
* Only one run at a time, enforced across processes by `data/results/.run.lock`. If the
  dashboard is running a test, CLI runs fail with "Another NetSpeedDiag process is running
  a test"; wait for `GET /api/progress` -> `running: false`.
* Always pass a meaningful `-l` label (`via-router`, `direct-modem`, `after-isp-fix`...)
  and notes describing what changed; comparisons depend on them.
* SSH checks with `auth: true` log in to the user's servers (BatchMode, keys only). Add or
  enable them only with the user's consent; private hosts go in `config/tests.local.json`.
* The dashboard has no authentication; keep `NSD_HOST=127.0.0.1`.

## Interpreting a run

Headline metrics (`summary`): `best_download_mbps`, `best_single_stream_download_mbps`,
`isp_cache_mbps`, `local_mbps`, `national_mbps`, `international_mbps`, `best_upload_mbps`,
`idle_latency_ms`, `idle_loss_pct`, `loaded_download_bloat_ms`, `loaded_download_loss_pct`,
`service_fail_pct`, `cloud_connect_ms`, `dns_best_ms`, `ssh_download_mbps`/`ssh_upload_mbps`.

Reasoning that has proven useful:

* Upload fine + download bad over the same cable/router: the local side is not the
  bottleneck; the problem is the ISP downstream path.
* Loss while idle with flat latency under load: packets are dropped, not queued. Points to
  a physical-layer problem (fiber signal, faulty port) or a policer, not congestion.
* Loss or heavy bufferbloat to the gateway: fix the LAN (cable, router, Wi-Fi) first.
* 1 connection much slower than N (`PER_FLOW_LIMIT`): loss or per-flow shaping. Ookla
  (many streams, nearby server) hides it; fast.com and real downloads show it.
* `isp_cache_mbps` slow: the Netflix cache sits inside the ISP, so transit and peering are
  excluded; the ISP access/aggregation network is at fault.
* International much slower than local (`INTERNATIONAL`): ISP transit / peering.
* `SYN_RETRANSMIT`, `DNS_FAILURES`: user-visible symptoms of packet loss.
* Intermittent faults: compare runs over time (`repeat`, `compare`) before concluding.
* NAT: `DOUBLE_NAT` counts home gateways (leading private hops that look like LAN
  devices); private hops after them are ISP routers, not NAT. `CGNAT` = 100.64.0.0/10.
  DMZ is invisible from inside (it only affects inbound traffic); bridge mode removes a hop.

Finding codes: `PLAN_DOWNLOAD`, `PLAN_UPLOAD`, `WIFI`, `LINK_SPEED`, `IFACE_ERRORS`,
`DOUBLE_NAT`, `CGNAT`, `GATEWAY_LOSS`, `IDLE_LOSS`, `LOADED_LOSS_DOWNLOAD|UPLOAD`,
`BUFFERBLOAT_DOWNLOAD|UPLOAD`, `PER_FLOW_LIMIT`, `ISP_CACHE`, `INTERNATIONAL`,
`TCP_SIGNALS_DOWNLOAD|UPLOAD`, `TARGET_ERRORS`, `SERVICE_FAILURES`, `SYN_RETRANSMIT`,
`SLOW_HANDSHAKE`, `CLOUD_LATENCY`, `DNS_FAILURES`, `DNS_SLOW`, `SSH_SESSION`,
`SSH_THROUGHPUT`, `ROUTE_LOSS`, `CONGESTION_CONTROL`. Severities: `crit`, `warn`, `info`, `ok`.

The `TCP_SIGNALS` percentages are loss/reordering indicators from kernel counters, not
loss rates; compare them between runs.

## Configuration

* `.env`: host/port, contracted plan (`NSD_PLAN_DOWNLOAD_MBPS`, `NSD_PLAN_UPLOAD_MBPS`),
  default profile, paths.
* `config/tests.json`: the catalog. Sections `labels`, `system`, `ping`, `route`,
  `services`, `download`, `upload`, `loaded_latency`, `analysis` (all thresholds),
  `profiles` (deep-merged over the base sections).
* `config/tests.local.json` (gitignored): merged on top. Lists of objects with `id` merge by
  id (same id overrides fields, new id appends); other lists replace.
* Placeholders: `@gateway`, `@system` (first resolver), `@city` / `@country` in Ookla
  searches. fast.com `category: "auto"` detects caches embedded in the user's own ISP.
* Every target and check accepts `"enabled": false`.

## Architecture

```
main.py                        CLI (argparse)
netspeeddiag/settings.py       .env, catalog loading + local merge, profiles, logging
netspeeddiag/system_probe.py   interface, TCP stack, public IP, first hops, kernel counters
netspeeddiag/latency_probe.py  ping (blocking and background), mtr
netspeeddiag/service_probe.py  tcp / https / ssh / dns checks
netspeeddiag/targets.py        static / ookla / fastcom target resolution
netspeeddiag/throughput.py     multi-connection HTTP download/upload engine
netspeeddiag/analyzer.py       summary metrics + findings (pure functions, thresholds)
netspeeddiag/runner.py         step orchestration, progress, cross-process lock
netspeeddiag/store.py          one JSON file per run, CSV export
netspeeddiag/web.py            Flask API; templates/index.html is the dashboard
```

A run document holds `id`, `label`, `notes`, `profile`, `status`, `config` (effective
profile incl. `analysis`), `plan`, `system`, `ping`, `route`, `services`, `download`,
`upload`, `loaded_latency`, `iface_delta`, `summary`, `findings`. It is saved after every
step, so partial runs keep their data.

Extending:

* New target type: `TargetResolver.resolve` in `targets.py`.
* New service check type: a function in `service_probe.py` returning the `_attempts` shape,
  dispatch in `DiagnosticRunner._run_check`, render in `servicesSection` (dashboard) and
  `print_report` (CLI).
* New finding: a rule in `analyzer.py`; thresholds in `DEFAULT_THRESHOLDS` and in the
  `analysis` catalog section; add a unit test; run `reanalyze` to apply to stored runs.

## Conventions

* English everywhere, concise. No emojis or decorative symbols in code, output or commits.
* PEP 8 naming, `from __future__ import annotations`, docstrings with Args / Returns /
  Raises on every public function, constants documented with a docstring below them.
* Tests: `unittest`, no network access, `.venv/bin/python -m unittest discover -s tests`.
* Dashboard: single template, vanilla JS, inline SVG charts, no build step. Editorial dark
  theme (Fraunces / IBM Plex); flat colors, no gradients; check there is no horizontal
  scroll from 390 px to desktop width after layout changes.
* Commit messages short, no co-author lines.
