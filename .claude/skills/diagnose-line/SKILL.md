---
name: diagnose-line
description: Diagnose the internet connection with NetSpeedDiag - run measurements, interpret findings, compare runs over time and write a summary for the ISP. Use when the user reports slow internet, asks to test the line, check if the ISP fixed something, compare before/after a change (router, modem, DMZ, bridge mode), monitor the connection, or prepare evidence for support.
---

# Diagnose the internet line

Work from the repository root. Use `.venv/bin/python` (Python 3.13). Read `AGENTS.md`
("Rules when running measurements" and "Interpreting a run") if not already in context.

## 1. Check state

```bash
.venv/bin/python main.py list -n 5
curl -s localhost:7071/api/progress 2>/dev/null   # a dashboard run in progress blocks new runs
```

If the venv is missing: `python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt`.

## 2. Measure

Pick the profile by purpose:

| Purpose | Command |
|---|---|
| Quick check / "is it fixed?" | `.venv/bin/python main.py run -p quick -l <label> -n "<what changed>" --brief` |
| Full diagnosis | `.venv/bin/python main.py run -p standard -l <label> -n "<context>"` |
| Intermittent problem | `.venv/bin/python main.py repeat -e 15 -c <n> -l monitor` (run in background) |

If the dashboard is serving and the user watches it, start through the API instead so the
run appears live: `curl -s -X POST localhost:7071/api/runs -H 'Content-Type: application/json'
-d '{"profile":"quick","label":"<label>","notes":"<notes>"}'`, then poll `/api/progress`
until `running` is false and read it with `show latest`.

Labels describe the condition (`via-router`, `direct-modem`, `after-dmz`, `bridge`,
`recheck`, `peak-hour`). Ask before long loops: every run moves real traffic.

## 3. Interpret

```bash
.venv/bin/python main.py show latest            # human report
.venv/bin/python main.py compare previous latest
```

Answer in this order:
1. Healthy or degraded, with the key numbers (best download, single connection, ISP cache,
   international, upload, idle loss).
2. Where the fault is, using the reasoning in AGENTS.md: LAN (gateway loss, link speed,
   Wi-Fi) vs ISP access (ISP cache slow, loss while idle, download-only) vs transit
   (international gap, route loss) vs server-specific.
3. What changed against the previous comparable run (same profile, similar label).
4. Next step: one concrete action (recheck later, test direct to modem, call ISP with the
   evidence, enable BBR, monitor with `repeat`).

Do not conclude from a single run when earlier runs disagree; say the problem is
intermittent and propose `repeat`.

## 4. Evidence for the ISP

When asked, write a short plain-text summary the user can paste to support:
- Public IP and ASN (`summary.public_ip`, `summary.isp`), wired link speed.
- Timeline table: run time, label, best download, single connection, ISP cache, upload,
  idle loss (from `list --json`).
- The facts that isolate the fault (e.g. "upload stays near its normal rate while download
  drops to a few percent of the plan", "even the ISP's own Netflix cache drops the same way",
  "several percent of loss with the line idle, latency flat under load").
- The specific request (check optical power / port errors, restore DMZ or bridge mode).
Keep it factual; no speculation presented as fact.
