"""
NetSpeedDiag command line.

    python main.py serve                       dashboard on NSD_HOST:NSD_PORT (default)
    python main.py run [-p PROFILE] [-l LABEL] [-n NOTES]
    python main.py repeat -e MIN [-c N] [-p PROFILE] [-l LABEL]
                                               runs spaced over time (peak-hour degradation)
    python main.py list [--json] [-n N]        stored runs, newest first
    python main.py show RUN_ID [--json|--brief]  report of a run ("latest", "previous" work as ids)
    python main.py compare A B [--json]        headline metrics and findings of two runs
    python main.py reanalyze [RUN_ID ...]      recompute findings (all runs when omitted)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta

from netspeeddiag import analyzer
from netspeeddiag.runner import DiagnosticRunner
from netspeeddiag.settings import load_settings, setup_logging
from netspeeddiag.store import ResultStore


def _fmt(value, suffix: str = "") -> str:
    """
    Format an optional number for the terminal.

    Args:
        value: Number or ``None``.
        suffix: Unit appended to numbers.

    Returns:
        The text (``-`` for ``None``).
    """
    return "-" if value is None else f"{value:g}{suffix}" if isinstance(value, (int, float)) else str(value)


def print_report(doc: dict) -> None:
    """
    Print the summary, throughput table and findings of a run.

    Args:
        doc: Run document.
    """
    s = doc.get("summary") or {}
    print(f"\nRun {doc['id']}  label={doc.get('label') or '-'}  profile={doc['profile']}  "
          f"status={doc['status']}  ({doc.get('duration_s', '?')} s)")
    print(f"Public IP {_fmt(s.get('public_ip'))}  {_fmt(s.get('isp'))}  "
          f"iface {_fmt(s.get('interface'))} @ {_fmt(s.get('link_speed_mbps'), ' Mbps')}")
    print(f"Best down {_fmt(s.get('best_download_mbps'), ' Mbps')} | single stream "
          f"{_fmt(s.get('best_single_stream_download_mbps'), ' Mbps')} | up {_fmt(s.get('best_upload_mbps'), ' Mbps')}")
    print(f"Idle latency {_fmt(s.get('idle_latency_ms'), ' ms')}  loss {_fmt(s.get('idle_loss_pct'), '%')}  | "
          f"under download load +{_fmt(s.get('loaded_download_bloat_ms'), ' ms')} loss "
          f"{_fmt(s.get('loaded_download_loss_pct'), '%')}")
    for direction in ("download", "upload"):
        tests = doc.get(direction) or []
        if not tests:
            continue
        print(f"\n{direction.upper():<36}{'cat':<15}{'str':>4}{'steady':>9}{'peak':>9}{'loss*':>7}")
        for t in tests:
            r = t.get("result")
            name = t["target"]["name"][:35]
            if not r:
                print(f"{name:<36}{t['target'].get('category', ''):<15}{_fmt(t.get('streams')):>4}  ERROR {t.get('error')}")
                continue
            print(f"{name:<36}{t['target']['category']:<15}{t['streams']:>4}{r['steady_mbps']:>9.1f}"
                  f"{r['peak_mbps']:>9.1f}{_fmt((r.get('tcp') or {}).get('loss_indicator_pct')):>7}")
    services = doc.get("services") or []
    if services:
        print(f"\n{'SERVICES':<36}{'type':<7}{'ok':>7}{'fail%':>7}{'conn ms':>9}{'hs ms':>8}  extra")
        for c in services:
            if c.get("error"):
                print(f"{c['name'][:35]:<36}{c['type']:<7}  ERROR {c['error']}")
                continue
            if c["type"] == "dns":
                for r in c.get("resolvers") or []:
                    print(f"{('DNS ' + r['name'])[:35]:<36}{'dns':<7}{r['ok']:>4}/{r['attempts']:<2}{_fmt(r['fail_pct']):>7}"
                          f"{_fmt((r.get('query_ms') or {}).get('avg')):>9}")
                continue
            hs = (c.get("tls_ms") or c.get("banner_ms") or {}).get("avg")
            session = c.get("session") or {}
            extra = (f"login failed: {session['error']}" if session.get("error") else
                     f"ssh {session.get('download_mbps')} down / {session.get('upload_mbps')} up Mbps"
                     if session.get("download_mbps") is not None else c.get("info") or "")
            print(f"{c['name'][:35]:<36}{c['type']:<7}{c['ok']:>4}/{c['attempts']:<2}{_fmt(c['fail_pct']):>7}"
                  f"{_fmt((c.get('connect_ms') or {}).get('avg')):>9}{_fmt(hs):>8}  {str(extra)[:60]}")
    print("\n* loss* = out-of-order (download) or retransmitted (upload) packets %, a loss/reordering signal\n\nFINDINGS")
    for f in doc.get("findings") or []:
        print(f"  [{f['severity'].upper():<4}] {f['title']}\n         {f['detail']}")


COMPARE_METRICS = (
    ("Best download (Mbps)", "best_download_mbps"),
    ("Single connection (Mbps)", "best_single_stream_download_mbps"),
    ("ISP cache (Mbps)", "isp_cache_mbps"),
    ("Local (Mbps)", "local_mbps"),
    ("National (Mbps)", "national_mbps"),
    ("International (Mbps)", "international_mbps"),
    ("Upload (Mbps)", "best_upload_mbps"),
    ("Idle latency (ms)", "idle_latency_ms"),
    ("Idle loss (%)", "idle_loss_pct"),
    ("Latency under load (+ms)", "loaded_download_bloat_ms"),
    ("Loss under load (%)", "loaded_download_loss_pct"),
    ("Service failures (%)", "service_fail_pct"),
    ("Cloud handshake (ms)", "cloud_connect_ms"),
    ("Best DNS (ms)", "dns_best_ms"),
    ("SSH download (Mbps)", "ssh_download_mbps"),
    ("SSH upload (Mbps)", "ssh_upload_mbps"),
)
"""Headline metrics shown by ``compare`` (label, summary key)."""


def resolve_run_id(store: ResultStore, run_id: str) -> str:
    """
    Expand the ``latest`` / ``previous`` aliases.

    Args:
        store: Result store.
        run_id: Run id or alias.

    Returns:
        The concrete run id (unchanged when not an alias).
    """
    aliases = {"latest": 0, "previous": 1}
    if run_id in aliases:
        runs = store.list()
        index = aliases[run_id]
        return runs[index]["id"] if len(runs) > index else run_id
    return run_id


def brief(doc: dict) -> dict:
    """
    Compact machine-readable view of a run (what an agent needs).

    Args:
        doc: Run document.

    Returns:
        Dict with the run metadata, ``summary`` and non-ok ``findings``.
    """
    return {
        **{k: doc.get(k) for k in ("id", "label", "notes", "profile", "status", "error", "duration_s")},
        "summary": doc.get("summary") or {},
        "findings": [f for f in doc.get("findings") or [] if f["severity"] != "ok"],
    }


def compare_runs(a: dict, b: dict) -> dict:
    """
    Compare two runs.

    Args:
        a: Older (baseline) run document.
        b: Newer run document.

    Returns:
        Dict with ``a`` / ``b`` ids, ``metrics`` (label, a, b, change
        %) and the finding codes only present in one of them.
    """
    metrics = []
    for label, key in COMPARE_METRICS:
        va, vb = (a.get("summary") or {}).get(key), (b.get("summary") or {}).get(key)
        change = round((vb - va) / va * 100, 1) if va not in (None, 0) and vb is not None else None
        metrics.append({"metric": label, "key": key, "a": va, "b": vb, "change_pct": change})
    codes = lambda d: {f["code"] for f in d.get("findings") or [] if f["severity"] in ("warn", "crit")}
    return {
        "a": {"id": a["id"], "label": a.get("label")}, "b": {"id": b["id"], "label": b.get("label")},
        "metrics": metrics,
        "problems_only_in_a": sorted(codes(a) - codes(b)),
        "problems_only_in_b": sorted(codes(b) - codes(a)),
    }


def main() -> int:
    """
    Parse the command line and dispatch.

    Returns:
        Process exit code.
    """
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Home internet line diagnostics")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the web dashboard (default)")
    run_p = sub.add_parser("run", help="execute a diagnostic run from the terminal")
    run_p.add_argument("-p", "--profile", default=settings.default_profile,
                       help=f"test profile ({', '.join(settings.profile_names())})")
    run_p.add_argument("-l", "--label", default="", help="short label, e.g. via-router / direct-modem")
    run_p.add_argument("-n", "--notes", default="", help="free text stored with the run")
    run_p.add_argument("--brief", action="store_true", help="print the brief JSON instead of the report")
    list_p = sub.add_parser("list", help="list stored runs")
    list_p.add_argument("--json", action="store_true", help="JSON output")
    list_p.add_argument("-n", "--limit", type=int, default=0, help="only the newest N runs")
    show_p = sub.add_parser("show", help="print a stored run")
    show_p.add_argument("run_id", help="run id, 'latest' or 'previous'")
    fmt_g = show_p.add_mutually_exclusive_group()
    fmt_g.add_argument("--json", action="store_true", help="dump the full JSON document")
    fmt_g.add_argument("--brief", action="store_true", help="JSON with metadata, summary and problems only")
    cmp_p = sub.add_parser("compare", help="compare two runs (A = baseline)")
    cmp_p.add_argument("run_a", help="baseline run id, 'latest' or 'previous'")
    cmp_p.add_argument("run_b", help="run id, 'latest' or 'previous'")
    cmp_p.add_argument("--json", action="store_true", help="JSON output")
    rep_p = sub.add_parser("repeat", help="execute runs spaced over time (Ctrl+C stops)")
    rep_p.add_argument("-p", "--profile", default="quick", help="test profile (default quick)")
    rep_p.add_argument("-l", "--label", default="", help="label for every run")
    rep_p.add_argument("-e", "--every", type=float, required=True, help="minutes between run starts")
    rep_p.add_argument("-c", "--count", type=int, default=0, help="number of runs (0 = until stopped)")
    re_p = sub.add_parser("reanalyze", help="recompute summary and findings of stored runs")
    re_p.add_argument("run_ids", nargs="*")
    args = parser.parse_args()

    setup_logging(settings)
    store = ResultStore(settings.results_dir)
    runner = DiagnosticRunner(settings, store)

    if args.command in (None, "serve"):
        from netspeeddiag.web import create_app
        print(f"Dashboard: http://{settings.host}:{settings.port}/", flush=True)
        create_app(settings, store, runner).run(host=settings.host, port=settings.port, threaded=True)
        return 0
    if args.command == "run":
        try:
            doc = runner.run(args.profile, args.label, args.notes)
        except (RuntimeError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(brief(doc), indent=2)) if args.brief else print_report(doc)
        return 0 if doc["status"] == "completed" else 1
    if args.command == "repeat":
        done = 0
        try:
            while not args.count or done < args.count:
                started = time.monotonic()
                done += 1
                try:
                    doc = runner.run(args.profile, args.label, f"repeat {done}/{args.count or 'inf'} every {args.every:g} min")
                    s = doc.get("summary") or {}
                    print(f"[{done}] {doc['id']} {doc['status']}: down {_fmt(s.get('best_download_mbps'))} "
                          f"x1 {_fmt(s.get('best_single_stream_download_mbps'))} up {_fmt(s.get('best_upload_mbps'))} "
                          f"loss {_fmt(s.get('idle_loss_pct'))}%", flush=True)
                except RuntimeError as e:
                    print(f"[{done}] skipped: {e}", flush=True)
                if args.count and done >= args.count:
                    break
                wait = max(0.0, args.every * 60 - (time.monotonic() - started))
                print(f"Next run at {(datetime.now() + timedelta(seconds=wait)):%H:%M}", flush=True)
                time.sleep(wait)
        except KeyboardInterrupt:
            print(f"Stopped after {done} run(s)")
        return 0
    if args.command == "list":
        runs = store.list()[:args.limit] if args.limit else store.list()
        if args.json:
            print(json.dumps(runs, indent=2))
            return 0
        for r in runs:
            s = r["summary"]
            print(f"{r['id']}  {r['profile']:<9}{(r.get('label') or '-'):<18}{r['status']:<10}"
                  f"down {_fmt(s.get('best_download_mbps')):>7}  x1 {_fmt(s.get('best_single_stream_download_mbps')):>7}  "
                  f"up {_fmt(s.get('best_upload_mbps')):>7}  loss {_fmt(s.get('idle_loss_pct'))}")
        return 0
    if args.command == "show":
        doc = store.get(resolve_run_id(store, args.run_id))
        if not doc:
            print(f"Run {args.run_id} not found", file=sys.stderr)
            return 1
        if args.json or args.brief:
            print(json.dumps(doc if args.json else brief(doc), indent=2))
        else:
            print_report(doc)
        return 0
    if args.command == "compare":
        a, b = (store.get(resolve_run_id(store, i)) for i in (args.run_a, args.run_b))
        if not a or not b:
            print("Run not found", file=sys.stderr)
            return 1
        result = compare_runs(a, b)
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        print(f"A = {a['id']} {a.get('label') or ''}\nB = {b['id']} {b.get('label') or ''}\n")
        print(f"{'Metric':<28}{'A':>10}{'B':>10}{'Change':>9}")
        for m in result["metrics"]:
            if m["a"] is None and m["b"] is None:
                continue
            change = "-" if m["change_pct"] is None else f"{m['change_pct']:+.0f}%"
            print(f"{m['metric']:<28}{_fmt(m['a']):>10}{_fmt(m['b']):>10}{change:>9}")
        print(f"\nProblems only in A: {', '.join(result['problems_only_in_a']) or '-'}")
        print(f"Problems only in B: {', '.join(result['problems_only_in_b']) or '-'}")
        return 0
    if args.command == "reanalyze":
        docs = [store.get(i) for i in args.run_ids] if args.run_ids else store.all()
        for doc in filter(None, docs):
            if any(settings.plan.values()):
                doc["plan"] = settings.plan
            doc.update(analyzer.analyze(doc, doc.get("plan") or settings.plan))
            store.save(doc)
            print(f"Reanalyzed {doc['id']}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
