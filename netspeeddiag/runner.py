"""
Diagnostic run orchestration.

A run executes the steps of a profile in order (system context, idle
latency + routes, service checks, download tests, upload tests, latency
under load),
records everything into one run document, analyzes it and stores it.
The document is saved after every step, so an interrupted run still
keeps the data measured so far.

Only one run executes at a time (measurements would disturb each
other), also across processes: a run holds an exclusive ``flock`` on
``<results_dir>/.run.lock``, so the dashboard and a terminal ``repeat``
never measure simultaneously. The dashboard starts runs in a background thread and polls
:meth:`DiagnosticRunner.progress`.
"""

from __future__ import annotations

import fcntl
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Dict, List, Optional

from . import analyzer, latency_probe, service_probe, system_probe, throughput
from .settings import VERSION, Settings
from .store import ResultStore
from .targets import TargetResolver

log = logging.getLogger(__name__)

MAX_LOG_LINES = 200
"""Progress log lines kept for the dashboard."""


class RunCancelled(Exception):
    """Raised inside a run when a cancel was requested."""


class DiagnosticRunner:
    """
    Executes diagnostic runs and exposes their live progress.

    Attributes:
        settings: Application settings.
        store: Where run documents are saved.
    """

    def __init__(self, settings: Settings, store: ResultStore):
        """
        Args:
            settings: Application settings.
            store: Result store.
        """
        self.settings = settings
        self.store = store
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._progress: Dict = {"running": False}
        self._lock_file = None

    # ------------------------------------------------------------------
    # Progress / control
    # ------------------------------------------------------------------

    def progress(self) -> Dict:
        """
        Snapshot of the current (or last) run progress.

        Returns:
            Dict with ``running``, ``id``, ``profile``, ``label``,
            ``step``, ``total``, ``message`` and ``log``.
        """
        with self._lock:
            return {**self._progress, "log": list(self._progress.get("log") or [])}

    def cancel(self) -> bool:
        """
        Request the running test to stop after the current measurement.

        Returns:
            ``True`` when a run was in progress.
        """
        if self.progress().get("running"):
            self._cancel.set()
            return True
        return False

    def _note(self, message: str, advance: bool = False) -> None:
        """
        Record a progress message.

        Args:
            message: Text for the progress log.
            advance: Whether this message starts a new step.

        Raises:
            RunCancelled: When a cancel was requested.
        """
        log.info(message)
        with self._lock:
            if advance:
                self._progress["step"] = self._progress.get("step", 0) + 1
            self._progress["message"] = message
            lines = self._progress.setdefault("log", [])
            lines.append(f"{datetime.now():%H:%M:%S} {message}")
            del lines[:-MAX_LOG_LINES]
        if self._cancel.is_set():
            raise RunCancelled()

    def start_background(self, profile: str, label: str = "", notes: str = "") -> str:
        """
        Start a run in a background thread.

        Args:
            profile: Profile name.
            label: Short label (e.g. ``via-router`` / ``direct-modem``).
            notes: Free text stored with the run.

        Returns:
            The new run id.

        Raises:
            RuntimeError: When a run is already in progress.
            ValueError: When the profile does not exist.
        """
        self.settings.resolve_profile(profile)
        run_id = self._claim(profile, label)
        threading.Thread(
            target=self._execute, args=(run_id, profile, label, notes), daemon=True,
        ).start()
        return run_id

    def run(self, profile: str, label: str = "", notes: str = "") -> Dict:
        """
        Execute a run in the calling thread.

        Args:
            profile: Profile name.
            label: Short label.
            notes: Free text stored with the run.

        Returns:
            The finished run document.
        """
        self.settings.resolve_profile(profile)
        return self._execute(self._claim(profile, label), profile, label, notes)

    def _claim(self, profile: str, label: str) -> str:
        """
        Reserve the runner for a new run.

        Args:
            profile: Profile name.
            label: Run label.

        Returns:
            The new run id.

        Raises:
            RuntimeError: When a run is already in progress.
        """
        with self._lock:
            if self._progress.get("running"):
                raise RuntimeError("A run is already in progress")
            self._acquire_process_lock()
            run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
            self._cancel.clear()
            self._progress = {
                "running": True, "id": run_id, "profile": profile, "label": label,
                "step": 0, "total": 0, "message": "Starting", "log": [],
            }
        return run_id

    def _acquire_process_lock(self) -> None:
        """
        Take the cross-process run lock.

        Raises:
            RuntimeError: When another process is measuring.
        """
        self.store.directory.mkdir(parents=True, exist_ok=True)
        handle = open(self.store.directory / ".run.lock", "w")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            raise RuntimeError("Another NetSpeedDiag process is running a test") from None
        self._lock_file = handle

    def _release_process_lock(self) -> None:
        """Release the cross-process run lock (idempotent)."""
        if self._lock_file:
            fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute(self, run_id: str, profile: str, label: str, notes: str) -> Dict:
        """
        Run every step, then analyze and save.

        Args:
            run_id: Run id.
            profile: Profile name.
            label: Run label.
            notes: Run notes.

        Returns:
            The run document (``status`` = completed / cancelled / failed).
        """
        config = self.settings.resolve_profile(profile)
        started = time.monotonic()
        doc = {
            "id": run_id, "version": VERSION, "started_at": datetime.now().astimezone().isoformat(),
            "finished_at": None, "label": label, "notes": notes, "profile": profile,
            "status": "running", "error": None, "plan": self.settings.plan, "config": config,
            "system": None, "ping": [], "route": [], "services": [], "download": [], "upload": [],
            "loaded_latency": {}, "iface_delta": {}, "summary": {}, "findings": [],
        }
        steps = self._plan_steps(config)
        with self._lock:
            self._progress["total"] = len(steps)
        resolver = TargetResolver()
        iface_before: Dict = {}
        try:
            for name, step in steps:
                self._note(name, advance=True)
                step(doc, config, resolver)
                if name == "System context":
                    iface = ((doc["system"] or {}).get("route") or {}).get("interface")
                    iface_before = system_probe.interface_counters(iface)
                self.store.save(doc)
            doc["status"] = "completed"
        except RunCancelled:
            doc["status"] = "cancelled"
        except Exception as e:
            log.exception("Run %s failed", run_id)
            doc["status"], doc["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            iface = (((doc.get("system") or {}).get("route")) or {}).get("interface")
            doc["iface_delta"] = system_probe.counter_delta(
                iface_before, system_probe.interface_counters(iface))
            doc["finished_at"] = datetime.now().astimezone().isoformat()
            doc["duration_s"] = round(time.monotonic() - started, 1)
            doc.update(analyzer.analyze(doc, self.settings.plan))
            self.store.save(doc)
            self._release_process_lock()
            with self._lock:
                self._progress["running"] = False
                self._progress["status"] = doc["status"]
                self._progress["message"] = f"Run {doc['status']}"
                self._progress.setdefault("log", []).append(
                    f"{datetime.now():%H:%M:%S} Run {doc['status']} in {doc['duration_s']} s")
        return doc

    def _plan_steps(self, config: Dict) -> List:
        """
        Build the ordered step list of a profile.

        Args:
            config: Effective profile configuration.

        Returns:
            List of ``(name, callable)`` pairs.
        """
        steps = [("System context", self._step_system), ("Idle latency and routes", self._step_latency)]
        services = config.get("services") or {}
        if services.get("enabled", True) and [c for c in services.get("checks") or [] if c.get("enabled", True)]:
            steps.append(("Service checks", self._step_services))
        for direction in ("download", "upload"):
            block = config.get(direction) or {}
            if block.get("enabled", True):
                for spec in self._selected(block):
                    steps.append((
                        f"{direction.capitalize()}: {spec.get('name', spec['id'])}",
                        self._throughput_step(direction, spec),
                    ))
        loaded = config.get("loaded_latency") or {}
        if loaded.get("enabled", True):
            for direction in ("download", "upload"):
                if loaded.get(f"{direction}_target"):
                    steps.append((f"Latency under {direction} load", self._loaded_step(direction)))
        return steps

    @staticmethod
    def _selected(block: Dict) -> List[Dict]:
        """
        Targets of a throughput block after the ``only`` filter.

        Args:
            block: ``download`` / ``upload`` config block.

        Returns:
            The selected target specs.
        """
        only = block.get("only") or []
        return [t for t in block.get("targets") or []
                if t.get("enabled", True) and (not only or t["id"] in only)]

    def _step_system(self, doc: Dict, config: Dict, resolver: TargetResolver) -> None:
        """Collect the system context."""
        sysconf = config.get("system") or {}
        doc["system"] = system_probe.collect(
            sysconf.get("public_ip_url", "https://ipinfo.io/json"),
            sysconf.get("first_hops_target", "8.8.8.8"),
        )
        resolver.context = doc["system"].get("public") or {}

    def _resolve_host(self, doc: Dict, host: str) -> str:
        """
        Expand the ``@gateway`` (default router) and ``@system`` (first
        resolver in ``/etc/resolv.conf``) placeholders.

        Args:
            doc: Run document (carries the system context).
            host: Configured host.

        Returns:
            The concrete host.
        """
        system = doc.get("system") or {}
        if host == "@gateway":
            return (system.get("route") or {}).get("gateway") or "127.0.0.1"
        if host == "@system":
            return (system.get("dns") or ["127.0.0.53"])[0]
        return host

    def _step_latency(self, doc: Dict, config: Dict, resolver: TargetResolver) -> None:
        """Idle pings to every target and mtr routes, all in parallel."""
        ping_conf = config.get("ping") or {}
        route_conf = config.get("route") or {}
        count, interval = int(ping_conf.get("count", 20)), float(ping_conf.get("interval_seconds", 0.2))
        ping_targets = [t for t in ping_conf.get("targets") or [] if t.get("enabled", True)]
        route_targets = (route_conf.get("targets") or []) if route_conf.get("enabled", True) else []
        if route_targets:
            self._note(f"Tracing {len(route_targets)} routes ({route_conf.get('cycles', 15)} cycles each)")
        with ThreadPoolExecutor(max_workers=len(ping_targets) + len(route_targets) or 1) as pool:
            pings = [
                (t, pool.submit(latency_probe.ping, self._resolve_host(doc, t["host"]), count, interval))
                for t in ping_targets
            ]
            routes = [
                pool.submit(latency_probe.mtr_report, target, int(route_conf.get("cycles", 15)))
                for target in route_targets
            ]
            doc["ping"] = [{"name": t.get("name", t["host"]), **f.result()} for t, f in pings]
            doc["route"] = [f.result() for f in routes]
        for p in doc["ping"]:
            self._note(f"  ping {p['name']}: avg {p.get('avg')} ms, loss {p.get('loss_pct')}%")

    def _step_services(self, doc: Dict, config: Dict, resolver: TargetResolver) -> None:
        """Run the enabled service checks (fast ones in parallel, SSH sessions after)."""
        conf = config.get("services") or {}
        checks = [c for c in conf.get("checks") or [] if c.get("enabled", True)]
        defaults = {"count": int(conf.get("count", 5)), "interval": float(conf.get("interval_seconds", 0.3)),
                    "timeout": float(conf.get("timeout_seconds", 5))}
        with ThreadPoolExecutor(max_workers=min(8, len(checks))) as pool:
            futures = [(c, pool.submit(self._run_check, doc, c, defaults)) for c in checks]
            results = [(c, f.result()) for c, f in futures]
        for check, result in results:
            if check.get("type") == "ssh" and check.get("auth"):
                self._note(f"  ssh session to {check.get('host')}"
                           + (f" with {check.get('throughput_mb')} MB transfer" if check.get("throughput_mb") else ""))
                result["session"] = service_probe.ssh_session(check)
            doc["services"].append(result)
            self._note(f"  {result['name']}: {self._check_line(result)}")

    def _run_check(self, doc: Dict, check: Dict, defaults: Dict) -> Dict:
        """
        Execute one service check (never raises).

        Args:
            doc: Run document (placeholders).
            check: Check spec.
            defaults: ``count`` / ``interval`` / ``timeout`` fallbacks.

        Returns:
            Result dict with ``id``, ``name``, ``type``, ``category``,
            ``target`` plus the probe statistics (or ``error``).
        """
        kind = check.get("type", "tcp")
        count = int(check.get("count", defaults["count"]))
        interval = float(check.get("interval_seconds", defaults["interval"]))
        timeout = float(check.get("timeout_seconds", defaults["timeout"]))
        host = self._resolve_host(doc, check.get("host", ""))
        base = {"id": check.get("id"), "name": check.get("name") or check.get("id"), "type": kind,
                "category": check.get("category", "other")}
        try:
            if kind == "tcp":
                port = int(check["port"])
                return {**base, "target": f"{host}:{port}", **service_probe.check_tcp(host, port, count, interval, timeout)}
            if kind == "https":
                port = int(check.get("port", 443))
                return {**base, "target": f"{host}:{port}", **service_probe.check_https(
                    host, port, check.get("path", "/"), count, interval, timeout)}
            if kind == "ssh":
                port = int(check.get("port", 22))
                return {**base, "target": f"{host}:{port}", **service_probe.check_ssh_banner(
                    host, port, min(count, 3), interval, timeout)}
            if kind == "dns":
                servers = []
                for server in check.get("servers") or ["@system"]:
                    spec = server if isinstance(server, dict) else {"address": server}
                    address = self._resolve_host(doc, spec["address"])
                    label = spec.get("name") or (f"{spec['address']} ({address})" if address != spec["address"] else address)
                    servers.append({"name": label, "address": address})
                names = check.get("names") or ["google.com"]
                return {**base, "target": ", ".join(names), **service_probe.check_dns(
                    servers, names, int(check.get("count", 3)), 0.1, min(timeout, 3.0))}
            return {**base, "error": f"unknown check type '{kind}'"}
        except Exception as e:
            return {**base, "error": f"{type(e).__name__}: {e}"}

    @staticmethod
    def _check_line(result: Dict) -> str:
        """
        One-line progress summary of a check result.

        Args:
            result: Check result.

        Returns:
            Short text.
        """
        if result.get("error"):
            return result["error"]
        if result["type"] == "dns":
            return "; ".join(f"{r['name']} {(r.get('query_ms') or {}).get('avg')} ms ({r['fail_pct']}% failed)"
                             for r in result["resolvers"])
        main = result.get("connect_ms") or {}
        line = f"connect {main.get('avg')} ms, {result['fail_pct']}% failed"
        session = result.get("session") or {}
        if session.get("error"):
            line += f"; login failed: {session['error']}"
        elif session.get("download_mbps") is not None:
            line += f"; ssh down {session['download_mbps']} / up {session.get('upload_mbps')} Mbps"
        return line

    def _find_spec(self, config: Dict, direction: str, target_id: str) -> Optional[Dict]:
        """
        Find a target spec by id (ignoring the ``only`` filter).

        Args:
            config: Effective profile configuration.
            direction: ``download`` / ``upload``.
            target_id: Target id.

        Returns:
            The spec, or ``None``.
        """
        return next((t for t in (config.get(direction) or {}).get("targets") or []
                     if t["id"] == target_id), None)

    def _throughput_step(self, direction: str, spec: Dict) -> Callable:
        """
        Build the step measuring one target at every stream count.

        Args:
            direction: ``download`` / ``upload``.
            spec: Target spec.

        Returns:
            The step callable.
        """
        def step(doc: Dict, config: Dict, resolver: TargetResolver) -> None:
            block = config.get(direction) or {}
            iface = ((doc.get("system") or {}).get("route") or {}).get("interface")
            try:
                target = resolver.resolve(spec, direction)
            except Exception as e:
                self._note(f"  cannot resolve {spec['id']}: {e}")
                doc[direction].append({
                    "target": {"id": spec["id"], "name": spec.get("name", spec["id"]),
                               "category": spec.get("category", "unknown")},
                    "streams": None, "result": None, "error": str(e),
                })
                return
            for streams in block.get("streams") or [1, 4]:
                result = throughput.measure(
                    target["url"], direction, int(streams), float(block.get("duration_seconds", 10)),
                    float(block.get("warmup_seconds", 2)), iface,
                )
                error = None
                if result["bytes"] == 0:
                    error = "no data transferred " + str(result["errors"] or result["status_codes"])
                doc[direction].append({
                    "target": target, "streams": int(streams),
                    "result": result if not error else None, "error": error, "raw": result if error else None,
                })
                self._note(
                    f"  x{streams}: {result['steady_mbps']} Mbps steady, peak {result['peak_mbps']}"
                    + (f" ({error})" if error else "")
                )
        return step

    def _loaded_step(self, direction: str) -> Callable:
        """
        Build the step measuring latency while the line is saturated.

        Args:
            direction: ``download`` / ``upload``.

        Returns:
            The step callable.
        """
        def step(doc: Dict, config: Dict, resolver: TargetResolver) -> None:
            conf = config.get("loaded_latency") or {}
            spec = self._find_spec(config, direction, conf[f"{direction}_target"])
            if not spec:
                self._note(f"  unknown {direction}_target '{conf[f'{direction}_target']}'")
                return
            try:
                target = resolver.resolve(spec, direction)
            except Exception as e:
                doc["loaded_latency"][direction] = {"error": str(e)}
                self._note(f"  cannot resolve {spec['id']}: {e}")
                return
            iface = ((doc.get("system") or {}).get("route") or {}).get("interface")
            sessions = [latency_probe.PingSession(self._resolve_host(doc, h))
                        for h in conf.get("ping_hosts") or ["8.8.8.8"]]
            for s in sessions:
                s.start()
            time.sleep(0.5)
            result = throughput.measure(
                target["url"], direction, int(conf.get("streams", 4)),
                float(conf.get("duration_seconds", 10)), 2.0, iface,
            )
            pings = [s.stop() for s in sessions]
            doc["loaded_latency"][direction] = {"target": target, "throughput": result, "pings": pings}
            for p in pings:
                self._note(f"  {p['host']} under load: avg {p.get('avg')} ms, loss {p.get('loss_pct')}%")
        return step
