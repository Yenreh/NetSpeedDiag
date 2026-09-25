"""
Run analysis: headline metrics and automatic findings.

Pure functions over a run document (no I/O), so they can be re-applied
to stored runs when the rules improve (``reanalyze``).

Every threshold lives in :data:`DEFAULT_THRESHOLDS` and can be overridden
from the ``analysis`` section of the test catalog; the values used are
stored with each run (``config.analysis``).

Finding severities: ``ok`` (checked and fine), ``info`` (context),
``warn`` (likely degrading the experience), ``crit`` (clear fault).
"""

from __future__ import annotations

from typing import Dict, List, Optional

SEVERITIES = ("crit", "warn", "info", "ok")
"""Finding severities, most severe first."""

DEFAULT_THRESHOLDS = {
    "loss_warn_pct": 1,             # idle ping loss that starts to hurt TCP
    "loss_crit_pct": 3,
    "loss_min_lost_packets": 2,     # ignore a single lost probe
    "loaded_loss_warn_pct": 2,      # loss while saturated (above idle + 1)
    "bloat_warn_ms": 30,            # latency increase under load
    "bloat_crit_ms": 100,
    "plan_ok_ratio": 0.8,           # best rate / contracted rate
    "plan_warn_ratio": 0.5,
    "per_flow_ratio": 3,            # multi / single connection rate
    "per_flow_single_max_mbps": 50,  # only flag when one connection is slow
    "isp_cache_slow_ratio": 0.5,    # ISP cache rate / best rate
    "international_warn_ratio": 0.3,  # abroad / same city
    "tcp_signal_pct": 1,            # out-of-order / retransmission share
    "route_loss_pct": 2,            # loss reaching the destination
    "service_fail_pct": 1,          # failed handshakes / queries
    "dns_slow_ms": 100,             # average resolver answer time
    "handshake_extra_ms": 100,      # TLS / banner time beyond one extra RTT
}
"""Default analysis thresholds (see the ``analysis`` catalog section)."""

LAN_RTT_MS = 3.0
"""Round trip under which a private hop is treated as a device at home."""


def _finding(severity: str, code: str, title: str, detail: str) -> Dict:
    """
    Build a finding.

    Args:
        severity: One of :data:`SEVERITIES`.
        code: Stable identifier (useful to compare runs).
        title: One-line statement.
        detail: Evidence and interpretation.

    Returns:
        The finding dict.
    """
    return {"severity": severity, "code": code, "title": title, "detail": detail}


def thresholds_for(doc: Dict) -> Dict:
    """
    Effective thresholds of a run.

    Args:
        doc: Run document.

    Returns:
        :data:`DEFAULT_THRESHOLDS` overridden by ``config.analysis``.
    """
    return {**DEFAULT_THRESHOLDS, **(((doc.get("config") or {}).get("analysis")) or {})}


def _tests(doc: Dict, direction: str) -> List[Dict]:
    """
    Return the successful throughput tests of a direction.

    Args:
        doc: Run document.
        direction: ``"download"`` or ``"upload"``.

    Returns:
        Tests carrying a ``result``.
    """
    return [t for t in doc.get(direction) or [] if t.get("result")]


def _best(tests: List[Dict], **filters) -> Optional[Dict]:
    """
    Return the test with the highest steady rate matching the filters.

    Args:
        tests: Throughput tests.
        **filters: ``streams`` (exact), ``category`` / ``target_id``
            (match on the resolved target), ``max_streams`` (bool, only
            each target's highest stream count).

    Returns:
        The best test, or ``None``.
    """
    pool = tests
    if "streams" in filters:
        pool = [t for t in pool if t["streams"] == filters["streams"]]
    if "category" in filters:
        pool = [t for t in pool if t["target"]["category"] == filters["category"]]
    if "target_id" in filters:
        pool = [t for t in pool if t["target"]["id"] == filters["target_id"]]
    if filters.get("max_streams"):
        top = {}
        for t in pool:
            top[t["target"]["id"]] = max(top.get(t["target"]["id"], 0), t["streams"])
        pool = [t for t in pool if t["streams"] == top[t["target"]["id"]]]
    return max(pool, key=lambda t: t["result"]["steady_mbps"], default=None)


def _rate(test: Optional[Dict]) -> Optional[float]:
    """
    Steady rate of a test.

    Args:
        test: Throughput test or ``None``.

    Returns:
        The steady Mbps, or ``None``.
    """
    return test["result"]["steady_mbps"] if test else None


def _ping_by_host(pings: List[Dict], host: str) -> Optional[Dict]:
    """
    Find a ping result by host.

    Args:
        pings: Ping results.
        host: Host to match.

    Returns:
        The matching result, or ``None``.
    """
    return next((p for p in pings if p.get("host") == host), None)


def _avg(block: Optional[Dict]) -> Optional[float]:
    """
    Average of a timing block.

    Args:
        block: Statistics dict (``avg`` key) or ``None``.

    Returns:
        The average, or ``None``.
    """
    return (block or {}).get("avg")


def _services(doc: Dict, kinds=("tcp", "https", "ssh")) -> List[Dict]:
    """
    Service check results of the given types that ran.

    Args:
        doc: Run document.
        kinds: Check types to keep.

    Returns:
        The results.
    """
    return [s for s in doc.get("services") or [] if s.get("type") in kinds]


def summarize(doc: Dict) -> Dict:
    """
    Compute the headline metrics of a run.

    Args:
        doc: Run document.

    Returns:
        Flat dict of the metrics shown in the history table and used by
        the findings.
    """
    system = doc.get("system") or {}
    iface = system.get("interface") or {}
    gateway = (system.get("route") or {}).get("gateway")
    downs, ups = _tests(doc, "download"), _tests(doc, "upload")
    internet_pings = [
        p for p in doc.get("ping") or [] if p.get("host") != gateway and p.get("received")
    ]
    sent = sum(p.get("sent") or 0 for p in internet_pings)
    idle_lost = sent - sum(p["received"] for p in internet_pings)
    idle_loss = round(100.0 * idle_lost / sent, 2) if sent else None
    idle_latency = min((p["avg"] for p in internet_pings if p.get("avg") is not None), default=None)

    loaded = {}
    for direction in ("download", "upload"):
        block = (doc.get("loaded_latency") or {}).get(direction) or {}
        worst_loss, worst_bloat = None, None
        for lp in block.get("pings") or []:
            if lp.get("host") == gateway:
                continue
            idle = _ping_by_host(doc.get("ping") or [], lp.get("host"))
            if lp.get("loss_pct") is not None:
                worst_loss = max(worst_loss or 0.0, lp["loss_pct"])
            if lp.get("avg") is not None and idle and idle.get("avg") is not None:
                bloat = round(lp["avg"] - idle["avg"], 1)
                worst_bloat = bloat if worst_bloat is None else max(worst_bloat, bloat)
        loaded[direction] = {"loss_pct": worst_loss, "bloat_ms": worst_bloat}

    checks = [s for s in _services(doc) if not s.get("error")]
    attempts = sum(s.get("attempts") or 0 for s in checks)
    failed = sum((s.get("attempts") or 0) - (s.get("ok") or 0) for s in checks)
    cloud = [_avg(s.get("connect_ms")) for s in checks if s.get("category") == "cloud"]
    resolvers = [r for s in _services(doc, ("dns",)) for r in s.get("resolvers") or []]
    dns_ok = [_avg(r.get("query_ms")) for r in resolvers if _avg(r.get("query_ms")) is not None]
    sessions = [s.get("session") or {} for s in _services(doc, ("ssh",))]

    return {
        "public_ip": (system.get("public") or {}).get("ip"),
        "isp": (system.get("public") or {}).get("org"),
        "interface": iface.get("name"),
        "wireless": iface.get("wireless"),
        "link_speed_mbps": iface.get("speed_mbps"),
        "congestion_control": (system.get("tcp") or {}).get("congestion_control"),
        "best_download_mbps": _rate(_best(downs)),
        "best_upload_mbps": _rate(_best(ups)),
        "best_single_stream_download_mbps": _rate(_best(downs, streams=1)),
        "isp_cache_mbps": _rate(_best(downs, category="isp-cache")),
        "local_mbps": _rate(_best(downs, category="local")),
        "national_mbps": _rate(_best(downs, category="national")),
        "international_mbps": _rate(_best(downs, category="international")),
        "idle_latency_ms": idle_latency,
        "idle_loss_pct": idle_loss,
        "idle_lost_packets": idle_lost if sent else None,
        "loaded_download_loss_pct": loaded["download"]["loss_pct"],
        "loaded_download_bloat_ms": loaded["download"]["bloat_ms"],
        "loaded_upload_loss_pct": loaded["upload"]["loss_pct"],
        "loaded_upload_bloat_ms": loaded["upload"]["bloat_ms"],
        "service_fail_pct": round(100.0 * failed / attempts, 1) if attempts else None,
        "cloud_connect_ms": min((c for c in cloud if c is not None), default=None),
        "dns_best_ms": min(dns_ok, default=None),
        "ssh_download_mbps": max((s["download_mbps"] for s in sessions if s.get("download_mbps")), default=None),
        "ssh_upload_mbps": max((s["upload_mbps"] for s in sessions if s.get("upload_mbps")), default=None),
    }


def _plan_findings(summary: Dict, plan: Dict, t: Dict) -> List[Dict]:
    """
    Compare the best rates with the contracted plan.

    Args:
        summary: :func:`summarize` output.
        plan: ``{"download_mbps", "upload_mbps"}`` (0 = unknown).
        t: Thresholds.

    Returns:
        Findings.
    """
    out = []
    for direction in ("download", "upload"):
        contracted = float(plan.get(f"{direction}_mbps") or 0)
        best = summary.get(f"best_{direction}_mbps")
        if not contracted or best is None:
            continue
        ratio = best / contracted
        severity = "ok" if ratio >= t["plan_ok_ratio"] else "warn" if ratio >= t["plan_warn_ratio"] else "crit"
        out.append(_finding(
            severity, f"PLAN_{direction.upper()}",
            f"Best {direction} is {ratio:.0%} of the plan ({best:.0f} of {contracted:.0f} Mbps)",
            f"Best steady {direction} rate of any target and connection count. Below "
            f"{t['plan_ok_ratio']:.0%} of the contracted rate on a wired connection is a service problem.",
        ))
    return out


def _link_findings(doc: Dict, summary: Dict) -> List[Dict]:
    """
    Local link checks (wired speed, Wi-Fi, errors, double NAT).

    Args:
        doc: Run document.
        summary: :func:`summarize` output.

    Returns:
        Findings.
    """
    out = []
    iface = (doc.get("system") or {}).get("interface") or {}
    if iface.get("wireless"):
        out.append(_finding(
            "warn", "WIFI", "Measured over Wi-Fi",
            "Wi-Fi adds its own loss and speed limits. Repeat on Ethernet before blaming the ISP.",
        ))
    speed = iface.get("speed_mbps")
    if speed and speed > 0:
        best = summary.get("best_download_mbps") or 0
        if speed < 1000 or iface.get("duplex") not in (None, "full"):
            out.append(_finding(
                "warn", "LINK_SPEED", f"Network card linked at {speed} Mbps {iface.get('duplex')}",
                "A cable or port problem can drop gigabit to 100 Mbps. Check the cable (Cat5e or better) "
                "and switch/router ports." + (" The measured speed is close to this limit." if best > 0.8 * speed else ""),
            ))
        else:
            out.append(_finding(
                "ok", "LINK_SPEED", f"Network card linked at {speed} Mbps {iface.get('duplex')}",
                "The local cable/port is not the bottleneck.",
            ))
    errs = {k: v for k, v in (doc.get("iface_delta") or {}).items() if k.endswith("errors") and v}
    if errs:
        out.append(_finding(
            "warn", "IFACE_ERRORS", "Interface errors during the run",
            f"Counters increased: {errs}. Points to a bad cable, port or NIC.",
        ))
    nat = nat_layers((doc.get("system") or {}).get("first_hops") or [])
    if nat["home"]:
        home = " -> ".join(nat["home"])
        if len(nat["home"]) >= 2:
            out.append(_finding(
                "info", "DOUBLE_NAT", f"Double NAT: {len(nat['home'])} home gateways ({home})",
                "Your own router sits behind the ISP modem, which also routes (NAT). Speed is rarely "
                "affected, but inbound connections (servers, port forwarding, some games / VPNs) need "
                "the modem in bridge mode or its DMZ pointed at your router. DMZ keeps the second hop "
                "in this list (it only forwards inbound traffic); bridge mode removes it.",
            ))
        else:
            out.append(_finding(
                "ok", "DOUBLE_NAT", f"Single home gateway ({home})",
                "Only one NAT device at home.",
            ))
    if nat["cgnat"]:
        out.append(_finding(
            "warn", "CGNAT", f"Carrier-grade NAT on the path ({', '.join(nat['cgnat'])})",
            "The ISP shares one public IP between customers (100.64.0.0/10). Inbound connections and "
            "port forwarding cannot work; ask the ISP for a public IP.",
        ))
    return out


def nat_layers(hops: List[Dict]) -> Dict:
    """
    Classify the first hops of the path.

    Home gateways are the leading private hops that answer like LAN
    devices (``192.168.0.0/16``, or under :data:`LAN_RTT_MS`); private
    hops after them belong to the ISP network (plain routing, not NAT)
    unless they are in the carrier-grade NAT range.

    Args:
        hops: ``first_hops`` entries (``host``, ``private``, optional
            ``cgnat`` / ``avg_ms``).

    Returns:
        Dict with ``home`` (gateway IPs in order), ``cgnat`` and
        ``isp_private`` (IPs).
    """
    home, cgnat, isp_private = [], [], []
    in_home = True
    for hop in hops:
        host = hop.get("host") or ""
        if hop.get("cgnat") or host.startswith("100.") and 64 <= int(host.split(".")[1] or 0) <= 127:
            cgnat.append(host)
            in_home = False
            continue
        if not hop.get("private"):
            in_home = False
            continue
        rtt = hop.get("avg_ms")
        lan_like = host.startswith("192.168.") or (rtt is not None and rtt < LAN_RTT_MS)
        if in_home and lan_like:
            home.append(host)
        else:
            in_home = False
            isp_private.append(host)
    return {"home": home, "cgnat": cgnat, "isp_private": isp_private}
    return out


def _latency_findings(doc: Dict, summary: Dict, t: Dict) -> List[Dict]:
    """
    Idle / loaded latency and loss checks.

    Args:
        doc: Run document.
        summary: :func:`summarize` output.
        t: Thresholds.

    Returns:
        Findings.
    """
    out = []
    gateway = ((doc.get("system") or {}).get("route") or {}).get("gateway")
    gw = _ping_by_host(doc.get("ping") or [], gateway) if gateway else None
    if gw and (gw.get("loss_pct") or 0) > 0:
        out.append(_finding(
            "crit" if gw["loss_pct"] >= 2 else "warn", "GATEWAY_LOSS",
            f"{gw['loss_pct']}% packet loss to the local router",
            "Loss on the LAN itself (cable, router or Wi-Fi). Fix this before testing the ISP.",
        ))
    loss = summary.get("idle_loss_pct")
    if loss is not None:
        lost = summary.get("idle_lost_packets") or 0
        minimum = t["loss_min_lost_packets"]
        severity = ("crit" if loss >= t["loss_crit_pct"] and lost >= max(minimum, 3) else
                    "warn" if loss >= t["loss_warn_pct"] and lost >= minimum else "info" if lost else "ok")
        out.append(_finding(
            severity, "IDLE_LOSS", f"Idle packet loss to internet hosts: {loss}% ({lost} lost)",
            f"All internet ping targets combined, idle line. Above {t['loss_warn_pct']}% hurts every TCP "
            "download; with few probes a single lost ping weighs a lot, so compare across runs.",
        ))
    for direction in ("download", "upload"):
        lloss = summary.get(f"loaded_{direction}_loss_pct")
        bloat = summary.get(f"loaded_{direction}_bloat_ms")
        if lloss is not None and lloss >= t["loaded_loss_warn_pct"] and lloss > (loss or 0) + 1:
            out.append(_finding(
                "warn", f"LOADED_LOSS_{direction.upper()}",
                f"Packet loss rises to {lloss}% while the {direction} is saturated",
                "Loss appears only under load. Without matching latency growth this points to a policer "
                "or an overloaded link dropping packets rather than normal queueing.",
            ))
        if bloat is not None:
            severity = "ok" if bloat < t["bloat_warn_ms"] else "warn" if bloat < t["bloat_crit_ms"] else "crit"
            out.append(_finding(
                severity, f"BUFFERBLOAT_{direction.upper()}",
                f"Latency under {direction} load: {bloat:+.1f} ms",
                f"Latency increase while the line is saturated (bufferbloat). Under {t['bloat_warn_ms']} ms "
                f"is good; high values make calls and games lag during {direction}s.",
            ))
    return out


def _throughput_findings(doc: Dict, summary: Dict, t: Dict) -> List[Dict]:
    """
    Throughput pattern checks (per-flow limits, where the slowness is).

    Args:
        doc: Run document.
        summary: :func:`summarize` output.
        t: Thresholds.

    Returns:
        Findings.
    """
    out = []
    downs = _tests(doc, "download")
    per_flow = []
    for target_id in sorted({x["target"]["id"] for x in downs}):
        single = _best(downs, target_id=target_id, streams=1)
        multi = _best(downs, target_id=target_id, max_streams=True)
        if not single or not multi or multi["streams"] <= 1:
            continue
        s, m = _rate(single), _rate(multi)
        if s is not None and m and s < t["per_flow_single_max_mbps"] and m >= t["per_flow_ratio"] * max(s, 0.1):
            per_flow.append(f"{single['target']['name']}: {s:.1f} Mbps x1 vs {m:.1f} Mbps x{multi['streams']}")
    if per_flow:
        out.append(_finding(
            "warn", "PER_FLOW_LIMIT", "A single connection is much slower than parallel connections",
            "; ".join(per_flow) + ". The line has capacity but each TCP flow collapses: typical of "
            "packet loss (TCP backs off on every drop) or per-flow shaping. Speed tests with many "
            "parallel streams (Ookla) hide it; real downloads and fast.com show it.",
        ))

    cache, local = summary.get("isp_cache_mbps"), summary.get("local_mbps")
    intl, best = summary.get("international_mbps"), summary.get("best_download_mbps")
    if cache is not None and best:
        slow = cache < t["isp_cache_slow_ratio"] * best
        out.append(_finding(
            "warn" if slow else "info", "ISP_CACHE",
            f"Netflix cache inside the ISP network: {cache:.1f} Mbps (best overall {best:.1f} Mbps)",
            "This fast.com server sits inside your ISP's own network, so no international transit "
            "or peering is involved. " + (
                "Being slow there points at the ISP access/aggregation network or the cache itself."
                if slow else "Its rate reflects the access line capacity."),
        ))
    if intl is not None and local:
        ratio = intl / local
        out.append(_finding(
            "warn" if ratio < t["international_warn_ratio"] else "ok", "INTERNATIONAL",
            f"International: {intl:.1f} Mbps vs same-city: {local:.1f} Mbps ({ratio:.0%})",
            "Best parallel-connection rates. A large gap points to congested international transit / "
            "peering of the ISP (check the routes for where latency and loss appear).",
        ))

    for direction in ("download", "upload"):
        noisy = []
        for x in _tests(doc, direction):
            ind = (x["result"].get("tcp") or {}).get("loss_indicator_pct")
            if ind is not None and ind >= t["tcp_signal_pct"]:
                noisy.append(f"{x['target']['name']} x{x['streams']}: {ind}%")
        if noisy:
            out.append(_finding(
                "info", f"TCP_SIGNALS_{direction.upper()}",
                "Out-of-order packets during download tests" if direction == "download"
                else "Retransmissions during upload tests",
                ("Share of received packets that arrived after a gap (caused by loss or by reordering "
                 "on the path; one loss makes many packets count)" if direction == "download"
                 else "Retransmitted segments per sent packet") +
                ". Near 0 on a clean path; compare between runs rather than reading it as a loss rate: "
                + "; ".join(noisy[:6]),
            ))

    failed = [f"{x['target']['name']} ({x.get('error')})"
              for d in ("download", "upload") for x in doc.get(d) or [] if x.get("error")]
    if failed:
        out.append(_finding(
            "info", "TARGET_ERRORS", f"{len(failed)} test(s) could not run",
            "; ".join(failed[:6]) + ". Unavailable targets are excluded from the analysis.",
        ))
    return out


def _service_findings(doc: Dict, summary: Dict, t: Dict) -> List[Dict]:
    """
    Protocol checks: failures, slow handshakes, DNS, cloud reach, SSH.

    Args:
        doc: Run document.
        summary: :func:`summarize` output.
        t: Thresholds.

    Returns:
        Findings.
    """
    out = []
    checks = _services(doc)
    broken = [f"{s['name']} ({s['error']})" for s in checks if s.get("error")]
    failing = [f"{s['name']}: {s['fail_pct']}% of {s['attempts']} ({', '.join(s.get('errors') or {})})"
               for s in checks if not s.get("error") and (s.get("fail_pct") or 0) >= t["service_fail_pct"]]
    if broken or failing:
        out.append(_finding(
            "warn", "SERVICE_FAILURES", f"{len(broken) + len(failing)} service check(s) failing",
            "; ".join(broken + failing) + ". Failed TCP/TLS/SSH handshakes break real applications even "
            "when speed tests look fine.",
        ))
    elif checks:
        out.append(_finding(
            "ok", "SERVICE_FAILURES", f"All {len(checks)} TCP/HTTPS/SSH checks connected",
            f"Overall handshake failure rate {summary.get('service_fail_pct')}%.",
        ))

    syn_retries = [f"{s['name']} (max {s['connect_ms']['max']:.0f} ms)" for s in checks
                   if not s.get("error") and (s.get("connect_ms") or {}).get("max") and s["connect_ms"]["max"] >= 900]
    if syn_retries:
        out.append(_finding(
            "warn", "SYN_RETRANSMIT", "Some TCP handshakes took about a second or more",
            "; ".join(syn_retries) + ". A lost SYN is resent after ~1 s, so these are handshakes that "
            "hit packet loss. Users feel it as pages or SSH sessions that hang before starting.",
        ))

    slow_hs = []
    for s in checks:
        conn = _avg(s.get("connect_ms"))
        extra = _avg(s.get("tls_ms")) or _avg(s.get("banner_ms"))
        if conn is not None and extra is not None and extra > 2 * conn + t["handshake_extra_ms"]:
            slow_hs.append(f"{s['name']}: connect {conn:.0f} ms, {'TLS' if s.get('tls_ms') else 'banner'} {extra:.0f} ms")
    if slow_hs:
        out.append(_finding(
            "info", "SLOW_HANDSHAKE", "Handshakes slower than the network round trip explains",
            "; ".join(slow_hs) + ". Either the server is slow to answer or packets were retransmitted "
            "during the handshake.",
        ))

    cloud = [s for s in checks if s.get("category") == "cloud" and not s.get("error") and s.get("connect_ms")]
    if cloud:
        parts = ", ".join(f"{s['name'].replace('DigitalOcean ', '')} {_avg(s['connect_ms']):.0f} ms"
                          for s in sorted(cloud, key=lambda s: _avg(s["connect_ms"])))
        out.append(_finding(
            "info", "CLOUD_LATENCY", f"Cloud reach: best TCP handshake {summary.get('cloud_connect_ms'):.0f} ms",
            f"TCP handshake (one round trip) per cloud endpoint: {parts}. Compare across runs; a jump "
            "means a worse route out of the ISP.",
        ))

    for dns in _services(doc, ("dns",)):
        for r in dns.get("resolvers") or []:
            avg = _avg(r.get("query_ms"))
            if (r.get("fail_pct") or 0) >= t["service_fail_pct"]:
                out.append(_finding(
                    "warn", "DNS_FAILURES", f"DNS resolver {r['name']}: {r['fail_pct']}% of queries failed",
                    f"Errors: {r.get('errors')}. Failing lookups look like sites that do not load at all.",
                ))
            elif avg is not None and avg >= t["dns_slow_ms"]:
                out.append(_finding(
                    "warn", "DNS_SLOW", f"DNS resolver {r['name']} is slow: {avg:.0f} ms average",
                    f"Every new site waits for DNS first. The fastest resolver answered in "
                    f"{summary.get('dns_best_ms'):.0f} ms.",
                ))

    for s in _services(doc, ("ssh",)):
        session = s.get("session") or {}
        if session.get("error"):
            out.append(_finding(
                "warn", "SSH_SESSION", f"SSH login to {s['name']} failed",
                f"{session['error']}. The check uses BatchMode (keys / agent only, no prompts); log in "
                "once manually to accept the host key.",
            ))
        elif session.get("download_mbps") is not None:
            best = summary.get("best_download_mbps")
            out.append(_finding(
                "info", "SSH_THROUGHPUT",
                f"SSH to {s['name']}: {session['download_mbps']:.1f} down / {session.get('upload_mbps') or 0:.1f} up Mbps",
                f"One encrypted TCP flow, like scp/rsync/git over SSH. Login took {session.get('auth_ms')} ms."
                + (f" Best parallel download this run: {best:.1f} Mbps." if best else ""),
            ))
    return out


def _route_findings(doc: Dict, t: Dict) -> List[Dict]:
    """
    Route checks: loss that persists to the destination.

    Args:
        doc: Run document.
        t: Thresholds.

    Returns:
        Findings.
    """
    out = []
    limit = t["route_loss_pct"]
    for route in doc.get("route") or []:
        hops = route.get("hops") or []
        if not hops:
            continue
        final = hops[-1]
        if (final.get("loss_pct") or 0) >= limit:
            origin = None
            for i, hop in enumerate(hops):
                if (hop.get("loss_pct") or 0) >= limit and all(
                        (h.get("loss_pct") or 0) >= 1 for h in hops[i:] if h.get("host") != "???"):
                    origin = hop
                    break
            out.append(_finding(
                "warn", "ROUTE_LOSS", f"Loss to {route['target']}: {final['loss_pct']:.1f}%",
                "Loss reaches the destination" + (
                    f", starting around hop {origin['hop']} ({origin['host']}, {origin.get('asn')})." if origin else ".")
                + " Loss seen only on intermediate hops is usually ICMP rate limiting and harmless.",
            ))
    return out


def _stack_findings(doc: Dict, findings: List[Dict]) -> List[Dict]:
    """
    TCP stack suggestions.

    Args:
        doc: Run document.
        findings: Findings computed so far.

    Returns:
        Findings.
    """
    tcp = (doc.get("system") or {}).get("tcp") or {}
    lossy = any(f["code"] == "PER_FLOW_LIMIT" for f in findings)
    if tcp.get("congestion_control") == "cubic" and lossy:
        return [_finding(
            "info", "CONGESTION_CONTROL", "This PC uses TCP cubic",
            "Cubic slows down on every lost packet. BBR tolerates random loss much better and can "
            "raise single-connection speeds on a lossy line (workaround, not a fix). Only affects "
            "uploads/ACK pacing from this machine; downloads depend on the server's algorithm.",
        )]
    return []


def analyze(doc: Dict, plan: Dict) -> Dict:
    """
    Compute the summary and findings of a run.

    Args:
        doc: Run document.
        plan: Contracted plan (``download_mbps`` / ``upload_mbps``).

    Returns:
        Dict with ``summary`` and ``findings`` (most severe first).
    """
    t = thresholds_for(doc)
    summary = summarize(doc)
    findings = []
    findings += _plan_findings(summary, plan, t)
    findings += _link_findings(doc, summary)
    findings += _latency_findings(doc, summary, t)
    findings += _throughput_findings(doc, summary, t)
    findings += _service_findings(doc, summary, t)
    findings += _route_findings(doc, t)
    findings += _stack_findings(doc, findings)
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    summary["findings"] = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {"summary": summary, "findings": findings}
