"""
Throughput target resolution.

Turns the configured target specs into concrete URLs at run time:

* ``static`` — the ``url`` is used as is.
* ``ookla`` — an Ookla (speedtest.net) server, either a fixed ``host``
  (``name:port``) or the ``index``-th match of a ``search`` in the
  public server list (``@city`` / ``@country`` search the location of
  the public IP, so the same catalog works anywhere). Download uses
  ``/download?size=``, upload ``/upload``.
* ``fastcom`` — a Netflix Open Connect server as used by fast.com. The
  public app token is scraped from the fast.com bundle and the API
  returns the nearest servers; ``server_index`` picks one. With
  ``category: "auto"`` the category is derived from the server: Netflix
  names caches embedded in an ISP ``...-isp.1.oca.nflxvideo.net``
  (``isp-cache``, the cleanest "ISP access network" measurement);
  others become ``national`` / ``international`` by country.
"""

from __future__ import annotations

import re
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

OOKLA_SERVERS_URL = "https://www.speedtest.net/api/js/servers?engine=js&search={search}&limit=10"
"""Public Ookla server-list endpoint."""

OOKLA_DOWNLOAD_BYTES = 25_000_000
"""Size requested per Ookla download request (the stream loops)."""

FASTCOM_HOME = "https://fast.com"
"""fast.com landing page (links the app bundle carrying the token)."""

FASTCOM_API = "https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount=5"
"""fast.com server-list API."""

FASTCOM_RANGE_BYTES = 26_214_400
"""Byte range requested per fast.com request (same as the web client)."""

HTTP_TIMEOUT = 10
"""Timeout in seconds for the resolution requests."""


class TargetResolver:
    """
    Resolves target specs to URLs, caching the fast.com and Ookla
    lookups for the duration of one run.
    """

    def __init__(self, context: Optional[Dict] = None):
        """
        Initialize empty caches.

        Args:
            context: Public IP info (``city``, ``country``, ``hostname``,
                ``org``) used by the
                ``@city`` / ``@country`` placeholders and the automatic
                fast.com category; can be set later via :attr:`context`.
        """
        self.context = context or {}
        self._lock = threading.Lock()
        self._fastcom_servers: Optional[List[Dict]] = None
        self._ookla_search: Dict[str, List[Dict]] = {}

    def resolve(self, spec: Dict, direction: str) -> Dict:
        """
        Resolve one target spec.

        Args:
            spec: Target spec from the config.
            direction: ``"download"`` or ``"upload"``.

        Returns:
            Dict with ``id``, ``name``, ``category``, ``type``, ``url``,
            ``host`` and ``detail`` (e.g. server location).

        Raises:
            RuntimeError: When the target cannot be resolved (unknown
                type, empty search result, fast.com API failure).
        """
        kind = spec.get("type", "static")
        base = {
            "id": spec["id"], "name": spec.get("name") or spec["id"],
            "category": spec.get("category", "unknown"), "type": kind, "detail": None,
        }
        if kind == "static":
            url = spec["url"]
        elif kind == "ookla":
            host, detail = self._ookla_host(spec)
            base["detail"] = detail
            url = (
                f"http://{host}/download?size={OOKLA_DOWNLOAD_BYTES}"
                if direction == "download" else f"http://{host}/upload"
            )
        elif kind == "fastcom":
            if direction != "download":
                raise RuntimeError("fast.com targets are download only")
            server = self._fastcom_server(int(spec.get("server_index", 0)))
            base["detail"] = server["location"]
            url = server["url"].replace("/speedtest?", f"/speedtest/range/0-{FASTCOM_RANGE_BYTES}?", 1)
            if base["category"] == "auto":
                base["category"] = self._fastcom_category(urlparse(url).hostname or "", server["country"])
        else:
            raise RuntimeError(f"Unknown target type '{kind}'")
        base["url"] = url
        base["host"] = urlparse(url).hostname
        return base

    def _ookla_host(self, spec: Dict):
        """
        Resolve an Ookla target to ``host:port``.

        Args:
            spec: Target spec with ``host`` or ``search`` (optional
                ``index`` into the search results).

        Returns:
            Tuple ``(host, detail)``.

        Raises:
            RuntimeError: When the search returns nothing.
        """
        if spec.get("host"):
            return spec["host"], None
        search = spec.get("search", "")
        for placeholder, key in (("@city", "city"), ("@country", "country")):
            if placeholder in search:
                if not self.context.get(key):
                    raise RuntimeError(f"'{placeholder}' needs the public IP location, which is unknown")
                search = search.replace(placeholder, self.context[key])
        with self._lock:
            if search not in self._ookla_search:
                resp = requests.get(OOKLA_SERVERS_URL.format(search=search), timeout=HTTP_TIMEOUT)
                self._ookla_search[search] = resp.json() or []
            servers = self._ookla_search[search]
        index = int(spec.get("index", 0))
        if len(servers) <= index:
            raise RuntimeError(f"No Ookla server found for search '{search}'")
        server = servers[index]
        return server["host"], f"{server.get('sponsor')} - {server.get('name')}"

    def _fastcom_server(self, index: int) -> Dict:
        """
        Return one fast.com server (token scraped once per run).

        Args:
            index: Position in the API's server list (nearest first).

        Returns:
            Dict with ``url`` and ``location``.

        Raises:
            RuntimeError: When the token or server list cannot be fetched.
        """
        with self._lock:
            if self._fastcom_servers is None:
                self._fastcom_servers = self._fetch_fastcom_servers()
        if len(self._fastcom_servers) <= index:
            raise RuntimeError(f"fast.com returned only {len(self._fastcom_servers)} servers")
        return self._fastcom_servers[index]

    @staticmethod
    def _fetch_fastcom_servers() -> List[Dict]:
        """
        Scrape the fast.com token and query the server list.

        Returns:
            List of ``{"url", "location"}`` dicts, nearest first.

        Raises:
            RuntimeError: When any step fails.
        """
        try:
            home = requests.get(FASTCOM_HOME, timeout=HTTP_TIMEOUT).text
            script = re.search(r"app-[a-z0-9]+\.js", home).group(0)
            bundle = requests.get(f"{FASTCOM_HOME}/{script}", timeout=HTTP_TIMEOUT).text
            token = re.search(r'token:"([A-Za-z0-9]+)"', bundle).group(1)
            data = requests.get(FASTCOM_API.format(token=token), timeout=HTTP_TIMEOUT).json()
        except Exception as e:
            raise RuntimeError(f"fast.com server lookup failed: {e}") from e
        servers = []
        for target in data.get("targets") or []:
            loc = target.get("location") or {}
            servers.append({
                "url": target["url"],
                "location": f"{loc.get('city', '?')}, {loc.get('country', '?')}",
                "country": loc.get("country"),
            })
        return servers

    def _is_own_isp(self, slug: str) -> bool:
        """
        Tell whether an Open Connect ISP slug belongs to the user's ISP.

        Args:
            slug: ISP part of the cache host name (e.g. ``examplenet``).

        Returns:
            ``True`` when a word of the public IP reverse DNS name or ASN
            organization (4+ letters) matches the slug.
        """
        words = re.findall(r"[a-z0-9]{4,}", " ".join(
            str(self.context.get(k) or "") for k in ("hostname", "org")).lower())
        stop = {"network", "networks", "telecom", "communications", "internet", "broadband", "services",
                "company", "corporation", "limited", "group", "static", "dynamic", "empresas", "servicios",
                "telecomunicaciones", "comunicaciones"}
        return any(w in slug or slug in w for w in words if w not in stop and not w.isdigit())

    def _fastcom_category(self, host: str, country: Optional[str]) -> str:
        """
        Derive the category of a fast.com server.

        Args:
            host: Server host name.
            country: Server country code from the fast.com API.

        Returns:
            ``isp-cache`` for caches embedded in the user's own ISP, else ``national`` or
            ``international`` compared with the public IP country
            (``national`` when the country is unknown).
        """
        parts = host.split(".", 1)[0].split("-")
        if len(parts) >= 2 and parts[-1] == "isp" and self._is_own_isp(parts[-2]):
            return "isp-cache"
        mine = self.context.get("country")
        return "international" if mine and country and mine != country else "national"
