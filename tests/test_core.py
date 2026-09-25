"""Unit tests (no network access)."""

import tempfile
import unittest
from pathlib import Path

from netspeeddiag import analyzer, latency_probe, service_probe, throughput
from netspeeddiag.targets import TargetResolver
from netspeeddiag.settings import deep_merge
from netspeeddiag.store import ResultStore

PING_OUTPUT = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.0 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=12.0 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=117 time=11.0 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
"""


def make_test(target_id, category, streams, mbps, name=None):
    """Build a minimal throughput test entry."""
    return {
        "target": {"id": target_id, "name": name or target_id, "category": category},
        "streams": streams,
        "result": {"steady_mbps": mbps, "tcp": {}},
    }


class PingParsingTest(unittest.TestCase):
    def test_parse(self):
        r = latency_probe.parse_ping_output(PING_OUTPUT, 4)
        self.assertEqual((r["sent"], r["received"], r["loss_pct"]), (4, 3, 25.0))
        self.assertEqual((r["min"], r["max"], r["avg"]), (10.0, 12.0, 11.0))
        self.assertEqual(r["jitter"], 1.5)

    def test_no_replies(self):
        r = latency_probe.summarize_rtts([], 5)
        self.assertEqual(r["loss_pct"], 100.0)
        self.assertIsNone(r["avg"])


class ThroughputSummaryTest(unittest.TestCase):
    def test_rates(self):
        # 1 MB per second for 4 s
        samples = [(t * 0.5, int(t * 0.5 * 1_000_000)) for t in range(9)]
        r = throughput.summarize(samples, [], 4.0, 2.0, "download", {"TCPOFOQueue": 0},
                                 {"rx_packets": 5000})
        self.assertAlmostEqual(r["mbps"], 8.0)
        self.assertAlmostEqual(r["steady_mbps"], 8.0)
        self.assertAlmostEqual(r["peak_mbps"], 8.0)
        self.assertEqual(r["tcp"]["loss_indicator_pct"], 0.0)

    def test_warmup_excluded(self):
        samples = [(0.0, 0), (1.0, 0), (2.0, 0), (3.0, 1_000_000), (4.0, 2_000_000)]
        r = throughput.summarize(samples, [], 4.0, 2.0, "download", {}, {})
        self.assertAlmostEqual(r["steady_mbps"], 8.0)
        self.assertAlmostEqual(r["mbps"], 4.0)


class AnalyzerTest(unittest.TestCase):
    def base_doc(self):
        return {
            "system": {"route": {"gateway": "192.168.0.1"},
                       "interface": {"name": "eth0", "speed_mbps": 1000, "duplex": "full", "wireless": False},
                       "tcp": {"congestion_control": "cubic"}, "first_hops": []},
            "ping": [{"host": "192.168.0.1", "sent": 20, "received": 20, "loss_pct": 0, "avg": 0.5},
                     {"host": "8.8.8.8", "sent": 20, "received": 20, "loss_pct": 0, "avg": 10.0}],
            "download": [], "upload": [], "route": [], "loaded_latency": {},
        }

    def codes(self, result, severity=None):
        return {f["code"] for f in result["findings"] if severity is None or f["severity"] == severity}

    def test_per_flow_limit(self):
        doc = self.base_doc()
        doc["download"] = [make_test("cf", "international", 1, 5.0), make_test("cf", "international", 4, 60.0)]
        result = analyzer.analyze(doc, {"download_mbps": 0, "upload_mbps": 0})
        self.assertIn("PER_FLOW_LIMIT", self.codes(result, "warn"))
        self.assertIn("CONGESTION_CONTROL", self.codes(result))
        self.assertEqual(result["summary"]["best_single_stream_download_mbps"], 5.0)

    def test_plan(self):
        doc = self.base_doc()
        doc["download"] = [make_test("x", "local", 4, 100.0)]
        result = analyzer.analyze(doc, {"download_mbps": 300, "upload_mbps": 0})
        self.assertIn("PLAN_DOWNLOAD", self.codes(result, "crit"))

    def test_bufferbloat_and_loaded_loss(self):
        doc = self.base_doc()
        doc["loaded_latency"] = {"download": {"pings": [
            {"host": "8.8.8.8", "sent": 50, "received": 45, "loss_pct": 10.0, "avg": 150.0}]}}
        result = analyzer.analyze(doc, {})
        self.assertIn("BUFFERBLOAT_DOWNLOAD", self.codes(result, "crit"))
        self.assertIn("LOADED_LOSS_DOWNLOAD", self.codes(result, "warn"))

    def test_single_lost_ping_not_alarming(self):
        doc = self.base_doc()
        doc["ping"][1].update(received=19, loss_pct=5.0)
        result = analyzer.analyze(doc, {})
        self.assertIn("IDLE_LOSS", self.codes(result, "info"))

    def test_double_nat(self):
        doc = self.base_doc()
        doc["system"]["first_hops"] = [{"host": "192.168.0.1", "private": True},
                                       {"host": "192.168.1.1", "private": True}]
        self.assertIn("DOUBLE_NAT", self.codes(analyzer.analyze(doc, {}), "info"))

    def test_nat_layers(self):
        hops = [{"host": "192.168.0.1", "private": True, "avg_ms": 0.5},
                {"host": "192.168.1.1", "private": True, "avg_ms": 1.4},
                {"host": "10.29.12.250", "private": True, "avg_ms": 4.0},
                {"host": "190.131.255.14", "private": False, "avg_ms": 10.8}]
        layers = analyzer.nat_layers(hops)
        self.assertEqual(layers["home"], ["192.168.0.1", "192.168.1.1"])
        self.assertEqual(layers["isp_private"], ["10.29.12.250"])
        single = analyzer.nat_layers([{"host": "192.168.1.1", "private": True, "avg_ms": 1.0},
                                      {"host": "100.72.0.1", "private": True, "cgnat": True}])
        self.assertEqual((single["home"], single["cgnat"]), (["192.168.1.1"], ["100.72.0.1"]))


class StoreAndSettingsTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ResultStore(Path(tmp))
            store.save({"id": "20260101-120000", "profile": "quick", "status": "completed",
                        "summary": {"best_download_mbps": 10}})
            self.assertEqual(store.get("20260101-120000")["profile"], "quick")
            self.assertEqual(len(store.list()), 1)
            self.assertIn("best_download_mbps", store.to_csv())
            self.assertTrue(store.delete("20260101-120000"))
            with self.assertRaises(ValueError):
                store.get("../etc/passwd")

    def test_deep_merge(self):
        merged = deep_merge({"a": {"b": 1, "c": [1, 2]}, "d": 1}, {"a": {"c": [3]}})
        self.assertEqual(merged, {"a": {"b": 1, "c": [3]}, "d": 1})

    def test_deep_merge_by_id(self):
        base = {"checks": [{"id": "a", "host": "x", "enabled": True}, {"id": "b", "host": "y"}]}
        merged = deep_merge(base, {"checks": [{"id": "a", "enabled": False}, {"id": "c", "host": "z"}]})
        self.assertEqual([c["id"] for c in merged["checks"]], ["a", "b", "c"])
        self.assertEqual(merged["checks"][0], {"id": "a", "host": "x", "enabled": False})


class ServiceAndTargetTest(unittest.TestCase):
    def test_dns_packet(self):
        packet = service_probe._dns_packet("google.com", 0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertIn(b"\x06google\x03com\x00", packet)
        self.assertTrue(packet.endswith(b"\x00\x01\x00\x01"))

    def test_fastcom_category(self):
        r = TargetResolver({"country": "XX", "hostname": "host-203-0-113-5.examplenet.net",
                            "org": "AS64500 EXAMPLENET COMMUNICATIONS"})
        self.assertEqual(r._fastcom_category("ipv4-c004-abc001-examplenetco-isp.1.oca.nflxvideo.net", "XX"), "isp-cache")
        self.assertEqual(r._fastcom_category("ipv4-c001-abc002-othercarrier-isp.1.oca.nflxvideo.net", "XX"), "national")
        self.assertEqual(r._fastcom_category("ipv4-c001-abc003-ix.1.oca.nflxvideo.net", "YY"), "international")

    def test_service_findings(self):
        doc = AnalyzerTest().base_doc()
        doc["services"] = [
            {"id": "do", "name": "DO NYC3", "type": "https", "category": "cloud", "attempts": 5, "ok": 4,
             "fail_pct": 20.0, "errors": {"timed out": 1},
             "connect_ms": {"avg": 75, "max": 1080, "p95": 1080}, "tls_ms": {"avg": 80}},
            {"id": "dns", "name": "DNS", "type": "dns", "resolvers": [
                {"name": "1.1.1.1", "attempts": 6, "ok": 6, "fail_pct": 0, "errors": {}, "query_ms": {"avg": 15}},
                {"name": "router", "attempts": 6, "ok": 6, "fail_pct": 0, "errors": {}, "query_ms": {"avg": 180}}]},
        ]
        result = analyzer.analyze(doc, {})
        codes = {f["code"] for f in result["findings"]}
        self.assertTrue({"SERVICE_FAILURES", "SYN_RETRANSMIT", "CLOUD_LATENCY", "DNS_SLOW"} <= codes)
        self.assertEqual(result["summary"]["service_fail_pct"], 20.0)
        self.assertEqual(result["summary"]["dns_best_ms"], 15)

    def test_thresholds_override(self):
        doc = AnalyzerTest().base_doc()
        doc["download"] = [make_test("x", "local", 4, 100.0)]
        doc["config"] = {"analysis": {"plan_ok_ratio": 0.3}}
        result = analyzer.analyze(doc, {"download_mbps": 300})
        self.assertIn("PLAN_DOWNLOAD", {f["code"] for f in result["findings"] if f["severity"] == "ok"})


if __name__ == "__main__":
    unittest.main()
