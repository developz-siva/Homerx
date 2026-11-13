import time, unittest, os, shutil
import pingmon as pm, report, wifi_monitor as w

class Parse(unittest.TestCase):
    def test_replies(self):
        for s, v in (("Reply from 8.8.8.8: bytes=32 time=14ms TTL=117", 14.0), ("Reply from 1.1.1.1: bytes=32 time<1ms TTL=64", 0.5), ("64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.4 ms", 12.4),
                     ("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=9.812 ms", 9.812), ("Antwort von 8.8.8.8: Bytes=32 Zeit=14ms TTL=117", 14.0), ("Request timed out.", None), ("Destination host unreachable.", None)):
            self.assertEqual(pm.parse_ping(s), v)
    def test_stats(self):
        s = pm.stats([(0, 10.0), (1, 12.0), (2, None), (3, 30.0)])
        self.assertEqual((s["sent"], s["lost"], s["loss_pct"], s["min"], s["max"]), (4, 1, 25.0, 10.0, 30.0)); self.assertEqual(s["jitter"], 10.0)
    def test_downsample_keeps_losses(self):
        d = pm.downsample([(i, None if i == 500 else 5.0) for i in range(3000)], 600); self.assertLessEqual(len(d), 600); self.assertTrue(any(x[1] is None for x in d))
    def test_findings_separate_lan_from_wan(self):
        mk = lambda n, g, loss, p95: {"name": n, "group": g, "stats": {"sent": 50, "loss_pct": loss, "p95": p95, "jitter": 3}}
        f = pm.findings([mk("LAN 1.1", "lan", 0, 3), mk("WAN 8.8.8.8", "wan", 10, 400)]); self.assertIn("Internet (WAN)", f[0]["title"])
        f = pm.findings([mk("LAN 1.1", "lan", 8, 90), mk("WAN 8.8.8.8", "wan", 10, 400)]); self.assertIn("inside your network", f[0]["detail"])

class Monitor(unittest.TestCase):
    def test_pings_for_the_whole_test_and_graphs_it(self):
        fake = lambda host, t=1000: 5.0 + (hash(host) % 7)
        be = w.SimBackend(w.Runner(None)); m = w.Monitor(be, 1, None); m.poll(); m.pingmon = pm.PingMonitor(ping_fn=fake, interval=0.2)
        macs = [c[0] for c in be.cl]
        r = m.start_multi({"items": [{"mac": macs[1], "traffic": "video", "quality": "1080p Full HD (5 Mbps)"}], "secs": 5, "ping": {"on": True, "lan": "192.168.1.1", "wan": "8.8.8.8, 1.1.1.1"}})
        self.assertTrue(r["ok"]); self.assertGreaterEqual(r["ping_targets"], 4)
        for _ in range(80):
            m.poll(); st = m.test_status()
            if st["state"] == "done" and not st["ping"]["running"]: break
            time.sleep(0.25)
        p = st["ping"]; self.assertFalse(p["running"]); names = [t["name"] for t in p["targets"]]
        self.assertIn("LAN 192.168.1.1", names); self.assertIn("WAN 8.8.8.8", names); self.assertTrue(any(t["group"] == "client" for t in p["targets"]))
        self.assertGreater(p["targets"][0]["stats"]["sent"], 10); self.assertGreater(p["elapsed"], 4)
        pdf = report.build_report(st, m.state, "x"); self.assertTrue(pdf.startswith(b"%PDF")); self.assertGreater(len(pdf), 3000)
    def test_bad_hosts_are_dropped_and_off_means_off(self):
        be = w.SimBackend(w.Runner(None)); m = w.Monitor(be, 1, None); m.pingmon = pm.PingMonitor(ping_fn=lambda h, t=1000: 1.0, interval=0.2)
        self.assertEqual(m._start_ping({"on": False}, []), 0)
        n = m._start_ping({"on": True, "lan": "-c 5 evil;rm", "wan": "8.8.8.8"}, []); targets = [t["host"] for t in m.pingmon.targets]
        self.assertNotIn("evil;rm", targets); self.assertNotIn("-c", targets); self.assertIn("8.8.8.8", targets); m.pingmon.stop()
    @unittest.skipUnless(shutil.which("ping"), "no ping binary")
    def test_real_ping_loopback(self):
        v = pm.ping_once("127.0.0.1"); self.assertTrue(v is None or v < 50)

if __name__ == "__main__": unittest.main()
