"""iperf3 fixtures are REAL `iperf3 -J` output (v3.17.1, loopback). The Ookla/speedtest-cli samples are synthetic, written to the documented JSON shapes."""
import json, os, shutil, threading, time, unittest, subprocess
import speedtools as s, wifi_monitor as w
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
def fx(n): return open(os.path.join(FX, n)).read()

class Parse(unittest.TestCase):
    def test_tcp(self):
        r = s.parse_iperf3(fx("iperf3_tcp_down.json"), "tcp_down")
        self.assertTrue(r["ok"]); self.assertGreater(r["mbps"], 100); self.assertIsInstance(r["retransmits"], int); self.assertGreaterEqual(len(r["series_mbps"]), 2)
    def test_udp(self):
        r = s.parse_iperf3(fx("iperf3_udp_down.json"), "udp_down")
        self.assertAlmostEqual(r["mbps"], 20, delta=1); self.assertIn("jitter_ms", r); self.assertEqual(r["loss_pct"], 0)
    def test_refused_is_friendly(self):
        r = s.parse_iperf3(fx("iperf3_refused.json"), "tcp_down")
        self.assertFalse(r["ok"]); self.assertIn("iperf3 -s", r["error"])
    def test_garbage(self): self.assertFalse(s.parse_iperf3("not json", "tcp_down")["ok"])
    def test_argv(self):
        a = s.iperf3_argv("192.168.1.20", "udp_up", 10, 2, 25)
        self.assertEqual(a[:3], ["iperf3", "-c", "192.168.1.20"]); self.assertEqual(a[a.index("-p") + 1], "5201"); self.assertIn("-R", a); self.assertEqual(a[a.index("-b") + 1], "25M"); self.assertIn("-u", a)
        self.assertNotIn("-R", s.iperf3_argv("192.168.1.20", "tcp_down", 10, 1, 1)); self.assertIn("-O", s.iperf3_argv("192.168.1.20", "tcp_down", 10, 1, 1))
    def test_argv_rejects_non_ip(self):
        for bad in ("1.2.3.4; rm -rf /", "$(id)", "host.name", "--help"):
            with self.assertRaises(ValueError): s.iperf3_argv(bad, "tcp_down", 10, 1, 1)
    def test_ookla(self):   # bandwidth is BYTES per second
        r = s.parse_speedtest(json.dumps({"type": "result", "ping": {"latency": 12.5, "jitter": 1.2}, "download": {"bandwidth": 12_500_000}, "upload": {"bandwidth": 2_500_000},
                                          "packetLoss": 0, "isp": "X", "server": {"name": "S", "location": "Dallas"}}))
        self.assertEqual((r["down_mbps"], r["up_mbps"], r["ping_ms"]), (100.0, 20.0, 12.5))
    def test_speedtest_cli(self):   # bits per second
        r = s.parse_speedtest(json.dumps({"download": 94_000_000.0, "upload": 11_000_000.0, "ping": 20.1, "server": {"sponsor": "Foo", "name": "Dallas"}, "client": {"isp": "Y"}}))
        self.assertEqual((r["down_mbps"], r["up_mbps"]), (94.0, 11.0))

PORT = 5733

def local_monitor():
    be = w.SimBackend(w.Runner(None)); mac = be.cl[0][0]
    be.ip_to_mac = lambda: {"127.0.0.1": mac}          # every poll maps 127.0.0.1 to the first simulated client
    mon = w.Monitor(be, 1, None); mon.iperf_port = PORT; mon.poll()
    return mon, mac

def wait_done(mon, secs=40):
    for _ in range(secs * 2):
        if mon.test and mon.test["state"] != "running": return
        time.sleep(0.5)

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class RealIperf(unittest.TestCase):
    """Runs the real iperf3 against a local server through the Monitor, including link sampling during the test."""
    def test_end_to_end(self):
        srv = subprocess.Popen(["iperf3", "-s", "-p", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1)
        try:
            mon, mac = local_monitor(); threading.Thread(target=mon.loop, daemon=True).start()
            self.assertEqual(mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_down"], "secs": 4}), {"ok": True})
            self.assertIn("already running", mon.start_test({"mac": mac, "traffic": "iperf3"}).get("error", ""))
            wait_done(mon)
            st = mon.test_status(); self.assertEqual(st["state"], "done", st); r = st["result"]
            self.assertGreater(r["mbps"], 100); self.assertGreaterEqual(r["link"]["n"], 1); self.assertTrue(r["insights"]); self.assertIsNotNone(r["pred"])
        finally: srv.kill()
    def test_udp_and_reverse(self):
        srv = subprocess.Popen(["iperf3", "-s", "-p", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1)
        try:
            mon, mac = local_monitor()
            mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["udp_up"], "secs": 3, "rate": 10}); wait_done(mon)
            r = mon.test_status()["result"]; self.assertTrue(r["ok"], r); self.assertAlmostEqual(r["mbps"], 10, delta=1); self.assertEqual(r["target_mbps"], 10)
            self.assertTrue(any(i["sev"] == "ok" for i in r["insights"]), r["insights"])
        finally: srv.kill()
    def test_refused_shows_error(self):
        mon, mac = local_monitor()      # nothing is listening on PORT
        mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_down"], "secs": 3}); wait_done(mon)
        self.assertEqual(mon.test["state"], "error"); self.assertIn("iperf3 -s", mon.test["result"]["error"])

class Validation(unittest.TestCase):
    def test_bad_requests(self):
        mon = w.Monitor(w.SimBackend(w.Runner(None)), 1, None); mon.poll()
        self.assertIn("error", mon.start_test({"mac": "x", "traffic": "video"}))          # not a test type
        self.assertIn("error", mon.start_test({"mac": "nope", "traffic": "iperf3"}))      # unknown client
        self.assertIn("error", mon.start_test({"mac": "x", "traffic": "iperf3", "secs": "abc"}))
if __name__ == "__main__": unittest.main()
