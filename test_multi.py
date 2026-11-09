"""Several clients tested at once, each judged against what its own traffic profile needs. Real iperf3 on loopback (127.0.0.x = different clients)."""
import os, shutil, subprocess, sys, threading, time, unittest
import iperf_agent as ag, iperf_client as ic, wifi_monitor as w, speedtools as s
from test_iperf_server import start_agent, monitor, wait_state

def res(mbps, mode="tcp_down", **k): return {"ok": True, "tool": "iperf3", "mode": mode, "mbps": mbps, "link": k.pop("link", {}), **k}
def T(req, demand="target", **k): return {"required": req, "demand": demand, "required_dir": "down", **k}

class Plumbing(unittest.TestCase):
    def test_agent_reports_its_slots(self):
        a = ag.Agent(5900, slots=4); st = a.status(); self.assertEqual((st["ports"], st["slots"]), ([5900, 5901, 5902, 5903], 4)); self.assertEqual(ag.Agent(5900).status()["ports"], [5900])
    def test_target_rate_reaches_the_client_commands(self):
        self.assertEqual(s.client_cmd("10.0.0.2", 5202, "tcp_down", 15, 1, 6, None, 6.0), "iperf3 -c 10.0.0.2 -p 5202 -t 15 -b 6M -R")
        j = {"server_ip": "10.0.0.2", "port": 5202, "mode": "tcp_down", "secs": 15, "streams": 1, "rate": 6, "tcp_rate": 6}
        self.assertEqual(ic.build_argv(j), ["iperf3", "-c", "10.0.0.2", "-p", "5202", "-t", "15", "-b", "6M", "-R"])
        self.assertIn("-b", s.iperf3_argv("10.0.0.2", "tcp_up", 8, 1, 6, 5201, None, 6)); self.assertNotIn("-b", s.iperf3_argv("10.0.0.2", "tcp_up", 8, 1, 6))

class StaleClients(unittest.TestCase):
    def mon(self, states):
        be = w.SimBackend(w.Runner(None)); mac = be.cl[0][0]
        be.ip_to_mac = lambda: {"10.0.0.50": "aa:bb:cc:00:00:01", "10.0.0.51": "aa:bb:cc:00:00:02", "10.0.0.52": "aa:bb:cc:00:00:03"}
        be.neigh_state = states
        m = w.Monitor(be, 1, None); return m
    def macs(self, m): return {l["mac"] for l in m.state["lan"]}
    def test_parse_states(self):
        txt = "192.168.1.5 dev br0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n192.168.1.6 dev br0 lladdr aa:bb:cc:dd:ee:02 STALE\n192.168.1.7 dev br0  FAILED\nfe80::1 dev br0 lladdr aa:bb:cc:dd:ee:03 router STALE\n"
        self.assertEqual(w.parse_neigh_states(txt), {"192.168.1.5": "REACHABLE", "192.168.1.6": "STALE", "192.168.1.7": "FAILED", "fe80::1": "STALE"})
    def test_leftover_entries_never_shown_and_active_ones_age_out(self):
        m = self.mon({"10.0.0.50": "REACHABLE", "10.0.0.51": "STALE", "10.0.0.52": "FAILED"}); m.poll()
        self.assertEqual(self.macs(m), {"aa:bb:cc:00:00:01"})                          # the stale / failed leftovers (e.g. from the previous AP) are not offered
        m.be.neigh_state = {"10.0.0.50": "STALE", "10.0.0.51": "STALE", "10.0.0.52": "FAILED"}; m.poll()
        self.assertIn("aa:bb:cc:00:00:01", self.macs(m))                              # just went idle: kept for a while
        m.lan_seen["aa:bb:cc:00:00:01"] -= 700; m.poll(); self.assertEqual(self.macs(m), set())    # not seen alive for > 10 min: gone
    def test_no_state_information_is_trusted(self):
        m = self.mon(None); m.poll(); self.assertEqual(len(self.macs(m)), 3)

class Verdict(unittest.TestCase):
    def test_target_demand_grades(self):
        self.assertEqual(w._verdict(res(25), T(25))["grade"], "GOOD")
        self.assertEqual(w._verdict(res(24), T(25))["grade"], "GOOD")           # 96%
        self.assertEqual(w._verdict(res(21), T(25))["grade"], "MARGINAL")      # 84%
        self.assertEqual(w._verdict(res(12), T(25))["grade"], "BAD")           # 48%
    def test_flat_out_grades_by_headroom(self):
        self.assertEqual(w._verdict(res(60), T(25, "max"))["grade"], "GOOD")
        self.assertEqual(w._verdict(res(30), T(25, "max"))["grade"], "MARGINAL")
        self.assertEqual(w._verdict(res(20), T(25, "max"))["grade"], "BAD")
    def test_loss_jitter_and_retries_cap_the_grade(self):
        self.assertEqual(w._verdict(res(25, "udp_up", loss_pct=6.0, jitter_ms=2), T(25))["grade"], "BAD")
        v = w._verdict(res(25, "udp_up", loss_pct=2.0, jitter_ms=2), T(25, loss_limit=1)); self.assertEqual(v["grade"], "MARGINAL"); self.assertTrue(any("loss" in r for r in v["reasons"]))
        self.assertEqual(w._verdict(res(25, "udp_up", loss_pct=0, jitter_ms=45), T(25))["grade"], "MARGINAL")
        v = w._verdict(res(25, link={"retry_avg": 30}), T(25)); self.assertEqual(v["grade"], "MARGINAL"); self.assertIn("retries", " ".join(v["reasons"]))
    def test_no_requirement_no_verdict(self): self.assertIsNone(w._verdict(res(25), {}))
    def test_summary_counts_and_overall_grade(self):
        def t(g, a, b): return {"state": "done", "required": 10, "win": (a, b), "result": {"verdict": {"grade": g, "measured": 12}, "link": {"util_max": 40}}}
        m = w._multi_summary([t("GOOD", 0, 10), t("MARGINAL", 1, 11)]); self.assertEqual((m["good"], m["marginal"], m["grade"], m["overlap_s"]), (1, 1, "MARGINAL", 9))
        m = w._multi_summary([t("GOOD", 0, 10), {"state": "error", "required": 10, "result": {"ok": False}}]); self.assertEqual((m["no_result"], m["grade"]), (1, "BAD"))

class ObserveReport(unittest.TestCase):
    def test_single_row_is_multi_status_and_pdf_report(self):
        import report
        be = w.SimBackend(w.Runner(None)); m = w.Monitor(be, 1, None); m.poll()
        self.assertTrue(m.start_multi({"items": [{"mac": be.cl[1][0], "traffic": "video", "quality": "1080p Full HD (5 Mbps)"}], "secs": 5})["ok"])
        for _ in range(80):
            m.poll(); st = m.test_status()
            if st["state"] == "done": break
            time.sleep(0.25)
        self.assertTrue(st["multi"]); self.assertEqual(st["state"], "done")
        pdf = report.build_report(st, m.state, "demo"); self.assertTrue(pdf.startswith(b"%PDF")); self.assertGreater(len(pdf), 1500)

class Observe(unittest.TestCase):
    """Real-traffic mode: no iperf, no agent - the AP's per-client counters are recorded for the chosen time and graded."""
    def mon(self):
        be = w.SimBackend(w.Runner(None)); m = w.Monitor(be, 1, None); m.poll(); return m
    def run_obs(self, m, items, secs=5):
        r = m.start_multi({"items": items, "secs": secs}); self.assertTrue(r.get("ok"), r)
        for _ in range(secs * 8 + 80):
            m.poll(); m.test_status()
            if all(t["state"] not in ("waiting", "running") for t in m.tests): break
            time.sleep(0.25)
        return r, m.test_status()
    def test_observe_needs_no_agent_and_grades_each_client(self):
        m = self.mon(); macs = [c[0] for c in m.be.cl]
        items = [{"mac": macs[1], "traffic": "video", "quality": "1080p Full HD (5 Mbps)"}, {"mac": macs[0], "traffic": "teams"}, {"mac": macs[3], "traffic": "voice"}]
        r, st = self.run_obs(m, items)
        self.assertEqual((r["observing"], r["iperf"]), (3, 0)); self.assertEqual(st["state"], "done")
        for x in st["tests"]:
            self.assertEqual(x["tool"] if "tool" in x else "observe", "observe"); self.assertTrue(x["result"]["ok"], x["result"]); self.assertIn(x["result"]["verdict"]["grade"], ("GOOD", "MARGINAL", "BAD", "NO TRAFFIC"))
        self.assertGreater(st["tests"][0]["result"]["avg_down_mbps"], 1)           # the simulated TV really pulls video
        self.assertEqual(st["summary"]["clients"], 3)
    def test_idle_client_is_no_traffic_not_bad(self):
        m = self.mon(); mac = m.be.cl[3][0]
        v = m._observe_verdict({"ok": True, "avg_down_mbps": 0.0, "avg_up_mbps": 0.0, "mbps": 0.0, "link": {}}, {"required": 5.0, "required_dir": "down", "traffic": "video", "label": "Video", "secs": 15, "quality": "1080p Full HD (5 Mbps)", "n": 1, "iface": None, "util_before": None})
        self.assertEqual(v["grade"], "NO TRAFFIC")
    def test_validation_and_iperf_rows_still_need_agent(self):
        m = self.mon(); mac = m.be.cl[0][0]
        self.assertIn("agent", m.start_multi({"items": [{"mac": mac, "traffic": "video", "method": "iperf"}], "secs": 5})["error"])
        self.assertIn("associated", " ".join(str(x) for x in [self._unassoc()]))
    def _unassoc(self):
        m = self.mon(); r = m._observe_result({"samples": [], "mac": "aa:bb:cc:dd:ee:ff", "secs": 5, "iface": None}); return r.get("error", r)

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 not installed")
class Concurrent(unittest.TestCase):
    PORT = 5760
    def setUp(self):
        subprocess.run(["pkill", "-x", "iperf3"]); time.sleep(0.3)
        Concurrent.PORT += 10; self.agent = ag.Agent(self.PORT, slots=3); self.agent.start()
        self.srv = ag.make_server(self.agent, "127.0.0.1", 0); threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"; time.sleep(1.0)
        self.mon, _ = monitor(self.url); self.mon.arm_timeout = 14; time.sleep(1.2)
    def tearDown(self): self.agent.stop(); self.srv.shutdown(); subprocess.run(["pkill", "-x", "iperf3"])
    def helper(self, ip, out):
        for _ in range(60):
            job = self.mon.pending_for(ip)
            if job.get("pending"):
                p = subprocess.run(ic.build_argv(job, "iperf3"), capture_output=True, text=True, timeout=60); out[ip] = (job, p.returncode); return
            time.sleep(0.25)
    def test_three_clients_two_run_one_never_shows(self):
        items = [{"ip": "127.0.0.2", "traffic": "video", "quality": "720p HD (3 Mbps)", "streams": 2},
                 {"ip": "127.0.0.3", "traffic": "teams", "quality": "1:1 video, recommended (≈1.6 Mbps)", "streams": 1},
                 {"ip": "127.0.0.4", "traffic": "voice", "quality": "G.711 (80 kbps)", "streams": 1}]
        items = [dict(i, method="iperf") for i in items]
        self.assertEqual(self.mon.start_multi({"items": items, "secs": 5, "demand": "target"}), {"ok": True, "count": 3, "observing": 0, "iperf": 3})
        self.assertEqual([t["port"] for t in self.mon.tests], [self.PORT, self.PORT + 1, self.PORT + 2])
        self.assertAlmostEqual(self.mon.tests[0]["required"], 6.0); self.assertIn("-b 6M", self.mon.tests[0]["cmd"]); self.assertIn(f"-p {self.PORT}", self.mon.tests[0]["cmd"])
        out = {}; th = [threading.Thread(target=self.helper, args=(ip, out)) for ip in ("127.0.0.2", "127.0.0.3")]
        for x in th: x.start()
        for x in th: x.join(70)
        self.assertEqual(sorted(out), ["127.0.0.2", "127.0.0.3"]); self.assertEqual(out["127.0.0.2"][0]["port"], self.PORT); self.assertEqual(out["127.0.0.3"][0]["port"], self.PORT + 1)
        for _ in range(100):
            if all(t["state"] != "waiting" for t in self.mon.tests): break
            time.sleep(0.3)
        st = self.mon.test_status(); self.assertTrue(st["multi"]); self.assertEqual(st["state"], "done")
        a, b, c = st["tests"]
        for r in (a, b): self.assertTrue(r["result"]["ok"], r["result"]); self.assertEqual(r["result"]["verdict"]["grade"], "GOOD", r["result"]["verdict"])
        self.assertAlmostEqual(a["result"]["mbps"], 6.0, delta=1.0)                  # rate-limited to what the profile needs, not flat out
        self.assertFalse(c["result"]["ok"]); self.assertIn("127.0.0.4", c["result"]["error"])
        m = st["summary"]; self.assertEqual((m["good"], m["no_result"], m["grade"]), (2, 1, "BAD")); self.assertIsNotNone(m["overlap_s"]); self.assertGreater(m["overlap_s"], 2)
    def test_iperf_row_mixed_with_profiles_is_load_not_graded(self):
        items = [{"ip": "127.0.0.2", "traffic": "spotify", "quality": "Very High (320 kbps)", "method": "iperf"},
                 {"ip": "127.0.0.3", "traffic": "iperf3", "quality": s.MODES["tcp_down"], "streams": 2},
                 {"ip": "127.0.0.4", "traffic": "iperf3", "quality": s.MODES["udp_up"], "rate": 20}]
        self.assertEqual(self.mon.start_multi({"items": items, "secs": 5}), {"ok": True, "count": 3, "observing": 0, "iperf": 3})
        a, b, c = self.mon.tests
        self.assertIsNone(b["required"]); self.assertIn("-P 2", b["cmd"]); self.assertNotIn(" -b ", b["cmd"]); self.assertIn("-u -b 20M", c["cmd"]); self.assertIn("-b 0.32M", a["cmd"])
        out = {}; th = [threading.Thread(target=self.helper, args=(ip, out)) for ip in ("127.0.0.2", "127.0.0.3", "127.0.0.4")]
        for x in th: x.start()
        for x in th: x.join(70)
        for _ in range(100):
            if all(t["state"] != "waiting" for t in self.mon.tests): break
            time.sleep(0.3)
        st = self.mon.test_status(); r = [x["result"] for x in st["tests"]]
        self.assertTrue(all(x["ok"] for x in r), r); self.assertEqual(r[0]["verdict"]["grade"], "GOOD"); self.assertIsNone(r[1]["verdict"]); self.assertIsNone(r[2]["verdict"])
        m = st["summary"]; self.assertEqual((m["good"], m["load_only"], m["no_result"], m["grade"], m["clients"]), (1, 2, 0, "GOOD", 3)); self.assertGreater(r[1]["mbps"], 100)
    def test_validation(self):
        two = [{"ip": "127.0.0.2", "traffic": "video", "method": "iperf"}, {"ip": "127.0.0.2", "traffic": "video", "method": "iperf"}]
        self.assertIn("already in the list", self.mon.start_multi({"items": two})["error"])
        self.assertIn("what this client will be doing", self.mon.start_multi({"items": [{"ip": "127.0.0.2", "traffic": "speedtest"}]})["error"])
        self.assertIn("valid IP", self.mon.start_multi({"items": [{"ip": "999.1.1.1", "traffic": "video", "method": "iperf"}]})["error"])
        self.assertIn("--slots", self.mon.start_multi({"items": [{"ip": f"127.0.0.{i + 2}", "traffic": "video", "method": "iperf"} for i in range(4)]})["error"])
        self.mon.iperf_server = None; self.assertIn("iperf agent", self.mon.start_multi({"items": [{"ip": "127.0.0.2", "traffic": "video", "method": "iperf"}]})["error"])
    def test_cancel_cancels_every_armed_test(self):
        self.mon.start_multi({"items": [{"ip": "127.0.0.2", "traffic": "video", "method": "iperf"}, {"ip": "127.0.0.3", "traffic": "video", "method": "iperf"}], "secs": 5})
        self.assertEqual(self.mon.cancel_test(), {"ok": True}); self.assertTrue(wait_state(self.mon, ("cancelled",), 5))
        time.sleep(1.5); self.assertEqual({t["state"] for t in self.mon.tests}, {"cancelled"})

if __name__ == "__main__": unittest.main()
