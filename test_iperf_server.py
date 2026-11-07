"""Server-PC mode: iperf_agent.py on a LAN PC + the selected client running `iperf3 -c <PC>`. Real-iperf3 tests skip when absent."""
import json, os, shutil, subprocess, sys, tempfile, threading, time, unittest
import iperf_agent as ag, speedtools as s, wifi_monitor as w

FX = os.path.join(os.path.dirname(__file__), "fixtures")
def fx(n): return open(os.path.join(FX, n)).read()

class ParseServer(unittest.TestCase):
    def test_modes_come_from_the_servers_own_record(self):
        for f, mode in (("server_tcp_up", "tcp_up"), ("server_tcp_down", "tcp_down"), ("server_udp_up", "udp_up"), ("server_udp_down", "udp_down")):
            r = s.parse_iperf3_server(fx(f + ".json")); self.assertTrue(r["ok"]); self.assertEqual(r["mode"], mode); self.assertEqual(r["remote_host"], "127.0.0.1")
            self.assertEqual((r["secs"], r["streams"]), (3, 1))
    def test_throughput_uses_the_filled_side(self):
        self.assertAlmostEqual(s.parse_iperf3_server(fx("server_tcp_up.json"))["mbps"], 17795.05, 1)     # sum_sent is 0 here
        r = s.parse_iperf3_server(fx("server_tcp_down.json")); self.assertAlmostEqual(r["mbps"], 18349.26, 1); self.assertEqual(r["retransmits"], 6)
    def test_series_drops_the_end_sliver(self): self.assertEqual(len(s.parse_iperf3_server(fx("server_tcp_up.json"))["series_mbps"]), 3)
    def test_udp_loss_known_only_when_server_receives(self):
        up, down = s.parse_iperf3_server(fx("server_udp_up.json")), s.parse_iperf3_server(fx("server_udp_down.json"))
        self.assertEqual((up["loss_pct"], up["jitter_ms"], up["target_mbps"]), (0, 1.85, 20.0)); self.assertIsNone(down["loss_pct"])
    def test_ipv4_mapped_peer(self): self.assertEqual(s.norm_host("::ffff:192.168.1.23"), "192.168.1.23")
    def test_garbage_and_error(self):
        self.assertFalse(s.parse_iperf3_server("nope")["ok"]); self.assertFalse(s.parse_iperf3_server('{"error":"the client has terminated"}')["ok"])
    def test_client_cmd(self):
        self.assertEqual(s.client_cmd("192.168.1.50", 5201, "tcp_up", 10, 1, 50), "iperf3 -c 192.168.1.50 -t 10")
        self.assertEqual(s.client_cmd("192.168.1.50", 5201, "tcp_down", 10, 4, 50), "iperf3 -c 192.168.1.50 -t 10 -P 4 -R")
        self.assertEqual(s.client_cmd("10.0.0.2", 5733, "udp_down", 8, 1, 25), "iperf3 -c 10.0.0.2 -p 5733 -t 8 -u -b 25M -R")
    def test_client_cmd_rejects_non_ip(self):
        with self.assertRaises(ValueError): s.client_cmd("x; rm -rf /", 5201, "tcp_up", 10, 1, 1)

IPORT = 5741
def start_agent(token=None, port=IPORT):
    a = ag.Agent(port, token=token); threading.Thread(target=a.run_forever, daemon=True).start()
    srv = ag.make_server(a, "127.0.0.1", 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return a, srv, f"http://127.0.0.1:{srv.server_address[1]}"

def monitor(url, client_ip="127.0.0.1", token=None):
    be = w.SimBackend(w.Runner(None)); mac = be.cl[0][0]
    be.ip_to_mac = lambda: {client_ip: mac}
    mon = w.Monitor(be, 1, None); mon.iperf_server, mon.iperf_server_ip, mon.iperf_token = url, "127.0.0.1", token
    mon.poll(); threading.Thread(target=mon.loop, daemon=True).start()
    return mon, mac

def wait_state(mon, states, secs=30):
    for _ in range(secs * 4):
        if mon.test and mon.test["state"] in states: return True
        time.sleep(0.25)
    return False

def client(*extra, secs=3): return subprocess.Popen(["iperf3", "-c", "127.0.0.1", "-p", str(IPORT), "-t", str(secs), *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class AgentEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent, cls.http, cls.url = start_agent(); time.sleep(1.2)
    @classmethod
    def tearDownClass(cls): cls.http.shutdown()

    def test_agent_status(self):
        st = self.agent.status(); self.assertEqual((st["state"], st["iperf_port"]), ("listening", IPORT))
    def test_armed_test_is_matched_scored_and_windowed(self):
        mon, mac = monitor(self.url)
        r = mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}); self.assertEqual(r, {"ok": True})
        st = mon.test_status(); self.assertEqual(st["state"], "waiting"); self.assertIn("iperf3 -c 127.0.0.1", st["cmd"])
        self.assertIn("already running", mon.start_test({"mac": mac, "traffic": "iperf3"}).get("error", ""))
        time.sleep(7); c = client(); c.wait(timeout=20)                            # the client starts well after arming
        self.assertTrue(wait_state(mon, ("done", "error")), mon.test_status()); st = mon.test_status(); self.assertEqual(st["state"], "done", st)
        res = st["result"]; self.assertEqual(res["mode"], "tcp_up"); self.assertGreater(res["mbps"], 100); self.assertTrue(res["insights"])
        self.assertGreaterEqual(res["link"]["n"], 1); self.assertLessEqual(res["link"]["n"], 7)     # 3 s test + 3 s slack at 1 s sampling (this Monitor uses interval=1)
        self.assertGreater(mon.test["n_raw"], res["link"]["n"] + 2, "samples taken while merely waiting must be excluded")
    def test_download_and_udp_modes_detected_from_the_client_command(self):
        mon, mac = monitor(self.url)
        mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3})     # armed as upload ...
        time.sleep(1.5); c = client("-R", "-u", "-b", "15M"); c.wait(timeout=20)                         # ... but the client ran UDP -R
        self.assertTrue(wait_state(mon, ("done", "error"))); st = mon.test_status(); self.assertEqual(st["state"], "done", st)
        self.assertEqual(st["mode"], "udp_down"); self.assertAlmostEqual(st["result"]["mbps"], 15, delta=1.5); self.assertIsNone(st["result"]["loss_pct"])
        self.assertTrue(any("loss and jitter are measured by the client" in i["title"] for i in st["result"]["insights"]))
    def test_other_clients_tests_are_ignored(self):
        mon, mac = monitor(self.url, client_ip="10.9.9.9"); mon.arm_timeout = 5
        mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3})
        time.sleep(1); c = client(); c.wait(timeout=20)                                                    # arrives from 127.0.0.1, not 10.9.9.9
        self.assertTrue(wait_state(mon, ("error",), 45)); st = mon.test_status()
        self.assertIn("127.0.0.1", st["others"]); self.assertIn("No iperf3 test from 10.9.9.9", st["result"]["error"]); self.assertIn("127.0.0.1", st["result"]["error"])
    def test_cancel(self):
        mon, mac = monitor(self.url)
        mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3})
        self.assertEqual(mon.cancel_test(), {"ok": True}); self.assertTrue(wait_state(mon, ("cancelled",), 5))
        self.assertIn("error", mon.cancel_test())
        self.assertEqual(mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}), {"ok": True}); mon.cancel_test()

class AgentProblems(unittest.TestCase):
    def test_unreachable_agent_explains_what_to_run(self):
        mon, mac = monitor("http://127.0.0.1:9")
        e = mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3})["error"]
        self.assertIn("iperf_agent.py", e)
    def test_token_required(self):
        a, srv, url = start_agent(token="sekret", port=5744)
        try:
            mon, mac = monitor(url); self.assertIn("token", mon.start_test({"mac": mac, "traffic": "iperf3", "secs": 3})["error"])
            mon, mac = monitor(url, token="sekret"); time.sleep(1.2)
            self.assertEqual(mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}), {"ok": True}); mon.cancel_test()
        finally: srv.shutdown()
    def test_client_ip_can_be_typed(self):
        a, srv, url = start_agent(port=5746)
        try:
            mon, mac = monitor(url); time.sleep(1.2)
            self.assertIn("not a valid", mon.start_test({"ip": "300.1.1.1", "traffic": "iperf3", "secs": 3})["error"])
            self.assertEqual(mon.start_test({"ip": "10.9.8.7", "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}), {"ok": True})
            self.assertEqual(mon.test["ip"], "10.9.8.7"); self.assertEqual(mon.test["mac"], "ip:10.9.8.7"); self.assertEqual(mon.pending_for("10.9.8.7")["pending"], True); mon.cancel_test()
            self.assertTrue(wait_state(mon, ("cancelled", "done", "error"), 10))
            self.assertEqual(mon.start_test({"ip": "127.0.0.1", "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}), {"ok": True})
            self.assertEqual(mon.test["mac"], mac)                      # a typed IP that is in the client list is tied to that client
            mon.cancel_test()
        finally: srv.shutdown()
    def test_missing_iperf3_reported(self):
        a = ag.Agent(5742, iperf_bin="definitely-not-iperf3"); threading.Thread(target=a.run_forever, daemon=True).start(); time.sleep(0.5)
        self.assertEqual(a.status()["state"], "error"); self.assertIn("not found", a.status()["last_error"])

if __name__ == "__main__": unittest.main()

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class PortBusy(unittest.TestCase):
    def test_busy_port_is_an_error_not_a_flood_of_results(self):
        hog = subprocess.Popen(["iperf3", "-s", "-p", "5743"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1)
        try:
            a = ag.Agent(5743); threading.Thread(target=a.run_forever, daemon=True).start(); time.sleep(2.5)
            self.assertEqual(a.status()["state"], "error"); self.assertIn("in use", a.status()["last_error"]); self.assertEqual(a.status()["last_id"], 0)
        finally: hog.kill()

import iperf_client as ic
class ClientHelper(unittest.TestCase):
    def test_argv_from_job(self):
        j = {"server_ip": "10.0.0.2", "port": 5201, "mode": "udp_down", "secs": 8, "streams": 2, "rate": 25}
        self.assertEqual(ic.build_argv(j), ["iperf3", "-c", "10.0.0.2", "-p", "5201", "-t", "8", "-P", "2", "-u", "-b", "25M", "-R"])
        self.assertEqual(ic.build_argv({**j, "mode": "tcp_up", "streams": 1}), ["iperf3", "-c", "10.0.0.2", "-p", "5201", "-t", "8"])
    def test_argv_rejects_bad_input(self):
        for bad in ({"server_ip": "x; rm -rf /"}, {"mode": "evil"}):
            with self.assertRaises(ValueError): ic.build_argv({"server_ip": "10.0.0.2", "port": 5201, "mode": "tcp_up", "secs": 5, "streams": 1, "rate": 1, **bad})
    def test_pending_is_matched_by_ip_and_claimed_once(self):
        be = w.SimBackend(w.Runner(None)); mac = be.cl[0][0]; be.ip_to_mac = lambda: {"192.168.1.77": mac}
        mon = w.Monitor(be, 1, None); mon.poll()
        self.assertEqual(mon.pending_for("192.168.1.77"), {"pending": False})
        mon.test = {"state": "waiting", "server": True, "ips": ["192.168.1.77"], "server_ip": "192.168.1.3", "port": 5201, "mode": "tcp_down", "secs": 10, "streams": 1, "rate": 50, "claimed": False}
        self.assertEqual(mon.pending_for("192.168.1.99"), {"pending": False})          # another device gets nothing
        j = mon.pending_for("192.168.1.77"); self.assertTrue(j["pending"]); self.assertEqual(j["mode"], "tcp_down")
        self.assertEqual(mon.pending_for("192.168.1.77"), {"pending": False})          # claimed: not started twice

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class ClientHelperEndToEnd(unittest.TestCase):
    def test_helper_runs_the_armed_test_by_itself(self):
        a, srv, url = start_agent(port=5745); time.sleep(1.2)
        mon, mac = monitor(url); mon.iperf_server_ip = "127.0.0.1"
        threading.Thread(target=w.serve, args=(mon, "127.0.0.1", 8745), daemon=True).start(); time.sleep(0.7)
        helper = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "iperf_client.py"), "--dashboard", "http://127.0.0.1:8745"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            self.assertEqual(mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}), {"ok": True})
            self.assertTrue(wait_state(mon, ("done", "error"), 40), mon.test_status()); st = mon.test_status()
            self.assertEqual(st["state"], "done", st); self.assertGreater(st["result"]["mbps"], 100); self.assertEqual(st["result"]["mode"], "tcp_up")
        finally: helper.kill(); srv.shutdown()

class SourceBinding(unittest.TestCase):
    def test_client_command_and_argv_carry_the_source(self):
        self.assertEqual(s.client_cmd("10.0.0.2", 5201, "tcp_down", 10, 1, 1, bind="192.168.1.77"), "iperf3 -c 10.0.0.2 -t 10 -R -B 192.168.1.77")
        self.assertEqual(s.iperf3_argv("192.168.1.9", "tcp_down", 5, 1, 1, bind="192.168.1.2")[-2:], ["-B", "192.168.1.2"])
        self.assertNotIn("-B", s.iperf3_argv("192.168.1.9", "tcp_down", 5, 1, 1))
        for f in (lambda: s.client_cmd("10.0.0.2", 5201, "tcp_up", 5, 1, 1, bind="x;y"), lambda: s.iperf3_argv("10.0.0.2", "tcp_up", 5, 1, 1, bind="$(id)")):
            with self.assertRaises(ValueError): f()
    def test_helper_argv_uses_dashboard_suggestion_or_own_override(self):
        j = {"server_ip": "10.0.0.2", "port": 5201, "mode": "tcp_up", "secs": 5, "streams": 1, "rate": 1, "bind": "192.168.1.77"}
        self.assertEqual(ic.build_argv(j)[-2:], ["-B", "192.168.1.77"]); self.assertEqual(ic.build_argv(j, bind="192.168.1.5")[-2:], ["-B", "192.168.1.5"])
        self.assertNotIn("-B", ic.build_argv(j, bind=None)); self.assertNotIn("-B", ic.build_argv({**j, "bind": None}))
    def test_pending_matches_the_stated_wifi_ip_when_polling_over_another_network(self):
        be = w.SimBackend(w.Runner(None)); mac = be.cl[0][0]; be.ip_to_mac = lambda: {"192.168.1.77": mac}
        mon = w.Monitor(be, 1, None); mon.poll()
        mon.test = {"state": "waiting", "server": True, "ips": ["192.168.1.77"], "server_ip": "192.168.1.3", "port": 5201, "mode": "tcp_up", "secs": 10, "streams": 1, "rate": 50, "claimed": False, "bind": "192.168.1.77"}
        self.assertEqual(mon.pending_for("10.20.0.9"), {"pending": False})                         # management address alone is not enough
        self.assertEqual(mon.pending_for("10.20.0.9", "192.168.1.5"), {"pending": False})         # a Wi-Fi IP that is not this client's
        j = mon.pending_for("10.20.0.9", "192.168.1.77"); self.assertTrue(j["pending"]); self.assertEqual(j["bind"], "192.168.1.77")
    def test_armed_command_binds_the_clients_ip_unless_disabled(self):
        a, srv, url = start_agent(port=5747); time.sleep(0.5)
        try:
            for on, expect in ((True, "-B 127.0.0.1"), (False, None)):
                mon, mac = monitor(url); mon.iperf_server_ip, mon.bind_client = "127.0.0.1", on
                mon.start_test({"mac": mac, "traffic": "iperf3", "quality": s.MODES["tcp_up"], "secs": 3}); cmd = mon.test_status()["cmd"]; mon.cancel_test()
                self.assertTrue(cmd.endswith(expect) if expect else "-B" not in cmd, cmd)
        finally: srv.shutdown()

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class SourceBindingReal(unittest.TestCase):
    def test_agent_listens_only_on_the_bound_address_and_client_binds_its_source(self):
        a = ag.Agent(5748, bind="127.0.0.1"); threading.Thread(target=a.run_forever, daemon=True).start(); time.sleep(1.3)
        self.assertEqual((a.status()["state"], a.status()["server_ip"]), ("listening", "127.0.0.1"))
        r = subprocess.run(["iperf3", "-c", "127.0.0.1", "-p", "5748", "-t", "2", "-B", "127.0.0.1", "-J"], capture_output=True, text=True, timeout=30); self.assertEqual(r.returncode, 0, r.stdout[-300:])
        for _ in range(20):
            if a.status()["last_id"]: break
            time.sleep(0.3)
        p = s.parse_iperf3_server(a.results_after(0)["results"][0]["raw"]); self.assertEqual(p["remote_host"], "127.0.0.1"); self.assertGreater(p["mbps"], 100)
    def test_bad_bind_address_is_reported(self):
        a = ag.Agent(5749, bind="203.0.113.77"); threading.Thread(target=a.run_forever, daemon=True).start(); time.sleep(1.5)
        self.assertEqual(a.status()["state"], "error"); self.assertTrue(a.status()["last_error"])
    def test_dashboard_run_uses_the_source(self):
        srv = subprocess.Popen(["iperf3", "-s", "-1", "-p", "5750", "-B", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(0.8)
        try: r = s.run_iperf3("127.0.0.1", "tcp_down", 2, 1, 1, port=5750, bind="127.0.0.1"); self.assertTrue(r["ok"], r); self.assertGreater(r["mbps"], 100)
        finally: srv.kill()

class FindIperf3(unittest.TestCase):
    def _fake(self, d, name="iperf3"):
        p = os.path.join(d, name); open(p, "w").write("#!/bin/sh\necho fake\n"); os.chmod(p, 0o755); return p
    def test_explicit_file_and_folder(self):
        d = tempfile.mkdtemp(); p = self._fake(d)
        self.assertEqual(s.find_iperf3(p), p); self.assertEqual(s.find_iperf3(d), p); self.assertIsNone(s.find_iperf3(os.path.join(d, "nope")))
        for mod in (ag, ic): self.assertEqual(mod.find_iperf3(d), p)                                     # the agent and the client carry their own copy
    def test_env_and_current_folder(self):
        d = tempfile.mkdtemp(); p = self._fake(d); old_env, old_cwd, old_path = os.environ.get("IPERF3_PATH"), os.getcwd(), os.environ["PATH"]
        try:
            os.environ["PATH"] = "/nonexistent"; os.environ["IPERF3_PATH"] = d; self.assertEqual(s.find_iperf3(), p)
            os.environ.pop("IPERF3_PATH"); os.chdir(d); self.assertEqual(s.find_iperf3(), p)
        finally:
            os.chdir(old_cwd); os.environ["PATH"] = old_path
            if old_env is not None: os.environ["IPERF3_PATH"] = old_env
    def test_not_found_message_tells_what_to_do(self):
        r = s.run_iperf3("127.0.0.1", "tcp_down", 1, 1, 1, iperf_bin="/definitely/not/here/iperf3")
        self.assertFalse(r["ok"]); self.assertIn("--iperf-bin", r["error"]); self.assertIn("/definitely/not/here/iperf3", r["error"])

@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class CopiedBinary(unittest.TestCase):
    def test_everything_works_with_iperf3_outside_path(self):
        real = shutil.which("iperf3"); d = tempfile.mkdtemp(); exe = os.path.join(d, "iperf3"); shutil.copy(real, exe); os.chmod(exe, 0o755)
        if subprocess.run([exe, "--version"], capture_output=True).returncode != 0: self.skipTest("binary is not relocatable here")
        env = dict(os.environ, PATH="/usr/bin:/bin")                                                      # a PATH without iperf3
        a = ag.Agent(5752, iperf_bin=d); threading.Thread(target=a.run_forever, daemon=True).start(); time.sleep(1.3)
        self.assertEqual(a.status()["state"], "listening", a.status())
        r = s.run_iperf3("127.0.0.1", "tcp_up", 2, 1, 1, port=5752, iperf_bin=exe); self.assertTrue(r["ok"], r)                 # dashboard-run test, explicit path
        for _ in range(20):
            if a.status()["last_id"]: break
            time.sleep(0.3)
        self.assertEqual(a.status()["last_id"], 1)
