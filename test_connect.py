"""Connection set-up from the dashboard: Monitor.connect / disconnect / auto-detect / memory over the same link / HTTP endpoints."""
import json, os, socket, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wifi_monitor as wm
from test_memwatch import FakeTelnetd
HERE = os.path.dirname(os.path.abspath(__file__))

def stub_wl():
    d = tempfile.mkdtemp(); stub = os.path.join(d, "wl")
    open(stub, "w").write('#!/bin/sh\ncase "$*" in\n *ver*) echo "7.14.164.2";;\n *"-i wl1 chanspec"*) echo "6g101/320-2 (0x7043)";;\n'
                          ' *"-i wl1 sta_info all"*) cat "%s/wl_sta_info_all_6g.txt";;\n'
                          ' *"-i wl1 chanim_stats"*) printf "chanspec tx inbss obss nocat nopkt doze txop goodtx badtx glitch badplcp knoise timestamp\\n0x7043 1 2 6 0 3 0 88 0 0 5 0 -89 1\\n";;\n'
                          ' *chanspec*) echo "wl driver adapter not found";;\n *assoclist*) ;;\nesac\n' % HERE)
    os.chmod(stub, 0o755); return d

class Connect(unittest.TestCase):
    def setUp(self):
        self.old = os.environ["PATH"]; os.environ["PATH"] = stub_wl() + ":" + self.old
        self.srv = FakeTelnetd(user="admin", password="pw"); self.tmp = tempfile.mkdtemp()
        self.mon = wm.Monitor(None, 5); self.mon.mem_dir = os.path.join(self.tmp, "mem"); self.mon.settings_path = os.path.join(self.tmp, "c.json")
    def tearDown(self):
        os.environ["PATH"] = self.old; self.mon.disconnect(); self.srv.close()
    def cfg(self, **k):
        return {"transport": "telnet", "host": "127.0.0.1", "port": str(self.srv.port), "user": "admin", "password": "pw", "max_flows": "0", **k}

    def test_starts_in_setup_mode_and_poll_is_a_noop(self):
        self.assertEqual(self.mon.conn["state"], "setup"); self.mon.poll(); self.assertEqual(self.mon.state["ts"], 0)
        self.assertEqual(json.loads(self.mon.snapshot())["connection"]["state"], "setup")

    def test_telnet_autodetects_wl_and_interface(self):
        r = self.mon.connect(self.cfg())
        self.assertTrue(r["ok"], r); self.assertEqual(r["backend"], "wl"); self.assertEqual(r["ifaces"], ["wl1"])
        self.assertEqual(self.mon.conn["state"], "connected"); self.assertTrue(self.mon.state["ts"]); self.assertEqual(self.mon.state["radios"][0]["iface"], "wl1")
        self.assertTrue(self.mon.state["clients"])

    def test_test_button_does_not_connect(self):
        r = self.mon.connect(self.cfg(), test=True)
        self.assertTrue(r["ok"], r); self.assertIsNone(self.mon.be); self.assertEqual(self.mon.conn["state"], "setup")

    def test_wrong_password_is_reported(self):
        r = self.mon.connect(self.cfg(password="bad"))
        self.assertFalse(r["ok"]); self.assertIn("rejected", r["error"]); self.assertIsNone(self.mon.be)

    def test_unreachable_host(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        r = self.mon.connect(self.cfg(port=str(port))); self.assertFalse(r["ok"]); self.assertTrue(r["error"])

    def test_missing_fields_are_explained(self):
        self.assertIn("serial port", self.mon.connect({"transport": "serial"})["error"])
        self.assertIn("IP", self.mon.connect({"transport": "telnet"})["error"])
        self.assertIn("web address", self.mon.connect({"transport": "ubus"})["error"])

    def test_bad_serial_port_gives_a_hint(self):
        r = self.mon.connect({"transport": "serial", "serial_port": "/dev/does-not-exist-9"})
        self.assertFalse(r["ok"]); self.assertRegex(r["error"], r"(?i)pyserial|cannot open")

    def test_memory_over_the_same_connection_then_disconnect_stops_it(self):
        r = self.mon.connect(self.cfg(mem_mode="same", mem_interval="60", mem_label="ap"))
        self.assertTrue(r["ok"], r); self.assertIsNotNone(self.mon.mem)
        col = self.mon.mem
        self.assertTrue(col.poll(), col.last_error); self.assertGreater(col.status()["samples"], 0)
        self.mon.disconnect(); self.assertTrue(col.stopped); self.assertIsNone(self.mon.mem)

    def test_memory_over_separate_telnet(self):
        r = self.mon.connect(self.cfg(mem_mode="telnet", mem_user="admin", mem_password="pw", mem_interval="60"))
        self.assertTrue(r["ok"], r); self.assertTrue(self.mon.mem.poll(), self.mon.mem.last_error)

    def test_memory_same_without_a_device_warns_but_connects(self):
        r = self.mon.connect({"transport": "sim", "mem_mode": "same"})
        self.assertTrue(r["ok"]); self.assertIn("memory collection not started", r["warning"]); self.assertIsNone(self.mon.mem)

    def test_reconnect_replaces_the_old_link_and_clears_history(self):
        self.mon.connect({"transport": "sim"}); self.assertEqual(self.mon.conn["info"]["backend"], "sim")
        self.mon.connect(self.cfg()); self.assertEqual(self.mon.conn["info"]["backend"], "wl")
        self.assertTrue(all(r["iface"] == "wl1" for r in self.mon.state["radios"]))

    def test_saved_form_never_contains_passwords(self):
        self.mon.connect(self.cfg(mem_mode="telnet", mem_user="admin", mem_password="secret2"))
        raw = open(self.mon.settings_path).read(); self.assertNotIn("pw\"", raw); self.assertNotIn("secret2", raw); self.assertEqual(self.mon.saved_form()["host"], "127.0.0.1")

    def test_tests_need_a_connection(self):
        self.assertIn("Not connected", self.mon.start_test({"mac": "x", "traffic": "video"})["error"])

class Http(unittest.TestCase):
    def setUp(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        self.mon = wm.Monitor(None, 5); self.mon.settings_path = os.path.join(tempfile.mkdtemp(), "c.json")
        threading.Thread(target=wm.serve, args=(self.mon, "127.0.0.1", self.port), daemon=True).start(); time.sleep(0.4)
    def call(self, path, body=None, ct="application/json"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", None if body is None else json.dumps(body).encode(), {"Content-Type": ct} if body is not None else {})
        try:
            with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e: return e.code, None
    def test_flow(self):
        st, c = self.call("/api/connection"); self.assertEqual(st, 200); self.assertEqual(c["state"], "setup"); self.assertIn("serial", c["transports"])
        st, p = self.call("/api/ports"); self.assertEqual(st, 200); self.assertIn("ports", p)
        self.assertEqual(self.call("/api/connect", {"transport": "sim"}, ct="text/plain")[0], 415)
        st, r = self.call("/api/connect/test", {"transport": "sim"}); self.assertTrue(r["ok"]); self.assertEqual(self.call("/api/connection")[1]["state"], "setup")
        st, r = self.call("/api/connect", {"transport": "sim"}); self.assertTrue(r["ok"])
        s = self.call("/api/state")[1]; self.assertEqual(s["connection"]["state"], "connected"); self.assertTrue(s["clients"])
        self.assertEqual(self.call("/api/connection")[1]["form"]["transport"], "sim")
        self.assertTrue(self.call("/api/disconnect", {})[1]["ok"]); self.assertEqual(self.call("/api/state")[1]["connection"]["state"], "setup")
    def test_page_has_the_connection_panel(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/") as r: html = r.read().decode()
        for needle in ("f_transport", "Serial console", "Telnet", "SSH", "api/connect", "f_serial_port", "f_mem_mode"): self.assertIn(needle, html)

if __name__ == "__main__": unittest.main()
