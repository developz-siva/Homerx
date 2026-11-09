import json, os, pty, select, subprocess, threading, time, unittest, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
import transport as t, wifi_monitor as w
from test_parsers import STA, SURVEY, IW_DEV

class PtySerial:
    """Behaves like pyserial.Serial but talks to a real shell on a pty (echo on, \\r\\n line endings, like a UART console)."""
    def __init__(self, env):
        self.master, slave = pty.openpty()
        self.p = subprocess.Popen(["sh"], stdin=slave, stdout=slave, stderr=slave, start_new_session=True, env=env)
        os.close(slave)
    def write(self, b): os.write(self.master, b)
    def read(self, n):
        r, _, _ = select.select([self.master], [], [], 0.2)
        return os.read(self.master, n) if r else b""
    def reset_input_buffer(self):
        while self.read(65536): pass
    def close(self): self.p.kill()

def fake_bin():
    d = tempfile.mkdtemp()
    for name, text in {"iw_dev": IW_DEV, "iw_sta": STA, "iw_survey": SURVEY}.items(): open(f"{d}/{name}.txt", "w").write(text)
    open(f"{d}/iw", "w").write(f"""#!/bin/sh
case "$*" in
 "dev") cat {d}/iw_dev.txt;; *station*) cat {d}/iw_sta.txt;; *survey*) cat {d}/iw_survey.txt;; esac
""")
    os.chmod(f"{d}/iw", 0o755); return d

class SerialT(unittest.TestCase):
    def test_serial(self):
        d = fake_bin(); ser = PtySerial({"PATH": f"{d}:/usr/bin:/bin", "TERM": "dumb"})
        try:
            r = t.SerialRunner(None, _serial=ser)
            self.assertEqual(r.run("printf 'a\\nb\\n'").strip().splitlines(), ["a", "b"])
            be = w.IwBackend(r)
            radios = be.radios(); self.assertEqual([x["iface"] for x in radios], ["wlan1", "wlan0"])
            st = be.stations("wlan1")[0]; self.assertEqual((st["rssi"], st["ap_tx_mbps"]), (-45, 866.7))
            self.assertEqual(be.survey("wlan1")["busy"], 2500)
            long = "echo " + "x" * 300                       # long command line (console may wrap/redraw)
            self.assertEqual(r.run(long).strip(), "x" * 300)
        finally: ser.close()

class CliSerial:
    """Console that logs in to a restricted 'foo>' CLI; only `sh` gets a real shell (the router case: '>' until you type sh)."""
    def __init__(self, env, allow_sh=True):
        self.sh = PtySerial(env); self.shell, self.q, self.sent, self.allow_sh = False, b"foo> ", [], allow_sh
    def write(self, b):
        self.sent.append(b.decode())
        if self.shell: return self.sh.write(b)
        if b.decode().strip() == "sh" and self.allow_sh: self.shell = True; self.sh.reset_input_buffer(); self.sh.write(b"\n")
        else: self.q += b"\r\nfoo> "
    def read(self, n):
        if self.shell: return self.sh.read(n)
        q, self.q = self.q, b""; time.sleep(0.05) if not q else None; return q
    def reset_input_buffer(self):
        if self.shell: self.sh.reset_input_buffer()
        else: self.q = b""
    def close(self): self.sh.close()

class CliPrompt(unittest.TestCase):
    ENV = {"PATH": "/usr/bin:/bin", "TERM": "dumb"}
    def test_prompt_detection(self):
        self.assertTrue(t.at_cli_prompt("\r\nfoo> ")); self.assertFalse(t.at_cli_prompt("root@ap:/# ")); self.assertFalse(t.at_cli_prompt("~ $ ")); self.assertFalse(t.at_cli_prompt(""))
    def test_serial_types_sh_automatically(self):
        ser = CliSerial(self.ENV)
        try:
            r = t.SerialRunner(None, _serial=ser); self.assertTrue(ser.shell, ser.sent)
            self.assertEqual(r.run("echo hello").strip(), "hello")
        finally: ser.close()
    def test_serial_custom_shell_command_and_none(self):
        ser = CliSerial(self.ENV, allow_sh=False)
        try:
            t.SerialRunner(None, _serial=ser, shell_cmd="none"); self.assertFalse(any(x.strip() == "sh" for x in ser.sent))
        finally: ser.close()

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        sid, obj, method, params = req["params"]
        if obj == "session": res = [0, {"ubus_rpc_session": "S" * 32}]
        elif sid != "S" * 32: res = [6]
        else:
            o = subprocess.run([params["command"], *params["params"]], capture_output=True, text=True, env={"PATH": self.server.path})
            res = [0, {"code": o.returncode, "stdout": o.stdout}]
        body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

class UbusT(unittest.TestCase):
    def test_ubus(self):
        srv = HTTPServer(("127.0.0.1", 0), H); srv.path = f"{fake_bin()}:/usr/bin:/bin"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        r = t.UbusHttpRunner(f"http://127.0.0.1:{srv.server_port}", "root", "pw")
        be = w.IwBackend(r)
        self.assertEqual(be.stations("wlan1")[0]["mac"], "aa:bb:cc:dd:ee:ff")
        r.sid = "stale"; self.assertIn("Station", r.run("iw dev wlan1 station dump"))   # re-login on expired session
        srv.shutdown()

if __name__ == "__main__": unittest.main()
