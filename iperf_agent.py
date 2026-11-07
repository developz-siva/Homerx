#!/usr/bin/env python3
"""
iperf_agent.py - run this on the LAN-side PC that acts as the iperf3 SERVER.

It keeps an `iperf3 -s` listening, records every finished test (JSON), and lets the Wi-Fi monitor dashboard read them over
HTTP so it can tie a test to the client you selected (by the client's IP) and add RSSI / PHY rate / retries during the run.

    py iperf_agent.py                         # Windows        python3 iperf_agent.py   # macOS / Linux
    py iperf_agent.py --http-port 8099 --token secret
    py iperf_agent.py --iperf-bin "C:\\tools\\iperf3\\iperf3.exe"      # iperf3 not on PATH

Then start the dashboard with:  --iperf-server http://<this PC's IP>:8099
Needs iperf3 installed on this PC (stdlib-only Python, no packages).
Security: the HTTP side is read-only (status + finished test results); use --token if the LAN is not fully trusted.
"""
import argparse, collections, json, shutil, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

def find_iperf3(explicit=None):
    """Locate iperf3: an explicit file or folder, PATH, $IPERF3_PATH, beside this script, the current folder, then usual install places.
    Returns a full path, or None."""
    import glob, os
    names = ["iperf3.exe", "iperf3"] if os.name == "nt" else ["iperf3"]
    def pick(d):
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p): return p
        return None
    if explicit and explicit != "iperf3":
        explicit = os.path.expandvars(os.path.expanduser(explicit))
        if os.path.isdir(explicit): return pick(explicit)
        if os.path.isfile(explicit): return explicit
        w = shutil.which(explicit)
        return w
    w = shutil.which("iperf3")
    if w: return w
    home = os.path.expanduser("~")
    dirs = [os.environ.get("IPERF3_PATH", ""), os.path.dirname(os.path.abspath(__file__)), os.getcwd(), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
            r"C:\iperf3", r"C:\iperf", r"C:\tools\iperf3", r"C:\Program Files\iperf3", r"C:\Program Files (x86)\iperf3", os.path.join(home, "iperf3")]
    for pat in (os.path.join(home, "Downloads", "iperf*"), os.path.join(home, "Desktop", "iperf*"), r"C:\iperf*", os.path.join(home, "iperf*")): dirs += glob.glob(pat)
    for d in dirs:
        if d and os.path.isdir(d):
            p = pick(d) or pick(os.path.join(d, "bin"))
            if p: return p
        elif d and os.path.isfile(d): return d
    return None

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("10.255.255.255", 1)); return s.getsockname()[0]       # picks the LAN interface; sends nothing
    except OSError: return None
    finally: s.close()

class Agent:
    def __init__(self, iperf_port=5201, iperf_bin="iperf3", token=None, bind=None):
        self.iperf_port, self.iperf_bin, self.token, self.bind = iperf_port, iperf_bin, token, bind
        self.results, self.next_id = collections.deque(maxlen=50), 1
        self.state, self.last_error, self.lock = "starting", "", threading.Lock()

    # ---- iperf3 server loop: one test per `iperf3 -s -1 -J` process, restarted immediately -------------------
    def add(self, raw):
        with self.lock:
            self.results.append({"id": self.next_id, "finished": time.monotonic(), "raw": raw}); self.next_id += 1

    def run_forever(self):
        while True:
            exe = find_iperf3(self.iperf_bin)
            if not exe:
                self.state, self.last_error = "error", ("iperf3 was not found" + (f" at {self.iperf_bin}" if self.iperf_bin != "iperf3" else "") + ". Searched PATH, this folder and the usual install folders. "
                    "Start the agent with --iperf-bin \"C:\\path\\to\\iperf3.exe\" (file or folder), or install it (Windows: https://iperf.fr/iperf-download.php, macOS: brew install iperf3, Linux: apt install iperf3).")
                sys.stderr.write(self.last_error + "\n"); time.sleep(5); continue
            self.state = "listening"
            try:
                p = subprocess.Popen([exe, "-s", "-1", "-J", "-p", str(self.iperf_port)] + (["-B", self.bind] if self.bind else []), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = p.communicate()
            except Exception as e:
                self.state, self.last_error = "error", str(e); time.sleep(3); continue
            err_json = ""
            if out.strip():
                try: err_json = json.loads(out).get("error") or ""
                except ValueError: err_json = "unparseable output from iperf3"
            if err_json and ("in use" in err_json or "unable to start" in err_json):     # we cannot listen at all: say so, back off
                self.state, self.last_error = "error", err_json
                sys.stderr.write(f"iperf3: {err_json}  (another iperf3 server on port {self.iperf_port}? stop it, or use --iperf-port)\n"); time.sleep(3)
            elif err_json:                                                                  # e.g. the client aborted mid-test: nothing to score
                print(time.strftime("%H:%M:%S"), "test aborted:", err_json, flush=True); time.sleep(0.3)
            elif out.strip():
                self.add(out); self.last_error = ""
                print(time.strftime("%H:%M:%S"), "test finished (", len(out), "bytes of JSON )", flush=True); time.sleep(0.2)
            elif err.strip():
                self.state, self.last_error = "error", err.strip()[:300]
                sys.stderr.write(f"iperf3: {self.last_error}\n"); time.sleep(3)
            else: time.sleep(0.5)

    # ---- HTTP -----------------------------------------------------------------------------------------------
    def status(self):
        with self.lock: last = self.next_id - 1
        return {"ok": True, "state": self.state, "last_error": self.last_error, "iperf_port": self.iperf_port,
                "server_ip": self.bind or lan_ip(), "hostname": socket.gethostname(), "last_id": last}

    def results_after(self, after):
        now = time.monotonic()
        with self.lock:
            rs = [{"id": r["id"], "age_s": round(now - r["finished"], 1), "raw": r["raw"]} for r in self.results if r["id"] > after]
            last = self.next_id - 1
        return {"results": rs, "last_id": last}

def make_server(agent, bind="0.0.0.0", port=8099):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if agent.token and self.headers.get("X-Token") != agent.token: self.send_error(401); return
            u = urlparse(self.path); qs = parse_qs(u.query)
            if u.path in ("/", "/index.html"):
                st = agent.status(); page = ("<!doctype html><meta charset=utf-8><title>iperf agent</title><body style='font:16px system-ui;margin:2em'><h3>iperf3 agent is running</h3>"
                    f"<p>State: <b>{st['state']}</b> &middot; iperf3 port {st['iperf_port']} &middot; tests recorded: {st['last_id']}</p>"
                    + (f"<p style='color:#b00'>{st['last_error']}</p>" if st['last_error'] else "") +
                    f"<p>On the Wi-Fi client run: <code>iperf3 -c {st['server_ip']} -p {st['iperf_port']}</code><br>Dashboard option: <code>--iperf-server http://{st['server_ip']}:{port}</code></p>"
                    "<p><a href=/status>/status</a> &middot; <a href=/results>/results</a></p>").encode()
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(page))); self.end_headers(); self.wfile.write(page); return
            if u.path == "/status": body = agent.status()
            elif u.path == "/results":
                try: after = int(qs.get("after", ["0"])[0])
                except ValueError: after = 0
                body = agent.results_after(after)
            else: self.send_error(404); return
            data = json.dumps(body).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self, *a): pass
    return ThreadingHTTPServer((bind, port), H)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iperf-port", type=int, default=5201, help="port the iperf3 server listens on (default 5201)")
    ap.add_argument("--iperf-bin", default="iperf3", help='iperf3 file or folder if it is not on PATH, e.g. --iperf-bin "C:\\tools\\iperf3"')
    ap.add_argument("--iperf-bind", metavar="IP", help="listen for iperf3 only on this local address (iperf3 -s -B); use it when this PC has several networks")
    ap.add_argument("--http-port", type=int, default=8099, help="port the dashboard reads results from (default 8099)")
    ap.add_argument("--bind", default="0.0.0.0", help="HTTP bind address (default all interfaces so the dashboard PC can reach it)")
    ap.add_argument("--token", help="optional shared secret; the dashboard must be started with the same --iperf-token")
    a = ap.parse_args()
    agent = Agent(a.iperf_port, iperf_bin=a.iperf_bin, token=a.token, bind=a.iperf_bind)
    threading.Thread(target=agent.run_forever, daemon=True).start()
    ip = a.iperf_bind or lan_ip() or "<this PC's IP>"
    print(f"iperf3 server listening on {ip}:{a.iperf_port}\nDashboard option:  --iperf-server http://{ip}:{a.http_port}" + (f" --iperf-token {a.token}" if a.token else "") +
          "\nOn a Wi-Fi client run:  iperf3 -c " + ip + "   (add -R for download, -u -b 50M for UDP)\nCtrl-C to stop.", flush=True)
    try: make_server(agent, a.bind, a.http_port).serve_forever()
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    main()
