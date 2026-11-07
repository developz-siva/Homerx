"""memwatch: parsing, leak analysis, PDF, telnet transport (against a fake telnetd that runs real commands), web glue."""
import json, os, re, shutil, socket, subprocess, sys, tempfile, threading, time, unittest, urllib.request
import memwatch as m, transport as tr, wifi_monitor as w

BUSYBOX = """MemTotal:         123456 kB
MemFree:           20000 kB
Buffers:            3000 kB
Cached:            30000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Shmem:              2048 kB
Slab:               9000 kB
SReclaimable:       3000 kB
SUnreclaim:         6000 kB
@@LOAD
0.52 0.40 0.30 1/80 1234
@@UP
8000.55 7000.10
@@PROCS
/proc/1/status:Name:\tinit
/proc/1/status:VmRSS:\t     900 kB
/proc/2/status:Name:\tkthreadd
/proc/310/status:Name:\twifi_agent
/proc/310/status:VmRSS:\t   20000 kB
/proc/311/status:Name:\twifi_agent
/proc/311/status:VmRSS:\t    5000 kB
@@TOP
Mem: 100000K used, 23456K free, 2048K shrd, 3000K buff, 30000K cached
  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
"""

class Parse(unittest.TestCase):
    def test_sample_without_memavailable_uses_free_buffers_cached(self):
        row, top, raw = m.parse_sample(BUSYBOX, now=100.0)
        self.assertEqual(row["avail_kb"], 20000 + 3000 + 30000)                      # old kernels have no MemAvailable
        self.assertEqual((row["load1"], row["uptime_s"], row["nproc"]), (0.52, 8000.55, 3))
        self.assertEqual(top[0], ("wifi_agent", 25000, 2))                           # same-named processes are summed
        self.assertIn("PID", raw)
    def test_kernel_threads_without_rss_are_skipped(self): self.assertNotIn(2, m.parse_proc_rss(BUSYBOX.split("@@PROCS")[1]))
    def test_garbage_returns_none(self): self.assertIsNone(m.parse_sample("sh: cat: not found"))

def synth(hours=72, step=300, leak_mb_h=1.0, total_mb=256, reboot_at=None, start_used=100, proc_leak=0.8):
    now, rows, procs = time.time(), [], []
    t0 = now - hours * 3600; t = t0
    while t <= now:
        h = (t - t0) / 3600; hs = h if reboot_at is None or h < reboot_at else h - reboot_at
        used = (start_used + leak_mb_h * hs) * 1024; tot = total_mb * 1024
        rows.append({"ts": t, "total_kb": tot, "free_kb": tot - used - 20000, "avail_kb": tot - used, "buffers_kb": 4000, "cached_kb": 20000, "slab_kb": 10000,
                     "sreclaim_kb": 5000, "sunreclaim_kb": 5000, "shmem_kb": 2000, "swap_total_kb": 0, "swap_free_kb": 0, "load1": 0.3, "uptime_s": hs * 3600 + 100, "nproc": 50})
        procs += [(t, "leaky", (20 + proc_leak * hs) * 1024, 1), (t, "steady", 9 * 1024, 1)]
        t += step
    return rows, procs, now

class Analyse(unittest.TestCase):
    def test_leak_is_found_with_eta_and_culprit(self):
        rows, procs, now = synth(leak_mb_h=2.0)
        d = m.analyse(rows, procs, 72, "", "gw", now); titles = " | ".join(i["title"] for i in d["insights"])
        self.assertIn("growing 2.0 MB/hour", titles); self.assertIn("leaky RSS is growing 0.80", titles)
        self.assertNotIn("steady RSS", titles); self.assertAlmostEqual(d["summary"]["used_trend_mb_per_h"], 2.0, delta=0.05)
        self.assertEqual(d["procs"][0]["name"], "leaky")
    def test_stable_device_is_ok(self):
        rows, procs, now = synth(leak_mb_h=0.0, proc_leak=0.0); d = m.analyse(rows, procs, 72, "", "", now)
        self.assertEqual([i["sev"] for i in d["insights"]], ["ok"])
    def test_trend_restarts_after_a_reboot(self):
        rows, procs, now = synth(leak_mb_h=1.5, reboot_at=50); d = m.analyse(rows, procs, 72, "", "", now)
        self.assertTrue(any("rebooted" in i["title"] for i in d["insights"]))
        self.assertAlmostEqual(d["summary"]["used_trend_mb_per_h"], 1.5, delta=0.05)           # not smeared across the drop
    def test_low_memory_is_critical(self):
        rows, procs, now = synth(leak_mb_h=0.0, total_mb=256, start_used=250); d = m.analyse(rows, procs, 72, "", "", now)
        self.assertEqual(d["insights"][0]["sev"], "crit")
    def test_short_history_says_so(self):
        rows, procs, now = synth(hours=1); d = m.analyse(rows, procs, 24, "", "", now); self.assertTrue(any("Not enough history" in i["title"] for i in d["insights"]))
    def test_empty(self): self.assertIsNone(m.analyse([], [], 24)["summary"])
    def test_downsampled_to_a_plottable_size(self):
        rows, procs, now = synth(hours=72, step=30); d = m.analyse(rows, procs, 72, "", "", now); self.assertLessEqual(len(d["series"]["t"]), 520)
    def test_range_selection(self):
        rows, procs, now = synth(hours=72); c = m.MemCollector(None, 60, tempfile.mkdtemp()); c.rows, c.procs = rows, procs
        n = {h: c.snapshot(h, now)["samples"] for h in (24, 48, 72)}; self.assertTrue(n[24] < n[48] < n[72]); self.assertAlmostEqual(n[24], 24 * 12, delta=2)

class Pdf(unittest.TestCase):
    def test_pdf_is_valid_and_readable(self):
        rows, procs, now = synth(leak_mb_h=1.0); d = m.analyse(rows, procs, 72, "top - 00:00\n  PID USER", "my-gw", now); b = m.build_pdf(d)
        self.assertTrue(b.startswith(b"%PDF-1.4") and b.rstrip().endswith(b"%%EOF")); self.assertEqual(len(re.findall(rb"/Type /Page /", b)), 3)
        if shutil.which("pdftotext"):
            f = tempfile.mktemp(suffix=".pdf"); open(f, "wb").write(b); txt = subprocess.run(["pdftotext", "-layout", f, "-"], capture_output=True, text=True).stdout
            for w_ in ("Device memory report - my-gw", "Memory in use vs available", "Largest processes by RSS", "leaky", "growing"): self.assertIn(w_, txt)
    def test_pdf_with_no_samples(self): self.assertTrue(m.build_pdf(m.analyse([], [], 24)).startswith(b"%PDF"))
    def test_text_is_escaped(self):
        pg = m.PdfPage(); pg.text(0, 0, "a(b)c\\d é"); self.assertIn("a\\(b\\)c\\\\d", pg.ops[0])

# ------------------------------------------------------------------------------------------ fake telnetd running real commands
class FakeTelnetd:
    def __init__(self, user="root", password="pw", echo=False, drop_after=None, banner=True):
        self.user, self.password, self.echo, self.drop_after, self.banner = user, password, echo, drop_after, banner
        self.srv = socket.socket(); self.srv.bind(("127.0.0.1", 0)); self.srv.listen(5); self.port = self.srv.getsockname()[1]; self.conns = 0
        threading.Thread(target=self._accept, daemon=True).start()
    def _accept(self):
        while True:
            try: c, _ = self.srv.accept()
            except OSError: return
            self.conns += 1; threading.Thread(target=self._serve, args=(c, self.conns), daemon=True).start()
    @staticmethod
    def _clean(b):
        out, i = bytearray(), 0
        while i < len(b):
            if b[i] == 255 and i + 2 < len(b) and b[i + 1] in (251, 252, 253, 254): i += 3
            else: out.append(b[i]); i += 1
        return bytes(out)
    def _line(self, c, buf):
        while b"\n" not in buf[0]:
            d = c.recv(4096)
            if not d: raise EOFError
            buf[0] += self._clean(d)
        line, _, buf[0] = buf[0].partition(b"\n"); return line.decode().strip("\r")
    def _serve(self, c, n):
        buf, served = [b""], 0
        try:
            if self.banner: c.sendall(bytes([255, 251, 1, 255, 253, 24, 255, 251, 3]))               # IAC WILL ECHO, DO TTYPE, WILL SGA
            if self.user:
                c.sendall(b"BCM-GW login: "); u = self._line(c, buf); c.sendall(b"Password: "); p = self._line(c, buf)
                if (u, p) != (self.user, self.password): c.sendall(b"\r\nLogin incorrect\r\n"); return
            c.sendall(b"\r\n# ")
            while True:
                cmd = self._line(c, buf)
                if self.echo: c.sendall(cmd.encode() + b"\r\n")
                out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout
                c.sendall(out.replace("\n", "\r\n").encode() + b"# "); served += 1
                if self.drop_after and served >= self.drop_after and n == 1: return
        except (EOFError, OSError): pass
        finally: c.close()
    def close(self): self.srv.close()

class Telnet(unittest.TestCase):
    def test_login_and_run(self):
        d = FakeTelnetd(); r = tr.TelnetRunner("127.0.0.1", d.port, "root", "pw")
        try:
            self.assertEqual(r.run("echo hello; echo world").strip().splitlines(), ["hello", "world"])
            self.assertIn("MemTotal", r.run("cat /proc/meminfo"))
        finally: d.close()
    def test_echoing_shell_and_no_login(self):
        d = FakeTelnetd(user=None, echo=True); r = tr.TelnetRunner("127.0.0.1", d.port)
        try: self.assertEqual(r.run("echo one").strip(), "one")                           # the echoed command line is stripped
        finally: d.close()
    def test_bad_password(self):
        d = FakeTelnetd()
        try:
            with self.assertRaises(ConnectionError) as e: tr.TelnetRunner("127.0.0.1", d.port, "root", "wrong")
            self.assertIn("rejected", str(e.exception))
        finally: d.close()
    def test_login_needed_but_not_given(self):
        d = FakeTelnetd()
        try:
            with self.assertRaises(ConnectionError) as e: tr.TelnetRunner("127.0.0.1", d.port)
            self.assertIn("--user", str(e.exception))
        finally: d.close()
    def test_reconnects_after_the_device_drops_the_link(self):
        d = FakeTelnetd(drop_after=3); r = tr.TelnetRunner("127.0.0.1", d.port, "root", "pw")        # 1st connection: 2 setup lines + "echo a", then hangs up
        try:
            self.assertEqual(r.run("echo a").strip(), "a"); time.sleep(0.3)
            self.assertEqual(r.run("echo b").strip(), "b"); self.assertGreaterEqual(d.conns, 2)
        finally: d.close()
    def test_refused_connection(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
        with self.assertRaises(ConnectionError): tr.TelnetRunner("127.0.0.1", p)
    def test_iac_stripping_across_packet_boundaries(self):
        r = tr.TelnetRunner.__new__(tr.TelnetRunner); r._iac = b""; sent = []
        class S:
            def sendall(self, b): sent.append(b)
        r.sock = S(); a = r._strip(b"ab\xff\xfd"); b = r._strip(b"\x01cd\xff\xff")
        self.assertEqual((a, b), (b"ab", b"cd\xff")); self.assertEqual(sent, [bytes([255, 252, 1])])

class EndToEnd(unittest.TestCase):
    def test_collect_over_telnet_persist_and_report(self):
        d = FakeTelnetd(); tmp = tempfile.mkdtemp()
        try:
            col = m.MemCollector(tr.TelnetRunner("127.0.0.1", d.port, "root", "pw"), 5, tmp, "fake")
            self.assertTrue(col.poll()); time.sleep(0.2); self.assertTrue(col.poll())
            st = col.status(); self.assertEqual((st["samples"], st["errors"]), (2, 0))
            self.assertTrue(os.path.getsize(os.path.join(tmp, "mem_samples.csv")) > 100)
            col2 = m.MemCollector(None, 5, tmp); self.assertEqual(len(col2.rows), 2)                 # history survives a restart
            self.assertGreater(col2.rows[-1]["total_kb"], 1000)
            self.assertTrue(m.build_pdf(col2.snapshot(24)).startswith(b"%PDF"))
        finally: d.close()
    def test_unreachable_device_is_reported_not_fatal(self):
        class Dead:
            def run(self, *a, **k): return ""
        c = m.MemCollector(Dead(), 5, tempfile.mkdtemp()); self.assertFalse(c.poll()); self.assertIn("no response", c.status()["last_error"])

class Web(unittest.TestCase):
    def test_pages_and_pdf_served_by_wifi_monitor(self):
        rows, procs, now = synth(hours=30); col = m.MemCollector(None, 60, tempfile.mkdtemp(), "gw"); col.rows, col.procs = rows, procs
        mon = w.Monitor(w.SimBackend(w.Runner(None)), 1, None); mon.poll(); mon.mem = col
        threading.Thread(target=w.serve, args=(mon, "127.0.0.1", 8746), daemon=True).start(); time.sleep(0.6)
        get = lambda p: urllib.request.urlopen("http://127.0.0.1:8746" + p, timeout=10)
        self.assertIn(b"Device memory", get("/mem").read())
        j = json.loads(get("/api/mem?hours=24").read()); self.assertEqual(j["status"]["samples"], len(rows)); self.assertTrue(j["data"]["series"]["t"])
        r = get("/api/mem/pdf?hours=48"); self.assertEqual(r.headers["Content-Type"], "application/pdf"); self.assertIn("attachment", r.headers["Content-Disposition"]); self.assertTrue(r.read().startswith(b"%PDF"))
        self.assertIn(b"/mem", get("/").read())                                                       # link from the Wi-Fi dashboard
    def test_not_enabled(self):
        self.assertEqual(m.handle_get(None, "/api/mem", {})[0], 404); self.assertEqual(m.handle_get(None, "/mem", {})[0], 200)


class Events(unittest.TestCase):
    def _synth_with_event(self, kept_mb, peak_mb=30, secs=600):
        rows, procs, now = synth(hours=6, leak_mb_h=0.0, proc_leak=0.0, step=60)
        s0 = now - 3 * 3600; e0 = s0 + secs
        for r in rows:                                    # the activity raises memory by peak_mb, then keeps kept_mb of it
            if s0 <= r["ts"] <= e0: r["avail_kb"] -= peak_mb * 1024
            elif r["ts"] > e0: r["avail_kb"] -= kept_mb * 1024
        return rows, procs, now, {"id": 1, "start": s0, "end": e0, "label": "iperf3 tcp up 300 Mbps", "kind": "test"}
    def test_memory_not_released_is_flagged(self):
        rows, procs, now, ev = self._synth_with_event(kept_mb=12); d = m.analyse(rows, procs, 24, "", "", now, [ev]); e = d["events"][0]
        self.assertAlmostEqual(e["retained"], 12, delta=0.1); self.assertAlmostEqual(e["peak_rise"], 30, delta=0.1)
        self.assertTrue(any(i["sev"] == "warn" and "not released" in i["title"] and "iperf3 tcp up" in i["title"] for i in d["insights"]))
    def test_released_memory_is_only_a_note(self):
        rows, procs, now, ev = self._synth_with_event(kept_mb=0); d = m.analyse(rows, procs, 24, "", "", now, [ev])
        self.assertFalse(any("not released" in i["title"] for i in d["insights"])); self.assertTrue(any("raised memory use by 30 MB" in i["title"] for i in d["insights"]))
    def test_event_shorter_than_the_sampling_interval(self):
        rows, procs, now, ev = self._synth_with_event(kept_mb=0, secs=20); ev["start"] = rows[100]["ts"] + 10; ev["end"] = ev["start"] + 20
        d = m.analyse(rows, procs, 24, "", "", now, [ev]); self.assertEqual(d["events"][0]["samples"], 0); self.assertTrue(any("No memory sample fell inside" in i["title"] for i in d["insights"]))
    def test_open_event_has_no_after(self):
        rows, procs, now, ev = self._synth_with_event(kept_mb=0); ev["end"] = None; e = m.analyse(rows, procs, 24, "", "", now, [ev])["events"][0]
        self.assertTrue(e["open"]); self.assertIsNone(e["retained"])
    def test_pdf_lists_events(self):
        rows, procs, now, ev = self._synth_with_event(kept_mb=12); b = m.build_pdf(m.analyse(rows, procs, 24, "top\n", "gw", now, [ev]))
        if shutil.which("pdftotext"):
            f = tempfile.mktemp(suffix=".pdf"); open(f, "wb").write(b); txt = subprocess.run(["pdftotext", "-layout", f, "-"], capture_output=True, text=True).stdout
            self.assertIn("Tests and markers", txt); self.assertIn("iperf3 tcp up 300 Mbps", txt); self.assertIn("+12.0", txt)
    def test_collector_events_persist_and_speed_up_sampling(self):
        tmp = tempfile.mkdtemp(); c = m.MemCollector(None, 60, tmp); self.assertEqual(c.sleep_for(), 60)
        e = c.add_event("Teams call"); self.assertEqual(c.sleep_for(), 5); self.assertEqual(c.open_event()["label"], "Teams call")
        time.sleep(0.05); self.assertIsNotNone(c.end_event()); self.assertEqual(c.sleep_for(), 60); self.assertIsNone(c.end_event())
        c2 = m.MemCollector(None, 60, tmp); self.assertEqual([(x["label"], x["end"] is not None) for x in c2.events], [("Teams call", True)])
        c.fast_check = lambda: True; self.assertEqual(c.sleep_for(), 5)
    def test_post_api(self):
        c = m.MemCollector(None, 60, tempfile.mkdtemp())
        self.assertTrue(m.handle_post(c, "/api/mem/event", {"action": "start", "label": "Video"})["ok"])
        self.assertIn("still running", m.handle_post(c, "/api/mem/event", {"action": "start", "label": "x"})["error"])
        self.assertTrue(m.handle_post(c, "/api/mem/event", {"action": "end"})["ok"]); self.assertIn("No activity", m.handle_post(c, "/api/mem/event", {"action": "end"})["error"])
        self.assertIn("start or end", m.handle_post(c, "/api/mem/event", {"action": "zap"})["error"]); self.assertIsNone(m.handle_post(c, "/other", {}))
    def test_finished_test_becomes_a_shaded_window(self):
        mon = w.Monitor(w.SimBackend(w.Runner(None)), 1, None); mon.poll(); mon.mem = m.MemCollector(None, 60, tempfile.mkdtemp())
        t = {"state": "running", "tool": "iperf3", "mode": "tcp_up", "mac": "x", "ip": "192.168.1.5", "secs": 10, "streams": 1, "rate": 50, "started": time.time() - 12, "samples": [], "result": None, "util_before": None}
        mon.test = t; mon._finish_test(t, {"ok": True, "tool": "iperf3", "mode": "tcp_up", "mbps": 312.4})
        ev = mon.mem.events[0]; self.assertEqual(ev["kind"], "test"); self.assertIn("iperf3 tcp up 312.4 Mbps (192.168.1.5)", ev["label"]); self.assertAlmostEqual(ev["end"] - ev["start"], 12, delta=1)
    def test_marker_http_endpoint_rules(self):
        col = m.MemCollector(None, 60, tempfile.mkdtemp()); mon = w.Monitor(w.SimBackend(w.Runner(None)), 1, None); mon.poll(); mon.mem = col
        threading.Thread(target=w.serve, args=(mon, "127.0.0.1", 8747), daemon=True).start(); time.sleep(0.6)
        def post(body, ct="application/json"):
            rq = urllib.request.Request("http://127.0.0.1:8747/api/mem/event", json.dumps(body).encode(), {"Content-Type": ct})
            return json.loads(urllib.request.urlopen(rq, timeout=5).read())
        self.assertTrue(post({"action": "start", "label": "video"})["ok"]); self.assertTrue(post({"action": "end"})["ok"]); self.assertEqual(col.events[0]["label"], "video")
        with self.assertRaises(urllib.error.HTTPError) as e: post({"action": "start"}, ct="text/plain")
        self.assertEqual(e.exception.code, 415)                                                          # cross-site forms cannot do this

from test_iperf_server import start_agent, monitor as _mon, wait_state, client as iperf_client, IPORT
import speedtools as sp
@unittest.skipUnless(shutil.which("iperf3"), "iperf3 binary not on PATH")
class TestWindowOnMemoryGraph(unittest.TestCase):
    def test_armed_iperf_test_is_marked_and_memory_sampled_during_it(self):
        a, srv, url = start_agent(port=5746); time.sleep(1.2)
        mon, mac = _mon(url); mon.iperf_server_ip = "127.0.0.1"
        col = m.MemCollector(m_runner_local(), 60, tempfile.mkdtemp(), "local"); col.fast_interval = 1; mon.mem = col
        col.fast_check = lambda: bool(mon.test and mon.test["state"] in ("running", "waiting"))
        threading.Thread(target=col.loop, daemon=True).start(); time.sleep(1.5)
        try:
            self.assertEqual(mon.start_test({"mac": mac, "traffic": "iperf3", "quality": sp.MODES["tcp_up"], "secs": 3}), {"ok": True}); time.sleep(2)
            c = subprocess.Popen(["iperf3", "-c", "127.0.0.1", "-p", "5746", "-t", "3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); c.wait(timeout=20)
            self.assertTrue(wait_state(mon, ("done",), 30)); time.sleep(1.5)
            ev = [e for e in col.events if e["kind"] == "test"]; self.assertEqual(len(ev), 1); self.assertIn("iperf3 tcp up", ev[0]["label"])
            inside = [r for r in col.rows if ev[0]["start"] <= r["ts"] <= ev[0]["end"]]; self.assertGreaterEqual(len(inside), 2)      # 1 s sampling while the test ran
            d = col.snapshot(24); self.assertEqual(d["events"][0]["label"], ev[0]["label"]); self.assertGreaterEqual(d["events"][0]["samples"], 2)
        finally: srv.shutdown()

def m_runner_local():
    from transport import Runner
    return Runner(None)



class ApOverTelnet(unittest.TestCase):
    """The Wi-Fi monitor itself (not only the memory collector) can read the AP over telnet."""
    def test_wifi_monitor_once_over_telnet(self):
        here = os.path.dirname(os.path.abspath(__file__)); d = tempfile.mkdtemp(); stub = os.path.join(d, "wl")
        open(stub, "w").write('#!/bin/sh\ncase "$*" in\n *"sta_info all"*) cat "%s/wl_sta_info_all_6g.txt";;\n *chanspec*) echo "6g101/320-2 (0x7043)";;\n'
                              ' *chanim_stats*) printf "chanspec tx inbss obss nocat nopkt doze txop goodtx badtx glitch badplcp knoise timestamp\\n0x7043 1 2 6 0 3 0 88 0 0 5 0 -89 1\\n";;\n *assoclist*) ;;\nesac\n' % here)
        os.chmod(stub, 0o755); old = os.environ["PATH"]; os.environ["PATH"] = d + ":" + old
        srv = FakeTelnetd(user="admin", password="pw")
        try:
            r = subprocess.run([sys.executable, os.path.join(here, "wifi_monitor.py"), "--backend", "wl", "--transport", "telnet", "--host", "127.0.0.1", "--telnet-port", str(srv.port),
                                "--telnet-user", "admin", "--password", "pw", "--ifaces", "wl1", "--max-flows", "0", "--once"], capture_output=True, text=True, timeout=120, env={**os.environ})
            self.assertEqual(r.returncode, 0, r.stderr[-600:]); self.assertIn("6G", r.stdout); self.assertRegex(r.stdout, r"(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}")
        finally: os.environ["PATH"] = old; srv.close()
    def test_wrong_password_exits_with_a_clear_message(self):
        srv = FakeTelnetd(user="admin", password="pw")
        try:
            r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "wifi_monitor.py"), "--backend", "wl", "--transport", "telnet", "--host", "127.0.0.1",
                                "--telnet-port", str(srv.port), "--telnet-user", "admin", "--password", "bad", "--ifaces", "wl1", "--once"], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(r.returncode, 0); self.assertIn("login was rejected", r.stderr + r.stdout)
        finally: srv.close()

if __name__ == "__main__": unittest.main()
