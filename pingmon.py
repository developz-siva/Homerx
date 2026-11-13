"""pingmon.py - ping the gateway / AP, the internet (WAN) and each client for the duration of a test; keeps the series for graphs.
Uses the operating system's own `ping` (no admin rights, standard library only). Runs from the PC that runs the dashboard."""
import os, re, subprocess, threading, time

WIN = os.name == "nt"
MAX_TARGETS = 70
_TIME = re.compile(r"(?:time|zeit|tiempo|temps|tempo|tijd)\s*[=<]\s*([\d.,]+)\s*ms|[=<]\s*([\d.,]+)\s*ms", re.I)

def parse_ping(out):
    """RTT in ms from one ping reply (Windows, Linux, macOS, several languages), or None."""
    for line in out.splitlines():
        if re.search(r"ttl\s*=", line, re.I) or re.search(r"\btime\b", line, re.I) or "ms" in line:
            m = _TIME.search(line)
            if m and re.search(r"ttl", line, re.I) or (m and "bytes from" in line.lower()):
                v = (m.group(1) or m.group(2)).replace(",", ".")
                try: return float(v) if "<" not in line.split("ms")[0][-8:] else max(float(v) / 2, 0.1)
                except ValueError: return None
    return None

def ping_once(host, timeout_ms=1000):
    """One echo request. Returns RTT in ms, or None for no reply / error."""
    argv = ["ping", "-n", "1", "-w", str(timeout_ms), host] if WIN else (["ping", "-c", "1", "-W", str(timeout_ms if os.uname().sysname == "Darwin" else max(1, timeout_ms // 1000)), host])
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_ms / 1000 + 3, creationflags=0x08000000 if WIN else 0)
    except (OSError, subprocess.SubprocessError): return None
    return parse_ping(r.stdout or "")

def have_ping():
    import shutil
    return bool(shutil.which("ping"))

def default_gateway():
    """Best-effort default gateway of this PC (None if unknown)."""
    try:
        if WIN:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True, timeout=8, creationflags=0x08000000).stdout
            best = None
            for l in out.splitlines():
                p = l.split()
                if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and re.match(r"\d+\.\d+\.\d+\.\d+$", p[2]):
                    m = int(p[4]) if p[4].isdigit() else 9999
                    if best is None or m < best[0]: best = (m, p[2])
            return best[1] if best else None
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m: return m.group(1)
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError): return None

def stats(samples):
    """samples: [(t, rtt|None)] -> sent / lost / loss% / min / avg / p95 / max / jitter (ms)."""
    sent = len(samples); ok = [v for _, v in samples if v is not None]
    if not sent: return {"sent": 0, "lost": 0, "loss_pct": 0.0, "min": None, "avg": None, "p95": None, "max": None, "jitter": None}
    s = sorted(ok); jit = [abs(a - b) for a, b in zip(ok, ok[1:])]
    return {"sent": sent, "lost": sent - len(ok), "loss_pct": round(100.0 * (sent - len(ok)) / sent, 1),
            "min": round(s[0], 1) if s else None, "avg": round(sum(ok) / len(ok), 1) if ok else None,
            "p95": round(s[min(len(s) - 1, int(0.95 * len(s)))], 1) if s else None, "max": round(s[-1], 1) if s else None,
            "jitter": round(sum(jit) / len(jit), 1) if jit else None}

def downsample(samples, n=600):
    if len(samples) <= n: return [[round(t, 1), None if v is None else round(v, 1)] for t, v in samples]
    k = -(-len(samples) // n); out = []
    for i in range(0, len(samples), k):
        b = samples[i:i + k]; vs = [v for _, v in b]
        out.append([round(b[0][0], 1), None if None in vs else round(max(vs), 1)])
    return out

def findings(targets):
    """Plain-language conclusions comparing gateway / WAN / clients."""
    out = []; by = {g: [t for t in targets if t["group"] == g and t["stats"]["sent"]] for g in ("lan", "wan", "client")}
    def bad(t, loss=2.0, p95=100.0): return t["stats"]["loss_pct"] >= loss or (t["stats"]["p95"] or 0) >= p95
    lan_bad = [t for t in by["lan"] if bad(t, 2.0, 30.0)]; wan_bad = [t for t in by["wan"] if bad(t, 2.0, 150.0)]
    for t in by["client"]:
        s = t["stats"]
        if s["loss_pct"] >= 2 or (s["p95"] or 0) >= 100:
            out.append({"sev": "warn", "title": f"{t['name']}: ping loss {s['loss_pct']}%, p95 {s['p95']} ms, jitter {s['jitter']} ms.", "detail": "Latency or loss to this client rose during the test (Wi-Fi link, power save, or the client was busy)."})
    if lan_bad: out.append({"sev": "warn", "title": "Gateway / AP latency or loss is high: " + ", ".join(f"{t['name']} (loss {t['stats']['loss_pct']}%, p95 {t['stats']['p95']} ms)" for t in lan_bad) + ".", "detail": "The problem is inside your network (this PC's link, the AP or the LAN), not your internet provider."})
    elif wan_bad: out.append({"sev": "warn", "title": "Internet (WAN) latency or loss is high while the gateway is fine: " + ", ".join(f"{t['name']} (loss {t['stats']['loss_pct']}%, p95 {t['stats']['p95']} ms)" for t in wan_bad) + ".", "detail": "Look at the modem / ISP side, or the router's uplink being saturated by the test."})
    elif by["lan"] or by["wan"]: out.append({"sev": "ok", "title": "Gateway and internet latency stayed healthy during the test."})
    return out

class PingMonitor:
    def __init__(self, ping_fn=ping_once, interval=1.0):
        self.ping_fn, self.interval = ping_fn, interval
        self.lock = threading.Lock(); self.targets = []; self.running = False; self.t0 = None; self.stop_ev = threading.Event(); self.t_end = None

    def start(self, targets):
        """targets: [(name, host, group)] with group lan | wan | client. Replaces any run in progress."""
        self.stop()
        seen, items = set(), []
        for name, host, group in targets:
            if host and host not in seen and len(items) < MAX_TARGETS: seen.add(host); items.append({"name": name, "host": host, "group": group, "samples": []})
        with self.lock: self.targets, self.running, self.t0, self.t_end = items, True, time.time(), None
        self.stop_ev = threading.Event()
        for t in items: threading.Thread(target=self._loop, args=(t, self.stop_ev, self.t0), daemon=True).start()
        return len(items)

    def _loop(self, t, ev, t0):
        n = 0
        while not ev.is_set():
            r = self.ping_fn(t["host"])
            if ev.is_set(): break
            with self.lock: t["samples"].append((time.time() - t0, r))
            n += 1; ev.wait(max(0.0, t0 + n * self.interval - time.time()))

    def stop(self):
        if self.running: self.stop_ev.set(); self.running = False; self.t_end = time.time()

    def snapshot(self, series=True):
        with self.lock:
            ts = [{"name": t["name"], "host": t["host"], "group": t["group"], "stats": stats(t["samples"]),
                   **({"samples": downsample(t["samples"])} if series else {})} for t in self.targets]
        return {"running": self.running, "elapsed": round((self.t_end or time.time()) - self.t0, 1) if self.t0 else 0, "targets": ts, "findings": findings(ts) if ts else []}
