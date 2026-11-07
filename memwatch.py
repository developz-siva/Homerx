#!/usr/bin/env python3
"""
memwatch.py - long-running memory monitor for an embedded device (router / gateway / AP).

Logs in over telnet (or ssh / a local shell), every --interval seconds reads /proc/meminfo, /proc/loadavg, /proc/uptime,
per-process RSS (/proc/<pid>/status) and a `top` snapshot, stores everything in CSV files (so it survives restarts), and gives you
  * a web page with memory graphs for the last 24 / 48 / 72 hours  (http://127.0.0.1:8090/mem)
  * a PDF report of the same graphs, a summary and leak / low-memory findings   (button on the page, or --pdf file.pdf)

    py memwatch.py --host 192.168.1.1 --user root --password secret          # telnet (default), page on :8090
    py memwatch.py --host 192.168.1.1 --transport ssh --user root
    py memwatch.py --pdf report.pdf --hours 72                               # PDF from the stored logs, no device needed
    py memwatch.py --host 192.168.1.1 --once                                 # one sample, print it, exit

The same collector is built into wifi_monitor.py (--mem-host ...) so one dashboard shows Wi-Fi and memory.
Python standard library only (no matplotlib / reportlab); the PDF is written directly.
"""
import argparse, csv, json, math, os, re, sys, threading, time, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

KEEP_DAYS = 7
SAMPLE_COLS = ["ts", "total_kb", "free_kb", "avail_kb", "buffers_kb", "cached_kb", "slab_kb", "sreclaim_kb", "sunreclaim_kb", "shmem_kb",
               "swap_total_kb", "swap_free_kb", "load1", "uptime_s", "nproc"]
PROC_COLS = ["ts", "name", "rss_kb", "count"]
EVENT_COLS = ["id", "start", "end", "label", "kind"]

# ---------------------------------------------------------------------------------------------- parsing
def parse_meminfo(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z_()0-9]+):\s+(\d+)", line)
        if m: d[m.group(1)] = int(m.group(2))
    return d

def parse_proc_rss(text):
    """Lines from `grep -H -E '^(Name|VmRSS):' /proc/[0-9]*/status` -> {pid: [name, rss_kb]} (kernel threads have no VmRSS)."""
    procs = {}
    for line in text.splitlines():
        m = re.match(r"/proc/(\d+)/status:(Name|VmRSS):\s*(.*)", line)
        if not m: continue
        pid, key, val = int(m.group(1)), m.group(2), m.group(3).strip()
        e = procs.setdefault(pid, ["?", 0])
        if key == "Name": e[0] = val
        else:
            n = re.match(r"(\d+)", val); e[1] = int(n.group(1)) if n else 0
    return {p: v for p, v in procs.items() if v[1] > 0}

def split_sections(text):
    """Split the combined command output on lines starting with @@NAME."""
    out, cur = {"MEM": []}, "MEM"
    for line in text.splitlines():
        if line.startswith("@@"): cur = line[2:].strip(); out.setdefault(cur, []); continue
        out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}

COMBINED = ("cat /proc/meminfo; echo @@LOAD; cat /proc/loadavg; echo @@UP; cat /proc/uptime; echo @@PROCS; "
            "grep -H -E '^(Name|VmRSS):' /proc/[0-9]*/status 2>/dev/null; echo @@TOP; top -b -n 1 2>/dev/null | head -n 30")

def parse_sample(text, now=None):
    """Combined command output -> (row dict, [(name, rss_kb, count)...], raw_top)."""
    sec = split_sections(text)
    mi = parse_meminfo(sec.get("MEM", ""))
    if "MemTotal" not in mi: return None
    total, free, buf, cached = mi["MemTotal"], mi.get("MemFree", 0), mi.get("Buffers", 0), mi.get("Cached", 0)
    avail = mi.get("MemAvailable", free + buf + cached)                       # old kernels have no MemAvailable
    try: load1 = float(sec.get("LOAD", "").split()[0])
    except (IndexError, ValueError): load1 = None
    try: up = float(sec.get("UP", "").split()[0])
    except (IndexError, ValueError): up = None
    procs = parse_proc_rss(sec.get("PROCS", ""))
    grouped = {}
    for name, rss in procs.values():
        g = grouped.setdefault(name, [0, 0]); g[0] += rss; g[1] += 1
    top = sorted(((n, v[0], v[1]) for n, v in grouped.items()), key=lambda x: -x[1])[:12]
    row = {"ts": round(now or time.time(), 1), "total_kb": total, "free_kb": free, "avail_kb": avail, "buffers_kb": buf, "cached_kb": cached,
           "slab_kb": mi.get("Slab", 0), "sreclaim_kb": mi.get("SReclaimable", 0), "sunreclaim_kb": mi.get("SUnreclaim", 0), "shmem_kb": mi.get("Shmem", 0),
           "swap_total_kb": mi.get("SwapTotal", 0), "swap_free_kb": mi.get("SwapFree", 0), "load1": load1, "uptime_s": up, "nproc": len(procs)}
    return row, top, sec.get("TOP", "").strip()

# ---------------------------------------------------------------------------------------------- collector
class MemCollector:
    def __init__(self, runner, interval=60, outdir="memlogs", label=""):
        self.r, self.interval, self.dir, self.label = runner, max(5, interval), outdir, label
        self.rows, self.procs, self.last_top = [], [], ""             # rows: list of dicts; procs: list of (ts, name, rss_kb, count)
        self.lock, self.errors, self.last_error, self.polls = threading.Lock(), 0, "", 0
        self.stopped = False
        self.events, self.fast_check, self.fast_interval = [], None, 5     # events: tests / manual markers shown on the graphs
        os.makedirs(outdir, exist_ok=True); self._load()

    def _path(self, n): return os.path.join(self.dir, n)
    def _load(self):
        cut = time.time() - KEEP_DAYS * 86400
        try:
            with open(self._path("mem_samples.csv"), newline="") as f:
                for r in csv.DictReader(f):
                    try:
                        row = {k: (float(v) if v not in ("", None) else None) for k, v in r.items()}
                        if row["ts"] >= cut: self.rows.append(row)
                    except (ValueError, KeyError, TypeError): pass
        except OSError: pass
        try:
            with open(self._path("mem_procs.csv"), newline="") as f:
                for r in csv.DictReader(f):
                    try:
                        ts = float(r["ts"])
                        if ts >= cut: self.procs.append((ts, r["name"], float(r["rss_kb"]), int(float(r["count"]))))
                    except (ValueError, KeyError, TypeError): pass
        except OSError: pass
        try: self.last_top = open(self._path("mem_top_last.txt")).read()
        except OSError: pass
        try:
            with open(self._path("mem_events.csv"), newline="") as f:
                for r in csv.DictReader(f):
                    try: self.events.append({"id": int(r["id"]), "start": float(r["start"]), "end": float(r["end"]) if r["end"] else None, "label": r["label"], "kind": r["kind"] or "manual"})
                    except (ValueError, KeyError, TypeError): pass
        except OSError: pass

    # ---- events: windows you want to see on the graphs (a throughput test, "video call", ...) ----
    def _save_events(self):
        try:
            with open(self._path("mem_events.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=EVENT_COLS); w.writeheader()
                for e in self.events: w.writerow({**e, "end": "" if e["end"] is None else e["end"]})
        except OSError as ex: self.last_error = f"cannot write events: {ex}"
    def add_event(self, label, start=None, end=None, kind="manual"):
        with self.lock:
            ev = {"id": max([e["id"] for e in self.events] + [0]) + 1, "start": start or time.time(), "end": end, "label": (label or "event")[:80], "kind": kind}
            self.events.append(ev); self.events = self.events[-500:]
        self._save_events(); return ev
    def end_event(self):
        with self.lock:
            op = [e for e in self.events if e["end"] is None]
            if not op: return None
            op[-1]["end"] = time.time(); ev = op[-1]
        self._save_events(); return ev
    def open_event(self): return next((e for e in reversed(self.events) if e["end"] is None), None)
    def sleep_for(self):
        """Sample faster while an event is open or a test is running, so short windows still get several points."""
        fast = bool(self.open_event()) or bool(self.fast_check and self.fast_check())
        return min(self.interval, self.fast_interval) if fast else self.interval

    def poll(self):
        self.polls += 1
        out = self.r.run(COMBINED, timeout=40)
        got = parse_sample(out) if out else None
        if not got:
            self.errors += 1; self.last_error = "no usable /proc/meminfo output from the device" if out else "no response from the device"
            return False
        row, top, raw = got
        with self.lock:
            self.rows.append(row); self.procs += [(row["ts"], n, float(k), c) for n, k, c in top]
            if raw: self.last_top = raw
            cut = time.time() - KEEP_DAYS * 86400
            if self.rows and self.rows[0]["ts"] < cut:
                self.rows = [x for x in self.rows if x["ts"] >= cut]; self.procs = [x for x in self.procs if x[0] >= cut]
        self.last_error = ""
        self._append("mem_samples.csv", SAMPLE_COLS, [row])
        self._append("mem_procs.csv", PROC_COLS, [{"ts": row["ts"], "name": n, "rss_kb": k, "count": c} for n, k, c in top])
        if raw:
            try: open(self._path("mem_top_last.txt"), "w").write(raw)
            except OSError: pass
        return True

    def _append(self, name, cols, rows):
        path = self._path(name); new = not os.path.exists(path)
        try:
            with open(path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                if new: w.writeheader()
                for r in rows: w.writerow(r)
        except OSError as e: self.last_error = f"cannot write {path}: {e}"

    def loop(self):
        while not self.stopped:
            t0 = time.time()
            try: self.poll()
            except Exception as e: self.errors += 1; self.last_error = str(e)
            while not self.stopped and time.time() - t0 < self.sleep_for():           # re-check every 0.5 s so a test that starts mid-wait speeds sampling up at once
                time.sleep(0.5)

    def status(self):
        with self.lock: n, last = len(self.rows), (self.rows[-1]["ts"] if self.rows else None)
        return {"enabled": True, "label": self.label, "samples": n, "last_ts": last, "interval": self.interval, "errors": self.errors,
                "last_error": self.last_error, "age_s": None if last is None else round(time.time() - last),
                "open_event": self.open_event(), "fast": self.sleep_for() < self.interval}

    def snapshot(self, hours, now=None):
        now = now or time.time(); cut = now - hours * 3600
        with self.lock:
            rows = [r for r in self.rows if r["ts"] >= cut]; procs = [p for p in self.procs if p[0] >= cut]; top = self.last_top
            events = [dict(e) for e in self.events if (e["end"] or now) >= cut]
        return analyse(rows, procs, hours, top, self.label, now, events)

# ---------------------------------------------------------------------------------------------- analysis
def slope(xs, ys):
    """Least-squares slope of ys per unit xs, or None."""
    n = len(xs)
    if n < 3: return None
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    return None if den == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den

def downsample(ts, maxn=500):
    if len(ts) <= maxn: return list(range(len(ts)))
    step = len(ts) / maxn; return sorted({int(i * step) for i in range(maxn)} | {len(ts) - 1})

def event_stats(ev, t, used, avail, total):
    """Memory before / peak / after one event. 'retained' (after - before) is what the event failed to give back."""
    s, e = ev["start"], ev["end"] or t[-1]
    inside = [i for i, x in enumerate(t) if s <= x <= e]
    before = [i for i, x in enumerate(t) if x < s and s - x <= 600]
    after = [i for i, x in enumerate(t) if x > e and x - e <= 900]
    st = {"id": ev["id"], "start": s, "end": ev["end"], "label": ev["label"], "kind": ev["kind"], "open": ev["end"] is None, "samples": len(inside),
          "used_before": used[before[-1]] if before else None, "used_peak": max(used[i] for i in inside) if inside else None,
          "used_after": used[after[0]] if (after and ev["end"]) else None, "avail_min": min(avail[i] for i in inside) if inside else None}
    st["retained"] = round(st["used_after"] - st["used_before"], 2) if st["used_before"] is not None and st["used_after"] is not None else None
    st["peak_rise"] = round(st["used_peak"] - st["used_before"], 2) if st["used_before"] is not None and st["used_peak"] is not None else None
    return st

def analyse(rows, procs, hours, top_raw="", label="", now=None, events=()):
    now = now or time.time()
    out = {"hours": hours, "label": label, "generated": now, "samples": len(rows), "summary": None, "insights": [], "series": {}, "procs": [], "top": top_raw, "events": []}
    if not rows: return out
    t = [r["ts"] for r in rows]; mb = lambda k: [round((r[k] or 0) / 1024, 2) for r in rows]
    total = rows[-1]["total_kb"] / 1024; avail, free = mb("avail_kb"), mb("free_kb")
    used = [round(total - a, 2) for a in avail]
    swap_used = [round(((r["swap_total_kb"] or 0) - (r["swap_free_kb"] or 0)) / 1024, 2) for r in rows]
    cached, bufs, slab, shmem = mb("cached_kb"), mb("buffers_kb"), mb("slab_kb"), mb("shmem_kb")
    unrec = mb("sunreclaim_kb"); load = [r["load1"] for r in rows]
    span_h = (t[-1] - t[0]) / 3600
    ups = [r["uptime_s"] for r in rows]
    k0 = 0                                                    # trends are computed since the last reboot: a reboot resets the leak
    for i in range(1, len(ups)):
        if ups[i] is not None and ups[i - 1] is not None and ups[i] + 30 < ups[i - 1]: k0 = i
    seg_h = (t[-1] - t[k0]) / 3600
    hr = [(x - t[k0]) / 3600 for x in t[k0:]]
    s_used = slope(hr, used[k0:]) if seg_h >= 1 else None
    since = " since the last reboot" if k0 else ""
    avg = lambda v: round(sum(v) / len(v), 1)
    out["summary"] = {"total_mb": round(total, 1), "first_ts": t[0], "last_ts": t[-1], "span_h": round(span_h, 1),
                      "used_now": used[-1], "used_min": min(used), "used_avg": avg(used), "used_max": max(used),
                      "avail_now": avail[-1], "avail_min": min(avail), "avail_avg": avg(avail), "avail_max": max(avail),
                      "swap_total_mb": round((rows[-1]["swap_total_kb"] or 0) / 1024, 1), "swap_used_max": max(swap_used),
                      "used_trend_mb_per_h": None if s_used is None else round(s_used, 2), "load1_now": load[-1], "nproc_now": int(rows[-1]["nproc"] or 0),
                      "uptime_h": None if rows[-1]["uptime_s"] is None else round(rows[-1]["uptime_s"] / 3600, 1)}
    idx = downsample(t)
    pick = lambda v: [v[i] for i in idx]
    out["series"] = {"t": pick(t), "used": pick(used), "avail": pick(avail), "free": pick(free), "cached": pick(cached), "buffers": pick(bufs),
                     "slab": pick(slab), "sunreclaim": pick(unrec), "shmem": pick(shmem), "swap_used": pick(swap_used),
                     "load1": pick([x if x is not None else 0 for x in load]), "total": round(total, 1)}
    # ---- per-process series (top 6 by peak RSS) ----
    byname = {}
    for ts, name, rss, _c in procs: byname.setdefault(name, {})[ts] = rss / 1024
    ranked = sorted(byname, key=lambda n: -max(byname[n].values()))[:6]
    tset = set(t)
    for n in ranked:
        d = byname[n]; pts = [(x, d.get(x)) for x in t]
        vals = [v for _, v in pts if v is not None]
        seg = [(x, v) for x, v in pts[k0:] if v is not None]
        sl = slope([(x - t[k0]) / 3600 for x, _ in seg], [v for _, v in seg]) if (len(seg) > 2 and seg_h >= 1) else None
        out["procs"].append({"name": n, "now": round(vals[-1], 2) if vals else None, "max": round(max(vals), 2), "first": round(seg[0][1] if seg else vals[0], 2),
                             "trend_mb_per_h": None if sl is None else round(sl, 3), "v": [None if pts[i][1] is None else round(pts[i][1], 2) for i in idx]})
    # ---- findings ----
    ins = out["insights"]
    def add(sev, title, detail): ins.append({"sev": sev, "title": title, "detail": detail})
    pct_avail = 100 * avail[-1] / total if total else 0
    if pct_avail < 5: add("crit", f"Only {avail[-1]:.0f} MB ({pct_avail:.0f}%) of memory is available now", "The device is close to out-of-memory; the kernel OOM killer may start killing processes.")
    elif pct_avail < 10: add("warn", f"Available memory is low: {avail[-1]:.0f} MB ({pct_avail:.0f}%)", "Watch the trend; a leak or a burst of traffic could push it into OOM.")
    low = min(avail)
    if low < 0.05 * total and pct_avail >= 5: add("warn", f"Available memory dipped to {low:.0f} MB during this window", "A temporary shortage; check what ran at that time.")
    if s_used is not None and seg_h >= 2:
        if s_used > 0.3 and (used[-1] - used[k0]) > 0.02 * total:
            eta = avail[-1] / s_used
            add("crit" if eta < 72 else "warn" if eta < 720 else "info", f"Memory in use is growing {s_used:.1f} MB/hour (+{used[-1]-used[k0]:.0f} MB over {seg_h:.0f} h{since})",
                f"At this rate the available {avail[-1]:.0f} MB is used up in about {eta:.0f} h. Suspect a leak; the processes below show where.")
        elif abs(s_used) < 0.3: add("ok", "Memory use is stable", f"Trend {s_used:+.2f} MB/hour over {seg_h:.0f} h{since}.")
    elif seg_h < 2: add("info", "Not enough history for a leak trend yet", f"Only {seg_h:.1f} h of samples{since}; leak detection needs about 2 h or more.")
    for p in out["procs"]:
        if p["trend_mb_per_h"] is not None and seg_h >= 2 and p["trend_mb_per_h"] > 0.15 and p["now"] - p["first"] > 3:
            add("warn", f"{p['name']} RSS is growing {p['trend_mb_per_h']:.2f} MB/hour", f"From {p['first']:.1f} MB to {p['now']:.1f} MB{since or ' in this window'}: a leak candidate.")
    s_slab = slope(hr, slab[k0:]) if seg_h >= 2 else None
    if s_slab is not None and s_slab > 0.15 and slab[-1] - slab[k0] > 5: add("warn", f"Kernel slab is growing {s_slab:.2f} MB/hour", f"{slab[k0]:.0f} to {slab[-1]:.0f} MB{since}: a kernel / driver allocation leak (not visible in any process).")
    if max(swap_used) > 1: add("warn", f"Swap in use (peak {max(swap_used):.0f} MB)", "Swapping on flash-based devices is slow and wears the flash.")
    for i in range(1, len(ups)):
        if ups[i] is not None and ups[i - 1] is not None and ups[i] + 30 < ups[i - 1]:
            add("warn", "The device rebooted in this window", f"Uptime reset at {time.strftime('%Y-%m-%d %H:%M', time.localtime(t[i]))}. A crash caused by memory exhaustion would show as a steady climb before this point."); break
    gaps = [(t[i], t[i + 1]) for i in range(len(t) - 1) if t[i + 1] - t[i] > 5 * max(60, (t[-1] - t[0]) / max(1, len(t)))]
    if gaps: add("info", f"{len(gaps)} gap(s) in the data", "The device or the telnet link was unreachable for a while (first gap starts " + time.strftime('%m-%d %H:%M', time.localtime(gaps[0][0])) + ").")
    evs = [event_stats(e, t, used, avail, total) for e in events]
    out["events"] = evs[-40:]
    for e in evs[-6:]:
        if e["retained"] is not None and e["retained"] > max(3.0, 0.015 * total):
            add("warn", f"Memory was not released after \"{e['label']}\": +{e['retained']:.1f} MB kept",
                f"In use went {e['used_before']:.0f} MB before, peaked at {e['used_peak']:.0f} MB, and was {e['used_after']:.0f} MB afterwards. If it grows again on every run it is a leak in that code path.")
        elif e["peak_rise"] is not None and e["peak_rise"] > max(5.0, 0.03 * total):
            add("info", f"\"{e['label']}\" raised memory use by {e['peak_rise']:.0f} MB at its peak", "Returned to normal afterwards." if e["retained"] is not None else "")
        elif e["samples"] == 0 and e["end"] is not None: add("info", f"No memory sample fell inside \"{e['label']}\"", "The window was shorter than the sampling interval; use a longer test or a smaller --interval.")
    if not ins: add("ok", "No memory problems found", "")
    return out

# ---------------------------------------------------------------------------------------------- PDF (no dependencies)
def _pdf_esc(s): return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

class PdfPage:
    def __init__(self): self.ops = []
    def _c(self, c, stroke=False): return "{:.3f} {:.3f} {:.3f} {}".format(*[x / 255 for x in c], "RG" if stroke else "rg")
    def text(self, x, y, s, size=9, font="F1", color=(30, 30, 30)):
        s = s.encode("latin-1", "replace").decode("latin-1")
        self.ops.append(f"BT {self._c(color)} /{font} {size} Tf {x:.1f} {y:.1f} Td ({_pdf_esc(s)}) Tj ET")
    def line(self, x1, y1, x2, y2, color=(200, 200, 200), w=0.5):
        self.ops.append(f"{self._c(color, True)} {w} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")
    def rect(self, x, y, w, h, fill=None, stroke=None):
        op = []
        if fill: op.append(self._c(fill))
        if stroke: op.append(self._c(stroke, True))
        self.ops.append(" ".join(op) + f" {x:.1f} {y:.1f} {w:.1f} {h:.1f} re " + ("B" if fill and stroke else "f" if fill else "S"))
    def polyline(self, pts, color, w=1.0):
        if len(pts) < 2: return
        self.ops.append(f"{self._c(color, True)} {w} w 1 j 1 J {pts[0][0]:.1f} {pts[0][1]:.1f} m " + " ".join(f"{x:.1f} {y:.1f} l" for x, y in pts[1:]) + " S")

class Pdf:
    W, H = 595, 842
    def __init__(self): self.pages = []
    def page(self): p = PdfPage(); self.pages.append(p); return p
    def build(self):
        objs = [b"<< /Type /Catalog /Pages 2 0 R >>", None,
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"]
        kids = []
        for pg in self.pages:
            content = zlib.compress("\n".join(pg.ops).encode("latin-1", "replace"))
            n = len(objs) + 1
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.W} {self.H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {n+1} 0 R >>".encode())
            objs.append(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(content) + content + b"\nendstream")
            kids.append(f"{n} 0 R")
        objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()
        out, offs = bytearray(b"%PDF-1.4\n"), []
        for i, o in enumerate(objs, 1):
            offs.append(len(out)); out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
        x = len(out); out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
        for o in offs: out += f"{o:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
        return bytes(out)

PALETTE = [(42, 111, 219), (232, 115, 26), (46, 158, 91), (138, 85, 212), (214, 64, 59), (26, 155, 171)]

def _nice_max(v):
    if v <= 0: return 1
    e = 10 ** math.floor(math.log10(v)); f = v / e
    for step in (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if f <= step + 1e-9: return step * e
    return 10 * e

def _tlabel(ts, span_h): return time.strftime("%H:%M" if span_h <= 30 else "%m-%d %H:%M", time.localtime(ts))

def pdf_chart(pg, x, y, w, h, title, series, t, unit="MB", ymax=None, events=()):
    """series: [(name, values, colour)], t: epoch list. (x, y) is the bottom-left of the plot area."""
    pg.text(x, y + h + 22, title, 10, "F2")
    lx = x
    for name, _v, col in series:
        pg.rect(lx, y + h + 8, 8, 6, fill=col); pg.text(lx + 11, y + h + 8, name, 7.5); lx += 18 + 4.3 * len(name)
    vals = [v for _n, vs, _c in series for v in vs if v is not None]
    top = ymax or _nice_max(max(vals) * 1.05 if vals else 1)
    pg.rect(x, y, w, h, fill=(252, 252, 252), stroke=(190, 190, 190))
    for i in range(6):
        gy = y + h * i / 5
        if 0 < i: pg.line(x, gy, x + w, gy, (225, 225, 225))
        lab = f"{top * i / 5:.0f}" if top >= 10 else f"{top * i / 5:.1f}"
        pg.text(x - 4 - 4.2 * len(lab), gy - 2.5, lab, 7, color=(90, 90, 90))
    t0, t1 = t[0], t[-1] if t[-1] > t[0] else t[0] + 1; span_h = (t1 - t0) / 3600
    for i in range(7):
        gx = x + w * i / 6; ts = t0 + (t1 - t0) * i / 6
        pg.line(gx, y, gx, y - 3, (120, 120, 120)); lab = _tlabel(ts, span_h)
        pg.text(min(gx - 12, x + w - 40) if i else gx - 4, y - 12, lab, 6.5, color=(90, 90, 90))
    for e in events:                                           # shaded windows for tests / markers, label at the top
        a, b = max(e["start"], t0), min(e["end"] or t1, t1)
        if b < t0 or a > t1: continue
        xa, xb = x + w * (a - t0) / (t1 - t0), x + w * (b - t0) / (t1 - t0)
        pg.rect(xa, y, max(xb - xa, 1.5), h, fill=(222, 233, 252) if e["kind"] == "test" else (253, 232, 205))
        pg.text(min(xa + 1.5, x + w - 30), y + h - 7, e["label"][:22], 5.8, "F1", (70, 90, 140) if e["kind"] == "test" else (160, 95, 20))
    for name, vs, col in series:
        pts = [(x + w * (ti - t0) / (t1 - t0), y + h * min(1.0, max(0.0, (v or 0) / top))) for ti, v in zip(t, vs) if v is not None]
        pg.polyline(pts, col, 1.1)

def _wrap(s, width_chars):
    words, lines, cur = s.split(), [], ""
    for wd in words:
        if len(cur) + len(wd) + 1 > width_chars and cur: lines.append(cur); cur = wd
        else: cur = (cur + " " + wd).strip()
    return lines + ([cur] if cur else [])

def build_pdf(data):
    pdf, W, H = Pdf(), Pdf.W, Pdf.H
    S, se = data.get("summary"), data["series"]
    gen = time.strftime("%Y-%m-%d %H:%M", time.localtime(data["generated"]))
    def header(pg, sub):
        pg.rect(0, H - 54, W, 54, fill=(31, 56, 100))
        pg.text(40, H - 28, "Device memory report" + (f" - {data['label']}" if data.get("label") else ""), 16, "F2", (255, 255, 255))
        pg.text(40, H - 44, sub, 8.5, "F1", (205, 215, 235))
    pg = pdf.page()
    if not S:
        header(pg, f"Last {data['hours']} h - generated {gen}"); pg.text(40, H - 100, "No samples were collected in this period.", 11); return pdf.build()
    header(pg, f"Last {data['hours']} h: {time.strftime('%Y-%m-%d %H:%M', time.localtime(S['first_ts']))} to {time.strftime('%Y-%m-%d %H:%M', time.localtime(S['last_ts']))} "
               f"({S['span_h']} h, {data['samples']} samples) - generated {gen}")
    y = H - 86
    rows = [("Total memory", f"{S['total_mb']:.0f} MB"), ("In use now (total - available)", f"{S['used_now']:.0f} MB   (min {S['used_min']:.0f} / avg {S['used_avg']:.0f} / max {S['used_max']:.0f})"),
            ("Available now", f"{S['avail_now']:.0f} MB   (min {S['avail_min']:.0f} / avg {S['avail_avg']:.0f} / max {S['avail_max']:.0f})"),
            ("In-use trend", "n/a (needs >= 1 h)" if S["used_trend_mb_per_h"] is None else f"{S['used_trend_mb_per_h']:+.2f} MB per hour"),
            ("Swap", "none" if not S["swap_total_mb"] else f"{S['swap_total_mb']:.0f} MB total, peak use {S['swap_used_max']:.0f} MB"),
            ("Load (1 min) / processes", f"{S['load1_now']} / {S['nproc_now']}"), ("Uptime", "n/a" if S["uptime_h"] is None else f"{S['uptime_h']} h")]
    for k, v in rows:
        pg.text(40, y, k, 9, "F2"); pg.text(210, y, v, 9); y -= 14
    y -= 6; pg.text(40, y, "Findings", 11, "F2"); y -= 15
    colr = {"crit": (200, 40, 40), "warn": (200, 120, 0), "info": (60, 100, 170), "ok": (40, 140, 70)}
    tag = {"crit": "CRITICAL", "warn": "WARNING", "info": "INFO", "ok": "OK"}
    for i in data["insights"]:
        pg.text(40, y, tag[i["sev"]], 8, "F2", colr[i["sev"]]); lines = _wrap(i["title"], 92)
        for l in lines: pg.text(100, y, l, 9, "F2"); y -= 11
        for l in _wrap(i["detail"], 100): pg.text(100, y, l, 8.5, "F1", (70, 70, 70)); y -= 10.5
        y -= 4
    t = se["t"]; cy = max(y - 215, 70)
    pdf_chart(pg, 70, cy, 470, 150, "Memory in use vs available (MB)", [("In use", se["used"], PALETTE[4]), ("Available", se["avail"], PALETTE[2]), ("Total", [se["total"]] * len(t), (150, 150, 150))], t, ymax=_nice_max(se["total"] * 1.02), events=data.get("events", []))
    pg = pdf.page(); header(pg, f"Last {data['hours']} h - generated {gen}")
    pdf_chart(pg, 70, H - 270, 470, 150, "Page cache, buffers, slab, shared (MB)", [("Cached", se["cached"], PALETTE[0]), ("Buffers", se["buffers"], PALETTE[1]), ("Slab", se["slab"], PALETTE[3]), ("Shmem", se["shmem"], PALETTE[5])], t)
    if data["procs"]:
        pdf_chart(pg, 70, H - 500, 470, 150, "Largest processes by RSS (MB)", [(p["name"][:14], [v for v in p["v"]], PALETTE[i % 6]) for i, p in enumerate(data["procs"])], t, events=data.get("events", []))
        yy = H - 530; pg.text(40, yy, "Process", 8.5, "F2"); [pg.text(x, yy, h, 8.5, "F2") for x, h in ((190, "First MB"), (250, "Now MB"), (310, "Peak MB"), (375, "Trend MB/h"))]
        for p in data["procs"]:
            yy -= 12; pg.text(40, yy, p["name"][:28], 8.5)
            pg.text(190, yy, f"{p['first']:.1f}", 8.5); pg.text(250, yy, f"{p['now']:.1f}", 8.5); pg.text(310, yy, f"{p['max']:.1f}", 8.5)
            tr = p["trend_mb_per_h"]; pg.text(375, yy, "n/a" if tr is None else f"{tr:+.3f}", 8.5, "F1", (200, 40, 40) if tr and tr > 0.15 else (30, 30, 30))
    if data.get("events"):
        yy = H - 640 if data["procs"] else H - 300
        pg.text(40, yy, "Tests and markers (shaded on the graphs)", 10, "F2"); yy -= 13
        for x_, h_ in ((40, "When"), (118, "Event"), (290, "Dur"), (330, "Before MB"), (385, "Peak MB"), (435, "After MB"), (490, "Kept MB")): pg.text(x_, yy, h_, 8, "F2")
        for e in data["events"][-12:][::-1]:
            yy -= 11; f = lambda v: "-" if v is None else f"{v:.0f}"
            dur = "open" if e["end"] is None else f"{max(0, e['end'] - e['start']):.0f}s"
            pg.text(40, yy, time.strftime("%m-%d %H:%M:%S", time.localtime(e["start"])), 7.5); pg.text(118, yy, e["label"][:34], 7.5); pg.text(290, yy, dur, 7.5)
            pg.text(330, yy, f(e["used_before"]), 7.5); pg.text(385, yy, f(e["used_peak"]), 7.5); pg.text(435, yy, f(e["used_after"]), 7.5)
            k = e["retained"]; pg.text(490, yy, "-" if k is None else f"{k:+.1f}", 7.5, "F2" if k and k > 3 else "F1", (200, 40, 40) if k and k > 3 else (30, 30, 30))
    if data.get("top"):
        pg = pdf.page(); header(pg, f"Last `top` snapshot - generated {gen}"); yy = H - 80
        for line in data["top"].splitlines()[:70]:
            pg.text(30, yy, line[:112], 6.6, "F3"); yy -= 8.6
    return pdf.build()

# ---------------------------------------------------------------------------------------------- web page
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Device memory</title>
<style>:root{--bg:#f6f8fb;--card:#fff;--fg:#1c2430;--mut:#667085;--line:#e3e8ef;--acc:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f141b;--card:#171e28;--fg:#e6ebf2;--mut:#93a0b3;--line:#2a3442;--acc:#5b8def}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,sans-serif}
header{padding:14px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--line);background:var(--card)}
h1{font-size:18px;margin:0}main{padding:16px 18px;max-width:1100px;margin:0 auto}.mut{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
button.b{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:7px 16px;border-radius:8px;cursor:pointer;font:inherit}button.b:hover{border-color:var(--acc)}
.seg button{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:6px 14px;cursor:pointer;font:inherit}.seg button:first-child{border-radius:8px 0 0 8px}.seg button:last-child{border-radius:0 8px 8px 0}
.seg button.on{background:var(--acc);color:#fff;border-color:var(--acc)}a.btn{background:var(--acc);color:#fff;text-decoration:none;padding:7px 14px;border-radius:8px}
.tiles{display:flex;gap:10px;flex-wrap:wrap}.tile{border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:130px}.tile b{display:block;font-size:18px}.tile span{color:var(--mut);font-size:12px}
.ins{padding:6px 10px;border-left:4px solid;margin:6px 0;border-radius:4px;background:var(--bg)}.crit{border-color:#d92d20}.warn{border-color:#f79009}.info{border-color:#3b82f6}.ok{border-color:#12b76a}
svg{width:100%;height:auto;display:block}.ax{fill:var(--mut);font-size:11px}.gl{stroke:var(--line)}h2{font-size:15px;margin:0 0 6px}.lg span{margin-right:14px;font-size:12px}.lg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
pre{overflow:auto;font-size:11px;background:var(--bg);padding:10px;border-radius:8px;max-height:320px}#tip{position:fixed;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px;display:none;box-shadow:0 4px 14px #0003}</style></head><body>
<header><h1>Device memory <span class=mut id=lab></span></h1><div class=seg id=seg><button data-h=24>24 h</button><button data-h=48>48 h</button><button data-h=72>72 h</button></div>
<a class=btn id=pdf href="#">Download PDF</a><span class=mut id=st></span><a href="/" class=mut style="margin-left:auto" id=home>Wi-Fi dashboard</a></header>
<main><div class=card><div class=tiles id=tiles></div></div>
<div class=card><h2>Mark an activity <span class=mut style="font-weight:400">(throughput tests are marked automatically)</span></h2>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><input id=evl placeholder="e.g. Teams video call on client 2" style="flex:1;min-width:220px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit">
<button class=b id=evs>Start</button><button class=b id=eve>End</button><span class=mut id=evst></span></div><div id=evtab style="margin-top:10px"></div></div><div class=card><h2>Findings</h2><div id=ins></div></div>
<div class=card><h2>Memory in use vs available (MB)</h2><div class=lg id=l1></div><svg id=c1></svg></div>
<div class=card><h2>Page cache, buffers, slab, shared (MB)</h2><div class=lg id=l2></div><svg id=c2></svg></div>
<div class=card><h2>Largest processes by RSS (MB)</h2><div class=lg id=l3></div><svg id=c3></svg><div id=ptab></div></div>
<div class=card><h2>Latest <code>top</code> snapshot</h2><pre id=top></pre></div></main><div id=tip></div>
<script>
const $=i=>document.getElementById(i),esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const COL=['#2a6fdb','#e8731a','#2e9e5b','#8a55d4','#d6403b','#1a9bab'];let H=+(localStorage.getItem('memh')||24),D=null;
function tl(ts,span){const d=new Date(ts*1000),p=n=>String(n).padStart(2,'0');return span>30?p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes()):p(d.getHours())+':'+p(d.getMinutes())}
function nice(v){if(v<=0)return 1;const e=Math.pow(10,Math.floor(Math.log10(v))),f=v/e;for(const st of [1,1.2,1.5,2,2.5,3,4,5,6,8,10])if(f<=st+1e-9)return st*e;return 10*e}
function chart(id,lid,series,t,ymax,evs){evs=evs||[];const W=1000,Hh=300,L=52,R=12,T=10,B=26,pw=W-L-R,ph=Hh-T-B,vals=series.flatMap(s=>s.v.filter(x=>x!=null)),top=ymax||nice((Math.max(...vals,1))*1.05),t0=t[0],t1=t[t.length-1]>t[0]?t[t.length-1]:t[0]+1,span=(t1-t0)/3600;
let g='';for(let i=0;i<=5;i++){const y=T+ph-ph*i/5,v=top*i/5;g+=`<line class="gl" x1="${L}" x2="${W-R}" y1="${y}" y2="${y}"></line><text class="ax" x="${L-6}" y="${y+4}" text-anchor="end">${v>=10||v===0?v.toFixed(0):v.toFixed(1)}</text>`}
for(let i=0;i<=6;i++){const x=L+pw*i/6;g+=`<text class="ax" x="${x}" y="${Hh-6}" text-anchor="${i==0?'start':i==6?'end':'middle'}">${tl(t0+(t1-t0)*i/6,span)}</text>`}
const X=ts=>L+pw*(ts-t0)/(t1-t0),Y=v=>T+ph-ph*Math.min(1,Math.max(0,v/top));
evs.forEach(e=>{const a=Math.max(e.start,t0),b=Math.min(e.end||t1,t1);if(b<t0||a>t1)return;const xa=X(a),w=Math.max(X(b)-xa,2),c=e.kind==='test'?'#3b82f6':'#f79009';
g+=`<g><title>${esc(e.label)}</title><rect x="${xa}" y="${T}" width="${w}" height="${ph}" fill="${c}" opacity="0.16"></rect><text class="ax" x="${Math.min(xa+3,W-R-60)}" y="${T+11}" style="fill:${c}">${esc(e.label.slice(0,26))}</text></g>`});
series.forEach((s,k)=>{let d='',pen=false;t.forEach((ts,i)=>{const v=s.v[i];if(v==null){pen=false;return}d+=(pen?'L':'M')+X(ts).toFixed(1)+' '+Y(v).toFixed(1);pen=true});g+=`<path d="${d}" fill=none stroke="${s.c}" stroke-width=1.8 stroke-linejoin=round />`});
const svg=$(id);svg.setAttribute('viewBox',`0 0 ${W} ${Hh}`);svg.innerHTML=g+`<line id="${id}x" class="gl" style="stroke:var(--mut);display:none" x1="0" x2="0" y1="${T}" y2="${T+ph}"></line>`;
$(lid).innerHTML=series.map(s=>`<span><i style="background:${s.c}"></i>${esc(s.n)}</span>`).join('');
svg.onmousemove=e=>{const r=svg.getBoundingClientRect(),px=(e.clientX-r.left)/r.width*W;if(px<L||px>W-R){svg.onmouseleave();return}const ts=t0+(px-L)/pw*(t1-t0);let b=0;t.forEach((x,i)=>{if(Math.abs(x-ts)<Math.abs(t[b]-ts))b=i});
const ln=$(id+'x');ln.style.display='';ln.setAttribute('x1',X(t[b]));ln.setAttribute('x2',X(t[b]));const tip=$('tip');tip.style.display='block';tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+14)+'px';
tip.innerHTML='<b>'+new Date(t[b]*1000).toLocaleString()+'</b><br>'+series.map(s=>`<i style="display:inline-block;width:8px;height:8px;background:${s.c};margin-right:5px"></i>${esc(s.n)}: ${s.v[b]==null?'-':s.v[b]+' MB'}`).join('<br>')};
svg.onmouseleave=()=>{$('tip').style.display='none';const ln=$(id+'x');if(ln)ln.style.display='none'}}
const T=(v,l)=>`<div class=tile><b>${v}</b><span>${l}</span></div>`;
function draw(d){D=d;const s=d.summary,se=d.series;$('lab').textContent=d.label||'';
if(!s){$('tiles').innerHTML='<span class=mut>No samples yet in this period. The collector samples every interval; give it a minute.</span>';$('ins').innerHTML='';['c1','c2','c3'].forEach(i=>$(i).innerHTML='');return}
$('tiles').innerHTML=T(s.total_mb.toFixed(0)+' MB','Total')+T(s.used_now.toFixed(0)+' MB','In use now')+T(s.avail_now.toFixed(0)+' MB','Available now')+T(s.avail_min.toFixed(0)+' MB','Lowest available')+T(s.used_trend_mb_per_h==null?'n/a':(s.used_trend_mb_per_h>0?'+':'')+s.used_trend_mb_per_h+' MB/h','In-use trend')+T(s.load1_now??'-','Load (1 min)')+T(s.uptime_h==null?'-':s.uptime_h+' h','Uptime')+T(d.samples,'Samples ('+s.span_h+' h)');
$('ins').innerHTML=d.insights.map(i=>`<div class="ins ${i.sev}"><b>${esc(i.title)}</b>${i.detail?'<div class=mut>'+esc(i.detail)+'</div>':''}</div>`).join('');
chart('c1','l1',[{n:'In use',v:se.used,c:COL[4]},{n:'Available',v:se.avail,c:COL[2]},{n:'Total',v:se.t.map(_=>se.total),c:'#98a2b3'}],se.t,nice(se.total*1.02),d.events);
chart('c2','l2',[{n:'Cached',v:se.cached,c:COL[0]},{n:'Buffers',v:se.buffers,c:COL[1]},{n:'Slab',v:se.slab,c:COL[3]},{n:'Shmem',v:se.shmem,c:COL[5]}],se.t);
chart('c3','l3',d.procs.map((p,i)=>({n:p.name,v:p.v,c:COL[i%6]})),se.t,0,d.events);
$('ptab').innerHTML=d.procs.length?'<table style="width:100%;border-collapse:collapse;margin-top:8px"><tr class=mut style="text-align:left"><th>Process<th>First MB<th>Now MB<th>Peak MB<th>Trend MB/h</tr>'+d.procs.map(p=>`<tr><td>${esc(p.name)}<td>${p.first}<td>${p.now}<td>${p.max}<td style="${p.trend_mb_per_h>0.15?'color:#d92d20;font-weight:600':''}">${p.trend_mb_per_h==null?'n/a':p.trend_mb_per_h}`).join('')+'</table>':'';
$('evtab').innerHTML=d.events.length?'<table style="width:100%;border-collapse:collapse"><tr class=mut style="text-align:left"><th>When<th>Event<th>Duration<th>Before MB<th>Peak MB<th>After MB<th>Kept MB</tr>'+d.events.slice().reverse().slice(0,15).map(e=>{const f=v=>v==null?'-':v.toFixed(0),k=e.retained;return`<tr><td>${new Date(e.start*1000).toLocaleString()}<td>${esc(e.label)}${e.kind==='test'?' <span class=mut>(test)</span>':''}<td>${e.open?'running…':Math.round(e.end-e.start)+' s'}<td>${f(e.used_before)}<td>${f(e.used_peak)}<td>${f(e.used_after)}<td style="${k>3?'color:#d92d20;font-weight:600':''}">${k==null?'-':(k>0?'+':'')+k.toFixed(1)}`}).join('')+'</table>':'<span class=mut>No tests or markers yet in this period.</span>';
$('top').textContent=d.top||'(no top output captured: is `top` available on the device?)'}
async function load(){try{const r=await fetch('api/mem?hours='+H);if(!r.ok){$('st').textContent='';document.querySelector('main').innerHTML='<div class=card>Memory collection is not enabled in this dashboard. Start it with <code>--mem-host &lt;device&gt;</code> (wifi_monitor.py) or run <code>memwatch.py</code>.</div>';return}
const j=await r.json();draw(j.data);const st=j.status;$('evst').textContent=st.open_event?('running: '+st.open_event.label+' (sampling every 5 s)'):'';$('st').textContent=st.last_ts?('last sample '+st.age_s+' s ago'+(st.last_error?' - '+st.last_error:'')):(st.last_error||'waiting for the first sample...')}catch(e){$('st').textContent='dashboard not reachable'}}
async function ev(action){const label=$('evl').value.trim();const r=await fetch('api/mem/event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,label})});const j=await r.json();if(j.error)$('evst').textContent=j.error;else{if(action==='end')$('evl').value='';load()}}
$('evs').onclick=()=>ev('start');$('eve').onclick=()=>ev('end');
function sel(){document.querySelectorAll('#seg button').forEach(b=>b.classList.toggle('on',+b.dataset.h===H));$('pdf').href='api/mem/pdf?hours='+H}
document.querySelectorAll('#seg button').forEach(b=>b.onclick=()=>{H=+b.dataset.h;try{localStorage.setItem('memh',H)}catch(e){}sel();load()});sel();load();setInterval(load,30000);
</script></body></html>"""

# ---------------------------------------------------------------------------------------------- HTTP glue
def handle_get(col, path, qs):
    """Used by memwatch's own server and by wifi_monitor. Returns (status, content_type, body_bytes, extra_headers) or None."""
    def hours():
        try: return max(1, min(int(qs.get("hours", 24)), 168))
        except (TypeError, ValueError): return 24
    if path in ("/mem", "/mem/"): return 200, "text/html; charset=utf-8", PAGE.encode(), {}
    if path == "/api/mem":
        if col is None: return 404, "application/json", b'{"error":"memory collection is not enabled"}', {}
        return 200, "application/json", json.dumps({"status": col.status(), "data": col.snapshot(hours())}).encode(), {}
    if path == "/api/mem/pdf":
        if col is None: return 404, "application/json", b'{"error":"memory collection is not enabled"}', {}
        h = hours(); name = f"memory_report_{time.strftime('%Y%m%d_%H%M')}_{h}h.pdf"
        return 200, "application/pdf", build_pdf(col.snapshot(h)), {"Content-Disposition": f'attachment; filename="{name}"'}
    return None

def handle_post(col, path, req):
    if path != "/api/mem/event": return None
    if col is None: return {"error": "memory collection is not enabled"}
    act = req.get("action")
    if act == "start":
        if col.open_event(): return {"error": f"\"{col.open_event()['label']}\" is still running: press End first."}
        return {"ok": True, "event": col.add_event(str(req.get("label") or "activity"), kind="manual")}
    if act == "end":
        ev = col.end_event(); return {"ok": True, "event": ev} if ev else {"error": "No activity is running."}
    return {"error": "action must be start or end"}

def serve(col, bind, port, allow_remote=False):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            u = urlparse(self.path)
            if self.client_address[0] not in ("127.0.0.1", "::1") and not allow_remote: self.send_error(403, "only this machine may add markers"); return
            if "application/json" not in (self.headers.get("Content-Type") or ""): self.send_error(415); return
            try: req = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 10000)) or b"{}")
            except Exception: req = {}
            res = handle_post(col, u.path, req)
            if res is None: self.send_error(404); return
            body = json.dumps(res).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            u = urlparse(self.path); r = handle_get(col, u.path, {k: v[0] for k, v in parse_qs(u.query).items()})
            if u.path == "/": r = (302, "text/plain", b"", {"Location": "/mem"})
            if r is None: self.send_error(404); return
            code, ct, body, hdr = r
            self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
            for k, v in hdr.items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    ThreadingHTTPServer((bind, port), H).serve_forever()

def make_runner(transport, host, port=None, user=None, password=None):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from transport import Runner, TelnetRunner
    if transport == "local": return Runner(None)
    if transport == "ssh": return Runner(host, user or "root", port or 22)
    return TelnetRunner(host, port or 23, user, password)

def add_cli_args(ap, prefix=""):
    p = prefix
    ap.add_argument(f"--{p}host", help="device to collect memory data from")
    ap.add_argument(f"--{p}transport", choices=["telnet", "ssh", "local"], default="telnet", help="how to reach it (default telnet)")
    ap.add_argument(f"--{p}port", type=int, help="telnet port (23) or ssh port (22)")
    ap.add_argument(f"--{p}user", help="login name, if the device asks for one")
    ap.add_argument(f"--{p}password", help="login password (or set MEM_PASS; prompts if a login is needed and none is given)")
    ap.add_argument(f"--{p}interval", type=int, default=60, help="seconds between samples (default 60)")
    ap.add_argument(f"--{p}dir", default="memlogs", help="folder for the CSV history (default memlogs)")
    ap.add_argument(f"--{p}label", default="", help="device name shown in the page and PDF")

def collector_from_args(a, prefix=""):
    g = lambda k: getattr(a, prefix.replace("-", "_") + k)
    pw = g("password") if g("password") is not None else os.environ.get("MEM_PASS")
    if pw is None and g("user") and g("transport") == "telnet":
        import getpass; pw = getpass.getpass(f"Password for {g('user')}@{g('host')}: ")
    try: runner = make_runner(g("transport"), g("host"), g("port"), g("user"), pw)
    except ConnectionError as e: sys.exit(f"memory collector: {e}")
    return MemCollector(runner, g("interval"), g("dir"), g("label") or g("host") or "")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_cli_args(ap)
    ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--web-port", type=int, default=8090)
    ap.add_argument("--hours", type=int, default=24, help="period for --pdf (24, 48 or 72)")
    ap.add_argument("--pdf", metavar="FILE", help="write a PDF report from the stored history and exit")
    ap.add_argument("--once", action="store_true", help="take one sample, print it and exit")
    a = ap.parse_args()
    if a.pdf:
        col = MemCollector(None, a.interval, a.dir, a.label); open(a.pdf, "wb").write(build_pdf(col.snapshot(a.hours))); print(f"wrote {a.pdf} ({col.status()['samples']} samples in {a.dir})"); return
    if not a.host and a.transport != "local": ap.error("--host is required (or use --pdf to report on stored data)")
    col = collector_from_args(a)
    if a.once:
        ok = col.poll(); print(json.dumps(col.rows[-1] if ok else {"error": col.last_error}, indent=1)); return
    threading.Thread(target=col.loop, daemon=True).start()
    print(f"collecting from {a.host or 'this machine'} every {a.interval}s into {a.dir}/  -  open http://{a.bind}:{a.web_port}/mem  (Ctrl-C to stop)", flush=True)
    try: serve(col, a.bind, a.web_port)
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    main()
