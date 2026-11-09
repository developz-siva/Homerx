"""PDF report of a multi-client test run (standard library only; reuses memwatch's tiny PDF writer)."""
import time, textwrap
from memwatch import Pdf

GRADE = {"GOOD": (18, 183, 106), "MARGINAL": (247, 144, 9), "BAD": (217, 45, 32), "NO TRAFFIC": (102, 112, 133)}
NAVY, GREY = (31, 56, 100), (110, 118, 135)

def _a(s): return str(s).replace("\u2248", "~").replace("\u2193", "down").replace("\u2191", "up").replace("\u2013", "-")
def _wrap(s, n): return textwrap.wrap(_a(s), n) or [""]

def build_report(status, state=None, label=""):
    """status = Monitor.test_status() of a finished multi run; state = Monitor.state (radios) for the header."""
    pdf, W, H = Pdf(), Pdf.W, Pdf.H
    gen = time.strftime("%Y-%m-%d %H:%M")
    rows, m = status.get("tests") or [], status.get("summary") or {}
    pg = [None]; y = [0]
    def header(sub):
        p = pdf.page(); pg[0] = p
        p.rect(0, H - 54, W, 54, fill=NAVY)
        p.text(40, H - 28, "Wi-Fi client assessment" + (f" - {label}" if label else ""), 16, "F2", (255, 255, 255))
        p.text(40, H - 44, sub, 8.5, "F1", (205, 215, 235)); y[0] = H - 80
    def need(h):
        if y[0] - h < 50: header(f"generated {gen} (continued)")
    header(f"generated {gen} - {len(rows)} client(s), {rows[0]['secs'] if rows else '?'} s window")
    p = pg[0]
    if m:
        p.rect(40, y[0] - 22, 90, 22, fill=GRADE.get(m.get("grade"), GREY)); p.text(48, y[0] - 15, f"Overall: {m.get('grade', '-')}", 10, "F2", (255, 255, 255))
        bits = [f"{m.get('good', 0)} good", f"{m.get('marginal', 0)} marginal", f"{m.get('bad', 0)} bad"]
        if m.get("no_traffic"): bits.append(f"{m['no_traffic']} no traffic")
        if m.get("load_only"): bits.append(f"{m['load_only']} load only")
        p.text(142, y[0] - 15, ", ".join(bits), 10, "F1"); y[0] -= 38
        line = f"Total delivered {m.get('measured_total', 0)} Mbps vs {m.get('required_total', 0)} Mbps needed"
        if m.get("util_max") is not None: line += f"; radio airtime up to {m['util_max']}% busy"
        p.text(40, y[0], line, 9.5, "F1"); y[0] -= 14
    for r in (state or {}).get("radios", []):
        p.text(40, y[0], f"{r.get('iface')}: {r.get('band')} channel {r.get('channel')}" + (f" - {r['util_pct']}% busy now" if r.get("util_pct") is not None else ""), 9, "F1", GREY); y[0] -= 12
    y[0] -= 10
    for t in rows:
        r = t.get("result") or {}; v = r.get("verdict") or {}; L = r.get("link") or {}
        grade = v.get("grade") or ("ERROR" if r and not r.get("ok") else "LOAD" if r else "-")
        reasons = [x for rs in v.get("reasons", []) for x in _wrap(rs, 105)] or ([r.get("error")] if r.get("error") else [])
        need(70 + 11 * len(reasons))
        p = pg[0]; top = y[0]
        p.rect(40, top - 18, 515, 18, fill=(238, 241, 247))
        p.text(46, top - 13, (t.get("host") or t.get("ip") or t.get("mac") or "?")[:34] + ("  " + (t.get("ip") or "") if t.get("host") else ""), 10, "F2")
        p.rect(470, top - 17, 80, 16, fill=GRADE.get(grade, GREY)); p.text(476, top - 12, grade, 9, "F2", (255, 255, 255))
        y[0] = top - 32
        p.text(46, y[0], _a(t.get('label', '')), 9.5, "F1"); y[0] -= 13
        if r.get("tool") == "observe": got = f"{r.get('avg_down_mbps', 0)} down / {r.get('avg_up_mbps', 0)} up Mbps (peak {r.get('peak_mbps', 0)})"
        elif r.get("mbps") is not None: got = f"{r['mbps']} Mbps"
        else: got = "-"
        need_s = "max throughput" if t.get("required") is None else f"{t['required']} Mbps {'down' if t.get('required_dir') == 'down' else 'up'}"
        p.text(46, y[0], f"Needs: {need_s}      Measured: {got}", 9, "F1"); y[0] -= 12
        if L.get("n"):
            p.text(46, y[0], f"Link: RSSI {L.get('rssi_avg', '-')} dBm, PHY {L.get('ap_tx_avg', '-')}/{L.get('sta_tx_avg', '-')} Mbps, retries {L.get('retry_avg', '-')}%, radio busy {L.get('util_avg', '-')}%", 9, "F1", GREY); y[0] -= 12
        for x in reasons: p.text(46, y[0], x, 8.5, "F1", (60, 60, 60)); y[0] -= 11
        y[0] -= 10
    need(40); pg[0].text(40, 30, "Watch-real-traffic results use the AP's own per-client counters; iperf3 rows are measured throughput. Capacity figures are a model, not a speed test.", 7, "F1", GREY)
    return pdf.build()
