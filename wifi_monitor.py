#!/usr/bin/env python3
"""
wifi_monitor.py - per-client Wi-Fi traffic / Tx rate / app-QoS and per-radio channel utilization, AP side.

Runs on your PC and talks to the AP over SSH (--host), or run it ON the AP (python3 needed) with no --host.
No third-party Python packages needed.

Backends (--backend):
  iw   OpenWrt, prplOS, RDK-B on mac80211 (uses `iw station dump`, `iw survey dump`)   [parsers unit-tested]
  wl   Broadcom (`wl assoclist`, `wl sta_info`, `wl chanim_stats`)                      [best effort, verify on HW]
  qca  Qualcomm/Atheros (`wlanconfig <if> list sta`, survey via iw if available)       [best effort, verify on HW]
  sim  Simulated AP for trying the dashboard

Traffic per client + app/QoS class comes from conntrack byte counters (needs nf_conntrack_acct=1, see README).
"""
import argparse, csv, json, os, random, re, shlex, socket, subprocess, sys, threading, time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import discovery, memwatch, planner, speedtools
from transport import Runner, SerialRunner, UbusHttpRunner
from urllib.parse import urlparse, parse_qs
from advisor import advise, advise_radio, resolve_type, norm_type, PROFILES

# ----------------------------------------------------------------------------- command runner (see transport.py)
# ----------------------------------------------------------------------------- parsers (pure, testable)
def band_of(freq):
    return "2.4G" if freq < 3000 else ("5G" if freq < 5925 else "6G")

def parse_iw_dev(text):
    out, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"Interface (\S+)", s)
        if m:
            cur = {"iface": m.group(1)}; out.append(cur); continue
        if cur is None: continue
        m = re.match(r"type (\S+)", s)
        if m: cur["type"] = m.group(1)
        m = re.match(r"channel (\d+) \((\d+) MHz\)", s)
        if m: cur["channel"], cur["freq"] = int(m.group(1)), int(m.group(2))
        m = re.match(r"ssid (.*)", s)
        if m: cur["ssid"] = m.group(1)
    res = []
    for d in out:
        if d.get("type") == "AP" and "freq" in d:
            d["band"] = band_of(d["freq"]); res.append(d)
    return res

def _rate(v):
    m = re.match(r"([\d.]+) MBit/s", v)
    return (float(m.group(1)), v[m.end():].strip()) if m else (None, "")

def parse_iw_stations(text):
    sts, cur = [], None
    for line in text.splitlines():
        m = re.match(r"Station ([0-9a-f:]{17})", line, re.I)
        if m:
            cur = {"mac": m.group(1).lower()}; sts.append(cur); continue
        if cur is None: continue
        k, _, v = line.strip().partition(":"); v = v.strip()
        try:
            if k == "inactive time": cur["inactive_ms"] = int(v.split()[0])
            elif k == "rx bytes": cur["rx_bytes"] = int(v)
            elif k == "tx bytes": cur["tx_bytes"] = int(v)
            elif k == "tx packets": cur["tx_packets"] = int(v)
            elif k == "tx retries": cur["tx_retries"] = int(v)
            elif k == "tx failed": cur["tx_failed"] = int(v)
            elif k == "signal": cur["rssi"] = int(v.split()[0])
            elif k == "tx bitrate": cur["ap_tx_mbps"], cur["ap_tx_phy"] = _rate(v)      # AP -> client
            elif k == "rx bitrate": cur["sta_tx_mbps"], cur["sta_tx_phy"] = _rate(v)    # client -> AP
            elif k == "connected time": cur["connected_s"] = int(v.split()[0])
        except (ValueError, IndexError):
            pass
    return sts

def parse_iw_survey(text):
    """Return the in-use channel's cumulative counters (ms): freq, active, busy, rx, tx."""
    cur = res = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Survey data"):
            cur = {}
        elif s.startswith("frequency:") and cur is not None:
            cur["freq"] = int(re.search(r"(\d+) MHz", s).group(1))
            if "[in use]" in s: res = cur
        elif cur is not None and ":" in s:
            k, _, v = s.partition(":"); m = re.match(r"(\d+) ms", v.strip())
            if m:
                key = {"channel active time": "active", "channel busy time": "busy",
                       "channel receive time": "rx", "channel transmit time": "tx"}.get(k.strip())
                if key: cur[key] = int(m.group(1))
    if res and "active" in res and "busy" in res:
        res.setdefault("rx", 0); res.setdefault("tx", 0)
        return res
    return None

def parse_neigh(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"(\S+) dev \S+ lladdr ([0-9a-f:]{17})", line, re.I)
        if m: out[m.group(1)] = m.group(2).lower()
    return out

def parse_leases(text):  # dnsmasq: expiry mac ip hostname clientid
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4 and p[3] != "*": out[p[1].lower()] = p[3]
    return out

def parse_conntrack(text):
    """-> list of {key, proto, src, dport, up, down} (cumulative bytes; up = client->WAN)."""
    flows = []
    for line in text.splitlines():
        proto = next((t for t in line.split()[:4] if t in ("tcp", "udp")), None)
        if not proto: continue
        o, r = {}, {}
        for k, v in re.findall(r"\b(src|dst|sport|dport|bytes)=(\S+)", line):
            d = o if k not in o else (r if k not in r else None)
            if d is not None: d[k] = v
        if "bytes" not in o or "bytes" not in r or "sport" not in o: continue
        flows.append({"key": (proto, o["src"], o["sport"], o["dst"], o["dport"]), "proto": proto,
                      "src": o["src"], "dport": int(o["dport"]),
                      "up": int(o["bytes"]), "down": int(r["bytes"])})
    return flows

def _kbps(pat, text):
    m = re.search(pat, text)
    return int(m.group(1)) / 1000 if m else None

def parse_wl_sta_info(text):
    """One `wl sta_info <mac>` block. Prefers the *median* rates: 'rate of last rx pkt' is often a 6 Mbps legacy
    control/null frame on an idle client (seen on real hardware), which is not the client's real uplink rate."""
    d = {}
    last_tx = _kbps(r"rate of last tx pkt:\s*(\d+) kbps", text); last_rx = _kbps(r"rate of last rx pkt:\s*(\d+) kbps", text)
    med_tx = _kbps(r"median tx rate:\s*(\d+) kbps", text); med_rx = _kbps(r"median rx rate:\s*(\d+) kbps", text)
    d["ap_tx_mbps"] = med_tx if med_tx else last_tx
    d["sta_tx_mbps"] = med_rx if med_rx else last_rx
    d = {k: v for k, v in d.items() if v is not None}
    m = re.search(r"smoothed rssi:\s*(-?\d+)", text) or re.search(r"\brssi:\s*(-?\d+)", text)
    if m: d["rssi"] = int(m.group(1))
    m = re.search(r"per antenna noise floor:\s*(-\d+)", text)
    if m: d["noise_dbm"] = int(m.group(1))
    for key, pat in (("tx_bytes", r"tx total bytes:\s*(\d+)"), ("rx_bytes", r"rx data bytes:\s*(\d+)"),
                     ("tx_packets", r"tx total pkts sent:\s*(\d+)|tx total pkts:\s*(\d+)"), ("tx_retries", r"tx pkts retries:\s*(\d+)"),
                     ("tx_failed", r"tx failures:\s*(\d+)"), ("connected_s", r"in network\s+(\d+)\s+seconds")):
        m = re.search(pat, text)
        if m: d[key] = int(next(g for g in m.groups() if g))
    m = re.search(r"idle\s+(\d+)\s+seconds", text)
    if m: d["inactive_ms"] = int(m.group(1)) * 1000
    m = re.search(r"chanspec\s+(\S+)", text)
    if m: d["chanspec"] = m.group(1)
    m = re.search(r"link bandwidth = (\d+)", text)
    if m: d["width_mhz"] = int(m.group(1))
    return d

def parse_wl_sta_info_all(text):
    """`wl sta_info all` -> list of station dicts (one serial round-trip instead of one per client)."""
    out = []
    parts = re.split(r"\[VER \d+\]\s+STA\s+([0-9a-fA-F:]{17}):", text)
    for i in range(1, len(parts) - 1, 2):
        d = parse_wl_sta_info(parts[i + 1]); d["mac"] = parts[i].lower(); out.append(d)
    return out

def parse_wl_chanspec(text):
    """'6g101/320-2 (0x7043)' | '36/80 (0xe02a)' | '11l (0x1b0b)' -> (band, channel, width_mhz|None)"""
    m = re.search(r"(?:^|\s)(?:(\d)g)?(\d+)(?:/(\d+))?", text.strip())
    if not m: return None
    ch = int(m.group(2))
    return ("6G" if m.group(1) == "6" else ("2.4G" if ch <= 14 else "5G")), ch, int(m.group(3)) if m.group(3) else None

def parse_wl_chanim(text):
    lines = [l.split() for l in text.splitlines() if l.strip()]
    for i, l in enumerate(lines):
        if l and l[0] == "chanspec" and i + 1 < len(lines):
            row = dict(zip(l, lines[i + 1]))
            try:
                busy = 100 - float(row["txop"])
                return {"util_pct": round(busy, 1), "tx_pct": float(row.get("tx", 0)),
                        "rx_pct": float(row.get("inbss", 0)), "other_pct": float(row.get("obss", 0))}
            except (KeyError, ValueError):
                return None
    return None

def parse_qca_sta_list(text):
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) > 5 and re.fullmatch(r"[0-9a-f:]{17}", p[0], re.I):
            f = lambda x: float(re.match(r"(\d+)", x).group(1)) if re.match(r"\d+", x) else None
            out.append({"mac": p[0].lower(), "ap_tx_mbps": f(p[3]), "sta_tx_mbps": f(p[4]),
                        "rssi": int(p[5]) - 95})  # wlanconfig reports SNR; ~-95 dBm noise floor assumed
    return out

# ----------------------------------------------------------------------------- traffic classification
IOT_HOST = re.compile(r"esp|tuya|nest|hue|ecobee|wyze|shelly|tasmota|sensor|thermostat|plug|cam|ring|iot|lutron|sonoff", re.I)
WMM = {"Conferencing": "VO/VI", "Video Streaming": "VI", "Web/Cloud": "BE", "Bulk": "BK", "IoT": "BE", "Infra": "BE"}

def classify(proto, dport, up_bps, down_bps, iot_client):
    if iot_client and max(up_bps, down_bps) < 3e6: return "IoT", "IoT device"
    if proto == "udp" and 3478 <= dport <= 3481: return "Conferencing", "Teams"
    if proto == "udp" and 19302 <= dport <= 19309: return "Conferencing", "Meet"
    if 8801 <= dport <= 8810: return "Conferencing", "Zoom"
    if dport in (1883, 8883, 5683, 5684): return "IoT", "MQTT/CoAP"
    if dport in (53, 853, 123, 67): return "Infra", "DNS/NTP"
    if proto == "udp" and dport == 443:
        return ("Video Streaming", "QUIC video") if down_bps > 1.5e6 else ("Web/Cloud", "QUIC")
    if proto == "tcp" and dport in (80, 443, 8080):
        if down_bps > 2e6: return "Video Streaming", "HTTPS stream"
        if up_bps > 2e6: return "Bulk", "Upload"
        return "Web/Cloud", "Web"
    return ("Bulk", "Other") if up_bps + down_bps > 2e6 else ("Web/Cloud", "Other")

# ----------------------------------------------------------------------------- backends
class Backend:
    def __init__(self, runner, ifaces=None):
        self.r, self.ifaces = runner, ifaces
    max_flows = 2000      # cap lines read from conntrack (slow serial / ubus size limits); 0 = skip traffic classification
    def flows(self):
        if not self.max_flows: return []
        n = int(self.max_flows)
        txt = self.r.run(f"head -n {n} /proc/net/nf_conntrack 2>/dev/null || conntrack -L -o extended 2>/dev/null | head -n {n}", timeout=30)
        return parse_conntrack(txt)
    def ip_to_mac(self): return parse_neigh(self.r.run("ip neigh"))
    def hostnames(self):
        return parse_leases(self.r.run("cat /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases 2>/dev/null"))

class IwBackend(Backend):
    def radios(self):
        r = parse_iw_dev(self.r.run("iw dev"))
        return [x for x in r if not self.ifaces or x["iface"] in self.ifaces]
    def stations(self, iface): return parse_iw_stations(self.r.run(f"iw dev {shlex.quote(iface)} station dump"))
    def survey(self, iface): return parse_iw_survey(self.r.run(f"iw dev {shlex.quote(iface)} survey dump"))

class WlBackend(Backend):
    def radios(self):
        out = []
        for i in self.ifaces or []:
            q = shlex.quote(i)
            cs = parse_wl_chanspec(self.r.run(f"wl -i {q} chanspec"))
            if cs: band, ch, width = cs
            else:
                m = re.search(r"current mac channel\s+(\d+)", self.r.run(f"wl -i {q} channel"))
                ch = int(m.group(1)) if m else 0; band = "2.4G" if 0 < ch <= 14 else "5G"; width = None
            out.append({"iface": i, "channel": ch, "band": band, "width_mhz": width})
        return out
    def stations(self, iface):
        q = shlex.quote(iface)
        out = parse_wl_sta_info_all(self.r.run(f"wl -i {q} sta_info all", timeout=30))
        if out: return out
        for mac in re.findall(r"([0-9a-f:]{17})", self.r.run(f"wl -i {q} assoclist"), re.I):   # older firmware: no 'sta_info all'
            d = parse_wl_sta_info(self.r.run(f"wl -i {q} sta_info {mac}")); d["mac"] = mac.lower(); out.append(d)
        return out
    def survey(self, iface): return parse_wl_chanim(self.r.run(f"wl -i {shlex.quote(iface)} chanim_stats"))

class QcaBackend(IwBackend):
    def radios(self):
        out = []
        for i in self.ifaces or []:
            d = next((x for x in parse_iw_dev(self.r.run(f"iw dev {shlex.quote(i)} info")) if True), None)
            out.append(d or {"iface": i, "channel": 0, "band": "?"})
        return out
    def stations(self, iface): return parse_qca_sta_list(self.r.run(f"wlanconfig {shlex.quote(iface)} list sta"))

class SimBackend(Backend):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.t = time.time(); self.surv = {}; self.cnt = {}
        self.rssi = {"01": -52, "02": -71, "03": -58, "04": -70, "05": -60, "06": -49, "07": -55}
        # mac, ip, host, band, flows[(proto,dport,up_bps,down_bps)], base phy
        self.cl = [
            ("a4:83:e7:00:00:01", "192.168.1.10", "siva-macbook", "5G", [("udp", 3478, 2.2e6, 2.6e6), ("tcp", 443, 3e5, 1e6)], 866),
            ("a4:83:e7:00:00:02", "192.168.1.11", "livingroom-tv", "5G", [("udp", 443, 6e4, 9e6)], 650),
            ("a4:83:e7:00:00:03", "192.168.1.12", "pixel-8", "5G", [("tcp", 443, 2e5, 1.5e6)], 433),
            ("a4:83:e7:00:00:04", "192.168.1.13", "esp32-sensor", "2.4G", [("tcp", 8883, 2e3, 1e3)], 72),
            ("a4:83:e7:00:00:05", "192.168.1.14", "driveway-cam", "2.4G", [("tcp", 443, 1.4e6, 5e4)], 144),
            ("a4:83:e7:00:00:06", "192.168.1.15", "hue-bridge", "2.4G", [("tcp", 1883, 3e3, 3e3)], 72),
            ("a4:83:e7:00:00:07", "192.168.1.16", "ipad", "2.4G", [("tcp", 443, 1e4, 2e4)], 433)]
    def radios(self):
        return [{"iface": "wlan0", "channel": 6, "freq": 2437, "band": "2.4G"},
                {"iface": "wlan1", "channel": 36, "freq": 5180, "band": "5G"}]
    def survey(self, iface):
        now = time.time()
        s = self.surv.setdefault(iface, {"freq": 2437 if iface == "wlan0" else 5180, "active": 0, "busy": 0, "rx": 0, "tx": 0, "_t": now})
        dt = (now - s["_t"]) * 1000; s["_t"] = now
        u = 0.35 if iface == "wlan0" else 0.18; u = min(0.95, max(0.02, u + random.uniform(-.05, .05)))
        s["active"] += dt; s["busy"] += dt * u; s["rx"] += dt * u * .45; s["tx"] += dt * u * .3
        return {k: int(v) for k, v in s.items() if k != "_t"}
    def stations(self, iface):
        band = "2.4G" if iface == "wlan0" else "5G"
        return [{"mac": m, "rssi": self.rssi[m[-2:]] + random.randint(-2, 2), "inactive_ms": random.randint(0, 300),
                 "ap_tx_mbps": phy * random.uniform(.6, 1), "sta_tx_mbps": phy * random.uniform(.5, .9),
                 "tx_packets": self._pk(m, 1000), "tx_retries": self._pk(m + "r", random.randint(20, 120))}
                for m, _, _, b, _, phy in self.cl if b == band]
    def _pk(self, key, rate):
        c = self.cnt.setdefault(("pk", key), [0, time.time()]); now = time.time()
        c[0] += int(rate * (now - c[1])); c[1] = now; return c[0]
    WIRED = [("b8:27:eb:00:00:50", "192.168.1.50", "nas-synology"), ("b8:27:eb:00:00:51", "192.168.1.51", "printer-hp")]
    def ip_to_mac(self): return {**{ip: m for m, ip, *_ in self.cl}, **{ip: m for m, ip, _ in self.WIRED}}
    def hostnames(self): return {**{m: h for m, _, h, *_ in self.cl}, **{m: h for m, _, h in self.WIRED}}
    def flows(self):
        now = time.time(); out = []
        for m, ip, h, b, fl, _ in self.cl:
            for proto, dport, up, down in fl:
                k = (proto, ip, "40000", "203.0.113.5", str(dport))
                c = self.cnt.setdefault(k, [0, 0, now]); dt = now - c[2]; c[2] = now
                c[0] += up / 8 * dt * random.uniform(.7, 1.3); c[1] += down / 8 * dt * random.uniform(.7, 1.3)
                out.append({"key": k, "proto": proto, "src": ip, "dport": dport, "up": int(c[0]), "down": int(c[1])})
        return out

class LocalBackend(Backend):
    """Run on the MacBook itself, no AP access: lists every LAN host (ping sweep + ARP) and reads THIS Mac's Wi-Fi link.
    Other devices' PHY rate/RSSI/traffic are not visible from a client - use --backend iw/wl/qca with --host for those."""
    TTL = 45
    def __init__(self, runner, ifaces=None, subnet=None):
        super().__init__(runner, ifaces); self.subnet, self.t = subnet, 0; self.wifi = None; self.arp = {}; self.names = {}
    def _refresh(self):
        if time.time() - self.t < self.TTL: return
        self.t = time.time()
        self.wifi = discovery.parse_mac_wifi(self.r.run("system_profiler SPAirPortDataType", timeout=30))
        self.arp = discovery.scan(self.subnet)
        me = discovery.local_ip()
        if me and self.wifi and self.wifi.get("mac"): self.arp[me] = self.wifi["mac"]
        rn = discovery.rdns(list(self.arp))
        self.names = {self.arp[ip]: n for ip, n in rn.items()}
        if self.wifi and self.wifi.get("mac"): self.names[self.wifi["mac"]] = socket.gethostname().split(".")[0] + " (this Mac)"
    def radios(self):
        self._refresh(); w = self.wifi
        return [{"iface": w["iface"], "channel": w["channel"], "band": w["band"]}] if w else []
    def stations(self, iface):
        w = self.wifi
        return [{"mac": w["mac"] or "00:00:00:00:00:01", "rssi": w["rssi"], "ap_tx_mbps": w["tx_rate"], "sta_tx_mbps": w["tx_rate"],
                 "inactive_ms": 0}] if w else []
    def survey(self, iface): return None
    def flows(self): return []
    def ip_to_mac(self): self._refresh(); return self.arp
    def hostnames(self): return self.names

BACKENDS = {"local": LocalBackend, "iw": IwBackend, "wl": WlBackend, "qca": QcaBackend, "sim": SimBackend}

# ----------------------------------------------------------------------------- monitor
class Monitor:
    def __init__(self, backend, interval, log_dir=None, types=None, offset=8.0):
        self.be, self.interval, self.log_dir = backend, interval, log_dir
        self.types, self.offset = {k.lower(): v for k, v in (types or {}).items()}, offset
        self.rssi_hist, self.mix_hist = {}, {}
        self.prev_surv, self.prev_flow, self.prev_sta = {}, None, {}
        self.last_t = None
        self.test, self.iperf_from, self.allow_remote_tests, self.iperf_port = None, "host", False, 5201
        self.iperf_server, self.iperf_token, self.iperf_server_ip, self.arm_timeout = None, None, None, 180
        self.mem = None                                         # memwatch.MemCollector when --mem-host is given      # server-PC mode: base URL of iperf_agent.py
        self.state = {"ts": 0, "radios": [], "clients": [], "summary": {}}
        self.lock = threading.Lock()

    def _util(self, iface, s):
        if not s: return {}
        if "util_pct" in s: return s
        prev, self.prev_surv[iface] = self.prev_surv.get(iface), s
        if not prev or prev["freq"] != s["freq"]: return {}
        da = s["active"] - prev["active"]
        if da <= 0: return {}
        p = lambda k: round(100 * max(0, s[k] - prev[k]) / da, 1)
        busy, tx, rx = p("busy"), p("tx"), p("rx")
        # "other" = busy time not explained by our own tx/rx (neighbour BSS, non-Wi-Fi interference)
        return {"util_pct": busy, "tx_pct": tx, "rx_pct": rx, "other_pct": round(max(0, busy - tx - rx), 1)}

    def poll(self):
        now = time.time(); dt = now - self.last_t if self.last_t else None; self.last_t = now
        radios, stas = [], {}
        for r in self.be.radios():
            radios.append({**r, **self._util(r["iface"], self.be.survey(r["iface"]))})
            for s in self.be.stations(r["iface"]):
                s.update(iface=r["iface"], band=r.get("band"), channel=r.get("channel")); stas[s["mac"]] = s

        ip2mac, hosts = self.be.ip_to_mac(), self.be.hostnames()
        cur = {f["key"]: f for f in self.be.flows()}
        per = {}  # mac -> {up, down, cats{(cat,app): bps}}
        if self.prev_flow is not None and dt:
            for k, f in cur.items():
                mac = ip2mac.get(f["src"])
                if not mac: continue
                p = self.prev_flow.get(k)
                du = max(0, f["up"] - (p["up"] if p else 0)); dd = max(0, f["down"] - (p["down"] if p else 0))
                if not du and not dd: continue
                ub, db = du * 8 / dt, dd * 8 / dt
                cat = classify(f["proto"], f["dport"], ub, db, bool(IOT_HOST.search(hosts.get(mac, ""))))
                e = per.setdefault(mac, {"up": 0, "down": 0, "cats": {}})
                e["up"] += ub; e["down"] += db; e["cats"][cat] = e["cats"].get(cat, 0) + ub + db
        self.prev_flow = cur

        mac2ips = {}
        for ip, m in ip2mac.items(): mac2ips.setdefault(m, []).append(ip)
        radio_by_if = {r["iface"]: r for r in radios}
        clients = []
        for mac, s in stas.items():
            t = per.get(mac, {"up": 0, "down": 0, "cats": {}})
            ps = self.prev_sta.get(mac); retry = None
            if ps and s.get("tx_packets") and s["tx_packets"] > ps[0]:
                retry = min(100.0, round(100 * max(0, s.get("tx_retries", 0) - ps[1]) / (s["tx_packets"] - ps[0]), 1))
            self.prev_sta[mac] = (s.get("tx_packets", 0), s.get("tx_retries", 0))
            cats = sorted(t["cats"].items(), key=lambda x: -x[1])
            clients.append({
                "mac": mac, "host": hosts.get(mac, ""), "iface": s["iface"], "band": s.get("band"), "channel": s.get("channel"),
                "rssi": s.get("rssi"), "ap_tx_phy_mbps": _r1(s.get("ap_tx_mbps")),
                "sta_tx_phy_mbps": _r1(s.get("sta_tx_mbps")),
                "up_mbps": round(t["up"] / 1e6, 3), "down_mbps": round(t["down"] / 1e6, 3),
                "retry_pct": retry, "active": (t["up"] + t["down"]) > 10_000,
                "apps": [{"class": c, "app": a, "mbps": round(b / 1e6, 3), "wmm": WMM.get(c, "BE")} for (c, a), b in cats]})
            cl = clients[-1]; cl["ips"] = mac2ips.get(mac, [])
            if s.get("rssi") is not None: self.rssi_hist.setdefault(mac, deque(maxlen=8)).append(s["rssi"])
            mh = self.mix_hist.setdefault(mac, deque(maxlen=12))
            mh.append({}); 
            for (c_, a_), b_ in cats: mh[-1][c_] = mh[-1].get(c_, 0) + b_
            tot = {}
            for d in mh:
                for k_, v_ in d.items(): tot[k_] = tot.get(k_, 0) + v_
            T = sum(tot.values()); mix = {k_: v_ / T for k_, v_ in tot.items()} if T > 50_000 else {}
            cl["mix"] = {k_: round(v_, 3) for k_, v_ in mix.items()}
            cl["type"] = resolve_type(self.types, mac, cl["host"], cl["ips"]) if self.types else None
            if cl["type"]:
                cl["insights"], cl["band_advice"] = advise(cl, cl["type"], list(self.rssi_hist.get(mac, [])), mix, radio_by_if, self.offset)
            else:
                cl["insights"], cl["band_advice"] = [], None
        clients.sort(key=lambda c: (c["type"] is None, -(c["up_mbps"] + c["down_mbps"])))
        for r in radios: r["insights"] = advise_radio(r)
        seen = {i for c in clients for i in c["ips"]} | {c["mac"] for c in clients} | {c["host"].lower() for c in clients if c["host"]}
        missing = [k for k in self.types if k not in seen]
        lan = {}
        for ip, m in ip2mac.items():
            if m in stas: continue
            e = lan.setdefault(m, {"mac": m, "ips": [], "host": hosts.get(m, ""), "wifi": False}); e["ips"].append(ip)
            e["type"] = resolve_type(self.types, m, e["host"], e["ips"]) if self.types else None
        by_class = {}
        for c in clients:
            for a in c["apps"]: by_class[a["class"]] = round(by_class.get(a["class"], 0) + a["mbps"], 3)
        with self.lock:
            self.state = {"ts": now, "interval": self.interval, "radios": radios, "clients": clients, "lan": list(lan.values()), "not_associated": missing,
                          "summary": {"clients": len(clients), "active": sum(c["active"] for c in clients),
                                      "mbps_by_class": by_class}}
        t = self.test
        if t and t["state"] in ("running", "waiting"):          # sample the tested client's link while the test runs (or is armed)
            c = next((c for c in clients if c["mac"] == t["mac"]), None)
            if c:
                r = radio_by_if.get(c["iface"], {})
                t["samples"].append({"rssi": c["rssi"], "ap_tx": c["ap_tx_phy_mbps"], "sta_tx": c["sta_tx_phy_mbps"],
                                     "retry": c["retry_pct"], "util": r.get("util_pct"), "t": now})
        if self.log_dir: self._log(now, radios, clients)

    def _log(self, ts, radios, clients):
        os.makedirs(self.log_dir, exist_ok=True)
        def w(name, rows, cols):
            path = os.path.join(self.log_dir, name); new = not os.path.exists(path)
            with open(path, "a", newline="") as f:
                cw = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                if new: cw.writeheader()
                for r in rows: cw.writerow(r)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
        w("radios.csv", [{"ts": stamp, **r} for r in radios],
          ["ts", "iface", "band", "channel", "util_pct", "tx_pct", "rx_pct", "other_pct"])
        w("clients.csv", [{"ts": stamp, **c, "top_app": c["apps"][0]["app"] if c["apps"] else "",
                           "top_class": c["apps"][0]["class"] if c["apps"] else "",
                           "advice": " | ".join(i["title"] for i in c["insights"] if i["sev"] != "ok")} for c in clients],
          ["ts", "mac", "host", "iface", "band", "rssi", "ap_tx_phy_mbps", "sta_tx_phy_mbps",
           "up_mbps", "down_mbps", "retry_pct", "active", "top_class", "top_app", "type", "advice"])

    def sleep_for(self):          # sample faster (every <=2 s) while a throughput test is running
        t = self.test
        return min(self.interval, 2.0) if t and t["state"] in ("running", "waiting") else self.interval

    def loop(self):
        while True:
            try: self.poll()
            except Exception as e: sys.stderr.write(f"[error] poll failed: {e}\n")
            time.sleep(self.sleep_for())

    # ---- measured tests: iperf3 / speedtest ------------------------------------------------------------
    def _find(self, st, mac):
        return next((c for c in st["clients"] if c["mac"] == mac), None) or next((l for l in st.get("lan", []) if l["mac"] == mac), None)

    def start_test(self, req):
        with self.lock:
            if self.test and self.test["state"] in ("running", "waiting"): return {"error": "A test is already running."}
            st = self.state
        mac, spec = req.get("mac", ""), planner.CATALOG.get(req.get("traffic", ""))
        if not spec or not spec.get("test"): return {"error": "That traffic type is not a measured test."}
        qd = spec["qualities"].get(req.get("quality")) or spec["qualities"][spec["default"]]
        try: secs, streams, rate = int(req.get("secs", 10)), int(req.get("streams", 1)), float(req.get("rate", 50))
        except (TypeError, ValueError): return {"error": "Duration, streams and rate must be numbers."}
        secs, streams, rate = max(3, min(secs, 120)), max(1, min(streams, 16)), max(0.1, min(rate, 10000.0))
        client, ip = self._find(st, mac), None
        server = bool(self.iperf_server) and spec["test"] == "iperf3"
        if spec["test"] == "iperf3":
            if not client or not client.get("ips"): return {"error": "No IP is known for that client yet; it must show an IP in the client list."}
            ip = client["ips"][0]
        if server:
            try: ag = self._agent("/status")
            except Exception as e: return {"error": self._agent_err(e)}
            if ag.get("state") == "error": return {"error": "The iperf3 server PC reports: " + (ag.get("last_error") or "error")}
            sip = self.iperf_server_ip or ag.get("server_ip")
            if not sip: return {"error": "Could not work out the server PC's LAN IP; pass --iperf-server-ip."}
            t = {"state": "waiting", "tool": "iperf3", "mode": qd.get("mode"), "mac": mac, "ip": ip, "ips": list(client["ips"]), "secs": secs, "streams": streams,
                 "rate": rate, "started": time.time(), "samples": [], "result": None, "server": True, "server_ip": sip, "port": ag.get("iperf_port", 5201),
                 "after": ag.get("last_id", 0), "others": [], "cancel": False, "claimed": False, "deadline": time.time() + self.arm_timeout,
                 "util_before": next((r.get("util_pct") for r in st["radios"] if r["iface"] == client.get("iface")), None)}
            t["cmd"] = speedtools.client_cmd(sip, t["port"], t["mode"], secs, streams, rate)
            self.test = t
            threading.Thread(target=self._wait_test, args=(t,), daemon=True).start()
            return {"ok": True}
        t = {"state": "running", "tool": spec["test"], "mode": qd.get("mode"), "mac": mac, "ip": ip, "secs": secs, "streams": streams,
             "rate": rate, "started": time.time(), "samples": [], "result": None,
             "util_before": (next((r.get("util_pct") for r in st["radios"] if client and r["iface"] == client.get("iface")), None))}
        self.test = t
        threading.Thread(target=self._run_test, args=(t,), daemon=True).start()
        return {"ok": True}

    def _agent(self, path):
        import urllib.request
        rq = urllib.request.Request(self.iperf_server.rstrip("/") + path, headers={"X-Token": self.iperf_token} if self.iperf_token else {})
        with urllib.request.urlopen(rq, timeout=4) as r: return json.loads(r.read())

    def _agent_err(self, e):
        if getattr(e, "code", None) == 401: return "The iperf3 server PC rejected the token (check --iperf-token)."
        return f"Cannot reach the iperf3 server PC at {self.iperf_server} ({e}). On that PC run `py iperf_agent.py` and allow TCP {self.iperf_server.rsplit(':', 1)[-1]} and 5201 through its firewall."

    def _wait_test(self, t):
        """Armed: wait for the selected client's iperf3 run to show up on the server PC, then score it."""
        fails, res = 0, None
        while t["state"] == "waiting":
            if t["cancel"]: t["state"] = "cancelled"; t["finished"] = time.time(); return
            if time.time() > t["deadline"]:
                res = {"ok": False, "error": f"No iperf3 test from {t['ip']} arrived within {self.arm_timeout}s." + (
                    " Tests were seen from " + ", ".join(t["others"]) + " instead; if that is the router's address the client is behind NAT and cannot be matched." if t["others"] else
                    " Check the client can reach the server PC on that port (firewall, same subnet, Wi-Fi client isolation).")}
                break
            try:
                r = self._agent(f"/results?after={t['after']}"); fails = 0
                for x in r.get("results", []):
                    t["after"] = max(t["after"], x["id"])
                    p = speedtools.parse_iperf3_server(x["raw"])
                    host = p.get("remote_host")
                    if not p.get("ok") and not host: continue          # aborted/garbled run: nothing to match
                    if host and host not in t["ips"]:
                        if host not in t["others"]: t["others"].append(host)
                        continue
                    res = p; res["_finish"] = time.time() - x.get("age_s", 0); break
            except Exception as e:
                fails += 1
                if fails >= 5: res = {"ok": False, "error": self._agent_err(e)}
            if res: break
            time.sleep(1.0)
        if t["state"] != "waiting": return
        if res.get("ok"):
            fin = res.pop("_finish", time.time()); win = (res.get("secs") or t["secs"]) + 3                # test length + slack for omit/ramp and clock jitter
            t["n_raw"] = len(t["samples"])
            t["samples"] = [x for x in t["samples"] if fin - win <= x.get("t", fin) <= fin + 1]
            t["mode"], t["secs"] = res["mode"], res.get("secs") or t["secs"]
            if res.get("target_mbps"): t["rate"] = res["target_mbps"]
        self._finish_test(t, res)

    def _run_test(self, t):
        try:
            if t["tool"] == "iperf3":
                res = speedtools.run_iperf3(t["ip"], t["mode"], t["secs"], t["streams"], t["rate"],
                                            runner=self.be.r if self.iperf_from == "ap" else None, port=self.iperf_port)
            else:
                res = speedtools.run_speedtest()
        except Exception as e:
            res = {"ok": False, "error": f"test failed: {e}"}
        self._finish_test(t, res)

    def _finish_test(self, t, res):
        if res.get("ok"):
            res["link"] = _summarise(t["samples"], t.get("util_before"))
            if t["tool"] == "iperf3" and t["mode"].startswith("udp"): res["target_mbps"] = res.get("target_mbps") or t["rate"]
            with self.lock: st = self.state
            res["insights"] = _test_insights(res, t)
            if self.log_dir: self._log_test(t, res)
        t["result"], t["finished"] = res, time.time()
        t["state"] = "done" if res.get("ok") else "error"

    def test_status(self):
        t = self.test
        if not t: return {"state": "idle"}
        out = {k: t[k] for k in ("state", "tool", "mode", "mac", "ip", "secs", "streams", "rate", "result")} | {
            "elapsed": round((t.get("finished") or time.time()) - t["started"]), "samples": len(t["samples"])}
        if t.get("server"): out |= {"server": True, "cmd": t["cmd"], "server_ip": t["server_ip"], "others": t["others"], "remaining": max(0, round(t["deadline"] - time.time())), "claimed": t["claimed"]}
        return out

    def pending_for(self, ip):
        """What an iperf_client.py helper running on `ip` should do now. Matched on the requester's real source IP."""
        t = self.test
        if not (t and t.get("server") and t["state"] == "waiting" and ip in t["ips"] and not t["claimed"]): return {"pending": False}
        t["claimed"] = True
        return {"pending": True, "server_ip": t["server_ip"], "port": t["port"], "mode": t["mode"], "secs": t["secs"], "streams": t["streams"], "rate": t["rate"]}

    def cancel_test(self):
        t = self.test
        if t and t["state"] == "waiting": t["cancel"] = True; return {"ok": True}
        return {"error": "No armed test to cancel."}

    def config(self):
        return {"iperf_server": bool(self.iperf_server)}

    def _log_test(self, t, res):
        os.makedirs(self.log_dir, exist_ok=True)
        path = os.path.join(self.log_dir, "tests.csv"); new = not os.path.exists(path)
        cols = ["ts", "mac", "ip", "tool", "mode", "mbps", "down_mbps", "up_mbps", "retransmits", "jitter_ms", "loss_pct", "ping_ms",
                "rssi_avg", "ap_tx_avg", "sta_tx_avg", "retry_avg", "util_avg", "util_max"]
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "mac": t["mac"], "ip": t["ip"], "tool": res.get("tool"), "mode": t["mode"], **res, **res.get("link", {})}
        with open(path, "a", newline="") as f:
            cw = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            if new: cw.writeheader()
            cw.writerow(row)

    def plan(self, mac, traffic, quality, n):
        with self.lock: st = self.state
        client = next((c for c in st["clients"] if c["mac"] == mac), None) or next((l for l in st.get("lan", []) if l["mac"] == mac), None)
        return planner.plan(client, traffic, quality, n, {r["iface"]: r for r in st["radios"]}, self.offset, client.get("type") if client else None)

    def snapshot(self):
        with self.lock: return json.dumps(self.state)

def _r1(x): return None if x is None else round(x, 1)

def _summarise(samples, util_before=None):
    def stat(k):
        v = [x[k] for x in samples if x.get(k) is not None]
        return (round(sum(v) / len(v), 1), round(max(v), 1)) if v else (None, None)
    rssi, _ = stat("rssi"); aptx, _ = stat("ap_tx"); statx, _ = stat("sta_tx"); retry, rmax = stat("retry"); util, umax = stat("util")
    return {"n": len(samples), "rssi_avg": rssi, "ap_tx_avg": aptx, "sta_tx_avg": statx, "retry_avg": retry, "retry_max": rmax,
            "util_avg": util, "util_max": umax, "util_before": util_before}

def _ins(sev, title, detail, action=""): return {"sev": sev, "title": title, "detail": detail, "action": action}

def _test_insights(res, t):
    out, L = [], res.get("link") or {}
    if res["tool"] == "iperf3":
        mbps, mode = res["mbps"], t["mode"]
        if mode.startswith("udp"):
            tgt = t["rate"]
            if res.get("loss_pct") is None: out.append(_ins("info", "UDP download: loss and jitter are measured by the client", "With -R the client is the receiver, so read loss/jitter from its own iperf3 output.", "Run without -R (upload) to have the server PC record them."))
            elif res["loss_pct"] > 5: out.append(_ins("crit", f"UDP loss {res['loss_pct']}%", f"At {tgt:g} Mbps the link drops {res['loss_pct']}% of packets.", "Real-time media at this rate would glitch; lower the rate or fix signal/airtime."))
            elif res["loss_pct"] > 1: out.append(_ins("warn", f"UDP loss {res['loss_pct']}%", "Above the ~1% that voice/video calls tolerate.", "Check retries and channel busy % below."))
            if (res.get("jitter_ms") or 0) > 30: out.append(_ins("warn", f"UDP jitter {res['jitter_ms']} ms", "Above the ~30 ms real-time media guideline.", "Look for airtime contention or retries."))
            if mbps < 0.95 * tgt: out.append(_ins("warn", f"Only {mbps:g} of {tgt:g} Mbps delivered", "The link could not sustain the requested rate.", "Lower the rate to find the ceiling, or improve the link."))
            elif res.get("loss_pct") is not None and res["loss_pct"] <= 1 and (res.get("jitter_ms") or 0) <= 30: out.append(_ins("ok", f"Sustained {tgt:g} Mbps", f"Loss {res['loss_pct']}%, jitter {res['jitter_ms']} ms: within real-time targets."))
        else:
            rng = f" (per-second {res['min_mbps']:g}–{res['max_mbps']:g})" if res.get("min_mbps") is not None else ""
            out.append(_ins("info", f"TCP {'download' if mode.endswith('down') else 'upload'}: {mbps:g} Mbps{rng}", "Measured end to end between the client and the iperf3 server; the link tiles show the Wi-Fi conditions during the run."))
            if (res.get("retransmits") or 0) > 100: out.append(_ins("info", f"{res['retransmits']} TCP retransmits", "Packet loss or reordering on the path limited throughput."))
        if (L.get("retry_avg") or 0) >= 15: out.append(_ins("warn", f"High Wi-Fi retries during test ({L['retry_avg']}%)", "Interference or a marginal link.", "Change channel/width or move closer."))
        if (L.get("util_max") or 0) >= 70: out.append(_ins("warn", f"Radio {L['util_max']}% busy at peak", "Little airtime was left; other devices compete.", "Run the test when the network is quiet, or move the client to a quieter band."))
        if not L.get("n"): out.append(_ins("info", "No link samples captured", "The test finished before a poll completed; use a longer duration or a smaller --interval."))
    else:
        d = res["down_mbps"]
        out.append(_ins("info", f"Internet {d:g} ↓ / {res['up_mbps']:g} ↑ Mbps, ping {res.get('ping_ms')} ms", "Measured by the machine running this dashboard, not by the selected client."))
    return out

ICON = {"crit": "[!!]", "warn": "[! ]", "info": "[i ]", "ok": "[ok]"}
def print_insights(st):
    print("\nINSIGHTS")
    for r in st["radios"]:
        for i in r.get("insights", []): print(f"  {ICON[i['sev']]} RADIO {i['title']} - {i['detail']} -> {i['action']}")
    for c in st["clients"]:
        if not c.get("type"): continue
        ba = c.get("band_advice") or {}
        print(f"  {c['host'] or c['mac']} ({c['type']}, {c['band']}, {c['rssi']} dBm"
              f"{', est other band ' + str(ba.get('est_rssi_other')) + ' dBm' if ba else ''}):")
        for i in c["insights"]:
            print(f"    {ICON[i['sev']]} {i['title']}: {i['detail']}" + (f"\n         -> {i['action']}" if i["action"] else ""))
    for k in st.get("not_associated", []): print(f"  [i ] '{k}' is not associated to this AP right now")

def print_table(st):
    print("\nRADIOS")
    for r in st["radios"]:
        print(f"  {r['iface']:<8}{str(r.get('band')):<6}ch{str(r.get('channel')):<5}"
              f"util={r.get('util_pct', 'n/a')}%  (tx {r.get('tx_pct', '-')} rx {r.get('rx_pct', '-')} other {r.get('other_pct', '-')})")
    print("\nCLIENTS (PHY = Mbps; AP>STA is AP Tx, STA>AP is client Tx; Up/Down = measured throughput)")
    print(f"  {'host/mac':<22}{'band':<6}{'rssi':<6}{'AP>STA':<8}{'STA>AP':<8}{'Up':<8}{'Down':<8}{'retry%':<8}top app (WMM)")
    for c in st["clients"]:
        a = c["apps"][0] if c["apps"] else None
        print(f"  {(c['host'] or c['mac']):<22}{str(c['band']):<6}{str(c['rssi']):<6}{str(c['ap_tx_phy_mbps']):<8}"
              f"{str(c['sta_tx_phy_mbps']):<8}{c['up_mbps']:<8}{c['down_mbps']:<8}{str(c['retry_pct']):<8}"
              f"{(a['app'] + ' / ' + a['class'] + ' (' + a['wmm'] + ')') if a else '-'}{'' if c['active'] else '   [idle]'}")

# ----------------------------------------------------------------------------- web dashboard
HTML = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Wi-Fi Monitor</title><style>
:root{--bg:#f6f7f9;--fg:#1c2330;--card:#fff;--mut:#667085;--line:#e4e7ec;--a:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6e9ef;--card:#181e28;--mut:#98a2b3;--line:#2a3342;--a:#6ea0ff}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif}
h1{font-size:18px;margin:0 0 12px}h2{font-size:14px;margin:0 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px;overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.bar{height:10px;background:var(--line);border-radius:5px;overflow:hidden;margin:6px 0}.bar>i{display:block;height:100%;background:var(--a)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:500}.mut{color:var(--mut)}.tag{display:inline-block;padding:1px 7px;border-radius:9px;background:var(--line);margin-right:4px;font-size:12px}
.hot{color:#d92d20;font-weight:600}
.ctl{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:12px}.ctl label{display:flex;flex-direction:column;font-size:12px;color:var(--mut);gap:4px}
.ctl select,.ctl input{font:inherit;padding:6px 8px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);min-width:150px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:10px 0}.tile{border:1px solid var(--line);border-radius:8px;padding:10px}
.tile b{display:block;font-size:20px}.tile span{color:var(--mut);font-size:12px}
.v{display:inline-block;padding:3px 10px;border-radius:12px;font-weight:600;color:#fff}.v.good{background:#12b76a}.v.marginal{background:#f79009}.v.poor{background:#d92d20}.v.unknown{background:#667085}</style></head><body>
<h1>Wi-Fi Monitor <span class=mut id=ts></span> <a href="/mem" style="font-size:13px;font-weight:400;margin-left:12px">Device memory &rarr;</a></h1>
<div class=card><h2>Traffic planner</h2>
<div class=ctl><label>Client<select id=pc></select></label><label>Traffic<select id=pt></select></label>
<label>Quality<select id=pq></select></label><label>Simultaneous streams<input id=pn type=number min=1 max=20 value=1 style="min-width:80px"></label></div>
<div id=pr class=mut>Select a client and a traffic type.</div>
<div id=tp style="display:none;margin-top:14px;border-top:1px solid var(--line);padding-top:12px">
<div class=ctl><label id=tdl>Duration (s)<input id=td type=number value=10 min=3 max=120 style="min-width:80px"></label>
<label id=tsl>Parallel streams<input id=tsn type=number value=1 min=1 max=16 style="min-width:80px"></label>
<label id=trl style="display:none">UDP target rate (Mbps)<input id=tr type=number value=50 min=0.1 step=any style="min-width:100px"></label>
<label>&nbsp;<button id=tb style="font:inherit;padding:7px 16px;border-radius:6px;border:0;background:var(--a);color:#fff;cursor:pointer">Run test</button></label></div>
<div id=tn class=mut style="margin-bottom:8px"></div><div id=tres></div></div></div>
<div class=grid id=radios></div><div class=card style="margin-top:14px"><h2>Traffic by class (Mbps)</h2><div id=cls></div></div>
<div class=card><h2>Insights &amp; recommendations</h2><div id=ins></div></div>
<div class=card><h2>Clients</h2><table id=t></table></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function tick(){let s;try{s=await (await fetch('api/state')).json()}catch(e){return}
if(!s.ts)return;document.getElementById('ts').textContent='· '+new Date(s.ts*1000).toLocaleTimeString();
document.getElementById('radios').innerHTML=s.radios.map(r=>{const u=r.util_pct;return `<div class=card><h2>${esc(r.iface)} · ${esc(r.band)} · ch ${esc(r.channel)}</h2>
<div style="font-size:26px" class="${u>70?'hot':''}">${u==null?'n/a':u+'%'} <span class=mut style="font-size:13px">channel busy</span></div>
<div class=bar><i style="width:${u||0}%"></i></div><div class=mut>AP tx ${r.tx_pct??'-'}% · rx ${r.rx_pct??'-'}% · other/interference ${r.other_pct??'-'}%</div></div>`}).join('');
document.getElementById('cls').innerHTML=Object.entries(s.summary.mbps_by_class||{}).map(([k,v])=>`<span class=tag>${esc(k)}: ${v}</span>`).join('')||'<span class=mut>waiting for traffic deltas…</span>';
document.getElementById('t').innerHTML='<tr><th>Client<th>Type<th>Band<th>RSSI<th>AP→STA PHY<th>STA→AP PHY<th>Up<th>Down<th>Retry%<th>Apps (WMM AC)</tr>'+
s.clients.map(c=>`<tr class="${c.active?'':'mut'}"><td>${esc(c.host||c.mac)}<div class=mut style="font-size:12px">${esc((c.ips||[]).join(', ')||c.mac)}</div><td>${esc(c.type||'—')}<td>${esc(c.band)}<td>${esc(c.rssi)}<td>${esc(c.ap_tx_phy_mbps)}<td>${esc(c.sta_tx_phy_mbps)}<td>${c.up_mbps}<td>${c.down_mbps}<td>${esc(c.retry_pct??'-')}
<td>${c.apps.map(a=>`<span class=tag>${esc(a.app)} ${a.mbps} · ${esc(a.wmm)}</span>`).join('')||'<span class=mut>idle</span>'}</tr>`).join('');}
const ic={crit:'🔴',warn:'🟠',info:'🔵',ok:'🟢'};
function insights(s){let h='';s.radios.forEach(r=>(r.insights||[]).forEach(i=>h+=row('RADIO '+r.iface,i)));
s.clients.filter(c=>c.type).forEach(c=>{const b=c.band_advice,t=esc(c.host||c.mac)+' <span class=mut>('+esc(c.type)+', '+esc(c.band)+', '+esc(c.rssi)+' dBm'+(b?'; est. other band '+esc(b.est_rssi_other)+' dBm':'')+')</span>';
h+='<div style="margin:10px 0 4px"><b>'+t+'</b></div>';c.insights.forEach(i=>h+=row('',i))});
(s.not_associated||[]).forEach(k=>h+='<div class=mut>'+esc(k)+' is not associated to this AP right now</div>');
document.getElementById('ins').innerHTML=h||'<span class=mut>Declare clients with --client IP=type to get recommendations.</span>'}
function row(w,i){return '<div style="padding:3px 0 3px 8px;border-left:3px solid var(--line)">'+ic[i.sev]+' '+(w?'<b>'+esc(w)+'</b> ':'')+esc(i.title)+' <span class=mut>— '+esc(i.detail)+'</span>'+(i.action?'<div class=mut style="margin-left:22px">→ '+esc(i.action)+'</div>':'')+'</div>'}
let CAT=null,SIG='';const $=id=>document.getElementById(id);
function fillClients(s){const all=[...s.clients.map(c=>({mac:c.mac,t:(c.host||c.mac)+' · '+(c.ips||[]).join(',')+' · Wi-Fi '+c.band+' '+c.rssi+' dBm'})),
...(s.lan||[]).map(l=>({mac:l.mac,t:(l.host||l.mac)+' · '+l.ips.join(',')+' · wired/other'}))];
const sig=JSON.stringify(all.map(a=>a.mac));if(sig===SIG)return;SIG=sig;const cur=$('pc').value;
$('pc').innerHTML='<option value="">— select client —</option>'+all.map(a=>`<option value="${esc(a.mac)}">${esc(a.t)}</option>`).join('');$('pc').value=cur}
function fillQual(){const k=$('pt').value;if(!CAT||!k)return;const c=CAT[k];$('pq').innerHTML=c.qualities.map(q=>`<option ${q===c.default?'selected':''}>${esc(q)}</option>`).join('')}
const T=(v,l)=>`<div class=tile><b>${v}</b><span>${l}</span></div>`;
async function plan(){const mac=$('pc').value,t=$('pt').value;if(!mac||!t){$('pr').innerHTML='<span class=mut>Select a client and a traffic type.</span>';return}
let r;try{r=await (await fetch(`api/plan?mac=${encodeURIComponent(mac)}&traffic=${t}&quality=${encodeURIComponent($('pq').value)}&n=${$('pn').value||1}`)).json()}catch(e){return}
if(r.error){$('pr').textContent=r.error;return}const q=r.required,l=r.link,c=r.capacity,g=r.targets;
let h=`<div><span class="v ${r.verdict.level}">${r.test?'THROUGHPUT TEST':esc(r.verdict.level.toUpperCase())}</span> <b>${esc(r.traffic)}</b> — ${esc(r.quality)} ×${r.streams}<div class=mut style="margin-top:4px">${esc(r.verdict.text)}</div></div><div class=tiles>`+
(r.test?'':T(q.down_mbps+' / '+q.up_mbps,'Required Mbps ↓ / ↑ (avg)')+T(q.peak_down_mbps+' / '+q.peak_up_mbps,'Peak Mbps ↓ / ↑')+T(q.gb_per_hour_down+' / '+q.gb_per_hour_up,'Data GB/hour ↓ / ↑')+T(q.pps,'Packets per second'));
if(c&&r.test)h+=T((c.radio_util_now_pct??'n/a')+'%','Radio busy now');else if(c)h+=T(c.usable_down_mbps+' / '+c.usable_up_mbps,'Usable Mbps ↓ / ↑ (model)')+T((c.headroom_down_x??'–')+'× / '+(c.headroom_up_x??'–')+'×','Headroom ↓ / ↑')+T(c.airtime_needed_pct+'%','Airtime this needs')+
T((c.radio_util_now_pct??'n/a')+'% → '+c.projected_radio_util_pct+'%','Radio busy now → projected')+T(c.max_streams,'Max simultaneous streams');
if(l&&l.rssi!=null)h+=T(l.rssi+' dBm'+(g.rssi_margin_db!=null?` (${g.rssi_margin_db>=0?'+':''}${g.rssi_margin_db} dB)`:''),'RSSI (margin vs '+g.min_rssi+' dBm needed)')+T((l.ap_tx_phy_mbps??'–')+' / '+(l.sta_tx_phy_mbps??'–'),'PHY Mbps AP→STA / STA→AP')+T((l.retry_pct??'–')+'%','Tx retries')+T(esc(l.band)+' ch '+esc(l.channel??'?'),'Band / channel');
h+='</div><div class=mut style="line-height:1.6"><b>QoS:</b> WMM '+esc(r.qos.wmm_ac)+' · DSCP '+esc(r.qos.dscp)+' · '+esc(r.qos.ports)+'<br><b>Targets:</b> '+esc(g.summary)+'</div>';
(r.insights||[]).forEach(i=>h+=row('',i));(r.notes||[]).forEach(n=>h+='<div class=mut style="margin-top:6px">ℹ '+esc(n)+'</div>');$('pr').innerHTML=h}
let SRV=false;
async function boot(){try{CAT=await (await fetch('api/catalog')).json();SRV=(await (await fetch('api/config')).json()).iperf_server}catch(e){return}
$('pt').innerHTML='<option value="">— select traffic —</option>'+Object.entries(CAT).map(([k,v])=>`<option value="${k}">${esc(v.label)}</option>`).join('');
$('pt').onchange=()=>{fillQual();testUI();plan()};$('pq').addEventListener('change',testUI);['pc','pq','pn'].forEach(i=>$(i).onchange=plan);$('tb').onclick=runTest;setInterval(tstat,1000)}
function testUI(){const k=$('pt').value,c=CAT&&CAT[k];$('tp').style.display=c&&c.test?'block':'none';if(!c||!c.test)return;const m=c.modes[$('pq').value]||'',ip=c.test==='iperf3';
$('tdl').style.display=ip?'':'none';$('tsl').style.display=ip?'':'none';$('trl').style.display=(ip&&m.startsWith('udp'))?'':'none';
$('tn').textContent=ip&&SRV?"Server-PC mode: press Run test, then run the shown iperf3 command on the selected Wi-Fi client. Download = add -R. The result is tied to the client by its IP; link metrics are captured during the run.":ip?"Needs an iperf3 server on the selected client (run: iperf3 -s; phones have iperf3 apps) with port 5201 allowed. Download = host to client, upload = client to host. Link metrics are sampled about every 2 s while the test runs.":"Runs on the machine running this dashboard: it measures that machine's internet speed, not the selected client's."}
async function runTest(){const mac=$('pc').value,k=$('pt').value;if(!mac||!k){$('tres').textContent='Select a client first.';return}
if($('tb').dataset.cancel){await fetch('api/test/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});return}
let r;try{r=await (await fetch('api/test/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac,traffic:k,quality:$('pq').value,secs:+$('td').value,streams:+$('tsn').value,rate:+$('tr').value})})).json()}catch(e){$('tres').textContent='Could not start the test.';return}
if(r.error){$('tres').innerHTML='<div class=hot>✖ '+esc(r.error)+'</div>';return}$('tres').textContent='Starting…';tstat()}
async function tstat(){let s;try{s=await (await fetch('api/test/status')).json()}catch(e){return}if(s.state==='idle')return;const wait=s.state==='waiting',run=s.state==='running';$('tb').disabled=run;$('tb').textContent=run?`Running… ${s.elapsed}s`:wait?'Cancel':'Run test';if(wait)$('tb').dataset.cancel=1;else delete $('tb').dataset.cancel;
if(wait){$('tres').innerHTML='<div class=hot style="color:inherit">⏳ <b>Armed — waiting for '+esc(s.ip)+'</b> ('+s.remaining+'s left). '+(s.claimed?'<b>The client helper picked it up and is running the test…</b> It would otherwise run:':'If the client runs iperf_client.py it starts by itself; otherwise run on that client:')+<pre style="user-select:all;margin:6px 0">'+esc(s.cmd)+'</pre><span class=mut>Link metrics are being sampled ('+s.samples+' so far).'+(s.others&&s.others.length?' Ignored tests from '+esc(s.others.join(', '))+'.':'')+'</span></div>';return}
if(s.state==='cancelled'){$('tres').innerHTML='<span class=mut>Cancelled.</span>';return}
if(run){$('tres').innerHTML='<span class=mut>Test in progress. Sampling link metrics ('+s.samples+' so far)…</span>';return}renderTest(s)}
function renderTest(s){const r=s.result||{};if(!r.ok){$('tres').innerHTML='<div class=hot>✖ '+esc(r.error||'failed')+'</div>';return}const L=r.link||{};let h='<div class=tiles>';
if(r.mode==='speedtest')h+=T(r.down_mbps+' / '+r.up_mbps,'Internet ↓ / ↑ Mbps')+T((r.ping_ms??'–')+' ms','Ping')+T((r.jitter_ms??'–')+' ms','Jitter')+T(esc(r.server||'–'),'Server');
else{h+=T(r.mbps+' Mbps','Measured '+((r.mode||s.mode).endsWith('up')?'upload (client to '+(s.server?'server PC':'host')+')':'download ('+(s.server?'server PC':'host')+' to client)'));
if(r.retransmits!=null)h+=T(r.retransmits,'TCP retransmits');
if(r.jitter_ms!=null)h+=T(r.jitter_ms+' ms','UDP jitter')+T(r.loss_pct+'%','UDP loss');if(r.min_mbps!=null)h+=T(r.min_mbps+' – '+r.max_mbps,'Per-second min – max Mbps')}
if(L.n)h+=T(L.rssi_avg+' dBm','RSSI during test')+T((L.ap_tx_avg??'–')+' / '+(L.sta_tx_avg??'–'),'PHY Mbps AP→STA / STA→AP')+T((L.retry_avg??'–')+'% (max '+(L.retry_max??'–')+')','Tx retries during test')+T((L.util_avg??'–')+'% (max '+(L.util_max??'–')+')','Radio busy during test');
h+='</div>';(r.insights||[]).forEach(i=>h+=row('',i));$('tres').innerHTML=h}
const _t=tick;tick=async function(){await _t();try{const s=await (await fetch('api/state')).json();if(!s.ts)return;insights(s);fillClients(s);plan()}catch(e){}};
boot();tick();setInterval(tick,3000);</script></body></html>"""

def serve(mon, bind, port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path); qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/api/catalog": body, ct = json.dumps(planner.catalog_public()).encode(), "application/json"
            elif u.path == "/api/plan":
                try: body = json.dumps(mon.plan(qs.get("mac", ""), qs.get("traffic", "video"), qs.get("quality"), qs.get("n", 1))).encode()
                except Exception as e: body = json.dumps({"error": str(e)}).encode()
                ct = "application/json"
            elif u.path.startswith(("/mem", "/api/mem")) and memwatch.handle_get(mon.mem, u.path, qs):
                code, ct, body, hdr = memwatch.handle_get(mon.mem, u.path, qs)
                self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
                for k, v in hdr.items(): self.send_header(k, v)
                self.end_headers(); self.wfile.write(body); return
            elif u.path == "/api/config": body, ct = json.dumps(mon.config()).encode(), "application/json"
            elif u.path == "/api/test/pending": body, ct = json.dumps(mon.pending_for(self.client_address[0])).encode(), "application/json"
            elif u.path == "/api/test/status": body, ct = json.dumps(mon.test_status()).encode(), "application/json"
            elif u.path.startswith("/api/state"): body, ct = mon.snapshot().encode(), "application/json"
            elif self.path in ("/", "/index.html"): body, ct = HTML.encode(), "text/html; charset=utf-8"
            else: self.send_error(404); return
            self.send_response(200); self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            u = urlparse(self.path)
            if self.client_address[0] not in ("127.0.0.1", "::1") and not mon.allow_remote_tests: self.send_error(403, "tests can only be started from this machine (see --allow-remote-tests)"); return
            if "application/json" not in (self.headers.get("Content-Type") or ""): self.send_error(415); return   # forces a CORS preflight for cross-site pages
            try: req = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 10000)) or b"{}")
            except Exception: req = {}
            if u.path == "/api/test/start": body = json.dumps(mon.start_test(req)).encode()
            elif u.path == "/api/test/cancel": body = json.dumps(mon.cancel_test()).encode()
            else: self.send_error(404); return
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    ThreadingHTTPServer((bind, port), H).serve_forever()

# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=BACKENDS, default="iw")
    ap.add_argument("--transport", choices=["ssh", "serial", "ubus"], default="ssh",
                    help="how to reach the AP: ssh (default), serial console, or ubus-over-HTTP web API (OpenWrt/prplOS)")
    ap.add_argument("--host", help="AP address for ssh (omit to run locally on the AP)")
    ap.add_argument("--serial-port", help="e.g. /dev/cu.usbserial-0001 (macOS) - for --transport serial")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--serial-user", help="console login name, if the console shows a login prompt")
    ap.add_argument("--http-url", help="e.g. http://192.168.1.1 - for --transport ubus")
    ap.add_argument("--http-user", default="root")
    ap.add_argument("--password", help="serial/web password (or set env WIFI_PASS; prompted if omitted)")
    ap.add_argument("--max-flows", type=int, help="max conntrack lines per poll (default 2000 ssh / 400 ubus / 300 serial; 0 = no app classification)")
    ap.add_argument("--user", default="root"); ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--ifaces", help="comma list of AP interfaces (required for wl/qca; optional filter for iw)")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--log-dir", help="append clients.csv / radios.csv here")
    ap.add_argument("--client", action="append", default=[], metavar="IP=TYPE",
                    help=f"declare a client's type, e.g. 192.168.1.20=tv (repeatable). Also accepts MAC or hostname. Types: {', '.join(PROFILES)}")
    ap.add_argument("--clients-file", help='JSON file {"192.168.1.20": "tv", ...}')
    ap.add_argument("--band-offset", type=float, default=8.0, help="dB RSSI drop assumed going 2.4G->5G (default 8)")
    ap.add_argument("--subnet", help="LAN to scan for --backend local (default: your /24, e.g. 192.168.1.0/24)")
    ap.add_argument("--iperf-from", choices=["host", "ap"], default="host",
                    help="where iperf3 runs for the dashboard's throughput test: this machine (default) or on the AP (AP needs iperf3 installed)")
    ap.add_argument("--iperf-port", type=int, default=5201, help="iperf3 server port on the client (default 5201)")
    ap.add_argument("--iperf-server", metavar="URL", help="server-PC mode: URL of iperf_agent.py on a LAN PC (e.g. http://192.168.1.50:8099). "
                    "Run test then waits for the selected client to run `iperf3 -c <that PC>`")
    ap.add_argument("--iperf-token", help="shared secret, if iperf_agent.py was started with --token")
    ap.add_argument("--iperf-server-ip", help="IP the clients should connect to, if different from what the agent reports")
    ap.add_argument("--allow-remote-tests", action="store_true", help="let other machines on the LAN start tests (default: only this machine)")
    memwatch.add_cli_args(ap, "mem-")
    ap.add_argument("--once", action="store_true", help="two polls, print table, exit (no web server)")
    ap.add_argument("--console", action="store_true", help="print table every interval as well")
    a = ap.parse_args()
    if a.transport != "ssh" and a.backend == "local": ap.error("--backend local doesn't use --transport")
    pw = a.password if a.password is not None else os.environ.get("WIFI_PASS")
    if a.transport == "serial":
        if not a.serial_port: ap.error("--transport serial needs --serial-port")
        if pw is None and a.serial_user:
            import getpass; pw = getpass.getpass("Console password: ")
        runner = SerialRunner(a.serial_port, a.baud, a.serial_user, pw)
    elif a.transport == "ubus":
        if not a.http_url: ap.error("--transport ubus needs --http-url")
        if pw is None:
            import getpass; pw = getpass.getpass(f"Web password for {a.http_user}: ")
        runner = UbusHttpRunner(a.http_url, a.http_user, pw)
    else:
        runner = Runner(a.host, a.user, a.ssh_port)
    args_ = (runner, a.ifaces.split(",") if a.ifaces else None)
    be = LocalBackend(*args_, subnet=a.subnet) if a.backend == "local" else BACKENDS[a.backend](*args_)
    types = json.load(open(a.clients_file)) if a.clients_file else {}
    for kv in a.client:
        k, _, v = kv.partition("=")
        if not norm_type(v): ap.error(f"unknown client type '{v}' in --client {kv}; use one of {', '.join(PROFILES)}")
        types[k] = v
    be.max_flows = a.max_flows if a.max_flows is not None else {"serial": 300, "ubus": 400}.get(a.transport, 2000)
    mon = Monitor(be, a.interval, a.log_dir, types, a.band_offset)
    mon.iperf_from, mon.allow_remote_tests, mon.iperf_port = a.iperf_from, a.allow_remote_tests, a.iperf_port
    mon.iperf_server, mon.iperf_token, mon.iperf_server_ip = a.iperf_server, a.iperf_token, a.iperf_server_ip
    if a.mem_host or a.mem_transport == "local":
        mon.mem = memwatch.collector_from_args(a, "mem-"); threading.Thread(target=mon.mem.loop, daemon=True).start()
        print(f"Memory collector: {a.mem_host} via {a.mem_transport} every {a.mem_interval}s -> {a.mem_dir}/   page: http://{a.bind}:{a.port}/mem")
    if a.once:
        mon.poll(); time.sleep(a.interval); mon.poll(); print_table(mon.state); print_insights(mon.state); return
    mon.poll()
    def bg():
        while True:
            time.sleep(mon.sleep_for())
            try:
                mon.poll()
                if a.console: print_table(mon.state); print_insights(mon.state)
            except Exception as e: sys.stderr.write(f"[error] {e}\n")
    threading.Thread(target=bg, daemon=True).start()
    print(f"Dashboard: http://{a.bind}:{a.port}/   (Ctrl-C to stop)")
    try: serve(mon, a.bind, a.port)
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    main()
