"""capture.py - analyse an 802.11 monitor-mode capture (pcap / pcapng, radiotap or raw 802.11). Standard library only.

What a sniffer can see even when the payload is encrypted: the QoS Control field of every data frame (user priority -> WMM access category),
retry bits, the PHY rate in the radiotap header, the EDCA / WMM parameters and the Wi-Fi 7 Multi-Link element in beacons and (re)association
frames. It cannot see DSCP or the app (that is inside the encrypted payload).

    python capture.py file.pcapng            # prints the findings as JSON
"""
import json, struct, sys, time

AC_OF_UP = {0: "BE", 1: "BK", 2: "BK", 3: "BE", 4: "VI", 5: "VI", 6: "VO", 7: "VO"}
ACS = ("VO", "VI", "BE", "BK")
MOD = [(1, 1 / 2), (2, 1 / 2), (2, 3 / 4), (4, 1 / 2), (4, 3 / 4), (6, 2 / 3), (6, 3 / 4), (6, 5 / 6), (8, 3 / 4), (8, 5 / 6), (10, 3 / 4), (10, 5 / 6), (12, 3 / 4), (12, 5 / 6)]
NSD_VHT = {20: 52, 40: 108, 80: 234, 160: 468}
NSD_HE = {20: 234, 40: 468, 80: 980, 160: 1960}
SUBTYPES = {0: "assoc req", 1: "assoc resp", 2: "reassoc req", 3: "reassoc resp", 4: "probe req", 5: "probe resp", 8: "beacon", 10: "disassoc", 11: "auth", 12: "deauth", 13: "action"}
PPDU_OVERHEAD_US = 36.0          # rough preamble + SIFS/ack allowance per frame, only used for the airtime *estimate*

def band_of(freq):
    if not freq: return None
    return "2.4G" if freq < 3000 else "6G" if freq >= 5925 else "5G"

def chan_of(freq):
    if not freq: return None
    if freq == 2484: return 14
    if freq < 3000: return (freq - 2407) // 5
    if freq >= 5925: return (freq - 5950) // 5
    return (freq - 5000) // 5

# ----------------------------------------------------------------------------------------------- file readers
def _pcap_packets(f, head):
    magic = head[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): en, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"): en, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else: raise ValueError("not a pcap file")
    rest = head + f.read(24 - len(head))
    lt = struct.unpack(en + "I", rest[20:24])[0] & 0x0FFFFFFF
    while True:
        h = f.read(16)
        if len(h) < 16: return
        sec, frac, incl, orig = struct.unpack(en + "IIII", h)
        data = f.read(incl)
        if len(data) < incl: return
        yield sec + frac / (1e9 if nano else 1e6), lt, data, orig

def _pcapng_packets(f, head):
    f.seek(0); ifs = []; en = "<"
    while True:
        h = f.read(8)
        if len(h) < 8: return
        if h[:4] == b"\x0a\x0d\x0d\x0a":
            bom = f.read(4); en = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(en + "I", h[4:])[0]; f.read(max(0, blen - 12)); ifs = []; continue
        btype = struct.unpack(en + "I", h[:4])[0]
        blen = struct.unpack(en + "I", h[4:])[0]; body = f.read(max(0, blen - 8))
        if len(body) < blen - 8: return
        if btype == 1:                                               # interface description
            lt = struct.unpack(en + "H", body[:2])[0]; res = 6                    # default if_tsresol = 10^-6
            i = 8
            while i + 4 <= len(body):
                code, ln = struct.unpack(en + "HH", body[i:i + 4])
                if code == 0: break
                if code == 9 and ln >= 1:
                    v = body[i + 4]; res = ("b", v & 0x7F) if v & 0x80 else v
                i += 4 + ((ln + 3) & ~3)
            ifs.append((lt, res))
        elif btype == 6 and len(body) >= 20:                         # enhanced packet
            iid, th, tl, incl, orig = struct.unpack(en + "IIIII", body[:20]); lt, res = ifs[iid] if iid < len(ifs) else (127, 6)
            ts = ((th << 32) | tl) / ((2 ** res[1]) if isinstance(res, tuple) else 10 ** res)
            yield ts, lt, body[20:20 + incl], orig
        elif btype == 3 and ifs and len(body) >= 4:                  # simple packet
            orig = struct.unpack(en + "I", body[:4])[0]; yield 0.0, ifs[0][0], body[4:4 + orig], orig

def iter_packets(path):
    with open(path, "rb") as f:
        head = f.read(4)
        if head == b"\x0a\x0d\x0d\x0a": yield from _pcapng_packets(f, head)
        else: yield from _pcap_packets(f, head)

# ----------------------------------------------------------------------------------------------- radiotap
_RT = [(8, 8), (1, 1), (1, 1), (2, 4), (2, 2), (1, 1), (1, 1), (2, 2), (2, 2), (2, 2), (1, 1), (1, 1), (1, 1), (1, 1), (2, 2), (2, 2), (1, 1), (1, 1),
       (4, 8), (1, 3), (4, 8), (2, 12), (8, 12), (2, 12), (2, 12), (2, 6), (2, 1), (2, 4)]       # (alignment, size) of radiotap fields 0..27

def parse_radiotap(b):
    """-> (header_len, info) ; info: freq, rssi, rate_mbps (legacy), phy ('HT'|'VHT'|'HE'|None), mcs, nss, bw, gi, a_mpdu"""
    if len(b) < 8 or b[0] != 0: return None
    ln = struct.unpack("<H", b[2:4])[0]; present = struct.unpack("<I", b[4:8])[0]; off = 8; p = present
    while p & 0x80000000 and off + 4 <= ln: p = struct.unpack("<I", b[off:off + 4])[0]; off += 4
    info = {}
    for bit in range(28):
        if not present & (1 << bit): continue
        al, sz = _RT[bit]; off = (off + al - 1) & ~(al - 1)
        if off + sz > ln: break
        v = b[off:off + sz]
        if bit == 1: info["flags"] = v[0]
        elif bit == 2: info["rate_mbps"] = v[0] * 0.5
        elif bit == 3: info["freq"] = struct.unpack("<H", v[:2])[0]
        elif bit == 5: info["rssi"] = struct.unpack("<b", v)[0]
        elif bit == 19:
            kn, fl, mcs = v[0], v[1], v[2]; info.update(phy="HT", mcs=mcs, nss=mcs // 8 + 1, bw=40 if fl & 3 == 1 else 20, gi=0.4 if fl & 4 else 0.8)
        elif bit == 21:
            kn = struct.unpack("<H", v[:2])[0]; fl = v[2]; bwc = v[3]; mn = v[4]
            info.update(phy="VHT", mcs=mn >> 4, nss=mn & 0xF, bw={0: 20, 1: 40, 4: 80, 11: 160}.get(bwc, 80 if bwc in (2, 3, 5, 6, 7, 8, 9, 10) else 20), gi=0.4 if fl & 4 else 0.8)
        elif bit == 23:
            d = struct.unpack("<6H", v); info.update(phy="HE", mcs=(d[2] >> 8) & 0xF, nss=d[5] & 0xF, bw={0: 20, 1: 40, 2: 80, 3: 160}.get(d[4] & 0xF, 20), gi={0: 0.8, 1: 1.6, 2: 3.2}.get((d[4] >> 4) & 3, 0.8))
        off += sz
    return ln, info

def rate_mbps(info):
    """PHY rate of the frame in Mbps (None if unknown)."""
    phy = info.get("phy")
    if phy is None: return info.get("rate_mbps")
    try:
        mcs, nss, bw, gi = info["mcs"], max(1, info["nss"]), info["bw"], info["gi"]
        if phy == "HT": nsd, mi, ts = {20: 52, 40: 108}[bw], MOD[mcs % 8], 3.6 if gi == 0.4 else 4.0
        elif phy == "VHT": nsd, mi, ts = NSD_VHT[bw], MOD[mcs], 3.6 if gi == 0.4 else 4.0
        else: nsd, mi, ts = NSD_HE[bw], MOD[mcs], 12.8 + gi
        return mi[0] * mi[1] * nsd * nss / ts
    except (KeyError, IndexError): return None

def phy_label(info):
    phy = info.get("phy")
    if not phy: return ("legacy %g Mbps" % info["rate_mbps"]) if info.get("rate_mbps") else "unknown"
    return f"{phy} MCS{info.get('mcs')} {info.get('nss')}ss {info.get('bw')}MHz"

# ----------------------------------------------------------------------------------------------- information elements
def _elements(b):
    i = 0
    while i + 2 <= len(b):
        t, ln = b[i], b[i + 1]
        if i + 2 + ln > len(b): return
        yield t, b[i + 2:i + 2 + ln]; i += 2 + ln

def _mac(b): return ":".join("%02x" % x for x in b)

def _edca(b, start):                          # 4 x (aci/aifsn, ecw, txop16) starting at `start`
    out = {}
    for k in range(4):
        r = b[start + 4 * k:start + 4 * k + 4]
        if len(r) < 4: break
        ac = ("BE", "BK", "VI", "VO")[(r[0] >> 5) & 3]
        out[ac] = {"aifsn": r[0] & 0xF, "cwmin": (1 << (r[1] & 0xF)) - 1, "cwmax": (1 << (r[1] >> 4)) - 1, "txop_us": struct.unpack("<H", r[2:4])[0] * 32, "acm": bool(r[0] & 0x10)}
    return out

def _multilink(d):
    """Basic Multi-Link element body (after the element-ID-extension byte)."""
    if len(d) < 3: return None
    ctl = struct.unpack("<H", d[:2])[0]; typ = ctl & 7; pres = ctl >> 4
    if typ != 0: return {"type": typ}
    cl = d[2]; ci = d[3:3 + cl]
    if len(ci) < 6: return None
    out = {"mld_mac": _mac(ci[:6]), "links": 1}; o = 6
    if pres & 1 and o < len(ci): out["link_id"] = ci[o] & 0xF; o += 1
    if pres & 2: o += 1
    if pres & 4: o += 2
    if pres & 8 and o + 2 <= len(ci):
        e = struct.unpack("<H", ci[o:o + 2])[0]; o += 2
        out["emlsr"] = bool(e & 1); out["emlmr"] = bool(e & 0x80)
    if pres & 16 and o + 2 <= len(ci):
        m = struct.unpack("<H", ci[o:o + 2])[0]; o += 2
        out["max_links"] = (m & 0xF) + 1; out["str_srs"] = bool(m & 0x10); out["ttlm"] = {0: "none", 1: "same", 3: "any"}.get((m >> 5) & 3, "none"); out["freq_sep"] = (m >> 7) & 0x1F
    rest = d[3 + cl:]; ids = []
    for t, sd in _elements(rest):                      # subelements share the element framing (id, length)
        if t == 0 and len(sd) >= 2: ids.append(struct.unpack("<H", sd[:2])[0] & 0xF)
    if ids: out["links"] = 1 + len(ids); out["other_link_ids"] = ids
    return out

def parse_ies(b):
    r = {}
    for t, d in _elements(b):
        if t == 0: r["ssid"] = d.decode("utf-8", "replace")
        elif t == 3 and d: r["channel"] = d[0]
        elif t == 45: r["ht"] = True
        elif t == 191: r["vht"] = True
        elif t == 12 and len(d) >= 18: r["edca"] = _edca(d, 2)
        elif t == 221 and d[:4] == b"\x00\x50\xf2\x02" and len(d) >= 24 and d[4] == 1 and "edca" not in r: r["edca"] = _edca(d, 8); r["wmm"] = True
        elif t == 221 and d[:4] == b"\x00\x50\xf2\x02": r["wmm"] = True
        elif t == 255 and d:
            x = d[0]
            if x == 35: r["he"] = True
            elif x == 108: r["eht"] = True
            elif x == 107: r["mlo"] = _multilink(d[1:])
    return r

# ----------------------------------------------------------------------------------------------- analyser
class Client:
    def __init__(self, mac):
        self.mac = mac; self.bssid = None
        self.dn = {a: [0, 0, 0] for a in ACS}; self.up = {a: [0, 0, 0] for a in ACS}      # frames, bytes, retries per access category
        self.air = 0.0; self.rssi = []; self.rates = {}; self.nulls = 0; self.mgmt = {}; self.assoc = None; self.reassoc = 0; self.t0 = None; self.t1 = None

class Analyzer:
    def __init__(self):
        self.n = 0; self.bad = 0; self.t0 = None; self.t1 = None; self.freqs = {}; self.cl = {}; self.aps = {}; self.mg = {}; self.reasons = {}
        self.types = {"data": 0, "mgmt": 0, "ctrl": 0}; self.retry = [0, 0]; self.linktypes = set()

    def _c(self, mac):
        c = self.cl.get(mac)
        if c is None: c = self.cl[mac] = Client(mac)
        return c

    def feed(self, ts, lt, data):
        self.n += 1; self.linktypes.add(lt)
        if self.t0 is None: self.t0 = ts
        self.t1 = ts
        info = {}
        if lt == 127:
            r = parse_radiotap(data)
            if not r: self.bad += 1; return
            ln, info = r; data = data[ln:]
        elif lt != 105: self.bad += 1; return
        if info.get("flags", 0) & 0x10 and len(data) >= 4: data = data[:-4]                     # FCS present: drop it
        if len(data) < 10: self.bad += 1; return
        fc0, fc1 = data[0], data[1]; typ, sub = (fc0 >> 2) & 3, (fc0 >> 4) & 15
        if info.get("freq"): self.freqs[info["freq"]] = self.freqs.get(info["freq"], 0) + 1
        retry = bool(fc1 & 8)
        if typ == 0: self.types["mgmt"] += 1; self._mgmt(data, sub, info, ts, retry)
        elif typ == 1: self.types["ctrl"] += 1
        elif typ == 2: self.types["data"] += 1; self._data(data, sub, fc1, info, ts, retry)
        else: self.bad += 1

    def _data(self, d, sub, fc1, info, ts, retry):
        tods, fromds = fc1 & 1, (fc1 >> 1) & 1
        if len(d) < 24 or tods == fromds: return                         # IBSS / WDS: not analysed
        qos = bool(sub & 8); null = bool(sub & 4)
        if tods: sta, bssid, dirn = d[10:16], d[4:10], "up"
        else: sta, bssid, dirn = d[4:10], d[10:16], "dn"
        if sta[0] & 1: return                                              # multicast / broadcast
        ac = "BE"
        if qos:
            hl = 24 + (6 if tods and fromds else 0)
            if len(d) >= hl + 2: ac = AC_OF_UP[d[hl] & 7]
        mac = _mac(sta); c = self._c(mac); c.bssid = _mac(bssid)
        if c.t0 is None: c.t0 = ts
        c.t1 = ts
        row = (c.up if dirn == "up" else c.dn)[ac]
        row[0] += 1; row[1] += len(d); row[2] += retry
        self.retry[0] += 1; self.retry[1] += retry
        if null: c.nulls += 1
        if info.get("rssi") is not None and dirn == "up" and len(c.rssi) < 5000: c.rssi.append(info["rssi"])
        rate = rate_mbps(info)
        if rate and not null:
            c.air += (len(d) * 8 / rate) + PPDU_OVERHEAD_US
            k = phy_label(info); c.rates[k] = c.rates.get(k, 0) + 1

    def _mgmt(self, d, sub, info, ts, retry):
        name = SUBTYPES.get(sub, f"mgmt-{sub}"); self.mg[name] = self.mg.get(name, 0) + 1
        if len(d) < 24: return
        a1, a2, a3 = d[4:10], d[10:16], d[16:22]; body = d[24:]
        if sub in (8, 5):                                                  # beacon / probe response
            if len(body) < 12: return
            ie = parse_ies(body[12:]); bssid = _mac(a3)
            ap = self.aps.setdefault(bssid, {"bssid": bssid, "ssid": None, "beacons": 0, "freq": None, "ie": {}})
            ap["beacons"] += sub == 8; ap["freq"] = info.get("freq") or ap["freq"]
            if ie.get("ssid"): ap["ssid"] = ie["ssid"]
            for k, v in ie.items():
                if k != "ssid" and (k not in ap["ie"] or sub == 8): ap["ie"][k] = v
        elif sub in (0, 2):                                                # (re)association request: the client's own capabilities
            if len(body) < 4: return
            off = 4 if sub == 0 else 10; ie = parse_ies(body[off:]); c = self._c(_mac(a2)); c.bssid = _mac(a1)
            c.assoc = ie; c.reassoc += sub == 2
        elif sub in (10, 12):
            if len(body) >= 2:
                rc = struct.unpack("<H", body[:2])[0]; self.reasons[rc] = self.reasons.get(rc, 0) + 1
            cm = _mac(a1) if _mac(a1) != _mac(a3) else _mac(a2)
            if cm[:2] != "ff" and not int(cm[:2], 16) & 1: c = self._c(cm); c.mgmt[name] = c.mgmt.get(name, 0) + 1
        elif sub in (1, 3) and len(body) >= 6:                             # association response: the AP's ML element for this client
            ie = parse_ies(body[6:]); c = self._c(_mac(a1)); c.assoc_resp = ie

# ----------------------------------------------------------------------------------------------- results
def _pct(a, b): return round(100.0 * a / b, 1) if b else 0.0

def _gen(ie):
    g = [n for k, n in (("ht", "Wi-Fi 4"), ("vht", "Wi-Fi 5"), ("he", "Wi-Fi 6/6E"), ("eht", "Wi-Fi 7")) if ie.get(k)]
    return g[-1] if g else "legacy"

def summarise(a, name=""):
    dur = max(0.001, (a.t1 or 0) - (a.t0 or 0))
    aps = []
    for ap in sorted(a.aps.values(), key=lambda x: -x["beacons"]):
        ie = ap["ie"]; f = ap["freq"]
        aps.append({"bssid": ap["bssid"], "ssid": ap["ssid"], "beacons": ap["beacons"], "freq": f, "band": band_of(f), "channel": ie.get("channel") or chan_of(f),
                    "generation": _gen(ie), "wmm": bool(ie.get("wmm") or ie.get("edca")), "edca": ie.get("edca"), "mlo": ie.get("mlo")})
    clients = []
    for mac, c in a.cl.items():
        fd = sum(v[0] for v in c.dn.values()); fu = sum(v[0] for v in c.up.values())
        if fd + fu == 0 and not c.assoc: continue
        bd = sum(v[1] for v in c.dn.values()); bu = sum(v[1] for v in c.up.values()); rd = sum(v[2] for v in c.dn.values()); ru = sum(v[2] for v in c.up.values())
        tot = fd + fu
        ac = {k: {"frames": c.dn[k][0] + c.up[k][0], "bytes": c.dn[k][1] + c.up[k][1], "share_pct": _pct(c.dn[k][0] + c.up[k][0], tot), "retry_pct": _pct(c.dn[k][2] + c.up[k][2], c.dn[k][0] + c.up[k][0])} for k in ACS}
        top = sorted(c.rates.items(), key=lambda x: -x[1])[:3]
        clients.append({"mac": mac, "bssid": c.bssid, "frames_dn": fd, "frames_up": fu, "mbps_dn": round(bd * 8 / 1e6 / dur, 3), "mbps_up": round(bu * 8 / 1e6 / dur, 3),
                        "retry_dn_pct": _pct(rd, fd), "retry_up_pct": _pct(ru, fu), "retry_pct": _pct(rd + ru, tot), "rssi_avg": round(sum(c.rssi) / len(c.rssi)) if c.rssi else None,
                        "airtime_est_pct": round(100.0 * c.air / 1e6 / dur, 1), "ac": ac, "phy": [{"rate": k, "frames": v} for k, v in top], "mlo": (c.assoc or {}).get("mlo"),
                        "generation": _gen(c.assoc or {}) if c.assoc else None, "reassoc": c.reassoc, "mgmt": c.mgmt or None})
    clients.sort(key=lambda x: -(x["mbps_dn"] + x["mbps_up"]))
    res = {"file": name, "frames": a.n, "unreadable": a.bad, "duration_s": round(dur, 1), "start": a.t0, "freqs": dict(sorted(a.freqs.items(), key=lambda x: -x[1])),
           "totals": {**a.types, "data_retry_pct": _pct(a.retry[1], a.retry[0])}, "mgmt": a.mg, "deauth_reasons": a.reasons, "aps": aps, "clients": clients}
    res["insights"] = insights(res)
    return res

REF = {"VO": (2, 3, 7, 1504), "VI": (2, 7, 15, 3008), "BE": (3, 15, 1023, 0), "BK": (7, 15, 1023, 0)}

def _ins(sev, title, detail="", action=""): return {"sev": sev, "title": title, "detail": detail, "action": action}

def insights(r):
    out = []
    if not r["frames"]: return [_ins("warn", "The capture contains no frames.")]
    if r["totals"]["data"] + r["totals"]["mgmt"] == 0 or (not r["freqs"] and not r["clients"]):
        out.append(_ins("warn", "No readable 802.11 frames.", "Capture in monitor mode (radiotap or raw 802.11), not a normal Wi-Fi or Ethernet capture."))
    if len(r["freqs"]) > 1: out.append(_ins("info", f"The capture spans {len(r['freqs'])} channels ({', '.join(str(chan_of(f)) + ' (' + str(band_of(f)) + ')' for f in list(r['freqs'])[:4])}).",
                                           "A single sniffer only hears one channel at a time. For Wi-Fi 7 MLO use one capture radio per link (2.4 / 5 / 6 GHz) and compare them."))
    for ap in r["aps"]:
        who = f"AP {ap['ssid'] or '(hidden)'} {ap['bssid']}"
        if not ap["wmm"]: out.append(_ins("warn", f"{who}: no WMM / EDCA parameters advertised.", "Without WMM there is no voice / video priority over the air.", "Enable WMM on the AP."))
        elif ap["edca"]:
            e = ap["edca"]
            if "VO" in e and "BE" in e and (e["VO"]["aifsn"], e["VO"]["cwmin"]) >= (e["BE"]["aifsn"], e["BE"]["cwmin"]):
                out.append(_ins("warn", f"{who}: voice (VO) has no contention advantage over best-effort.", f"VO AIFSN {e['VO']['aifsn']} CWmin {e['VO']['cwmin']} vs BE AIFSN {e['BE']['aifsn']} CWmin {e['BE']['cwmin']}.", "Check the AP's EDCA configuration."))
            else:
                diffs = [f"{k} AIFSN {e[k]['aifsn']}/CW {e[k]['cwmin']}-{e[k]['cwmax']}" for k in ACS if k in e and (e[k]["aifsn"], e[k]["cwmin"], e[k]["cwmax"]) != REF[k][:3]]
                out.append(_ins("ok" if not diffs else "info", f"{who}: WMM advertised" + (" with default EDCA values." if not diffs else f"; non-default EDCA: {'; '.join(diffs)}."), "", ""))
        m = ap.get("mlo")
        if ap["generation"] == "Wi-Fi 7" and not m: out.append(_ins("info", f"{who} is Wi-Fi 7 but advertises no Multi-Link element on this link.", "MLO may be off, or the element is on another link's beacons."))
        elif m: out.append(_ins("ok", f"{who}: MLO advertised (MLD {m.get('mld_mac')}, link id {m.get('link_id', '?')}" + (f", {m['links']} links" if m.get("links", 1) > 1 else "") + ").", "TID-to-link mapping: " + str(m.get("ttlm", "n/a")) + "."))
    for c in r["clients"][:40]:
        who = f"Client {c['mac']}"; fr = c["frames_dn"] + c["frames_up"]
        if fr >= 300:
            be = c["ac"]["BE"]["share_pct"]; rt = c["ac"]["VO"]["share_pct"] + c["ac"]["VI"]["share_pct"]; bk = c["ac"]["BK"]["share_pct"]
            if be >= 97: out.append(_ins("info", f"{who}: {be}% of {fr} frames are best-effort (no VO / VI).", "If this client runs calls, video or games they are not getting WMM priority.", "Check DSCP marking and the AP's DSCP-to-WMM mapping."))
            elif rt >= 5: out.append(_ins("ok", f"{who}: {round(rt, 1)}% of frames use VO / VI priority queues."))
            if bk >= 20: out.append(_ins("info", f"{who}: {bk}% of frames are in the background (BK) queue.", "Background traffic is the lowest priority and may be slow by design."))
            vo = c["ac"]["VO"]
            if vo["frames"] >= 100 and vo["retry_pct"] >= 15: out.append(_ins("warn", f"{who}: voice (VO) frames retried {vo['retry_pct']}% of the time.", "Voice is very sensitive to retries.", "Improve signal or reduce interference."))
        if c["retry_pct"] >= 35 and fr >= 200: out.append(_ins("crit", f"{who}: {c['retry_pct']}% of frames are retries.", "Poor link or interference.", "Check signal, channel and neighbours."))
        elif c["retry_pct"] >= 20 and fr >= 200: out.append(_ins("warn", f"{who}: {c['retry_pct']}% of frames are retries."))
        if c["rssi_avg"] is not None and c["rssi_avg"] < -75 and c["frames_up"] >= 50: out.append(_ins("warn", f"{who}: weak uplink signal at the sniffer ({c['rssi_avg']} dBm).", "This is measured at the sniffer, not at the AP, so it also depends on where the sniffer sits."))
        if c["airtime_est_pct"] >= 40: out.append(_ins("warn", f"{who} uses about {c['airtime_est_pct']}% of the airtime (estimated from frame size and PHY rate).", "A heavy or slow client takes airtime from everyone else."))
        if c["phy"] and c["phy"][0]["rate"].startswith("legacy") and c["frames_dn"] + c["frames_up"] >= 200: out.append(_ins("warn", f"{who} mostly sends at {c['phy'][0]['rate']}.", "Legacy rates are slow and cost a lot of airtime."))
        m = c["mlo"]
        if m and m.get("mld_mac"):
            out.append(_ins("ok", f"{who}: Wi-Fi 7 MLO client (MLD {m['mld_mac']})" + (f", EMLSR" if m.get("emlsr") else "") + (", EMLMR" if m.get("emlmr") else "") + (f", up to {m['max_links']} links" if m.get("max_links") else "") + "."))
        elif c["generation"] == "Wi-Fi 7" and any(a.get("mlo") for a in r["aps"]): out.append(_ins("info", f"{who} is Wi-Fi 7 but did not request Multi-Link in its association.", "It is using a single link."))
        if c["reassoc"] >= 3 or ((c["mgmt"] or {}).get("deauth", 0) + (c["mgmt"] or {}).get("disassoc", 0)) >= 3: out.append(_ins("warn", f"{who}: roamed or dropped repeatedly ({c['reassoc']} reassociations).", "", "Look at 802.11k/v/r settings and band steering."))
    if r["mgmt"].get("deauth", 0) + r["mgmt"].get("disassoc", 0) >= 10: out.append(_ins("warn", f"{r['mgmt'].get('deauth', 0)} deauth and {r['mgmt'].get('disassoc', 0)} disassoc frames.", "Reasons seen: " + ", ".join(f"{k} x{v}" for k, v in list(r["deauth_reasons"].items())[:4])))
    if not out: out.append(_ins("info", "Nothing notable found in this capture."))
    order = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
    out.sort(key=lambda i: order.get(i["sev"], 4)); return out[:80]

def analyse_file(path, name="", progress=None, max_frames=5_000_000):
    a = Analyzer(); last = 0.0
    for ts, lt, data, orig in iter_packets(path):
        a.feed(ts, lt, data)
        if a.n >= max_frames: break
        if progress and a.n % 20000 == 0 and time.time() - last > 0.3: progress(a.n); last = time.time()
    r = summarise(a, name)
    if a.n >= max_frames: r["insights"].insert(0, _ins("info", f"Only the first {max_frames:,} frames were analysed."))
    return r

if __name__ == "__main__":
    print(json.dumps(analyse_file(sys.argv[1], sys.argv[1]), indent=1))
