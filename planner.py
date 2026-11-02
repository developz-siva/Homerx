"""
planner.py - "what if this client ran X?" calculator.

Pick a client + a traffic type (+ quality, + number of simultaneous streams). It computes the bitrate the traffic needs
and compares it with what that client's Wi-Fi link can carry right now: PHY rates, retries, free airtime on its radio,
RSSI vs what the traffic needs, plus QoS (WMM/DSCP) and latency/jitter/loss targets.

Bitrates are IP-level nominal values:
  Teams  - Microsoft Learn "Configure media bit rate for Teams" (audio 58 kbps, 1:1 video 1.5 Mbps, best 4 Mbps; meetings 2.5 up/4.0 down)
  Zoom   - Zoom system requirements (1:1 720p 1.2 Mbps, 1080p 3.8 up/3.0 down, group 720p 2.6/1.8, audio 60-80 kbps)
  Netflix- 720p HD >= 3 Mbps, 4K >= 15 Mbps (Netflix help); 480p/1080p/HDR are typical values
  Cloud gaming - NVIDIA GeForce NOW: 720p60 15, 1080p60 25, 1440p120 35, 4K60 40, 4K120 45 Mbps, latency < 80 ms
  Spotify/Apple Music - nominal codec rates (Spotify 24/96/160/320 kbps + lossless; Apple AAC 256 kbps, ALAC 16/44.1 ~1.4 Mbps,
  24/48 ~2.3 Mbps, 24/192 ~9.2 Mbps, Atmos ~768 kbps)
  Voice  - Opus ~32 kbps / G.711 64 kbps codec rate + 40 B IP/UDP/RTP header at 50 pps
  Online games - rule-of-thumb estimates (small packets, 30-128 pps); treat as approximate.
Capacity numbers are a MODEL (airtime = per-frame overhead + payload/PHY rate), not a speed test.
"""
from advisor import advise, PROFILES
from speedtools import MODES

OVERHEAD_US = 200.0      # DIFS + avg backoff + preamble + SIFS + (Block)Ack per transmit opportunity

def q(down, up, **kw): return dict(down=down, up=up, **kw)

CATALOG = {
    "video": dict(label="Video streaming (Netflix / YouTube)", pkt=1400, agg=16, burst=1.5, rt=False, ac="VI", dscp="34 (often unmarked → BE)",
                  min_rssi=-70, targets="Buffered: tolerates ~100s of ms jitter; keep loss < 1% (TCP/QUIC retransmits stall the buffer)",
                  ports="TCP/UDP 443 (QUIC)", default="1080p Full HD (≈5 Mbps)", cls="Video Streaming", ctype="tv",
                  qualities={"480p SD (≈1.5 Mbps)": q(1.5, .05), "720p HD (3 Mbps)": q(3, .05), "1080p Full HD (≈5 Mbps)": q(5, .05),
                             "4K UHD (15 Mbps)": q(15, .1), "4K HDR / Dolby Vision (≈25 Mbps)": q(25, .1)}),
    "spotify": dict(label="Audio - Spotify", pkt=1400, agg=8, burst=2.0, rt=False, ac="BE", dscp="0 (BE)", min_rssi=-75,
                    targets="Buffered: tolerant of jitter; 1-2 Mbps burst when filling the buffer", ports="TCP 443 / 4070", default="Very High (320 kbps)",
                    cls="Web/Cloud", ctype="speaker",
                    qualities={"Low (≈24 kbps)": q(.024, .01), "Normal (≈96 kbps)": q(.096, .01), "High (≈160 kbps)": q(.160, .01),
                               "Very High (320 kbps)": q(.320, .01), "Lossless FLAC (≈1.4 Mbps)": q(1.4, .01)}),
    "apple_music": dict(label="Audio - Apple Music", pkt=1400, agg=8, burst=2.0, rt=False, ac="BE", dscp="0 (BE)", min_rssi=-75,
                        targets="Buffered: tolerant of jitter; lossless/Hi-Res needs steady throughput", ports="TCP 443",
                        default="AAC (256 kbps)", cls="Web/Cloud", ctype="speaker",
                        qualities={"AAC (256 kbps)": q(.256, .01), "Dolby Atmos (≈768 kbps)": q(.768, .01),
                                   "Lossless 16-bit/44.1 kHz (≈1.4 Mbps)": q(1.4, .01), "Lossless 24-bit/48 kHz (≈2.3 Mbps)": q(2.3, .01),
                                   "Hi-Res Lossless 24-bit/192 kHz (≈9.2 Mbps)": q(9.2, .02)}),
    "voice": dict(label="Voice call (VoIP / Wi-Fi calling)", pkt=120, agg=1, burst=1.0, rt=True, ac="VO", dscp="46 (EF)", min_rssi=-75,
                  targets="One-way delay ≤ 150 ms, jitter ≤ 30 ms, loss ≤ 1%", ports="UDP (RTP), SIP/IMS", default="Opus HD voice (≈48 kbps)",
                  cls="Conferencing", ctype="phone", lat_ms=150, jitter_ms=30, loss_pct=1,
                  qualities={"Opus HD voice (≈48 kbps)": q(.048, .048, pkt=120), "G.711 (80 kbps)": q(.080, .080, pkt=200)}),
    "teams": dict(label="Microsoft Teams call", pkt=1100, agg=2, burst=1.3, rt=True, ac="VI (audio VO)", dscp="46 audio / 34 video / 18 sharing (when QoS is configured)",
                  min_rssi=-67, targets="Commonly cited Teams targets: one-way latency < 50 ms (RTT < 100 ms), jitter < 30 ms, loss < 1%",
                  ports="UDP 3478-3481 (TCP 443 fallback)", default="1:1 video, recommended (≈1.6 Mbps)", cls="Conferencing", ctype="laptop",
                  lat_ms=50, jitter_ms=30, loss_pct=1,
                  qualities={"Audio only (58 kbps)": q(.058, .058, pkt=200), "1:1 video, recommended (≈1.6 Mbps)": q(1.558, 1.558),
                             "1:1 video, best (≈4.1 Mbps)": q(4.058, 4.058), "Meeting video (≈2.6 Mbps up / 4.1 down)": q(4.058, 2.558),
                             "1:1 screen share (≈1.6 Mbps)": q(1.558, 1.558)}),
    "zoom": dict(label="Zoom call", pkt=1100, agg=2, burst=1.3, rt=True, ac="VI (audio VO)", dscp="Zoom default differs; recommended 46 audio / 34 video",
                 min_rssi=-67, targets="Rule of thumb: latency < 150 ms, jitter < 40 ms, loss < 2% (Zoom adapts quality below this)",
                 ports="UDP 8801-8810 (TCP 443 / 8801-8802 fallback)", default="1:1 720p HD (1.2 Mbps)", cls="Conferencing", ctype="laptop",
                 lat_ms=150, jitter_ms=40, loss_pct=2,
                 qualities={"Audio only (60-80 kbps)": q(.07, .07, pkt=200), "1:1 720p HD (1.2 Mbps)": q(1.2, 1.2),
                            "1:1 1080p HD (3.8 up / 3.0 down)": q(3.0, 3.8), "Group 720p HD (2.6 up / 1.8 down)": q(1.8, 2.6),
                            "Group 1080p HD (3.8 up / 3.0 down)": q(3.0, 3.8), "Screen share (≈150 kbps)": q(.15, .15)}),
    "game": dict(label="Game", pkt=200, agg=1, burst=1.2, rt=True, ac="VI/VO", dscp="46 or 34 (if you prioritise it); games usually send unmarked",
                 min_rssi=-67, targets="Online play: RTT < 50 ms, jitter < 15 ms, loss < 1%. Cloud gaming: latency < 80 ms to the data centre (NVIDIA)",
                 ports="UDP (game specific)", default="Online multiplayer, typical (≈0.2 Mbps)", cls="Web/Cloud", ctype="console",
                 lat_ms=50, jitter_ms=15, loss_pct=1,
                 qualities={"Online multiplayer, typical (≈0.2 Mbps)": q(.2, .1, pkt=150, est=True),
                            "Fast-paced FPS, high tick-rate (≈0.5 Mbps)": q(.5, .25, pkt=150, est=True),
                            "Cloud gaming 720p60 (15 Mbps)": q(15, .5, pkt=1300, agg=4, lat_ms=80, est_up=True),
                            "Cloud gaming 1080p60 (25 Mbps)": q(25, .5, pkt=1300, agg=4, lat_ms=80, est_up=True),
                            "Cloud gaming 1440p120 (35 Mbps)": q(35, .5, pkt=1300, agg=4, lat_ms=80, est_up=True),
                            "Cloud gaming 4K60 (40 Mbps)": q(40, .5, pkt=1300, agg=4, lat_ms=80, est_up=True)}),
}

CATALOG["iperf3"] = dict(
    label="Throughput test - iperf3 (measured)", test="iperf3", pkt=1400, agg=16, burst=1.0, rt=False, ac="BE", dscp="0 (BE)", min_rssi=-70,
    targets="Measures real throughput between this machine and the client. The client must run an iperf3 server (iperf3 -s).",
    ports="TCP/UDP 5201", default=MODES["tcp_down"], cls="Bulk", ctype="laptop",
    qualities={name: q(0, 0, mode=m) for m, name in MODES.items()})
CATALOG["speedtest"] = dict(
    label="Internet speed test - speedtest (this machine)", test="speedtest", pkt=1400, agg=16, burst=1.0, rt=False, ac="BE", dscp="0 (BE)",
    min_rssi=-70, targets="Measures the internet speed of the machine running this dashboard, not of the selected client.",
    ports="TCP 8080/443", default="Internet speed (download + upload + ping)", cls="Bulk", ctype="laptop",
    qualities={"Internet speed (download + upload + ping)": q(0, 0, mode="speedtest")})

def catalog_public():
    return {k: {"label": v["label"], "default": v["default"], "qualities": list(v["qualities"]), "test": v.get("test"),
                "modes": {n: d.get("mode") for n, d in v["qualities"].items()}} for k, v in CATALOG.items()}

def _pkt_us(rate_mbps, nbytes, agg, retry):
    """time one packet occupies the air incl. amortised overhead and retries (µs)"""
    return (OVERHEAD_US / agg + nbytes * 8 / rate_mbps) / max(0.2, 1 - retry)

def _dir(req_mbps, phy, pkt, agg, retry):
    """-> (airtime fraction used, max sustainable Mbps if this flow had the whole channel)"""
    t = _pkt_us(phy, pkt, agg, retry)
    pps_need = req_mbps * 1e6 / (pkt * 8)
    return pps_need * t / 1e6, (1e6 / t) * pkt * 8 / 1e6

def plan(client, traffic, quality=None, n=1, radios=None, offset=8.0, declared_type=None):
    spec = CATALOG[traffic]
    quality = quality if quality in spec["qualities"] else spec["default"]
    qd = spec["qualities"][quality]
    n = max(1, min(int(n or 1), 20))
    pkt, agg = qd.get("pkt", spec["pkt"]), qd.get("agg", spec["agg"])
    down, up = qd["down"] * n, qd["up"] * n
    out = {
        "traffic": spec["label"], "quality": quality, "streams": n,
        "required": {"down_mbps": round(down, 3), "up_mbps": round(up, 3),
                     "peak_down_mbps": round(down * spec["burst"], 3), "peak_up_mbps": round(up * spec["burst"], 3),
                     "pps": round((down + up) * 1e6 / (pkt * 8)),
                     "gb_per_hour_down": round(down * 0.45, 3), "gb_per_hour_up": round(up * 0.45, 3)},  # Mbps*3600/8/1000
        "qos": {"wmm_ac": spec["ac"], "dscp": spec["dscp"], "ports": spec["ports"], "realtime": spec["rt"]},
        "targets": {"summary": spec["targets"], "min_rssi": spec["min_rssi"],
                    "latency_ms": qd.get("lat_ms", spec.get("lat_ms")), "jitter_ms": spec.get("jitter_ms"), "loss_pct": spec.get("loss_pct")},
        "notes": [], "insights": [], "verdict": {"level": "unknown", "text": ""},
    }
    if qd.get("est") or qd.get("est_up"):
        out["notes"].append("Some figures for this item (game tick-rate traffic / cloud-gaming upstream) are estimates, not published specs.")
    if not client:
        out["verdict"] = {"level": "unknown", "text": "Client not found."}; return out

    rssi, band = client.get("rssi"), client.get("band")
    ap_tx, sta_tx, retry = client.get("ap_tx_phy_mbps"), client.get("sta_tx_phy_mbps"), (client.get("retry_pct") or 0) / 100
    radio = (radios or {}).get(client.get("iface"), {}); util = radio.get("util_pct")
    out["link"] = {"band": band, "rssi": rssi, "ap_tx_phy_mbps": ap_tx, "sta_tx_phy_mbps": sta_tx,
                   "retry_pct": client.get("retry_pct"), "radio_util_pct": util, "channel": client.get("channel")}
    if not ap_tx or not sta_tx or band is None:
        out["verdict"] = {"level": "unknown", "text": "No Wi-Fi link data for this device (wired, or not associated to the AP under test). "
                                                       "Only the required bitrate is shown."}
        return out

    # ---- capacity model -------------------------------------------------------------------------------
    free = max(0.05, 1 - (util or 0) / 100)
    a_dn, cap_dn = _dir(down, ap_tx, pkt, agg, retry)
    a_up, cap_up = _dir(up, sta_tx, pkt, agg, retry)
    usable_dn, usable_up = cap_dn * free, cap_up * free
    ratio_dn = usable_dn / down if down > 0.001 else None
    ratio_up = usable_up / up if up > 0.001 else None
    own_air = (a_dn + a_up) * 100
    projected = (util or 0) + own_air
    ratios = [r for r, req in ((ratio_dn, down), (ratio_up, up)) if r is not None and req >= 0.05] or [r for r in (ratio_dn, ratio_up) if r]
    worst = min(ratios) if ratios else 99
    per_stream = max(qd["down"], qd["up"]) if max(qd["down"], qd["up"]) > 0 else 1
    out["capacity"] = {
        "usable_down_mbps": round(usable_dn, 1), "usable_up_mbps": round(usable_up, 1),
        "headroom_down_x": None if ratio_dn is None else round(min(ratio_dn, 99), 1),
        "headroom_up_x": None if ratio_up is None else round(min(ratio_up, 99), 1),
        "airtime_needed_pct": round(own_air, 1), "radio_util_now_pct": util, "projected_radio_util_pct": round(projected, 1),
        "max_streams": int(min(usable_dn / qd["down"] if qd["down"] > 0.001 else 99, usable_up / qd["up"] if qd["up"] > 0.05 else 99)),
    }
    # ---- verdict --------------------------------------------------------------------------------------
    reasons, level = [], "good"
    def worsen(l, why):
        nonlocal level
        reasons.append(why)
        if {"good": 0, "marginal": 1, "poor": 2}[l] > {"good": 0, "marginal": 1, "poor": 2}[level]: level = l
    if worst < 1.2: worsen("poor", f"link can carry only ~{worst:.1f}× the required rate")
    elif worst < 2.0: worsen("marginal", f"only {worst:.1f}× headroom over the required rate (aim for ≥ 2×)")
    if rssi is not None:
        margin = rssi - spec["min_rssi"]; out["targets"]["rssi_margin_db"] = margin
        if margin < -5: worsen("poor", f"RSSI {rssi} dBm is {-margin} dB below the {spec['min_rssi']} dBm this traffic needs")
        elif margin < 0: worsen("marginal", f"RSSI {rssi} dBm is {-margin} dB below the {spec['min_rssi']} dBm target")
    if projected > 85: worsen("poor", f"radio would be ~{projected:.0f}% busy")
    elif projected > 70: worsen("marginal", f"radio would be ~{projected:.0f}% busy (shared airtime)")
    if spec["rt"] and retry * 100 > 10: worsen("poor" if retry * 100 > 20 else "marginal", f"{retry*100:.0f}% Tx retries hurt latency/jitter of real-time media")
    out["verdict"] = {"level": level, "text": ("Link can carry this comfortably." if not reasons else (lambda t: t[0].upper() + t[1:])("; ".join(reasons)) + ".")}
    if spec.get("test"):          # measured-test entries: show the model's predicted maximum, the real number comes from Run test
        out["test"] = {"tool": spec["test"], "mode": qd.get("mode")}
        out["predicted"] = {"down_mbps": out["capacity"]["usable_down_mbps"], "up_mbps": out["capacity"]["usable_up_mbps"]}
        out["verdict"] = {"level": "unknown", "text": "Predicted maximum from the link model is shown below. Press Run test to measure real throughput."}

    if not client.get("active") and ap_tx < 40:
        out["notes"].append("This client is idle, so its PHY rate may be a low 'resting' value from management frames; "
                            "start some traffic on it and re-check for a realistic figure.")
    out["notes"].append("Capacity is a model (airtime = frame overhead + payload/PHY rate, scaled by free airtime and retries), not a speed test.")

    # ---- reuse the band/link advisor with this traffic as the workload --------------------------------
    ctype = declared_type or spec["ctype"]
    if ctype in PROFILES:
        mix = {spec["cls"]: 1.0}
        c2 = dict(client, up_mbps=up, down_mbps=down)
        ins, adv = advise(c2, ctype, [rssi] if rssi is not None else [], mix, radios or {}, offset)
        out["insights"] = [i for i in ins if not i["title"].startswith("Observed traffic")]
        out["band_advice"] = adv
        out["assumed_type"] = ctype
    return out
