"""
advisor.py - turns per-client measurements + the declared client type into insights and recommendations.

Important limitation: an AP only measures RSSI on the band the client is *associated* to. The other band's RSSI is
ESTIMATED as  rssi_other = rssi_now -/+ band_offset  (default 8 dB: 5 GHz loses roughly 6-10 dB vs 2.4 GHz at the same
spot because of free-space loss plus wall attenuation). Every band recommendation is labelled with that estimate.
To replace the estimate with a measurement, use 802.11k beacon reports (hostapd_cli req_beacon) - see README.
"""
from statistics import median

# min_rssi: lowest RSSI (dBm) you want sustained for the target use. need_mbps: typical throughput the device wants.
PROFILES = {
    "laptop":  dict(pref="5G",   min_rssi={"5G": -70, "2.4G": -72}, need_mbps=15, expect={"Web/Cloud", "Conferencing", "Video Streaming", "Bulk", "Infra"}),
    "phone":   dict(pref="5G",   min_rssi={"5G": -72, "2.4G": -75}, need_mbps=10, expect={"Web/Cloud", "Conferencing", "Video Streaming", "Bulk", "Infra"}),
    "tablet":  dict(pref="5G",   min_rssi={"5G": -70, "2.4G": -73}, need_mbps=10, expect={"Web/Cloud", "Conferencing", "Video Streaming", "Infra"}),
    "tv":      dict(pref="5G",   min_rssi={"5G": -67, "2.4G": -70}, need_mbps=25, expect={"Video Streaming", "Web/Cloud", "Infra"}),
    "console": dict(pref="5G",   min_rssi={"5G": -67, "2.4G": -70}, need_mbps=20, expect={"Video Streaming", "Bulk", "Web/Cloud", "Infra"}),
    "camera":  dict(pref="2.4G", min_rssi={"5G": -70, "2.4G": -75}, need_mbps=3,  expect={"IoT", "Video Streaming", "Bulk", "Web/Cloud", "Infra"}),
    "speaker": dict(pref="2.4G", min_rssi={"5G": -70, "2.4G": -75}, need_mbps=2,  expect={"Video Streaming", "Web/Cloud", "IoT", "Infra"}),
    "iot":     dict(pref="2.4G", min_rssi={"5G": -72, "2.4G": -78}, need_mbps=0.2, expect={"IoT", "Infra"}),
}
ALIASES = {"pc": "laptop", "computer": "laptop", "macbook": "laptop", "smartphone": "phone", "ipad": "tablet",
           "streamer": "tv", "roku": "tv", "firetv": "tv", "xbox": "console", "playstation": "console", "ps5": "console",
           "ipcam": "camera", "cam": "camera", "sensor": "iot", "bulb": "iot", "plug": "iot", "thermostat": "iot",
           "hub": "iot", "bridge": "iot", "echo": "speaker", "sonos": "speaker"}
SEV = {"crit": 3, "warn": 2, "info": 1, "ok": 0}
BAND_MARGIN = 3  # dB of headroom required before recommending a band change (avoids ping-pong)

def norm_type(t):
    t = (t or "").strip().lower()
    t = ALIASES.get(t, t)
    return t if t in PROFILES else None

def resolve_type(cfg, mac, host, ips):
    """cfg maps IP / MAC / hostname -> type. Returns normalised type or None."""
    for key in [mac, host, *ips]:
        if key and key.lower() in cfg: return norm_type(cfg[key.lower()])
    return None

def _i(sev, title, detail, action=""):
    return {"sev": sev, "title": title, "detail": detail, "action": action}

def advise(c, ctype, rssi_hist, mix, radios, offset=8.0):
    """c: client dict. mix: {class: share 0-1} over recent polls. radios: {iface: radio dict}. -> (insights, band_advice)"""
    p = PROFILES[ctype]; out = []
    band, rssi = c.get("band"), (median(rssi_hist) if rssi_hist else c.get("rssi"))
    if rssi is None or band not in ("2.4G", "5G", "6G"):
        return [_i("info", "No RSSI / band data", "The AP did not report signal for this client.")], None
    on24 = band == "2.4G"
    other = "5G" if on24 else "2.4G"
    est_other = rssi + (-offset if on24 else offset)           # estimated RSSI on the other band
    min_here, min_other = p["min_rssi"][("2.4G" if on24 else "5G")], p["min_rssi"][other]
    radio = radios.get(c["iface"], {}); util = radio.get("util_pct")
    other_radio = next((r for r in radios.values() if r.get("band") == other), None)
    other_util = other_radio.get("util_pct") if other_radio else None
    down_up = max(c.get("up_mbps") or 0, c.get("down_mbps") or 0)
    advice = {"stay": True, "target_band": band, "est_rssi_other": round(est_other, 1)}
    est_note = f"(est. {other} RSSI ≈ {est_other:.0f} dBm, derived from {rssi:.0f} dBm {band} with a {offset:.0f} dB band offset)"

    # ---- A. band fit --------------------------------------------------------------------------------------
    def move(to, sev, title, why, how):
        advice.update(stay=False, target_band=to); out.append(_i(sev, title, f"{why} {est_note}", how))
    steer = "Enable band steering / 802.11v BSS-transition on the AP, or give this client a band-specific SSID."
    if p["pref"] == "5G":
        if on24:
            if est_other >= min_other + BAND_MARGIN and not (other_util is not None and other_util > 75):
                move("5G", "warn", "Should be on 5 GHz",
                     f"A {ctype} is on 2.4 GHz but 5 GHz should still be usable (need ≥ {min_other} dBm).", steer)
            else:
                out.append(_i("info", "2.4 GHz is the right band here",
                              f"5 GHz would probably be too weak for a {ctype} {est_note}.",
                              "Improve coverage (move AP closer, add a wired/mesh node) rather than forcing 5 GHz."))
        else:
            if rssi < min_here:
                if p["need_mbps"] <= 10 and est_other >= p["min_rssi"]["2.4G"] + BAND_MARGIN:
                    move("2.4G", "warn", "5 GHz signal too weak - 2.4 GHz is the better fallback",
                         f"{rssi:.0f} dBm is below the {min_here} dBm target; light use ({p['need_mbps']} Mbps) fits 2.4 GHz.",
                         "Lower max rate but steadier link. Better fix: add coverage.")
                else:
                    out.append(_i("crit" if rssi < min_here - 5 else "warn", "Weak 5 GHz signal",
                                  f"{rssi:.0f} dBm vs ≥ {min_here} dBm needed for ~{p['need_mbps']} Mbps. "
                                  f"2.4 GHz would not fix throughput for a {ctype}.",
                                  "Move the AP/client closer, add a wired-backhaul AP/mesh node, or raise AP Tx power."))
            else:
                out.append(_i("ok", "Correct band", f"{ctype} on 5 GHz at {rssi:.0f} dBm."))
    else:  # prefers 2.4G (iot, camera, speaker)
        heavy = ctype == "camera" and (c.get("up_mbps") or 0) >= 3
        if on24:
            if heavy and est_other >= min_other + BAND_MARGIN:
                move("5G", "warn", "Camera uplink is heavy for 2.4 GHz",
                     f"{c['up_mbps']} Mbps upstream on a shared, slow 2.4 GHz channel.", steer)
            elif rssi < min_here:
                out.append(_i("warn", "Weak 2.4 GHz signal", f"{rssi:.0f} dBm vs ≥ {min_here} dBm target.",
                              "Reposition AP, or add an AP/extender near this device; check for 2.4 GHz interference."))
            else:
                out.append(_i("ok", "Correct band", f"{ctype} on 2.4 GHz at {rssi:.0f} dBm."))
        else:
            if rssi < min_here:
                move("2.4G", "warn", "Move to 2.4 GHz for range",
                     f"{ctype} on 5 GHz at {rssi:.0f} dBm (target ≥ {min_here}); 2.4 GHz gains range for low-rate devices.",
                     "Use a 2.4 GHz-only SSID for IoT; this also keeps their slow frames off the 5 GHz airtime.")
            elif ctype in ("iot", "speaker") or (ctype == "camera" and not heavy):
                out.append(_i("info", "Works on 5 GHz, but 2.4 GHz is the usual home for this device",
                              f"Signal is fine ({rssi:.0f} dBm) so it's not urgent.",
                              "Optional: pin to a 2.4 GHz IoT SSID to keep low-rate traffic off 5 GHz and gain range."))
            else:
                out.append(_i("ok", "Correct band", f"{ctype} on 5 GHz at {rssi:.0f} dBm."))

    if rssi < -75 and not any(i["sev"] == "crit" for i in out):
        out.append(_i("crit", "Very weak signal", f"{rssi:.0f} dBm sustained.", "Expect low rates and drops; fix coverage."))

    # ---- B. observed traffic vs declared type -------------------------------------------------------------
    if mix:
        dom = max(mix, key=mix.get)
        odd = {k: v for k, v in mix.items() if k not in p["expect"] and v >= 0.25}
        summary = ", ".join(f"{k} {v*100:.0f}%" for k, v in sorted(mix.items(), key=lambda x: -x[1])[:3])
        out.append(_i("info", f"Observed traffic: {summary}", f"Dominant class: {dom}."))
        for k, v in odd.items():
            out.append(_i("warn", f"Traffic doesn't match declared type '{ctype}'",
                          f"{v*100:.0f}% of recent bytes are {k}, unusual for a {ctype}.",
                          "Check the client type you entered, or inspect the device (compromised/misconfigured?)."))

    # ---- C. link quality ----------------------------------------------------------------------------------
    r = c.get("retry_pct")
    if r is not None and r >= 15:
        cause = ("interference or a busy channel (signal is fine)" if rssi >= -65 else "weak signal / marginal link")
        out.append(_i("crit" if r >= 30 else "warn", f"High Tx retries ({r}%)", f"Likely {cause}.",
                      "Change channel, narrow width (2.4G: 20 MHz), or move the client." if rssi >= -65 else
                      "Improve signal first."))
    ap_tx = c.get("ap_tx_phy_mbps")
    if ap_tx and band == "5G" and rssi >= -60 and ap_tx < 150:
        out.append(_i("warn", "PHY rate low for this signal",
                      f"{ap_tx} Mbps at {rssi:.0f} dBm on 5 GHz suggests 1 spatial stream, 20 MHz or a legacy client.",
                      "Verify client capability; check AP channel width (80 MHz) and that legacy rates aren't forced."))

    # ---- D. real-time call readiness ----------------------------------------------------------------------
    if mix and mix.get("Conferencing", 0) >= 0.2:
        probs = []
        if rssi < -67: probs.append(f"RSSI {rssi:.0f} dBm (want ≥ -67)")
        if r is not None and r > 5: probs.append(f"retries {r}% (want ≤ 5%)")
        if util is not None and util > 50: probs.append(f"channel busy {util}% (want ≤ 50%)")
        if on24: probs.append("on 2.4 GHz (more contention)")
        if probs:
            out.append(_i("warn", "Call conditions are marginal", "; ".join(probs) + ".",
                          "Prefer 5 GHz with good RSSI; ensure WMM is on so Teams' DSCP 46/34 maps to VO/VI."))
        else:
            out.append(_i("ok", "Call conditions look good", "RSSI, retries and airtime are all within targets for real-time media."))

    # ---- E. airtime on this client's radio ----------------------------------------------------------------
    if util is not None and util >= 50:
        oth = radio.get("other_pct") or 0
        note = " Most of the busy time is not ours → neighbours/interference." if util and oth / util > 0.4 else ""
        sev = "warn" if util >= 70 else "info"
        alt = ""
        if other_util is not None and other_util < util - 25 and est_other >= min_other + BAND_MARGIN and p["pref"] != "2.4G":
            alt = f" The {other} radio is much quieter ({other_util}%)."
        out.append(_i(sev, f"{band} radio busy {util}%", f"High airtime hurts latency for everyone on this radio.{note}{alt}",
                      "Move to a cleaner channel (2.4G: 1/6/11), push capable clients to 5 GHz, or reduce chatty IoT."))

    out.sort(key=lambda i: -SEV[i["sev"]])
    return out, advice

def advise_radio(r):
    out = []; u = r.get("util_pct")
    if u is None: return out
    if u >= 70: out.append(_i("warn", f"{r['iface']} ({r['band']}) saturated: {u}% busy", "Latency and throughput will suffer.",
                              "Change channel / reduce width / offload clients to the other band."))
    oth = r.get("other_pct") or 0
    if u >= 30 and oth / u > 0.5:
        out.append(_i("info", f"{r['iface']}: {oth}% of airtime is non-own traffic", "Neighbouring networks or non-Wi-Fi interference.",
                      "Run a channel scan; pick the least-occupied channel."))
    if r["band"] == "2.4G" and r.get("channel") not in (1, 6, 11, None, 0):
        out.append(_i("warn", f"{r['iface']} on 2.4 GHz channel {r['channel']}", "Overlaps neighbouring channels.", "Use 1, 6 or 11."))
    return out
