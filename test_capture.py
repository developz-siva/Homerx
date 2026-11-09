"""Capture analysis on synthesised monitor-mode captures (radiotap + 802.11, pcap and pcapng)."""
import os, struct, tempfile, unittest
import capture as cp

AP, STA1, STA2 = bytes.fromhex("aabbcc000001"), bytes.fromhex("021122334455"), bytes.fromhex("0211223344ff")

def rt(freq=5180, rssi=-50, rate=None, he=None, fcs=False):
    if he:                                              # channel, antsignal, HE
        body = struct.pack("<HH", freq, 0x0140) + struct.pack("<b", rssi) + b"\x00" + struct.pack("<6H", 0, 0, he["mcs"] << 8, 0, he["bw"] | (he.get("gi", 0) << 4), he["nss"])
        present = (1 << 3) | (1 << 5) | (1 << 23)
        return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + body
    body = struct.pack("<B", int(rate * 2) if rate else 0) + b"\x00" + struct.pack("<HH", freq, 0x0140) + struct.pack("<b", rssi)       # rate, pad, channel, signal
    present = (1 << 2) | (1 << 3) | (1 << 5)
    return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + body

def mac_hdr(fc0, fc1, a1, a2, a3): return bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x00\x00"

def qos_up(up, retry=False, size=200): return mac_hdr(0x88, 0x01 | (8 if retry else 0), AP, STA1, AP) + struct.pack("<H", up) + b"x" * size
def qos_dn(up, size=1200, sta=STA1): return mac_hdr(0x88, 0x02, sta, AP, AP) + struct.pack("<H", up) + b"x" * size

def ie(t, d): return bytes([t, len(d)]) + d
def ext(x, d): return ie(255, bytes([x]) + d)

def beacon(freq=5180):
    wmm = b"\x00\x50\xf2\x02\x01\x01\x00" + b"\x00" + b"".join(bytes([a, e, 0, 0]) if False else struct.pack("<BBH", a, e, t) for a, e, t in
                                                          [(0x03, 0xA4, 0), (0x27, 0xA4, 0), (0x42, 0x43, 94), (0x62, 0x32, 47)])
    ml = struct.pack("<H", 0x0001 | (0x01 << 4) | (0x08 << 4)) if False else None
    mlctl = struct.pack("<H", 0 | ((1 | 8 | 16) << 4))
    common = AP + bytes([1]) + struct.pack("<H", 0x0001) + struct.pack("<H", 0x0003 | 0x40)                   # mld mac, link id, EML (EMLSR), MLD caps (max links 4, ttlm any)
    mle = bytes([107]) + mlctl + bytes([len(common) + 1]) + common
    body = b"\x00" * 8 + struct.pack("<HH", 100, 0x1011) + ie(0, b"HomeNet") + ie(3, bytes([36])) + ie(45, b"\x00" * 26) + ie(191, b"\x00" * 12) + ie(221, wmm) + ext(35, b"\x00" * 10) + ext(108, b"\x00" * 10) + ie(255, mle)
    return mac_hdr(0x80, 0, b"\xff" * 6, AP, AP) + body

def assoc_req():
    mlctl = struct.pack("<H", 0 | ((1 | 8 | 16) << 4))
    common = STA1 + b"\x00" + struct.pack("<H", 0x0001) + struct.pack("<H", 0x0003)
    mle = bytes([107]) + mlctl + bytes([len(common) + 1]) + common
    return mac_hdr(0x00, 0, AP, STA1, AP) + struct.pack("<HH", 0x1011, 10) + ie(0, b"HomeNet") + ie(45, b"\x00" * 26) + ext(35, b"\x00" * 10) + ext(108, b"\x00" * 10) + ie(255, mle)

def pcap(path, frames, big=False):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        for i, fr in enumerate(frames): f.write(struct.pack("<IIII", 1000 + i // 1000, (i % 1000) * 1000, len(fr), len(fr)) + fr)

def pcapng(path, frames):
    def blk(t, body):
        pad = (-len(body)) % 4; ln = 12 + len(body) + pad
        return struct.pack("<II", t, ln) + body + b"\x00" * pad + struct.pack("<I", ln)
    with open(path, "wb") as f:
        f.write(blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(blk(1, struct.pack("<HHI", 127, 0, 65535)))
        for i, fr in enumerate(frames): f.write(blk(6, struct.pack("<IIIII", 0, 0, 1000 + i * 1000, len(fr), len(fr)) + fr))

class Capture(unittest.TestCase):
    def frames(self):
        R = rt(rate=24)
        fr = [rt() + beacon() for _ in range(5)] + [rt() + assoc_req()]
        fr += [rt(rssi=-60, rate=6) + qos_up(0) for _ in range(380)]                                    # client 1 best-effort uplink at 6 Mbps legacy
        fr += [rt(rssi=-60, rate=6) + qos_up(6, retry=(i % 4 == 0)) for i in range(120)]                  # voice with 25% retries
        fr += [rt(he={"mcs": 11, "nss": 2, "bw": 3}) + qos_dn(5) for _ in range(300)]                    # video downlink, HE MCS11 2ss 160 MHz
        fr += [rt(rate=24) + qos_dn(0, sta=STA2) for _ in range(400)]                                    # client 2: all best effort
        fr += [R + mac_hdr(0xC4, 0, AP, AP, AP)[:10] for _ in range(5)]                                    # a control frame
        return fr
    def check(self, r):
        self.assertEqual(r["unreadable"], 0); self.assertEqual(r["totals"]["mgmt"], 6)
        ap = r["aps"][0]; self.assertEqual((ap["ssid"], ap["channel"], ap["band"], ap["generation"], ap["wmm"]), ("HomeNet", 36, "5G", "Wi-Fi 7", True))
        self.assertEqual(ap["edca"]["VO"]["aifsn"], 2); self.assertEqual(ap["edca"]["BE"]["cwmax"], 1023); self.assertEqual(ap["edca"]["VO"]["txop_us"], 47 * 32)
        self.assertEqual(ap["mlo"]["mld_mac"], "aa:bb:cc:00:00:01"); self.assertTrue(ap["mlo"]["emlsr"]); self.assertEqual(ap["mlo"]["max_links"], 4)
        c = {x["mac"]: x for x in r["clients"]}; c1, c2 = c["02:11:22:33:44:55"], c["02:11:22:33:44:ff"]
        self.assertEqual((c1["frames_up"], c1["frames_dn"]), (500, 300)); self.assertEqual(c1["ac"]["VO"]["frames"], 120); self.assertEqual(c1["ac"]["VI"]["frames"], 300)
        self.assertEqual(c1["ac"]["VO"]["retry_pct"], 25.0); self.assertEqual(c1["rssi_avg"], -60)
        self.assertEqual(c2["ac"]["BE"]["share_pct"], 100.0)
        self.assertEqual(c1["generation"], "Wi-Fi 7"); self.assertEqual(c1["mlo"]["mld_mac"], "02:11:22:33:44:55")
        self.assertTrue(any(p["rate"] == "HE MCS11 2ss 160MHz" for p in c1["phy"]))
        t = " ".join(i["title"] for i in r["insights"])
        self.assertIn("voice (VO) frames retried 25.0%", t); self.assertIn("02:11:22:33:44:ff: 100.0% of 400 frames are best-effort", t); self.assertIn("MLO", t)
    def test_pcap(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.pcap"); pcap(p, self.frames()); self.check(cp.analyse_file(p, "a.pcap"))
    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.pcapng"); pcapng(p, self.frames()); self.check(cp.analyse_file(p, "a.pcapng"))
    def test_he_rate(self):
        self.assertAlmostEqual(cp.rate_mbps({"phy": "HE", "mcs": 11, "nss": 2, "bw": 160, "gi": 0.8}), 2401.9, delta=1.0)    # matches the AP's 2401 Mbps max rate
        self.assertAlmostEqual(cp.rate_mbps({"phy": "VHT", "mcs": 9, "nss": 2, "bw": 80, "gi": 0.4}), 866.7, delta=1.0)
    def test_not_a_capture(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.pcap"); open(p, "wb").write(b"hello world, not a capture at all")
            with self.assertRaises(ValueError): cp.analyse_file(p)
    def test_truncated_file_is_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.pcap"); pcap(p, self.frames()); open(p, "ab").write(b"\x01\x02\x03")
            self.assertGreater(cp.analyse_file(p)["frames"], 1000)

class Endpoint(unittest.TestCase):
    def test_monitor_analyses_in_background_and_reports_bad_files(self):
        import time, wifi_monitor as w
        mon = w.Monitor(w.SimBackend(w.Runner(None)), 1, None)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.pcapng"); pcapng(p, Capture().frames())
            self.assertEqual(mon.start_capture(p, "a.pcapng"), {"ok": True})
            for _ in range(50):
                if mon.capture_status()["state"] != "analysing": break
                time.sleep(0.1)
            s = mon.capture_status(); self.assertEqual(s["state"], "done"); self.assertEqual(s["result"]["frames"], 1211); self.assertFalse(os.path.exists(p))
            q = os.path.join(d, "b.pcap"); open(q, "wb").write(b"not a capture file at all, sorry")
            mon.start_capture(q, "b.pcap")
            for _ in range(50):
                if mon.capture_status()["state"] != "analysing": break
                time.sleep(0.1)
            self.assertEqual(mon.capture_status()["state"], "error"); self.assertIn("pcap", mon.capture_status()["error"])

if __name__ == "__main__": unittest.main()
