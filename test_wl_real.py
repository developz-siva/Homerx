"""Parser/pipeline tests using a REAL `wl -i wl1 sta_info all` capture from a Broadcom Wi-Fi 7 board (6 GHz, 320 MHz), MACs anonymised."""
import os, unittest, wifi_monitor as w, advisor as a
FIX = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wl_sta_info_all_6g.txt")).read()

class FakeRunner:
    host = "fake"
    def run(self, cmd, timeout=15):
        if "chanspec" in cmd: return "6g101/320-2 (0x7043)\n"
        if "sta_info all" in cmd: return FIX
        if "chanim_stats" in cmd: return "chanspec tx inbss obss nocat nopkt doze txop goodtx badtx glitch badplcp knoise timestamp\n0x7043 1 2 6 0 3 0 88 0 0 5 0 -89 1\n"
        return ""

class T(unittest.TestCase):
    def test_split_and_values(self):
        s = w.parse_wl_sta_info_all(FIX); self.assertEqual([x["mac"] for x in s], ["aa:bb:cc:00:00:01", "22:bb:cc:00:00:02"])
        c1, c2 = s
        self.assertEqual((c1["rssi"], c1["noise_dbm"], c1["idle" if False else "inactive_ms"]), (-65, -82, 4000))
        self.assertAlmostEqual(c1["ap_tx_mbps"], 3629.58, 2); self.assertEqual(c1["sta_tx_mbps"], 735.0)
        self.assertEqual((c1["tx_packets"], c1["tx_retries"], c1["width_mhz"]), (95, 41, 320))
        self.assertEqual(c2["sta_tx_mbps"], 144.11)          # median, NOT the 6 Mbps legacy control frame
        self.assertEqual((c2["tx_packets"], c2["tx_retries"], c2["connected_s"]), (15946, 391, 173149))
    def test_chanspec(self):
        self.assertEqual(w.parse_wl_chanspec("6g101/320-2 (0x7043)"), ("6G", 101, 320))
        self.assertEqual(w.parse_wl_chanspec("36/80 (0xe02a)"), ("5G", 36, 80))
        self.assertEqual(w.parse_wl_chanspec("11l (0x1b0b)"), ("2.4G", 11, None))
    def test_pipeline_band_is_6g(self):
        be = w.WlBackend(FakeRunner(), ["wl1"]); mon = w.Monitor(be, 1, None, {"192.168.1.5": "phone"})
        mon.poll()
        r = mon.state["radios"][0]; self.assertEqual((r["band"], r["channel"]), ("6G", 101))
        self.assertEqual(len(mon.state["clients"]), 2); self.assertTrue(all(c["band"] == "6G" for c in mon.state["clients"]))
    def test_advisor_6g_falls_back_to_5g(self):
        c = {"band": "6G", "iface": "wl1", "rssi": -74, "up_mbps": 0, "down_mbps": 0, "retry_pct": 0, "ap_tx_phy_mbps": 1600}
        ins, adv = a.advise(c, "phone", [-74], {}, {"wl1": {"band": "6G", "util_pct": 5}})
        self.assertEqual(adv["target_band"], "5G"); self.assertTrue(any("6 GHz signal too weak" in i["title"] for i in ins))
if __name__ == "__main__": unittest.main()
