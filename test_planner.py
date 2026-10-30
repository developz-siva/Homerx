import unittest, planner as p, discovery as d

LINK = {"mac": "m", "iface": "w", "band": "5G", "rssi": -55, "ap_tx_phy_mbps": 650, "sta_tx_phy_mbps": 520, "retry_pct": 2, "active": True, "channel": 36}
R = {"w": {"band": "5G", "util_pct": 15}}

class T(unittest.TestCase):
    def test_teams_numbers(self):
        r = p.plan(LINK, "teams", "1:1 video, recommended (≈1.6 Mbps)", 1, R)
        self.assertAlmostEqual(r["required"]["down_mbps"], 1.558, 3)
        self.assertEqual(r["verdict"]["level"], "good")
    def test_zoom_1080(self):
        r = p.plan(LINK, "zoom", "1:1 1080p HD (3.8 up / 3.0 down)", 1, R)
        self.assertEqual((r["required"]["down_mbps"], r["required"]["up_mbps"]), (3.0, 3.8))
    def test_data_per_hour(self):
        self.assertAlmostEqual(p.plan(LINK, "video", "4K UHD (15 Mbps)", 1, R)["required"]["gb_per_hour_down"], 6.75, 2)
    def test_weak_link_poor(self):
        weak = dict(LINK, band="2.4G", rssi=-80, ap_tx_phy_mbps=20, sta_tx_phy_mbps=15, retry_pct=35)
        self.assertEqual(p.plan(weak, "video", "4K UHD (15 Mbps)", 1, {"w": {"band": "2.4G", "util_pct": 60}})["verdict"]["level"], "poor")
    def test_streams_scale(self):
        a = p.plan(LINK, "video", "1080p Full HD (≈5 Mbps)", 1, R); b = p.plan(LINK, "video", "1080p Full HD (≈5 Mbps)", 4, R)
        self.assertAlmostEqual(b["required"]["down_mbps"], 4 * a["required"]["down_mbps"], 3)
        self.assertGreater(b["capacity"]["airtime_needed_pct"], a["capacity"]["airtime_needed_pct"])
    def test_no_link(self):
        r = p.plan({"mac": "x", "ips": ["1.2.3.4"]}, "voice", None, 1, R)
        self.assertEqual(r["verdict"]["level"], "unknown"); self.assertGreater(r["required"]["down_mbps"], 0)
    def test_every_catalog_entry_runs(self):
        for k, v in p.CATALOG.items():
            for q in v["qualities"]: p.plan(LINK, k, q, 2, R)
    def test_arp_mac(self):
        t = "? (192.168.1.5) at a4:83:e7:0:0:1 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent"
        self.assertEqual(d.parse_arp(t), {"192.168.1.5": "a4:83:e7:00:00:01"})
    def test_mac_wifi(self):
        txt = """Wi-Fi:
      Interfaces:
        en0:
          MAC Address: f0:18:98:1:2:3
          Status: Connected
          Current Network Information:
            Home:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Signal / Noise: -55 dBm / -92 dBm
              Transmit Rate: 866
          Other Local Wi-Fi Networks:
            Foo:
              Channel: 6 (2GHz, 20MHz)
"""
        w = d.parse_mac_wifi(txt)
        self.assertEqual((w["iface"], w["band"], w["rssi"], w["tx_rate"], w["mac"]), ("en0", "5G", -55, 866.0, "f0:18:98:01:02:03"))
if __name__ == "__main__": unittest.main()
