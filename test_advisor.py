import unittest, advisor as a

def cl(band, rssi, **k):
    return {"band": band, "iface": "w", "rssi": rssi, "up_mbps": 0, "down_mbps": 0, "retry_pct": 0, "ap_tx_phy_mbps": 600, **k}
R = {"w": {"band": "5G", "util_pct": 10}, "x": {"band": "2.4G", "util_pct": 30}}
def titles(ins): return [i["title"] for i in ins]

class T(unittest.TestCase):
    def test_laptop_24_move(self):
        ins, adv = a.advise(cl("2.4G", -55), "laptop", [-55], {}, R)
        self.assertFalse(adv["stay"]); self.assertEqual(adv["target_band"], "5G")
    def test_laptop_24_far_stay(self):
        ins, adv = a.advise(cl("2.4G", -68), "laptop", [-68], {}, R)   # est 5G -76 < -70+3
        self.assertTrue(adv["stay"])
    def test_tv_weak_5g_needs_coverage(self):
        ins, adv = a.advise(cl("5G", -72), "tv", [-72], {}, R)
        self.assertTrue(adv["stay"]); self.assertIn("Weak 5 GHz signal", titles(ins))
    def test_iot_weak_5g_to_24(self):
        ins, adv = a.advise(cl("5G", -74), "iot", [-74], {}, R)
        self.assertEqual(adv["target_band"], "2.4G")
    def test_camera_heavy_uplink(self):
        ins, adv = a.advise(cl("2.4G", -50, up_mbps=4), "camera", [-50], {}, R)
        self.assertEqual(adv["target_band"], "5G")
    def test_mismatch(self):
        ins, _ = a.advise(cl("2.4G", -60), "iot", [-60], {"Video Streaming": 0.9}, R)
        self.assertTrue(any("doesn't match" in t for t in titles(ins)))
    def test_call_marginal(self):
        ins, _ = a.advise(cl("5G", -70, retry_pct=9), "laptop", [-70], {"Conferencing": 0.8}, R)
        self.assertIn("Call conditions are marginal", titles(ins))
    def test_types(self):
        self.assertEqual(a.norm_type("Roku"), "tv"); self.assertIsNone(a.norm_type("toaster"))
        self.assertEqual(a.resolve_type({"192.168.1.5": "tv"}, "aa", "h", ["192.168.1.5"]), "tv")

if __name__ == "__main__": unittest.main()
