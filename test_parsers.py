import unittest, wifi_monitor as w

IW_DEV = """phy#1
\tInterface wlan1
\t\tifindex 5
\t\tssid Home5
\t\ttype AP
\t\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
phy#0
\tInterface wlan0
\t\tssid Home
\t\ttype AP
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
\tInterface mon0
\t\ttype monitor
"""
STA = """Station aa:bb:cc:dd:ee:ff (on wlan1)
\tinactive time:\t120 ms
\trx bytes:\t12345
\ttx bytes:\t67890
\ttx packets:\t500
\ttx retries:\t25
\tsignal:  \t-45 [-47, -46] dBm
\ttx bitrate:\t866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
\trx bitrate:\t780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2
\tconnected time:\t1234 seconds
"""
SURVEY = """Survey data from wlan1
\tfrequency:\t\t\t5180 MHz [in use]
\tnoise:\t\t\t\t-95 dBm
\tchannel active time:\t\t10000 ms
\tchannel busy time:\t\t2500 ms
\tchannel receive time:\t\t1500 ms
\tchannel transmit time:\t\t500 ms
Survey data from wlan1
\tfrequency:\t\t\t5200 MHz
\tchannel active time:\t\t99 ms
\tchannel busy time:\t\t99 ms
"""
CT = ("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.20 dst=1.2.3.4 sport=5555 dport=443 packets=10 bytes=1000 "
      "src=1.2.3.4 dst=203.0.113.9 sport=443 dport=5555 packets=12 bytes=5000 [ASSURED] mark=0 use=2\n"
      "ipv4     2 udp      17 20 src=192.168.1.21 dst=52.1.1.1 sport=4000 dport=3478 packets=3 bytes=300 "
      "src=52.1.1.1 dst=203.0.113.9 sport=3478 dport=4000 packets=3 bytes=400 mark=0 use=1\n")

class T(unittest.TestCase):
    def test_dev(self):
        r = w.parse_iw_dev(IW_DEV)
        self.assertEqual([(x["iface"], x["band"], x["channel"]) for x in r], [("wlan1", "5G", 36), ("wlan0", "2.4G", 6)])
    def test_sta(self):
        s = w.parse_iw_stations(STA)[0]
        self.assertEqual((s["rssi"], s["ap_tx_mbps"], s["sta_tx_mbps"], s["tx_retries"]), (-45, 866.7, 780.0, 25))
    def test_survey(self):
        s = w.parse_iw_survey(SURVEY)
        self.assertEqual((s["freq"], s["active"], s["busy"]), (5180, 10000, 2500))
    def test_ct(self):
        f = w.parse_conntrack(CT)
        self.assertEqual((f[0]["up"], f[0]["down"], f[1]["dport"]), (1000, 5000, 3478))
    def test_classify(self):
        self.assertEqual(w.classify("udp", 3478, 1e6, 1e6, False)[1], "Teams")
        self.assertEqual(w.classify("udp", 443, 1e4, 8e6, False)[0], "Video Streaming")
        self.assertEqual(w.classify("tcp", 8883, 1e3, 1e3, False)[0], "IoT")
        self.assertEqual(w.classify("tcp", 443, 1e3, 1e3, True)[0], "IoT")
    def test_wl(self):
        d = w.parse_wl_sta_info("rate of last tx pkt: 866667 kbps - rate of last rx pkt: 780000 kbps\nsmoothed rssi: -52\n")
        self.assertEqual((d["ap_tx_mbps"], d["rssi"]), (866.667, -52))
        c = w.parse_wl_chanim("chanspec tx inbss obss nocat nopkt doze txop goodtx badtx glitch badplcp knoise timestamp\n0xe06a 2 10 5 3 4 0 76 1 1 1 1 -90 1\n")
        self.assertEqual(c["util_pct"], 24.0)
        real = "version: 4\nchspec       tx      inbss   obss    nocat   nopkt   doze    txop    goodtx  badtx   glitch  badplcp knoise  idle    busy    timestamps\n36/160       2       1       18      10      6       0       66      1       1       126     3       -91     67      34      12508982\n"
        c = w.parse_wl_chanim(real); self.assertEqual((c["util_pct"], c["tx_pct"], c["other_pct"]), (34.0, 2.0, 18.0))

if __name__ == "__main__":
    unittest.main()
