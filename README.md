# wifi_client_monitor

Per-client traffic, Tx rate and app/QoS class, plus per-radio channel utilization, measured on the AP.

## Run
    python3 wifi_monitor.py --backend sim --once --interval 2          # try it with no hardware
    python3 wifi_monitor.py --backend iw  --host 192.168.1.1 --log-dir logs     # OpenWrt / prplOS / mac80211 RDK-B
    python3 wifi_monitor.py --backend wl  --host 192.168.1.1 --ifaces eth6,eth7 # Broadcom
    python3 wifi_monitor.py --backend qca --host 192.168.1.1 --ifaces ath0,ath1 # Qualcomm
Dashboard: http://127.0.0.1:8080 (use --bind 0.0.0.0 to expose). Needs key-based SSH to the AP; or copy the
script to the AP and run without --host. Logs: logs/clients.csv, logs/radios.csv.

## AP prerequisites
- Per-app traffic needs conntrack byte counters:  `sysctl -w net.netfilter.nf_conntrack_acct=1`
  (persist in /etc/sysctl.conf). Without it only PHY rates / RSSI / channel utilization are shown.
- Client hostnames come from dnsmasq leases (/tmp/dhcp.leases) when present.

## What the columns mean
- AP>STA PHY = AP Tx rate to the client; STA>AP PHY = client's Tx rate as seen by the AP (last-packet rates, not throughput).
- Up/Down = measured throughput from conntrack deltas (Up = client Tx).
- Retry% = AP Tx retries / Tx packets over the interval.
- Channel utilization = busy time / active time from the survey (iw) or 100 - txop (Broadcom chanim). "other" = busy not
  explained by own tx/rx (neighbour BSS / interference).
- Classes (Conferencing, Video Streaming, IoT, Web, Bulk, Infra) are heuristics: Teams UDP 3478-3481, Meet 19302-19309,
  Zoom 8801-8810, MQTT/CoAP, QUIC/HTTPS above a rate threshold, IoT by hostname. The WMM column is the AC each class
  *should* map to, not a measured per-AC counter. Edit IOT_HOST / classify() to tune.

## Status
iw parsers + classifier are unit-tested (python3 test_parsers.py); the simulator exercises the full pipeline.
The wl and qca backends are best effort: output formats vary by SDK version, so verify on real hardware.

## Client types, insights and band recommendations
Declare clients by IP (MAC or hostname also work):

    python3 wifi_monitor.py --backend iw --host 192.168.1.1 \
        --client 192.168.1.20=laptop --client 192.168.1.21=tv --client 192.168.1.30=camera --client 192.168.1.31=iot
    # or --clients-file clients.json   ({"192.168.1.20": "laptop", ...})

Types: laptop, phone, tablet, tv, console, camera, speaker, iot (aliases like macbook, ipad, roku, sensor, bulb work).
Per client the tool reports: observed traffic mix vs what that type should do, band fit, link quality (retries, PHY rate
vs RSSI), real-time call readiness (Teams etc.) and airtime on its radio; radios get saturation / interference / channel checks.

**Caveat:** the AP only measures RSSI on the band a client is associated to. The other band's RSSI is *estimated*
(default 8 dB lower on 5 GHz; tune with --band-offset). A change is only recommended with 3 dB of headroom, using the
median of the last 8 samples. Treat band advice as a strong hint; confirm with 802.11k beacon reports
(`hostapd_cli req_beacon`) or by testing the client on the other band.

## Traffic planner (select a client + traffic type)
The dashboard's top card lists every device on the LAN. Pick a client, a traffic type (Video, Spotify, Apple Music,
Voice call, Teams, Zoom, Game), a quality level and the number of simultaneous streams. You get: required bitrate
(avg/peak, up/down), data per hour, packets/s, usable capacity and headroom on that client's link, airtime needed,
radio utilization now -> projected, max simultaneous streams, RSSI margin vs what the traffic needs, WMM/DSCP/ports,
latency/jitter/loss targets, and band recommendations. Verdict: GOOD / MARGINAL / POOR.

Client list sources:
- `--backend iw|wl|qca --host <AP>`: all Wi-Fi clients with real PHY/RSSI/retries plus wired hosts from the AP's neighbour table.
- `--backend local` (run on the MacBook, no AP access): ping-sweeps your /24 (`--subnet` to override), reads ARP,
  and reads THIS Mac's own Wi-Fi link via `system_profiler SPAirPortDataType`. Other devices show "wired/other" (no link data),
  so only the required bitrate is computed for them. The Mac sweep refreshes every 45 s.

Bitrate sources are listed at the top of planner.py (Microsoft Learn for Teams, Zoom system requirements, Netflix help,
NVIDIA GeForce NOW; Spotify/Apple are nominal codec rates; online-game rates are estimates).
Capacity is a model, not a speed test.

    python3 wifi_monitor.py --backend local                       # MacBook only
    python3 wifi_monitor.py --backend iw --host 192.168.1.1       # with AP data

## Reaching the AP: SSH, serial console, or web API (--transport)
All backends (iw / wl / qca) work over any transport.

    # SSH (default)
    python3 wifi_monitor.py --backend iw --host 192.168.1.1
    # Serial console (USB-UART). pip3 install pyserial ; port on macOS: ls /dev/cu.usb*
    python3 wifi_monitor.py --backend iw --transport serial --serial-port /dev/cu.usbserial-0001 --baud 115200 \
        [--serial-user root --password ...]
    # Web API: OpenWrt/prplOS ubus-over-HTTP (rpcd). Password via --password, env WIFI_PASS, or prompt.
    python3 wifi_monitor.py --backend iw --transport ubus --http-url http://192.168.1.1 --http-user root

Notes
- Serial: console must be at a shell (or a login prompt - use --serial-user/--password). It is slow, so conntrack reads are
  capped (--max-flows, default 300; 0 = skip app classification). Don't have another terminal program (screen/minicom) open on the port.
- ubus: needs rpcd + uhttpd-mod-ubus, and the user must be allowed `file exec` (root on stock OpenWrt). rpcd caps output size,
  so --max-flows defaults to 400.
- Vendor web UIs that don't expose ubus (many carrier/RDK-B GUIs) can't be driven generically. Use SSH or serial for those,
  or tell me the model and I can write an adapter.
- --backend local needs no transport (Mac only).

## Throughput tests: iperf3 and speedtest (in the Traffic planner)
Pick **Throughput test - iperf3 (measured)** or **Internet speed test - speedtest** in the Traffic dropdown. The card first
shows the link model's *predicted* maximum for that client, then a **Run test** button measures the real thing while the
monitor samples that client's RSSI, PHY rates, Tx retries and radio busy % about every 2 s during the test.

- **iperf3** (client-specific): start a server on the client (`iperf3 -s`; phones have iperf3 apps) and allow port 5201.
  The dashboard machine runs `iperf3 -c <client IP>`. Modes (from the client's point of view): TCP download / upload,
  UDP download / upload at a target rate (gives jitter and packet loss - use it to validate a Teams/Zoom/voice rate).
  Options: duration, parallel streams, UDP rate. Install iperf3 on the dashboard machine: macOS `brew install iperf3`,
  Windows from https://iperf.fr/iperf-download.php, Linux `apt install iperf3`.
  `--iperf-from ap` runs iperf3 on the AP instead (isolates the Wi-Fi hop; the AP needs iperf3), `--iperf-port` changes the port.
- **speedtest**: internet speed of the machine running the dashboard (not of the selected client). Needs the Ookla CLI
  (`brew tap teamookla/speedtest && brew install speedtest`, Windows `winget install Ookla.Speedtest.CLI`) or `pip install speedtest-cli`.
- Results include insights (measured vs model, UDP loss/jitter thresholds, high retries, busy radio) and are appended to
  `tests.csv` when `--log-dir` is set.
- Safety: tests start only from the machine running the dashboard (`--allow-remote-tests` to change), the target IP always
  comes from the client list (never free text), and the POST endpoint requires a JSON content type.
