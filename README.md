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

**Client not in the dropdown?** Type its IP in the "or client IP" box next to it (the box wins over the dropdown). The test still works with the client helper or the shown command; link metrics (RSSI/PHY) appear only if that IP is a client the AP reports.

## Easiest: start the dashboard and pick the connection in it
    py wifi_monitor.py                       # Windows        python3 wifi_monitor.py   # macOS / Linux
    py wifi_monitor.py --log-dir logs --bind 0.0.0.0     # add --bind 0.0.0.0 if clients run iperf_client.py

With no device given, the dashboard opens with a **Connection** panel. Choose how logs are collected - **Serial console**, **Telnet**, **SSH**,
**Web API (ubus)**, **This computer**, or **Demo data** - fill in the fields (serial port list with a Refresh button, baud, IP, user, password), press **Test**
to check it without switching, then **Connect**. The Wi-Fi tool set (`wl` / `iw` / `wlanconfig`) and the interfaces (wl0..wl3) are auto-detected unless you
enter them. The same panel sets up **memory collection** (over the same connection, or a separate telnet / SSH login) and the **iperf agent URL**.
Click the status chip at the top (e.g. `● telnet · 192.168.1.254`) to reopen the panel, change the connection, or Disconnect.
- Passwords are used for the session only and are never saved; the other fields are remembered in `<log-dir>/connection.json`.
- The connection can only be changed from the PC running the dashboard (loopback), never from another machine.
- Serial "Access is denied": another program (PuTTY, Tera Term) has the port open - close it. SSH: leave Password blank to use your SSH key, or type the password (needs `pip install paramiko`).
- Console lands at a `>` prompt (restricted CLI) instead of `#`? For Serial and Telnet the tool types `sh` automatically when the prompt ends in `>`. Use the **Shell command** field for a different command (e.g. `shell`), or `none` to skip.
- All the old command-line options still work (`--transport`, `--host`, `--serial-port`, ...); `--setup` forces the panel even when they are given.

## Test several clients at the same time (and see if the bandwidth is good or bad)
The **Test several clients at the same time** card (below the Traffic planner) lets you add one row per client: pick the client (or type its IP), what it is doing
(audio, video, 4K, Teams call, game, or a plain **iperf3** run), the quality and the number of streams. **Run all** arms every row at once.
For 30-40 clients use **Add all connected clients**, then a **Quick fill** pattern (e.g. audio / video / 4K / Teams call repeating, or audio / iperf / video / game) and **Apply to all rows**;
change any row by hand, and **Save** the whole set as a named scenario to rerun later (kept in this browser).
iperf3 rows have no requirement to judge: they are extra load, and the other clients' verdicts show what that load does to them.

- **Setup:** the iperf agent on the server PC runs one iperf3 server per client (`--slots 8` by default: ports 5201-5208; for 40 clients use `--slots 40` and allow TCP ports 5201-5240 on the server PC's firewall; max 64). Run `iperf_client.py`
  on every client PC. Start the helpers first, then press Run all, so the tests overlap (the result says how many seconds they ran together).
- **What each client is judged against:** the Mbps its own activity needs (the "Required" figure of the planner, e.g. 8 x 4K video = 200 Mbps).
  *Demand = exactly what each needs* asks each client for that rate (TCP `-b`, or UDP for real-time uploads) and checks it was delivered. *Flat out* lets TCP run unlimited and reports the headroom.
- **Verdict per client:** GOOD (>= 95% of the need delivered, or >= 1.5x headroom flat out), MARGINAL (80-95%, or 1.0-1.5x), BAD (below). Loss, jitter and heavy Wi-Fi retries can lower a verdict, and the reasons are listed.
  UDP loss/jitter are only measurable for uploads (client to server); downloads are judged on delivered Mbps.
- A summary line shows how many were good / marginal / bad, the total measured vs needed, and how busy the radio got.

## Reaching the AP: SSH, telnet, serial console, or web API (--transport)
All backends (iw / wl / qca) work over any transport.

    # SSH (default)
    python3 wifi_monitor.py --backend iw --host 192.168.1.1
    # Telnet (no serial cable / no ssh): optional login, reconnects by itself. Password via --password, env WIFI_PASS, or prompt.
    py wifi_monitor.py --backend wl --transport telnet --host 192.168.10.254 --telnet-user admin --ifaces wl1
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

## Device memory monitor (telnet / ssh), 24 / 48 / 72 h graphs and PDF
`memwatch.py` watches the memory of the device itself (router / gateway / AP) for days. Every `--interval` seconds (default 60) it logs
in and reads `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime`, per-process RSS (`/proc/<pid>/status`) and a `top -b -n 1` snapshot, and
appends everything to CSV files in `memlogs/` (so it survives restarts and keeps 7 days).

    py memwatch.py --host 192.168.1.1 --user root --password secret      # telnet is the default; page at http://127.0.0.1:8090/mem
    py memwatch.py --host 192.168.1.1 --transport ssh --user root
    py memwatch.py --pdf report.pdf --hours 72                           # PDF from the stored history, no device needed
    py memwatch.py --host 192.168.1.1 --once                             # one sample, print, exit

Or inside the Wi-Fi dashboard, one tool for both: add `--mem-host 192.168.1.1 --mem-user root --mem-password secret` (also
`--mem-transport`, `--mem-port`, `--mem-interval`, `--mem-dir`, `--mem-label`) to the usual `wifi_monitor.py` command. The dashboard
header then has a **Device memory** link (`/mem`). The password may also come from the `MEM_PASS` environment variable, or is asked for.

- **Page:** buttons for **24 h / 48 h / 72 h**; graphs of memory in use vs available, page cache / buffers / slab / shared, and the largest
  processes by RSS (hover for values), a summary, the latest `top`, and a **Download PDF** button.
- **PDF:** summary, findings, the same graphs, a per-process table and the raw `top` snapshot. Written without any library
  (no matplotlib / reportlab), so it works on a plain Windows Python.
- **Findings:** in-use memory growing (MB/hour and hours until the free memory is gone), the process or kernel slab that is growing, low
  available memory, swap use, device reboots (trends restart after a reboot) and gaps in the data. Leak detection needs about 2 h of history.
- **Memory while you run other tests (one tool, not separate):** start `wifi_monitor.py` with the `--mem-host ...` options. The memory
  collector runs in its own thread with its own telnet connection, so it keeps going during iperf3 / speedtest runs. Every finished
  throughput test is added to the memory graphs as a shaded window (e.g. "iperf3 tcp up 312 Mbps (192.168.1.5)"), sampling speeds up to every
  5 s while a test is armed or running, and the report shows memory **before / peak / after** each test plus **Kept MB**. A test that leaves
  memory behind is flagged ("Memory was not released after ..."), which catches leaks that only happen under load.
  For anything else (a Teams call, Netflix on the TV, a video test) type a name on the Device memory page and press **Start**, then
  **End** when finished: it is shaded the same way and sampled every 5 s while open. The windows and the table are in the PDF too.
- **Telnet:** a built-in client (no `telnetlib`, which Python 3.13 removed) that handles an optional login and reconnects if the device
  drops the connection. Needs a root shell on the device; busybox `grep`, `cat` and `top` are enough. The telnet password travels in clear text:
  use it on a trusted LAN only (use `--transport ssh` otherwise).

## Throughput tests: iperf3 and speedtest (in the Traffic planner)
Pick **Throughput test - iperf3 (measured)** or **Internet speed test - speedtest** in the Traffic dropdown. The card first
shows the client's current link (RSSI, PHY rates, retries, radio busy %), then a **Run test** button measures the real thing while the
monitor samples that client's RSSI, PHY rates, Tx retries and radio busy % about every 2 s during the test.

- **iperf3** (client-specific): start a server on the client (`iperf3 -s`; phones have iperf3 apps) and allow port 5201.
  The dashboard machine runs `iperf3 -c <client IP>`. Modes (from the client's point of view): TCP download / upload,
  UDP download / upload at a target rate (gives jitter and packet loss - use it to validate a Teams/Zoom/voice rate).
  Options: duration, parallel streams, UDP rate. Install iperf3 on the dashboard machine: macOS `brew install iperf3`,
  Windows from https://iperf.fr/iperf-download.php, Linux `apt install iperf3`.
  `--iperf-from ap` runs iperf3 on the AP instead (isolates the Wi-Fi hop; the AP needs iperf3), `--iperf-port` changes the port.
- **Server-PC mode (recommended for real clients - no iperf3 server needed on the phone/laptop)**: a spare PC on the LAN acts as
  the iperf3 server and the *selected Wi-Fi client* runs `iperf3 -c <PC>`.
  1. On the server PC (iperf3 installed): `py iperf_agent.py` (Windows) or `python3 iperf_agent.py`. It runs `iperf3 -s`, records
     every finished test and serves them on port 8099 (`--token` to protect it). Allow TCP 5201 and 8099 through its firewall.
     If iperf3 is not on PATH (Windows): `py iperf_agent.py --iperf-bin "C:\\path\\to\\iperf3.exe"`.
  2. Start the dashboard with `--iperf-server http://<PC IP>:8099` (`--iperf-token`, `--iperf-server-ip` optional).
  3. Select the client, choose *Throughput test - iperf3*, press **Run test**. The dashboard *arms* the test and shows the exact
     command for that client, e.g. `iperf3 -c 192.168.1.50 -t 10 -R` (add `-R` for download, `-u -b 50M` for UDP, `-P 4` for streams).
  4. Run it on the client. The result is matched to the client by its IP (tests from other devices are ignored), the mode is read
     from what the client actually ran, and the link metrics (RSSI, PHY rate, retries, busy %) are taken only from the
     test window. 180 s time-out, **Cancel** button. If the client is behind NAT its tests arrive from the router's IP and cannot
     be matched. For `-u ... -R` the client, not the server, measures loss/jitter.
- **Client helper (no typing on the client)**: run `iperf_client.py` once on the Wi-Fi device and leave it running. When you press
  **Run test** for that device, it starts `iperf3 -c <server PC> ...` by itself (duration, streams, UDP rate, `-R` all come from the dashboard).
  Start the dashboard with `--bind 0.0.0.0` so the device can reach it (the Run-test button itself stays localhost-only). The device is
  recognised by its IP; the dashboard and helper must not be on the same machine.
  - **Windows:** `py iperf_client.py --dashboard http://<dashboard PC>:8080` (`--iperf-bin "C:\\path\\iperf3.exe"` if not on PATH).
  - **Ubuntu / Linux / macOS:** `sudo apt install iperf3 python3`, then `python3 iperf_client.py --dashboard http://<dashboard PC>:8080`.
  - **Android:** install Termux, then `pkg install python iperf3` and run the same script. Keep Termux in the foreground (or acquire its wakelock).
  - **iPhone/iPad:** iOS cannot run background scripts, so use any iperf3 app and type the command the dashboard shows.
- **iperf3 not on PATH (Windows):** the dashboard, `iperf_agent.py` and `iperf_client.py` look for iperf3 on PATH, in `IPERF3_PATH`, next to the
  scripts, in the current folder and in the usual places (`C:\\iperf3`, `Downloads\\iperf*`, ...). Otherwise point at it with
  `--iperf-bin "C:\\path\\to\\iperf3.exe"` (the file or its folder) on whichever script reports it missing. The official Windows build also needs
  its `cygwin1.dll` in the same folder as `iperf3.exe`. `iperf_client.py` prints the iperf3 it found when it starts.
- **Several networks (e.g. a management IP besides the LAN IP): choose the source address.** iperf3's `-B` pins which local address a test
  uses, so traffic leaves by the right network instead of whatever the routing table prefers.
  - *Server PC:* `py iperf_agent.py --iperf-bind 192.168.1.3` listens only on that address (`iperf3 -s -B`); the page and the client
    command then show that IP. Keep `--iperf-server-ip` equal to it if you set that.
  - *Wi-Fi client:* the dashboard adds `-B <client's Wi-Fi IP>` to the command it shows (turn off with `--no-client-bind`), which also makes the
    test arrive from the IP the dashboard knows, so it is matched correctly. `iperf_client.py` applies it automatically; if the client reaches the
    dashboard over another network, give its Wi-Fi address once: `py iperf_client.py --dashboard http://<dashboard>:8080 --bind 192.168.1.77`
    (used as `-B` and to identify the device). `--no-bind` ignores the suggestion.
  - *Tests the dashboard runs itself* (client runs `iperf3 -s`): `--iperf-src <this PC's LAN IP>`.
  `-B` pins the address, not the interface: if two interfaces are on the same subnet the OS may still choose; use different subnets or a host route.
- **speedtest**: internet speed of the machine running the dashboard (not of the selected client). Needs the Ookla CLI
  (`brew tap teamookla/speedtest && brew install speedtest`, Windows `winget install Ookla.Speedtest.CLI`) or `pip install speedtest-cli`.
- Results include insights (UDP loss/jitter thresholds, high retries, busy radio) and are appended to
  `tests.csv` when `--log-dir` is set.
- Safety: tests start only from the machine running the dashboard (`--allow-remote-tests` to change), the target IP always
  comes from the client list (never free text), and the POST endpoint requires a JSON content type.
