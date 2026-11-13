# Cheat sheet - Wi-Fi client monitor

Windows: use `py` (or `python`). macOS / Linux: `python3`. Run everything from the project folder. `Ctrl+C` stops a program.

## 1. One-time setup
```
git clone https://github.com/developz-siva/Homerx.git        # first time
git pull                                                      # get the latest (every PC)
pip install pyserial paramiko                                 # serial console / SSH with password (only what you use)
```
iperf3 (only for throughput rows): Windows - unzip the Windows build (iperf3.exe + cygwin1.dll) to `C:\iperf3`; macOS `brew install iperf3`; Linux `apt install iperf3`.

## 2. Dashboard (the main program)
```
py wifi_monitor.py --setup                                   # easiest: opens with no connection, pick serial / telnet / SSH on the page
py wifi_monitor.py --transport ssh --host 192.168.1.1        # SSH key login
py wifi_monitor.py --transport telnet --host 192.168.1.1
py wifi_monitor.py --transport serial --serial-port COM5 --baud 115200        # macOS: /dev/cu.usbserial-0001
py wifi_monitor.py --backend sim                             # demo with simulated clients (no AP needed)
```
Open **http://127.0.0.1:8080**. Useful extras:

| Option | Meaning |
|---|---|
| `--backend wl` / `iw` / `qca` | Wi-Fi tool set on the AP (default: auto-detect). Broadcom: `wl` with `--ifaces wl0,wl1` |
| `--ifaces wl0,wl1` | radios to watch (required for wl / qca) |
| `--max-flows 0` | skip conntrack (no per-app info, lighter on the AP) |
| `--interval 5` | seconds between polls |
| `--bind 0.0.0.0 --port 8080` | let other PCs open the dashboard (default: this PC only) |
| `--log-dir logs` | keep clients.csv / radios.csv history |
| `--allow-remote-tests` | let other machines on the LAN start tests |

## 3. Test clients - watch real traffic (no iperf)
1. Connection card: choose transport, click **Connect**.
2. **Test clients** card: one row per client (or **Add all connected clients**); pick the activity and quality.
3. Start the real app on each device (Netflix, Spotify, Teams ...), then **Run all** (use 60 s; skip to a NEW song just after pressing Run).
4. **Download PDF report** when it finishes. Set a row to **Idle** to leave it out.

## 4. Test clients - iperf3 rows (server PC with two networks, e.g. 192.168.10.76)
On the PC (server + dashboard):
```
py iperf_agent.py --slots 8 --iperf-bin "C:\iperf3" --iperf-bind 192.168.10.76
py wifi_monitor.py --setup --iperf-server http://127.0.0.1:8099 --iperf-server-ip 192.168.10.76 --bind 0.0.0.0
```
On each Wi-Fi client PC / laptop:
```
py iperf_client.py --dashboard http://192.168.10.76:8080
```
Manual test from a client:  `iperf3 -c 192.168.10.76`   (`-R` download, `-u -b 50M` UDP)
Firewall: allow TCP+UDP 5201-5208 and TCP 8099 inbound on the server PC.
`--iperf-bind` must be an address that `ipconfig` shows on that PC ("Cannot assign requested address" = it is not).

## 5. Stop iperf (Windows)
The agent restarts iperf3 automatically, so stop the agent first: press **Ctrl+C** in its window, then
```
taskkill /F /IM iperf3.exe
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'iperf' } | Select ProcessId, CommandLine      # find leftovers
netstat -ano | findstr :5201                                                                                    # who holds a port
```

## 6. Device memory (separate page, usually port 8090)
```
py memwatch.py --host 192.168.1.1 --transport telnet --interval 60 --label "CR1000B"
py memwatch.py --host 192.168.1.1 --transport ssh --user root
py memwatch.py --once --host 192.168.1.1                      # one sample, print and exit
py memwatch.py --pdf mem.pdf --hours 72                       # PDF report from stored history
```
Or just set **Collect memory via** in the dashboard's Connection card and open **Device memory**.

## 7. Capture analysis (sniffer pcap)
Dashboard -> **Capture analysis** card -> choose `.pcap` / `.pcapng` -> **Analyse**. Command line: `py capture.py file.pcapng`.
On a Broadcom AP: `wl -i wl0 monitor 1`, capture with tcpdump on the monitor interface, copy the file to your PC.

## 8. AP-side commands (Broadcom `wl`, serial console: type `sh` at `>` to get `#`)
```
wl -i wl0 chanspec                    # channel / width
wl -i wl0 assoclist                   # connected MACs
wl -i wl0 sta_info <MAC>              # RSSI, rates, byte counters, retries for one client
wl -i wl0 chanim_stats                # airtime / channel busy
wl -i wl0 ver                         # confirms the wl tool works
```
A serial port can be used by only one program: click **Disconnect** in the dashboard before using PuTTY / Tera Term.

## 9. Tests, updates
```
py -m pytest -q                       # full test suite (about 4 min; stop iperf3 first)
py -m pytest test_capture.py -q       # one file
git pull                              # then restart the dashboard
```
