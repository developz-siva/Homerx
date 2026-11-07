#!/usr/bin/env python3
"""
iperf_client.py - leave this running on the Wi-Fi client you want to test (Windows, Ubuntu/Linux, macOS, Android via Termux).

When you press "Run test" for THIS device in the Wi-Fi dashboard, the dashboard arms the test and this helper starts
`iperf3 -c <server PC> ...` by itself (duration, streams, UDP rate and -R for download all come from the dashboard).
You never have to type the iperf3 command on the client.

    Windows :  py iperf_client.py --dashboard http://192.168.1.20:8080
    Ubuntu  :  python3 iperf_client.py --dashboard http://192.168.1.20:8080
    Android :  Termux: pkg install python iperf3 && python iperf_client.py --dashboard http://192.168.1.20:8080

The dashboard must be started with  --bind 0.0.0.0  so this device can reach it. The device is recognised by its IP address.
Needs iperf3 on this device (use --iperf-bin if it is not on PATH). Python standard library only.
"""
import argparse, ipaddress, json, shutil, subprocess, sys, time, urllib.request

def build_argv(job, iperf_bin="iperf3", bind="auto"):
    """Build the iperf3 command from the dashboard's job. Every field is validated; nothing goes through a shell."""
    ipaddress.ip_address(job["server_ip"])
    mode = job["mode"]
    if mode not in ("tcp_up", "tcp_down", "udp_up", "udp_down"): raise ValueError("bad mode")
    argv = [iperf_bin, "-c", job["server_ip"], "-p", str(int(job["port"])), "-t", str(max(1, min(int(job["secs"]), 300)))]
    if int(job["streams"]) > 1: argv += ["-P", str(min(int(job["streams"]), 16))]
    if mode.startswith("udp"): argv += ["-u", "-b", f"{float(job['rate']):g}M"]
    if mode.endswith("down"): argv.append("-R")
    src = job.get("bind") if bind == "auto" else bind               # -B: the Wi-Fi address, so the test leaves by the right network
    if src: ipaddress.ip_address(src); argv += ["-B", src]
    return argv

def fetch(url):
    with urllib.request.urlopen(url, timeout=5) as r: return json.loads(r.read())

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dashboard", required=True, help="dashboard URL, e.g. http://192.168.1.20:8080")
    ap.add_argument("--iperf-bin", default="iperf3", help="path to iperf3 if not on PATH")
    ap.add_argument("--bind", metavar="IP", help="this device's Wi-Fi IP: used as iperf3 -B and to identify this device to the dashboard "
                    "(needed when the device reaches the dashboard over a different network, e.g. a management address)")
    ap.add_argument("--no-bind", action="store_true", help="never add -B (ignore the address the dashboard suggests)")
    ap.add_argument("--poll", type=float, default=1.0, help="seconds between checks (default 1)")
    a = ap.parse_args()
    if not shutil.which(a.iperf_bin): sys.exit(f"iperf3 not found ({a.iperf_bin}). Install it or pass --iperf-bin.")
    url = a.dashboard.rstrip("/") + "/api/test/pending" + (f"?ip={a.bind}" if a.bind else "")
    if a.bind: ipaddress.ip_address(a.bind)
    print(f"Watching {a.dashboard} for tests armed for this device. Ctrl-C to stop.", flush=True)
    warned = False
    while True:
        try:
            job = fetch(url); warned = False
            if job.get("pending"):
                argv = build_argv(job, a.iperf_bin, None if a.no_bind else (a.bind or "auto"))
                print(time.strftime("%H:%M:%S"), "running:", " ".join(argv), flush=True)
                subprocess.run(argv)
                print(time.strftime("%H:%M:%S"), "done; result is in the dashboard", flush=True)
        except KeyboardInterrupt: return
        except Exception as e:
            if not warned: print(f"cannot reach the dashboard ({e}); is it started with --bind 0.0.0.0 and the port open?", flush=True); warned = True
        try: time.sleep(a.poll)
        except KeyboardInterrupt: return

if __name__ == "__main__":
    main()
