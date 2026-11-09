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

BAD = {}                                                    # candidate path -> why it cannot be run

def _runs(p):
    """True if `p --version` can be started. A file that exists but is not a program for this OS (WinError 193) is skipped, and remembered in BAD."""
    import subprocess
    try: subprocess.run([p, "--version"], capture_output=True, timeout=10); return True
    except subprocess.TimeoutExpired: return True
    except OSError as e: BAD[p] = str(e); return False

def bad_hint():
    if not BAD: return ""
    p, why = next(iter(BAD.items()))
    return (f" Found {p} but it cannot be run ({why})." + (" That is not a Windows program: download the Windows build of iperf3 (iperf3.exe with its cygwin1.dll), not a Linux/macOS file or a source zip." if "193" in why else ""))

def find_iperf3(explicit=None):
    """Locate iperf3: an explicit file or folder, PATH, $IPERF3_PATH, beside this script, the current folder, then usual install places.
    Returns a full path, or None."""
    import glob, os
    names = ["iperf3.exe"] if os.name == "nt" else ["iperf3"]
    def pick(d):
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p) and _runs(p): return p
        return None
    if explicit and explicit != "iperf3":
        explicit = os.path.expandvars(os.path.expanduser(explicit))
        if os.path.isdir(explicit): return pick(explicit)
        if os.path.isfile(explicit): return explicit if _runs(explicit) else None
        w = shutil.which(explicit)
        return w if w and _runs(w) else None
    w = shutil.which("iperf3")
    if w and _runs(w): return w
    home = os.path.expanduser("~")
    dirs = [os.environ.get("IPERF3_PATH", ""), os.path.dirname(os.path.abspath(__file__)), os.getcwd(), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
            r"C:\iperf3", r"C:\iperf", r"C:\tools\iperf3", r"C:\Program Files\iperf3", r"C:\Program Files (x86)\iperf3", os.path.join(home, "iperf3")]
    for pat in (os.path.join(home, "Downloads", "iperf*"), os.path.join(home, "Desktop", "iperf*"), r"C:\iperf*", os.path.join(home, "iperf*")): dirs += glob.glob(pat)
    for d in dirs:
        if d and os.path.isdir(d):
            p = pick(d) or pick(os.path.join(d, "bin"))
            if p: return p
        elif d and os.path.isfile(d) and _runs(d): return d
    return None

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
    exe = find_iperf3(a.iperf_bin)
    if not exe: sys.exit("iperf3 was not found" + (f" at {a.iperf_bin}" if a.iperf_bin != "iperf3" else "") + "." + bad_hint() + " Searched PATH, this folder and the usual install folders. Pass --iperf-bin \"C:\\path\\to\\iperf3.exe\" (file or folder) or install it.")
    print(f"using {exe}", flush=True)
    url = a.dashboard.rstrip("/") + "/api/test/pending" + (f"?ip={a.bind}" if a.bind else "")
    if a.bind: ipaddress.ip_address(a.bind)
    print(f"Watching {a.dashboard} for tests armed for this device. Ctrl-C to stop.", flush=True)
    warned = False
    while True:
        try:
            job = fetch(url); warned = False
            if job.get("pending"):
                argv = build_argv(job, exe, None if a.no_bind else (a.bind or "auto"))
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
