"""
speedtools.py - run iperf3 / speedtest and return normalised results.

iperf3  : measures throughput between the machine running this dashboard (or the AP, --iperf-from ap) and ONE client.
          The client must be running an iperf3 server (`iperf3 -s`; iOS/Android have iperf3 apps).
          Direction is from the CLIENT's point of view:  download = host -> client,  upload = client -> host (iperf3 -R).
speedtest: internet speed of the machine running the dashboard (Ookla `speedtest` CLI or `speedtest-cli`), NOT of a selected client.
"""
import ipaddress, json, shlex, shutil, subprocess

MODES = {"tcp_down": "TCP download (host → client)", "tcp_up": "TCP upload (client → host)",
         "udp_down": "UDP download (host → client)", "udp_up": "UDP upload (client → host)"}

def find_iperf3(explicit=None):
    """Locate iperf3: an explicit file or folder, PATH, $IPERF3_PATH, beside this script, the current folder, then usual install places.
    Returns a full path, or None."""
    import glob, os
    names = ["iperf3.exe", "iperf3"] if os.name == "nt" else ["iperf3"]
    def pick(d):
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p): return p
        return None
    if explicit and explicit != "iperf3":
        explicit = os.path.expandvars(os.path.expanduser(explicit))
        if os.path.isdir(explicit): return pick(explicit)
        if os.path.isfile(explicit): return explicit
        w = shutil.which(explicit)
        return w
    w = shutil.which("iperf3")
    if w: return w
    home = os.path.expanduser("~")
    dirs = [os.environ.get("IPERF3_PATH", ""), os.path.dirname(os.path.abspath(__file__)), os.getcwd(), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
            r"C:\iperf3", r"C:\iperf", r"C:\tools\iperf3", r"C:\Program Files\iperf3", r"C:\Program Files (x86)\iperf3", os.path.join(home, "iperf3")]
    for pat in (os.path.join(home, "Downloads", "iperf*"), os.path.join(home, "Desktop", "iperf*"), r"C:\iperf*", os.path.join(home, "iperf*")): dirs += glob.glob(pat)
    for d in dirs:
        if d and os.path.isdir(d):
            p = pick(d) or pick(os.path.join(d, "bin"))
            if p: return p
        elif d and os.path.isfile(d): return d
    return None

def iperf3_argv(ip, mode, secs, streams, rate_mbps, port=5201, bind=None):
    ipaddress.ip_address(ip)                                   # never pass anything but a literal IP to the command line
    if mode not in MODES: raise ValueError(f"unknown iperf3 mode {mode}")
    argv = ["iperf3", "-c", ip, "-p", str(int(port)), "-t", str(int(secs)), "-P", str(int(streams)), "-J"]
    if mode.startswith("tcp") and secs >= 6: argv += ["-O", "2"]            # skip TCP slow start in the totals
    if mode.startswith("udp"): argv += ["-u", "-b", f"{float(rate_mbps):g}M"]
    if mode.endswith("up"): argv.append("-R")
    if bind: ipaddress.ip_address(bind); argv += ["-B", bind]       # source address: pins the route when this machine has several networks
    return argv

def _series(j):
    out = []
    for it in j.get("intervals", []):
        s = it.get("sum") or {}
        if "bits_per_second" in s and not s.get("omitted") and s.get("seconds", 1) >= 0.5: out.append(s["bits_per_second"] / 1e6)
    return out

def parse_iperf3(text, mode):
    try: j = json.loads(text)
    except Exception: return {"ok": False, "error": "iperf3 gave no JSON: " + (text.strip()[:200] or "empty output")}
    if j.get("error"): return {"ok": False, "error": _friendly(j["error"])}
    e = j.get("end") or {}
    ser = _series(j)
    res = {"ok": True, "tool": "iperf3", "mode": mode, "series_mbps": [round(x, 1) for x in ser]}
    if ser: res.update(min_mbps=round(min(ser), 1), max_mbps=round(max(ser), 1))
    if mode.startswith("udp"):
        s = e.get("sum") or {}; rcv = e.get("sum_received") or {}
        res.update(mbps=round((rcv.get("bits_per_second") or s.get("bits_per_second", 0)) / 1e6, 2), jitter_ms=round(s.get("jitter_ms", 0), 2),
                   loss_pct=round(s.get("lost_percent", 0), 2), packets=s.get("packets"))
    else:
        snd, rcv = e.get("sum_sent") or {}, e.get("sum_received") or {}
        res.update(mbps=round((rcv.get("bits_per_second") or snd.get("bits_per_second", 0)) / 1e6, 2), retransmits=snd.get("retransmits"))
    return res

def client_cmd(server_ip, port, mode, secs, streams, rate_mbps, bind=None):
    """The command the Wi-Fi client should run against the server PC."""
    ipaddress.ip_address(server_ip)
    c = f"iperf3 -c {server_ip}" + (f" -p {int(port)}" if int(port) != 5201 else "") + f" -t {int(secs)}"
    if int(streams) > 1: c += f" -P {int(streams)}"
    if mode.startswith("udp"): c += f" -u -b {float(rate_mbps):g}M"
    if mode.endswith("down"): c += " -R"
    if bind: ipaddress.ip_address(bind); c += f" -B {bind}"
    return c

def norm_host(h):
    h = (h or "").strip()
    return h[7:] if h.lower().startswith("::ffff:") else h          # dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d

def parse_iperf3_server(text):
    """Parse the JSON an `iperf3 -s -J` process prints after ONE test. The mode, peer and settings come from the
    server's own record, so the same code handles every client command. Direction is from the CLIENT's view:
    reverse=0 -> the client sent (upload), reverse=1 -> the server sent (download)."""
    try: j = json.loads(text)
    except Exception: return {"ok": False, "error": "iperf3 server gave no JSON: " + (text.strip()[:200] or "empty output")}
    if j.get("error"): return {"ok": False, "error": _friendly(j["error"])}
    st = (j.get("start") or {}); ts = st.get("test_start") or {}; e = j.get("end") or {}
    conn = (st.get("connected") or [{}])[0]
    udp = str(ts.get("protocol", "")).upper() == "UDP"; down = bool(ts.get("reverse"))
    mode = ("udp_" if udp else "tcp_") + ("down" if down else "up")
    ser = _series(j)
    res = {"ok": True, "tool": "iperf3", "mode": mode, "remote_host": norm_host(conn.get("remote_host")), "secs": ts.get("duration"),
           "streams": ts.get("num_streams"), "series_mbps": [round(x, 1) for x in ser]}
    if ser: res.update(min_mbps=round(min(ser), 1), max_mbps=round(max(ser), 1))
    snd, rcv, tot = e.get("sum_sent") or {}, e.get("sum_received") or {}, e.get("sum") or {}
    bps = rcv.get("bits_per_second") or snd.get("bits_per_second") or tot.get("bits_per_second") or 0   # exactly one side is filled in
    if not bps and not e: return {"ok": False, "error": "The test ended before it produced a result (client disconnected?)."}
    res["mbps"] = round(bps / 1e6, 2)
    if udp:
        res["target_mbps"] = round((st.get("target_bitrate") or ts.get("target_bitrate") or 0) / 1e6, 2) or None
        if not down:                                              # the server is the receiver, so it measured jitter and loss
            res.update(jitter_ms=round(tot.get("jitter_ms", 0), 2), loss_pct=round(tot.get("lost_percent", 0), 2), packets=tot.get("packets"))
        else: res.update(jitter_ms=None, loss_pct=None)           # the CLIENT measures those for -R; they appear in its own output
    elif down: res["retransmits"] = snd.get("retransmits")
    return res

def _friendly(err):
    if "Connection refused" in err or "unable to connect" in err:
        return "Could not connect: start an iperf3 server on the client first (`iperf3 -s`) and allow port 5201 through its firewall. (" + err[:80] + ")"
    return err

def run_iperf3(ip, mode, secs=10, streams=1, rate_mbps=50, runner=None, port=5201, bind=None, iperf_bin=None):
    """runner=None -> run on this machine; runner=<transport Runner> -> run on the AP."""
    argv = iperf3_argv(ip, mode, secs, streams, rate_mbps, port, bind)
    try:
        if runner is not None:
            out = runner.run(" ".join(shlex.quote(a) for a in argv) + " 2>&1", timeout=secs + 30)
            if "not found" in out and "{" not in out: return {"ok": False, "error": "iperf3 is not installed on the AP"}
        else:
            exe = find_iperf3(iperf_bin)
            if not exe:
                return {"ok": False, "error": "iperf3 was not found on this machine" + (f" at {iperf_bin}" if iperf_bin else "") + ". Searched PATH, this folder and the usual install folders. "
                        "Point to it with --iperf-bin \"C:\\path\\to\\iperf3.exe\" (a file or its folder), or install it (macOS: brew install iperf3 · Windows: https://iperf.fr/iperf-download.php · Linux: apt install iperf3)."}
            argv[0] = exe
            out = subprocess.run(argv, capture_output=True, text=True, timeout=secs + 30).stdout
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "iperf3 timed out"}
    except Exception as ex:
        return {"ok": False, "error": f"iperf3 failed: {ex}"}
    i = out.find("{")                                           # serial consoles may add noise before the JSON
    return parse_iperf3(out[i:] if i >= 0 else out, mode)

def parse_speedtest(text):
    try: j = json.loads(text)
    except Exception: return {"ok": False, "error": "speedtest gave no JSON: " + (text.strip()[:200] or "empty output")}
    if isinstance(j.get("download"), dict):                     # Ookla CLI: bandwidth in BYTES/s
        return {"ok": True, "tool": "speedtest", "mode": "speedtest", "down_mbps": round(j["download"]["bandwidth"] * 8 / 1e6, 1),
                "up_mbps": round(j["upload"]["bandwidth"] * 8 / 1e6, 1), "ping_ms": (j.get("ping") or {}).get("latency"),
                "jitter_ms": (j.get("ping") or {}).get("jitter"), "loss_pct": j.get("packetLoss"),
                "server": ((j.get("server") or {}).get("name") or "") + " " + ((j.get("server") or {}).get("location") or ""), "isp": j.get("isp")}
    if "download" in j:                                         # speedtest-cli: bits/s
        sv = j.get("server") or {}
        return {"ok": True, "tool": "speedtest-cli", "mode": "speedtest", "down_mbps": round(j["download"] / 1e6, 1),
                "up_mbps": round(j.get("upload", 0) / 1e6, 1), "ping_ms": j.get("ping"), "server": (sv.get("sponsor") or "") + " " + (sv.get("name") or ""),
                "isp": (j.get("client") or {}).get("isp")}
    return {"ok": False, "error": "unrecognised speedtest output"}

def run_speedtest():
    """Try the Ookla CLI first (`speedtest`), then `speedtest-cli`."""
    tries = []
    if shutil.which("speedtest"): tries.append(["speedtest", "--accept-license", "--accept-gdpr", "-f", "json"])
    if shutil.which("speedtest-cli"): tries.append(["speedtest-cli", "--json"])
    if not tries:
        return {"ok": False, "error": "No speedtest tool found. Install the Ookla CLI (macOS: `brew tap teamookla/speedtest && brew install speedtest`; "
                                       "Windows: `winget install Ookla.Speedtest.CLI`) or `pip install speedtest-cli`."}
    last = None
    for argv in tries:
        try: out = subprocess.run(argv, capture_output=True, text=True, timeout=120).stdout
        except Exception as ex: last = {"ok": False, "error": f"{argv[0]} failed: {ex}"}; continue
        r = parse_speedtest(out)
        if r["ok"]: return r
        last = r
    return last
