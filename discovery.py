"""
discovery.py - find every device on the home LAN from the machine running the dashboard (e.g. your MacBook),
and read this Mac's own Wi-Fi link. Used by `--backend local`. macOS-oriented but works on Linux too.
"""
import concurrent.futures as cf, ipaddress, platform, re, socket, subprocess

def norm_mac(m):
    """macOS prints MACs without leading zeros ('a4:83:e7:0:0:1') - normalise to 'a4:83:e7:00:00:01'."""
    parts = m.strip().lower().split(":")
    return ":".join(p.zfill(2) for p in parts) if len(parts) == 6 else None

def _skip_mac(m):
    return m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or m.startswith("01:00:5e") or m.startswith("33:33")

def parse_arp(text):
    """`arp -an` (macOS: '? (192.168.1.5) at a4:83:e7:0:0:1 on en0 ifscope [ethernet]'; Linux similar) -> {ip: mac}"""
    out = {}
    for line in text.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{5,17})\b", line)
        if not m or "incomplete" in line: continue
        mac = norm_mac(m.group(2))
        if mac and not _skip_mac(mac): out[m.group(1)] = mac
    return out

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1)); return s.getsockname()[0]   # no packet is sent
    except OSError:
        return None
    finally:
        s.close()

def default_subnet(ip=None):
    ip = ip or local_ip()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ip else None

def _ping(ip):
    flags = ["-c", "1", "-t", "1"] if platform.system() == "Darwin" else ["-c", "1", "-W", "1"]
    try: subprocess.run(["ping", *flags, ip], capture_output=True, timeout=3)
    except Exception: pass

def scan(subnet=None, sweep=True):
    """Ping-sweep the subnet to populate the ARP cache, then read it. -> {ip: mac}"""
    subnet = subnet or default_subnet()
    if sweep and subnet:
        hosts = [str(h) for h in ipaddress.ip_network(subnet).hosts()][:512]
        with cf.ThreadPoolExecutor(64) as ex: list(ex.map(_ping, hosts))
    try: txt = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10).stdout
    except Exception: txt = ""
    arp = parse_arp(txt)
    if subnet:
        net = ipaddress.ip_network(subnet)
        arp = {ip: m for ip, m in arp.items() if ipaddress.ip_address(ip) in net}
    return arp

def rdns(ips, timeout_workers=32):
    """reverse-DNS names (router DHCP/DNS usually knows them) -> {ip: name}"""
    def one(ip):
        try: return ip, socket.gethostbyaddr(ip)[0].split(".")[0]
        except Exception: return ip, ""
    with cf.ThreadPoolExecutor(timeout_workers) as ex: return {ip: n for ip, n in ex.map(one, ips) if n}

def parse_mac_wifi(text):
    """`system_profiler SPAirPortDataType` -> this Mac's current Wi-Fi link, or None.
    Best effort: field names differ slightly between macOS versions (the SSID line is the 'Current Network Information' child)."""
    if "Current Network Information" not in text: return None
    iface = re.search(r"^\s*(en\d+):\s*$", text, re.M)
    mac = re.search(r"MAC Address:\s*([0-9a-fA-F:]{11,17})", text)
    sec = text.split("Current Network Information", 1)[1]
    sec = re.split(r"Other Local Wi-Fi Networks", sec)[0]
    ch = re.search(r"Channel:\s*(\d+)\s*\(([\d.]+)\s*GHz", sec)
    sn = re.search(r"Signal / Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", sec)
    rate = re.search(r"Transmit Rate:\s*(\d+)", sec)
    if not (sn and rate): return None
    ghz = float(ch.group(2)) if ch else 5.0
    return {"iface": iface.group(1) if iface else "en0", "mac": norm_mac(mac.group(1)) if mac else None,
            "channel": int(ch.group(1)) if ch else None, "band": "2.4G" if ghz < 3 else ("5G" if ghz < 5.9 else "6G"),
            "rssi": int(sn.group(1)), "noise": int(sn.group(2)), "tx_rate": float(rate.group(1))}
