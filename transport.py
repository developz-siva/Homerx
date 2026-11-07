"""
transport.py - how the monitor runs commands on the AP. Every backend (iw / wl / qca) only needs `runner.run(cmd) -> str`,
so any of these transports work with any backend:

  Runner          ssh (or local shell when host is None)
  TelnetRunner    telnet to the device (embedded busybox telnetd, login optional); reconnects by itself if the link drops
  SerialRunner    UART / USB-serial console (needs `pip install pyserial`; console must be at a root shell or a login prompt)
  UbusHttpRunner  OpenWrt / prplOS style web API: JSON-RPC `ubus` over HTTP (/ubus), runs commands through rpcd's `file exec`.
                  Needs rpcd + uhttpd-mod-ubus and a user allowed to call file.exec (root on stock OpenWrt).
Vendor web UIs that don't expose ubus (many RDK-B / carrier GUIs) can't be driven generically - use ssh/serial there.
"""
import json, re, socket, subprocess, sys, threading, time, urllib.request

def _warn(msg): sys.stderr.write(f"[warn] {msg}\n")

class Runner:
    def __init__(self, host=None, user="root", port=22):
        self.host, self.user, self.port = host, user, port
    def run(self, cmd, timeout=15):
        if self.host:
            argv = ["ssh", "-p", str(self.port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{self.user}@{self.host}", cmd]
        else:
            argv = ["sh", "-c", cmd]
        try: return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout
        except Exception as e:
            _warn(f"`{cmd}` failed: {e}"); return ""

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]")

class SerialRunner:
    """Send `cmd; echo <marker>` on the console and read until the marker. The marker is typed with '' inside it so that an
    echoed command line can't be mistaken for the real marker."""
    host = "serial"
    def __init__(self, port, baud=115200, user=None, password=None, _serial=None):
        if _serial is None:
            try: import serial
            except ImportError: sys.exit("serial transport needs pyserial:  pip install pyserial")
            _serial = serial.Serial(port, baud, timeout=0.2)
        self.s, self.lock, self.n = _serial, threading.Lock(), 0
        self._login(user, password)
        self._raw("stty -echo 2>/dev/null; PS1=''\n", 1.0)

    def _drain(self, secs):
        end, buf = time.time() + secs, b""
        while time.time() < end:
            c = self.s.read(4096)
            if c: buf += c; end = max(end, time.time() + 0.3)
        return buf.decode(errors="replace")
    def _raw(self, text, wait): self.s.write(text.encode()); return self._drain(wait)
    def _login(self, user, password):
        out = self._raw("\n", 1.5).lower()
        if "login:" in out:
            if not user: sys.exit("console is at a login prompt: pass --serial-user / --password")
            out = self._raw(user + "\n", 1.5).lower()
        if "password:" in out:
            if password is None: sys.exit("console asks for a password: pass --password")
            self._raw(password + "\n", 2.0)

    def run(self, cmd, timeout=20):
        with self.lock:
            self.n += 1
            tag, marker = f"__WM_E''ND_{self.n}__", f"__WM_END_{self.n}__"
            self.s.reset_input_buffer()
            self.s.write(f"{cmd}; echo {tag}\n".encode())
            buf, end = "", time.time() + timeout
            while time.time() < end:
                c = self.s.read(4096)
                if c:
                    buf += c.decode(errors="replace")
                    if marker in ANSI.sub("", buf).replace("\r", ""): break
            else:
                _warn(f"serial: timeout waiting for `{cmd[:60]}` (slow link? use --max-flows or --no-flows)")
            text = ANSI.sub("", buf).replace("\r", "")
            i = text.find(tag)                       # drop the echoed command line, if the console echoes
            if i >= 0:
                j = text.find("\n", i); text = text[j + 1:] if j >= 0 else ""
            return text.split(marker)[0]

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

class TelnetRunner:
    """Telnet client without telnetlib (removed in Python 3.13). Refuses every option, handles an optional login, then
    runs commands the same marker way as SerialRunner. Reconnects once per call if the connection was lost."""
    def __init__(self, host, port=23, user=None, password=None, connect_timeout=8):
        self.host, self.port, self.user, self.password, self.ct = host, int(port), user, password, connect_timeout
        self.sock, self.lock, self.n, self._iac = None, threading.Lock(), 0, b""
        self._connect()

    # ---- low level ---------------------------------------------------------------------------------------
    def _strip(self, data):
        """Remove telnet IAC sequences from received bytes, answering negotiations with WONT / DONT."""
        data, out, i = self._iac + data, bytearray(), 0
        self._iac = b""
        while i < len(data):
            b = data[i]
            if b != IAC: out.append(b); i += 1; continue
            if i + 1 >= len(data): self._iac = data[i:]; break
            c = data[i + 1]
            if c == IAC: out.append(IAC); i += 2
            elif c in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data): self._iac = data[i:]; break
                opt = data[i + 2]
                if c == DO: self.sock.sendall(bytes([IAC, WONT, opt]))
                elif c == WILL: self.sock.sendall(bytes([IAC, DONT, opt]))
                i += 3
            elif c == SB:
                j = data.find(bytes([IAC, SE]), i)
                if j < 0: self._iac = data[i:]; break
                i = j + 2
            else: i += 2
        return bytes(out)
    def _read(self, secs):
        self.sock.settimeout(0.2); end, buf = time.time() + secs, b""
        while time.time() < end:
            try: c = self.sock.recv(4096)
            except socket.timeout: continue
            if not c:
                if buf: break                                         # keep what arrived (e.g. "Login incorrect") before the hang-up
                raise ConnectionError("connection closed by the device")
            buf += self._strip(c); end = max(end, time.time() + 0.3)
        return buf.decode(errors="replace").replace("\r", "")
    def _send(self, text): self.sock.sendall(text.encode("utf-8", "replace").replace(bytes([IAC]), bytes([IAC, IAC])))

    def _connect(self):
        self.close()
        try: self.sock = socket.create_connection((self.host, self.port), timeout=self.ct)
        except OSError as e: raise ConnectionError(f"cannot connect to {self.host}:{self.port} ({e})")
        self._iac = b""
        out = self._read(1.5).lower()
        for _ in range(3):                                           # login / password prompts, if any
            if out.rstrip().endswith(("login:", "username:", "user:", "user name:")) or "login:" in out[-40:]:
                if not self.user: raise ConnectionError("the device asks for a login: pass --user (and --password)")
                self._send(self.user + "\n"); out = self._read(1.5).lower()
            elif "password:" in out[-40:]:
                if self.password is None: raise ConnectionError("the device asks for a password: pass --password")
                self._send(self.password + "\n"); out = self._read(2.0).lower()
            else: break
        if any(w in out for w in ("login incorrect", "login failed", "access denied", "authentication fail")): raise ConnectionError("login was rejected")
        self._send("\n"); self._read(0.8)
        self._send("stty -echo 2>/dev/null; PS1=''\n"); self._read(0.8)
    def close(self):
        try:
            if self.sock: self.sock.close()
        except OSError: pass
        self.sock = None

    # ---- Runner API ----------------------------------------------------------------------------------------
    def _run_once(self, cmd, timeout):
        self.n += 1
        tag, marker = f"__WM_E''ND_{self.n}__", f"__WM_END_{self.n}__"
        self._read(0.05); self._send(f"{cmd}; echo {tag}\n")
        buf, end = "", time.time() + timeout
        self.sock.settimeout(0.3)
        while time.time() < end:
            try: c = self.sock.recv(8192)
            except socket.timeout: continue
            if not c: raise ConnectionError("connection closed by the device")
            buf += self._strip(c).decode(errors="replace").replace("\r", "")
            if marker in ANSI.sub("", buf): break
        else: raise TimeoutError(f"timeout waiting for `{cmd[:60]}`")
        text = ANSI.sub("", buf)
        i = text.find(tag)                                           # drop the echoed command line, if the shell echoes
        if i >= 0:
            j = text.find("\n", i); text = text[j + 1:] if j >= 0 else ""
        return text.split(marker)[0]
    def run(self, cmd, timeout=20):
        with self.lock:
            for attempt in (0, 1):
                try:
                    if self.sock is None: self._connect()
                    return self._run_once(cmd, timeout)
                except (OSError, ConnectionError, TimeoutError) as e:
                    self.close()
                    if attempt: _warn(f"telnet `{cmd[:50]}` failed: {e}"); return ""
        return ""

class UbusHttpRunner:
    host = "ubus-http"
    def __init__(self, url, user="root", password=""):
        self.url = url.rstrip("/") + "/ubus"; self.user, self.password, self.sid, self.id = user, password, None, 0
        self._login()
    def _call(self, sid, obj, method, params, timeout=15):
        self.id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.id, "method": "call", "params": [sid, obj, method, params]}).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)
    def _login(self):
        r = self._call("0" * 32, "session", "login", {"username": self.user, "password": self.password})
        try: self.sid = r["result"][1]["ubus_rpc_session"]
        except Exception: sys.exit(f"ubus login failed ({r.get('error') or r.get('result')}); check URL / user / password")
    def run(self, cmd, timeout=15):
        try:
            for attempt in (0, 1):
                r = self._call(self.sid, "file", "exec", {"command": "/bin/sh", "params": ["-c", cmd]}, timeout)
                res = r.get("result") or [None]
                if res[0] == 6 and attempt == 0: self._login(); continue        # session expired
                if res[0] == 6: _warn("ubus: access denied for file.exec - give this user the 'file exec' ACL in rpcd"); return ""
                if res[0] != 0: _warn(f"ubus error {res[0]} for `{cmd[:60]}`"); return ""
                return (res[1] or {}).get("stdout", "")
        except Exception as e:
            _warn(f"ubus `{cmd[:60]}` failed: {e}")
        return ""
