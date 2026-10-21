"""Gommage: tiny Tor client (Windows, Linux) with custom bridges (webtunnel/obfs4/...), system proxy or whole-system VPN.
Run: python gommage.py   (first run needs the Tor Expert Bundle, or on Linux the system's tor; see ensure_tor)
"""
import ctypes, glob, hashlib, io, ipaddress, json, ntpath, os, re, shutil, signal, socket, sqlite3, ssl, subprocess, sys
import tarfile, threading, time, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))  # .deb install vendors pywebview here
import webview

WIN = sys.platform == "win32"
if WIN:
    import winreg
EXE = ".exe" if WIN else ""
VER = "15.0.25"  # ponytail: pinned; bump when Tor ships a new bundle
URL = f"https://dist.torproject.org/torbrowser/{VER}/tor-expert-bundle-{'windows' if WIN else 'linux'}-x86_64-{VER}.tar.gz"
if WIN:
    HOME = os.path.join(os.environ["APPDATA"], "Gommage")
    OLD_HOME = os.path.join(os.environ["APPDATA"], "TorBridge")  # the app's former name: carry its data over
    if os.path.isdir(OLD_HOME) and not os.path.exists(HOME):
        try:
            os.rename(OLD_HOME, HOME)
        except OSError:
            HOME = OLD_HOME  # old copy still running and holding files; keep using its folder, move it next launch
else:  # GOMMAGE_HOME: set by relaunch_root so the root copy keeps the user's settings
    HOME = os.environ.get("GOMMAGE_HOME") or os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Gommage")
SOCKS = 9050  # defaults; overwritten from settings by apply_ports()
HTTP = 8118  # HTTPS CONNECT proxy: browsers resolve DNS through Tor (plain SOCKS via WinINET leaks/breaks DNS)
LISTEN = "127.0.0.1"
LOCAL = "127.0.0.1"  # address this PC uses to reach Tor (LISTEN, or loopback when LISTEN is 0.0.0.0)
REG = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
SETTINGS = os.path.join(HOME, "settings.json")
DB = os.path.join(HOME, "history.db")
LOG = os.path.join(HOME, "log.txt")
NOFLASH = 0x08000000 if WIN else 0  # CREATE_NO_WINDOW
COUNTRIES = {"Any": "", "Netherlands": "nl", "Germany": "de", "France": "fr", "UK": "gb", "USA": "us",
             "Canada": "ca", "Sweden": "se", "Switzerland": "ch", "Finland": "fi", "Austria": "at"}
SINGBOX = os.path.join(HOME, "sing-box" + EXE)
SB_VER = "1.11.15"  # ponytail: pinned; config below uses 1.11 syntax (newer majors renamed DNS fields)
SB_FILE = f"sing-box-{SB_VER}-" + ("windows-amd64.zip" if WIN else "linux-amd64.tar.gz")  # ponytail: x86_64 only
# Integrity pins: a download that doesn't match is never run. sing-box's comes from its GitHub release digest.
# Tor's is from Tor Project's sha256sums-signed-build.txt for VER (fetched over Tor). Update both whenever a version is
# bumped; if TOR_SHA256 is ever left empty the bundle is checked against that checksum list from the same server.
SB_SHA256 = ("9acbda81d7a9a93d8d0616990cf8b804523adfcd0215d11a2dd9370746d2be28" if WIN else
             "950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5")
TOR_SHA256 = ("c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252" if WIN else
              "19cf18726eecb362e0f21d27afa9ea9efe5da928bfdfbb1ceb5fe54519e87f4a")
APP_MODES = {"all": "All apps via Tor", "except": "All apps except the list", "only": "Only apps in the list"}
# Tor's own traffic must never loop into the tunnel
TOR_PROCS = ["tor.exe", "lyrebird.exe", "conjure-client.exe"] if WIN else ["tor", "lyrebird", "obfs4proxy", "conjure-client"]
FW_RULE = "Gommage-noIPv6"
DNS_PORT = 9053  # Tor's DNS for VPN mode; not 53, which local DNS tools (e.g. Shecan) often hold


def kill_tree(proc):
    if WIN:
        run("taskkill", "/T", "/F", "/PID", str(proc.pid))
    else:  # Tor was started in its own session (see popen), so its process group is Tor + its transports
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass


def run(*cmd, input=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=NOFLASH, input=input)
    except FileNotFoundError:
        return None  # optional tool not installed (e.g. resolvectl, nft)


def popen(cmd, **kw):
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=NOFLASH,
                            start_new_session=not WIN, **kw)


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() if WIN else os.geteuid() == 0


def block_ipv6(on):
    """Block global IPv6 (2000::/3) outbound; loopback/link-local untouched. Needs admin/root."""
    if WIN:
        run("netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}")
        if on:
            run("netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE}", "dir=out",
                "action=block", "remoteip=2000::/3")
        else:
            run("netsh", "advfirewall", "firewall", "delete", "rule", "name=TorBridge-noIPv6")  # left by the old name
    elif shutil.which("nft"):
        run("nft", "delete", "table", "inet", "gommage")
        if on:
            run("nft", "-f", "-", input="table inet gommage { chain out { type filter hook output priority 0;"
                                        " ip6 daddr 2000::/3 reject; } }")
    else:
        rule = ["OUTPUT", "-d", "2000::/3", "-m", "comment", "--comment", FW_RULE, "-j", "REJECT"]
        while (r := run("ip6tables", "-D", *rule)) and r.returncode == 0:
            pass
        if on:
            run("ip6tables", "-I", *rule)


def db(sql, args=()):
    with sqlite3.connect(DB) as c:
        c.execute("CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, start TEXT, end TEXT,"
                  " mode TEXT, country TEXT, status TEXT)")
        cur = c.execute(sql, args)
        return cur.lastrowid if sql.lstrip().upper().startswith("INSERT") else cur.fetchall()


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def apply_ports(listen, socks, http):
    """Validate user-entered listen IP/ports and make them active. Raises ValueError on bad input."""
    global LISTEN, LOCAL, SOCKS, HTTP
    ip = ipaddress.IPv4Address(listen.strip())
    s, h = int(socks), int(http)
    if not (1 <= s <= 65535 and 1 <= h <= 65535) or s == h or DNS_PORT in (s, h):
        raise ValueError(f"ports must be 1-65535, different from each other and not {DNS_PORT} (used for DNS)")
    LISTEN, SOCKS, HTTP = str(ip), s, h
    LOCAL = "127.0.0.1" if ip.is_unspecified else LISTEN


def migrate_old_name():
    """Drop the old name's autostart entry (the data folder is moved at import, above)."""
    if not WIN:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, "TorBridge")
            return True  # autostart was on under the old name: caller re-registers it
    except OSError:
        return False


def load_settings():
    s = {"bridges": "", "country": "Any", "vpn": False, "block_ipv6": False, "bypass": "", "bypass_ir": True, "app_mode": "all", "apps": "",
         "listen": "127.0.0.1", "socks": SOCKS, "http": HTTP, "autostart": False, "autoconnect": False,
         "last_good": [], "community": True, "stats": {}}
    try:
        s.update(json.load(open(SETTINGS, encoding="utf8")))
    except (OSError, ValueError):
        try:  # older versions kept only bridges.txt
            s["bridges"] = open(os.path.join(HOME, "bridges.txt"), encoding="utf8").read()
        except OSError:
            pass
    return s


def set_proxy(on):
    if not WIN:  # GNOME (and desktops that read its settings); as root it would write root's dconf, so skip
        if shutil.which("gsettings") and os.geteuid() != 0:
            for scheme in ("http", "https"):
                run("gsettings", "set", f"org.gnome.system.proxy.{scheme}", "host", LOCAL)
                run("gsettings", "set", f"org.gnome.system.proxy.{scheme}", "port", str(HTTP))
            run("gsettings", "set", "org.gnome.system.proxy", "mode", "manual" if on else "none")
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(on))
        if on:
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"{LOCAL}:{HTTP}")
    w = ctypes.windll.wininet  # tell running apps to reload
    w.InternetSetOptionW(0, 39, 0, 0)
    w.InternetSetOptionW(0, 37, 0, 0)


def check_sha256(data, expect, what):
    got = hashlib.sha256(data).hexdigest()
    if got != expect.lower():
        raise RuntimeError(f"{what} failed its integrity check (sha256 {got[:16]}…) - not using it")


def tor_sha256(base, log):
    """Expected hash of the Tor bundle: the pin if set, else Tor Project's published checksum list."""
    if TOR_SHA256:
        return TOR_SHA256
    name = os.path.basename(URL)
    try:
        sums = urllib.request.urlopen(f"{base}/sha256sums-signed-build.txt", timeout=60).read().decode()
        return next(l.split()[0] for l in sums.splitlines() if l.strip().endswith(name))
    except Exception as e:
        log(f"  checksum list unavailable: {e}")
        return None


def builtin_bridges():
    """Tor's built-in bridges {transport: [lines]}; they ship with the Expert Bundle only (not distro packages)."""
    try:
        return json.load(open(os.path.join(HOME, "tor", "pluggable_transports", "pt_config.json")))["bridges"]
    except OSError:
        return {}


def geoip(name="geoip"):
    """Tor's GeoIP file: the bundle's, else (Linux) the distro's tor-geoipdb."""
    p = os.path.join(HOME, "data", name)
    return p if WIN or os.path.exists(p) else os.path.join("/usr/share/tor", name)


def ensure_tor(log):
    """(tor, pluggable transport): the Expert Bundle in HOME, else on Linux the system's tor + lyrebird/obfs4proxy,
    else the bundle, from a file you downloaded or fetched here."""
    tor = os.path.join(HOME, "tor", "tor" + EXE)
    found = tor, os.path.join(HOME, "tor", "pluggable_transports", "lyrebird" + EXE)
    if os.path.exists(tor):
        return found
    if not WIN and shutil.which("tor") and (pt := shutil.which("lyrebird") or shutil.which("obfs4proxy")):
        return shutil.which("tor"), pt
    # 1) a bundle already downloaded by hand (Downloads or app folder)
    for d in (HOME, os.path.expanduser(os.path.join("~", "Downloads"))):
        for f in glob.glob(os.path.join(d, "**", os.path.basename(URL)), recursive=True):
            data = open(f, "rb").read()
            if TOR_SHA256:
                check_sha256(data, TOR_SHA256, f)
            else:
                log(f"  {f}: no pinned hash to check against, using the file you provided")
            log(f"Using {f}")
            tarfile.open(fileobj=io.BytesIO(data)).extractall(HOME, filter="data")
            return found
    # 2) download, trying mirrors
    for u in (URL, URL.replace("dist.", "archive.").replace("/torbrowser/", "/tor-package-archive/torbrowser/")):
        try:
            log(f"Downloading {u}")
            data = urllib.request.urlopen(u, timeout=60).read()
            expect = tor_sha256(u.rsplit("/", 1)[0], log)
            if not expect:
                raise RuntimeError("couldn't verify the download")
            check_sha256(data, expect, "Tor download")
            tarfile.open(fileobj=io.BytesIO(data)).extractall(HOME, filter="data")
            return found
        except Exception as e:
            log(f"  failed: {e}")
    raise RuntimeError(f"Download blocked. Get this file with any VPN/proxy/friend:\n{URL}\n"
                       f"and put it in your Downloads folder (or {HOME}), then press Connect again.")


def ensure_singbox(log):
    """sing-box (TUN + per-app routing, wintun embedded on Windows); fetched through Tor since GitHub may be filtered."""
    if os.path.exists(SINGBOX):
        return
    local = glob.glob(os.path.expanduser(os.path.join("~", "Downloads", "**", SB_FILE)), recursive=True)
    if local:
        log(f"Using {local[0]}")
        data = open(local[0], "rb").read()
    else:
        # api.github.com rejects most Tor exits, so the release is pinned instead of looked up
        via_tor = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://{LOCAL}:{HTTP}"}))
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VER}/{SB_FILE}"
        log(f"Downloading {url}")
        r = via_tor.open(url, timeout=120)
        total, data = int(r.headers.get("Content-Length", 0)), b""
        while chunk := r.read(256 * 1024):
            data += chunk
            log(f"  sing-box: {len(data) // 1024} / {total // 1024} KB")
    check_sha256(data, SB_SHA256, "sing-box download")
    if WIN:
        z = zipfile.ZipFile(io.BytesIO(data))
        open(SINGBOX, "wb").write(z.read(next(m for m in z.namelist() if m.endswith("sing-box.exe"))))
    else:
        t = tarfile.open(fileobj=io.BytesIO(data))
        open(SINGBOX, "wb").write(t.extractfile(next(m for m in t.getmembers() if m.name.endswith("/sing-box"))).read())
        os.chmod(SINGBOX, 0o755)


def clean_bridges(text):
    # accept lines with or without leading "Bridge "; drop blanks/comments
    out = []
    for l in text.splitlines():
        l = re.sub(r"^\s*bridge\s+", "", l.strip(), flags=re.I)
        if l and not l.startswith("#") and l not in out:
            out.append(l)
    return out


def bridge_target(line):
    """(host, port, tls) lyrebird dials for a bridge line, or None if it can't be probed (snowflake/meek)."""
    m = re.search(r"url=https?://([^/\s:]+)", line)
    if line.startswith("webtunnel") and m:
        return m.group(1), 443, True
    m = re.match(r"\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
    if m and not m.group(1).startswith("192.0.2."):
        return m.group(1), int(m.group(2)), False
    return None


def probe(line, timeout=6):
    """Latency in ms if reachable, False if not, None = transport we can't probe directly."""
    t = bridge_target(line)
    if not t:
        return None
    host, port, tls = t
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout) as c:
            if tls:  # webtunnel: real cert check catches DNS poisoning + wrong-cert bridges
                with ssl.create_default_context().wrap_socket(c, server_hostname=host):
                    pass
        return round((time.perf_counter() - t0) * 1000)
    except OSError:
        return False


def probe_all(lines, timeout=6):
    with ThreadPoolExecutor(128) as ex:
        return dict(zip(lines, ex.map(lambda l: probe(l, timeout), lines)))


# ---------- public bridge lists ----------
# Auto-updated collections on GitHub. Fetched through Tor when connected, otherwise direct, then via the jsDelivr
# mirror (often reachable when raw.githubusercontent.com is not). Lines are only accepted if they match a strict
# obfs4 / webtunnel shape, so a tampered list can't inject anything else. Bridges seen in several independent
# sources rank higher: planting a hostile bridge in more than one list is harder.
BRIDGE_SOURCES = [
    ("Delta-Kronecker", "Delta-Kronecker/Tor-Bridges-Collector", ["bridge/obfs4_tested.txt", "bridge/webtunnel_tested.txt"]),
    ("scriptzteam", "scriptzteam/Tor-Bridges-Collector", ["bridges-webtunnel"]),
]
VALID_BRIDGE = re.compile(
    r"obfs4 \d{1,3}(?:\.\d{1,3}){3}:\d{1,5} [0-9A-F]{40} cert=[A-Za-z0-9+/]{60,90} iat-mode=[012]"
    r"|webtunnel \[[0-9a-fA-F:]+\]:\d{1,5} [0-9A-F]{40} url=https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~/-]*)? ver=[0-9.]+")


def fetch_public(via_proxy=None, log=print):
    """{bridge line: [source names]} from the public lists; only well-formed obfs4/webtunnel lines."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": via_proxy} if via_proxy else {}))
    found = {}
    for name, repo, files in BRIDGE_SOURCES:
        for f in files:
            for url in (f"https://raw.githubusercontent.com/{repo}/main/{f}", f"https://cdn.jsdelivr.net/gh/{repo}@main/{f}"):
                try:
                    text = opener.open(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}),
                                       timeout=20).read(2_000_000).decode("utf8", "replace")
                except Exception as e:
                    log(f"public list {name}/{f}: {e}")
                    continue
                ok = [l for l in clean_bridges(text) if VALID_BRIDGE.fullmatch(l)]
                for l in ok:
                    found.setdefault(l, [])
                    if name not in found[l]:
                        found[l].append(name)
                log(f"public list {name}/{f}: {len(ok)} bridges")
                break
    return found


def fingerprint(line):
    m = re.search(r"\b([0-9A-F]{40})\b", line)
    return m.group(1) if m else line


def bridge_score(latency, stat):
    """Lower is better: probe latency, scaled down by past successes and up by past failures."""
    ok, fail = (stat or [0, 0, 0])[:2]
    return latency * (1 + fail) / (1 + 2 * ok)


def pick_public(found, res, limit=15):
    """Reachable public bridges, one per fingerprint: up to 2/3 confirmed by several lists, the rest fastest
    (keeps a mix of transports, since only some lists carry obfs4)."""
    seen, alive = set(), []
    for l in sorted((l for l in found if res.get(l) not in (False, None)), key=lambda l: res[l]):
        if fingerprint(l) not in seen:
            seen.add(fingerprint(l))
            alive.append(l)
    multi = [l for l in alive if len(found[l]) > 1][:limit * 2 // 3]
    return multi + [l for l in alive if l not in multi][:limit - len(multi)]


def plan_tiers(lines, res, builtin, stats=None, public=None):
    """Ordered attempts: your reachable bridges best-first (latency + track record), then untestable ones,
    then public lists (fetched lazily: None = fetch if reached), then built-ins. Bridges that keep failing go last."""
    stats = stats or {}
    hist = lambda l: stats.get(fingerprint(l))
    alive = sorted((l for l in lines if res.get(l) not in (False, None)), key=lambda l: bridge_score(res[l], hist(l)))
    flaky = [l for l in alive if (hist(l) or [0, 0])[0] == 0 and (hist(l) or [0, 0])[1] >= 3]
    alive = [l for l in alive if l not in flaky]
    untested = [l for l in lines if res.get(l) is None]
    tiers = [("best bridges", alive[:3]), ("other bridges", alive[3:]), ("your snowflake/meek", untested)]
    if public:
        tiers.append(("public lists", None))
    tiers += [(f"built-in {n}", builtin.get(n, [])) for n in ("obfs4", "snowflake", "meek")]
    tiers.append(("bridges that keep failing", flaky))
    seen, out = set(), []
    for name, t in tiers:  # drop empty tiers and lines already tried earlier; keep the lazy public placeholder
        if t is None:
            out.append((name, None))
            continue
        t = [l for l in t if l not in seen]
        seen.update(t)
        if t:
            out.append((name, t))
    return out


MOAT = "https://bridges.torproject.org/moat/circumvention/"
# ponytail: Tor Browser's domain-fronted route to Moat; unverified from Iran, used only as a last resort
MOAT_FRONT = ("https://www.phpmyadmin.net/moat/circumvention/", "1723079976.rsc.cdn77.org")


def bridge_strings(obj):
    """Every bridge line anywhere in a Moat JSON reply."""
    if isinstance(obj, str):
        return [obj] if re.match(r"(obfs4|webtunnel|snowflake|meek_lite|conjure) ", obj) else []
    items = obj.values() if isinstance(obj, dict) else obj if isinstance(obj, list) else []
    return [b for x in items for b in bridge_strings(x)]


def fetch_bridges(via_proxy=None, log=print):
    """Ask the Tor Project (Moat API) for bridges that work in Iran. Tries through Tor, direct, then fronted."""
    body = json.dumps({"country": "ir", "transports": ["obfs4", "webtunnel", "snowflake", "meek"]}).encode()
    routes = ([("via Tor", MOAT, None, via_proxy)] if via_proxy else []) + \
             [("direct", MOAT, None, None), ("fronted", MOAT_FRONT[0], MOAT_FRONT[1], None)]
    for name, base, host, proxy in routes:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy} if proxy else {}))
        for ep, data in (("settings", body), ("builtin", b"{}")):
            req = urllib.request.Request(base + ep, data=data, method="POST",
                                         headers={"Content-Type": "application/vnd.api+json", **({"Host": host} if host else {})})
            try:
                got = bridge_strings(json.load(opener.open(req, timeout=40)))
                if got:
                    log(f"got {len(got)} bridges from Tor Project ({name}, {ep})")
                    return list(dict.fromkeys(got))
            except Exception as e:
                log(f"bridge fetch {name}/{ep}: {e}")
    return []


def speed_test(proxy, seconds=8):
    """(latency_ms, mbps) through the HTTP proxy, downloading from Cloudflare for at most `seconds`."""
    o = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}))
    o.addheaders = [("User-Agent", "Mozilla/5.0")]  # Cloudflare 403s urllib's default UA
    t0 = time.perf_counter()
    o.open("https://speed.cloudflare.com/__down?bytes=0", timeout=30).read()
    lat = (time.perf_counter() - t0) * 1000
    r = o.open("https://speed.cloudflare.com/__down?bytes=25000000", timeout=30)
    t0, n = time.perf_counter(), 0
    while time.perf_counter() - t0 < seconds and (chunk := r.read(64 * 1024)):
        n += len(chunk)
    return round(lat), n * 8 / 1e6 / max(time.perf_counter() - t0, 0.001)


# seconds without bootstrap progress before switching bridges. Below 75% the bridge itself is failing, so
# give up fast; at 75%+ the bridge works and only circuits are slow (often a strict exit country), so be patient.
STALL_EARLY, STALL_LATE = 40, 180


def control(*cmds):
    """Send commands to Tor's ControlPort (cookie auth). Returns the raw reply."""
    port = open(os.path.join(HOME, "control.port")).read().strip().split(":")[-1]
    cookie = open(os.path.join(HOME, "data", "control_auth_cookie"), "rb").read().hex()
    with socket.create_connection(("127.0.0.1", int(port)), 5) as c:
        c.sendall(("".join(f"{x}\r\n" for x in (f"AUTHENTICATE {cookie}",) + cmds + ("QUIT",))).encode())
        out = b""
        while chunk := c.recv(4096):
            out += chunk
    return out.decode(errors="replace")


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
FROZEN = getattr(sys, "frozen", False)  # running as the PyInstaller exe
APP_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # where ui.html, fonts, assets live


def self_cmd():
    """(program, args) that start this app again without a console window."""
    if FROZEN:
        return sys.executable, ""
    return sys.executable.replace("python.exe", "pythonw.exe"), f'"{os.path.abspath(__file__)}"'


def set_autostart(on):
    if not WIN:  # XDG autostart entry, read by GNOME/KDE/Xfce at login
        f = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "autostart", "gommage.desktop")
        if on:
            os.makedirs(os.path.dirname(f), exist_ok=True)
            exe, args = self_cmd()
            open(f, "w").write(f'[Desktop Entry]\nType=Application\nName=Gommage\nExec="{exe}" {args}\n')
        elif os.path.exists(f):
            os.remove(f)
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            exe, args = self_cmd()
            winreg.SetValueEx(k, "Gommage", 0, winreg.REG_SZ, f'"{exe}" {args}'.strip())
        else:
            try:
                winreg.DeleteValue(k, "Gommage")
            except FileNotFoundError:
                pass


def split_nets(text):
    """Direct list -> (cidrs, domains). Lines: IP, CIDR or domain; '#' comments."""
    nets, hosts = [], []
    for l in text.splitlines():
        l = l.split("#")[0].strip()
        if not l:
            continue
        try:
            nets.append(str(ipaddress.ip_network(l, strict=False)))
        except ValueError:
            hosts.append(re.sub(r"^\w+://|/.*$", "", l))
    return nets, hosts


def app_names(text):
    """App list -> exe names (accepts full paths too), lowercase-insensitive match is done by sing-box."""
    return [ntpath.basename(l.strip()) for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def country_nets(geoip, cc):
    """CIDRs of one country from Tor's geoip file (lines: low_int,high_int,CC)."""
    out = []
    for l in open(geoip):
        p = l.strip().split(",")
        if len(p) == 3 and p[2] == cc:
            lo, hi = ipaddress.IPv4Address(int(p[0])), ipaddress.IPv4Address(int(p[1]))
            out += [str(n) for n in ipaddress.summarize_address_range(lo, hi)]
    return out


def singbox_config(mode, apps, direct_cidrs, direct_domains, socks):
    """sing-box 1.11 config: TUN for the whole system, rules decide Tor vs direct per app / IP / domain."""
    direct = [{"process_name": TOR_PROCS, "outbound": "direct"}, {"ip_is_private": True, "outbound": "direct"}]
    if direct_cidrs:
        direct.append({"ip_cidr": direct_cidrs, "outbound": "direct"})
    if direct_domains:
        direct.append({"domain_suffix": direct_domains, "outbound": "direct"})
    if mode == "except" and apps:
        direct.append({"process_name": apps, "outbound": "direct"})
    # Tor can't carry UDP: reject it at once (apps fall back to TCP, e.g. QUIC -> HTTPS) instead of timing out
    if mode == "only":
        direct.append({"process_name": apps or ["-none-"], "network": "udp", "action": "reject"})
        direct.append({"process_name": apps or ["-none-"], "outbound": "tor"})
    else:
        direct.append({"network": "udp", "action": "reject"})
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "tor-dns", "address": f"udp://127.0.0.1:{DNS_PORT}", "detour": "direct"}]},
        "inbounds": [{"type": "tun", "tag": "tun", "interface_name": "Gommage", "address": ["172.19.0.1/30"],
                      "auto_route": True, "strict_route": True, "stack": "gvisor",
                      # hand Tor the hostname (from TLS/HTTP sniffing), not the IP: exit resolves it, fewer leaks
                      "sniff": True, "sniff_override_destination": True}],
        "outbounds": [{"type": "socks", "tag": "tor", "server": socks[0], "server_port": socks[1], "version": "5"},
                      {"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True, "final": "direct" if mode == "only" else "tor",
                  "rules": [{"protocol": "dns", "action": "hijack-dns"}] + direct},
    }


# ---------- look ----------
class Api:
    """Methods the page calls via window.pywebview.api.*  (kept apart so pywebview doesn't walk App's internals)."""
    def __init__(self, app):
        self._app = app

    def init(self):
        a = self._app
        return {"settings": a.s, "countries": COUNTRIES, "app_modes": APP_MODES, "log_path": LOG, "windows": WIN,
                "state": a.ui_state, "log": open(LOG, encoding="utf8", errors="replace").read()[-20000:] if os.path.exists(LOG) else ""}

    def set(self, key, value):
        a = self._app
        a.s[key] = value
        if key == "autostart":
            set_autostart(bool(value))
        a.save_settings()

    def toggle(self):
        self._app.toggle()

    def new_identity(self):
        self._app.new_identity()

    def speed(self):
        if self._app.proc:
            threading.Thread(target=self._app.run_speed, daemon=True).start()

    def add_builtin(self, name):
        self._app.add_builtin(name)

    def test_bridges(self):
        self._app.test_bridges()

    def get_bridges(self):
        self._app.get_bridges()

    def pick_app(self):
        self._app.pick_app()

    def history(self):
        return db("SELECT start, end, mode, country, status FROM sessions ORDER BY id DESC LIMIT 200")

    def open_log(self):
        if os.path.exists(LOG):
            os.startfile(LOG) if WIN else run("xdg-open", LOG)

    def minimize(self):
        self._app.win.minimize()

    def close(self):
        self._app.win.destroy()


class App:
    def __init__(self):
        self.proc = self.tun = None
        self.sid = None
        self.cancelled = False
        self.state_ = "idle"
        self.ui_state = {}
        self.closing = False
        relink_autostart = migrate_old_name()
        self.s = load_settings()
        if relink_autostart and self.s["autostart"]:
            set_autostart(True)
        if self.s["country"] not in COUNTRIES:
            self.s["country"] = "Any"
        self.render("Disconnected", "red")
        self.win = webview.create_window("Gommage", os.path.join(APP_DIR, "ui.html"),
                                         js_api=Api(self), width=400, height=780, min_size=(380, 740),
                                         frameless=True, easy_drag=False, background_color="#121419")
        self.win.events.closing += self.quit_app
        if WIN:
            self.win.events.shown += self.round_corners
        self.win.events.loaded += lambda: self.s["autoconnect"] and self.after(500, self.toggle)
        threading.Thread(target=self.traffic, daemon=True).start()

    def round_corners(self):
        """Windows 11: rounded corners and no light border on the frameless window."""
        try:
            hwnd = self.win.native.Handle.ToInt64()
            dwm = ctypes.windll.dwmapi.DwmSetWindowAttribute
            dwm(hwnd, 33, ctypes.byref(ctypes.c_int(2)), 4)  # DWMWA_WINDOW_CORNER_PREFERENCE = round
            dwm(hwnd, 34, ctypes.byref(ctypes.c_uint(0xFFFFFFFE)), 4)  # DWMWA_BORDER_COLOR = none
        except Exception:
            pass  # Windows 10: square corners

    def mainloop(self):
        webview.start()

    def after(self, ms, fn, *a):
        """Tk-style deferred call; the page is updated from any thread via evaluate_js."""
        threading.Timer(ms / 1000, fn, a).start()

    def push(self, **kw):
        self.ui_state.update({k: v for k, v in kw.items() if k != "log"})
        if self.closing:
            return  # evaluate_js would wait forever on a window that is shutting down
        try:
            self.win.evaluate_js(f"window.ui && ui({json.dumps(kw)})")
        except Exception:
            pass  # window not ready yet / closing; init() hands over ui_state

    def render(self, text, color):
        self.state_ = {"green": "on", "orange": "busy", "red": "err" if text.startswith(("Error", "Bad")) else "idle"}[color]
        title, _, rest = text.partition(" (")
        title = title.removeprefix("Error: ")
        title = title[:1].upper() + title[1:]
        if self.state_ == "err" and len(title) > 22:  # long error text goes under a short headline
            title, rest = "Couldn't connect", title + (f" ({rest}" if rest else "")
        m = re.search(r"(\d+)%", title)
        sub = rest.rstrip(")") if rest else ""
        if self.state_ == "on":
            sub = " · ".join(x for x in (sub, f"SOCKS {LOCAL}:{SOCKS}") if x)
        if hasattr(self, "win"):
            self.push(state=self.state_, title={"Disconnected": "Not Connected"}.get(title, title), sub=sub,
                      pct=int(m.group(1)) if m else None)
        else:
            self.ui_state.update(state=self.state_, title="Not Connected", sub="", pct=None)

    def traffic(self):
        """Live down/up rate from Tor's byte counters, once a second while connected."""
        last = None
        while True:
            time.sleep(1)
            if self.state_ != "on":
                last = None
                continue
            try:
                r = control("GETINFO traffic/read traffic/written")
                cur = (int(re.search(r"traffic/read=(\d+)", r)[1]), int(re.search(r"traffic/written=(\d+)", r)[1]))
            except Exception:
                continue
            if last:
                self.push(down=cur[0] - last[0], up=cur[1] - last[1])
            last = cur

    # ---------- helpers ----------
    def save_settings(self):
        os.makedirs(HOME, exist_ok=True)
        json.dump(self.s, open(SETTINGS, "w", encoding="utf8"), indent=1)

    def set_bridges(self, text):
        self.s["bridges"] = text
        self.save_settings()
        self.push(bridges=text)

    def log(self, s):
        try:
            open(LOG, "a", encoding="utf8").write(s.rstrip() + "\n")
        except OSError:
            pass
        self.push(log=s.rstrip() + "\n")

    def add_builtin(self, name):
        try:
            ensure_tor(self.log)
            got = builtin_bridges().get(name)
            if not got:
                raise RuntimeError("built-in bridges come with the Tor Expert Bundle; your system tor doesn't have them")
            cur = self.s["bridges"]
            self.set_bridges(cur + ("\n" if cur and not cur.endswith("\n") else "") + "\n".join(got) + "\n")
        except Exception as e:
            self.log(f"ERROR: {e}")

    def show_exit(self, delay=1):
        time.sleep(delay)
        try:
            via_tor = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://{LOCAL}:{HTTP}"}))
            ip = json.load(via_tor.open("https://check.torproject.org/api/ip", timeout=30))["IP"]
            cc = re.search(r"ip-to-country/\S+=(\w+)", control(f"GETINFO ip-to-country/{ip}"))
            exit_ = {"ip": ip, "cc": cc.group(1).lower() if cc else ""}
        except Exception as e:
            exit_ = {"ip": "exit IP unknown", "cc": ""}
            self.log(f"exit check: {e}")
        if self.proc:
            self.push(exit=exit_)

    def learn(self, lines):
        """After a connect: credit the bridge Tor really uses (its entry guard) and put it first next time."""
        used = set()
        try:
            used = set(re.findall(r"\$([0-9A-F]{40})", control("GETINFO entry-guards")))
        except Exception as e:
            self.log(f"entry-guards: {e}")
        stats = self.s.setdefault("stats", {})
        for l in lines:
            fp = fingerprint(l)
            if fp in used or not used:
                st = stats.setdefault(fp, [0, 0, 0])
                st[0] += 1
                st[2] = int(time.time())
        self.s["last_good"] = [l for l in lines if fingerprint(l) in used] + [l for l in lines if fingerprint(l) not in used]
        self.save_settings()

    def penalise(self, lines):
        stats = self.s.setdefault("stats", {})
        for l in lines:
            stats.setdefault(fingerprint(l), [0, 0, 0])[1] += 1
        self.save_settings()

    def add_public(self, lines, found):
        """Append public bridges under a comment naming where they came from."""
        lines = [l for l in lines if l not in clean_bridges(self.s["bridges"])]
        if not lines:
            return 0
        srcs = ", ".join(sorted({n for l in lines for n in found.get(l, [])}))
        text = self.s["bridges"]
        block = f"# public lists ({srcs}), {time.strftime('%Y-%m-%d')}\n" + "\n".join(lines) + "\n"
        self.set_bridges(text + ("\n" if text.strip() and not text.endswith("\n") else "") + block)
        self.log(f"added {len(lines)} public bridges from {srcs}")
        return len(lines)

    def run_speed(self):
        self.push(speed="testing…")
        try:
            lat, mbps = speed_test(f"http://{LOCAL}:{HTTP}")
            text = f"{mbps:.1f} Mbps · {lat} ms"
            self.log(f"speed test: {mbps:.2f} Mbps, {lat} ms")
        except Exception as e:
            text = "speed test failed"
            self.log(f"speed test: {e}")
        self.push(speed=text)

    def get_bridges(self):
        self.push(test="looking for fresh bridges…")

        def go():
            via = f"http://{LOCAL}:{HTTP}" if self.proc else None
            cur = clean_bridges(self.s["bridges"])
            found = fetch_public(via, self.log) if self.s.get("community", True) else {}
            if via:  # Tor Project's own API only answers through Tor from Iran
                for l in fetch_bridges(via, self.log):
                    found.setdefault(l, []).append("Tor Project")
            found = {l: v for l, v in found.items() if l not in cur}
            if not found:
                return self.push(test="no new bridges found - check your connection")
            self.push(test=f"testing {len(found)} bridges…")
            if self.proc:  # inside our own tunnel a probe means nothing: trust multi-source lines most
                pick = sorted(found, key=lambda l: -len(found[l]))[:15]
            else:
                pick = pick_public(found, probe_all(list(found), 4))
            n = self.add_public(pick, found)
            self.push(test=f"{n} new bridges added" if n else "none of the new bridges are reachable right now")
        threading.Thread(target=go, daemon=True).start()

    def new_identity(self):
        def go():
            try:
                control("SIGNAL NEWNYM")
                self.push(exit={"ip": "getting new identity…", "cc": ""})
                self.show_exit(4)
            except Exception as e:
                self.log(f"NEWNYM failed: {e}")
        threading.Thread(target=go, daemon=True).start()

    def test_bridges(self):
        lines = clean_bridges(self.s["bridges"])
        self.push(test=f"testing {len(lines)}…")

        def go():
            res = probe_all(lines)
            dead = [l for l in lines if res[l] is False]
            for l in lines:
                r = res[l]
                self.log((f"OK {r:>4}ms " if r not in (False, None) else {False: "DEAD      ", None: "SKIP      "}[r]) + l[:90])
            ok = sum(v not in (False, None) for v in res.values())
            self.push(test=f"{ok} ok · {len(dead)} dead · {len(lines) - ok - len(dead)} untested")
            if dead and self.win.create_confirmation_dialog("Gommage", f"Remove {len(dead)} unreachable bridge(s)?"):
                self.set_bridges("\n".join(l for l in lines if l not in dead) + "\n")
        threading.Thread(target=go, daemon=True).start()

    def pick_app(self):
        paths = self.win.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=True, file_types=("Programs (*.exe)",) if WIN else ())
        cur = self.s["apps"]
        for name in (os.path.basename(p) for p in paths or ()):
            if name not in app_names(cur):
                cur += ("\n" if cur and not cur.endswith("\n") else "") + name + "\n"
        self.s["apps"] = cur
        self.save_settings()
        self.push(apps=cur)

    def after_connect(self):
        time.sleep(12)
        self.run_speed()
        if self.proc:  # keep a fresh reserve for next time, fetched safely through Tor
            via = f"http://{LOCAL}:{HTTP}"
            found = {l: ["Tor Project"] for l in fetch_bridges(via, self.log)[:10]}
            if self.s.get("community", True) and len(clean_bridges(self.s["bridges"])) < 40:
                for l, v in fetch_public(via, self.log).items():
                    if len(v) > 1:  # in the background only take bridges confirmed by two lists
                        found.setdefault(l, v)
            cur = clean_bridges(self.s["bridges"])
            self.add_public([l for l in found if l not in cur][:15], found)

    def status(self, t, c):
        self.after(0, lambda: self.render(t, c))
        if self.sid:
            db("UPDATE sessions SET status=? WHERE id=?", (t, self.sid))

    # ---------- connect / disconnect ----------
    def toggle(self):
        if self.state_ == "busy" and not self.proc:
            return  # still starting up
        self.save_settings()
        if self.proc:
            self.stop()
            return
        try:
            apply_ports(str(self.s["listen"]).strip(), str(self.s["socks"]).strip(), str(self.s["http"]).strip())
        except ValueError as e:
            self.render(f"Bad IP/port: {e}", "red")
            return
        if (self.s["vpn"] or self.s["block_ipv6"]) and not is_admin() and not WIN:
            threading.Thread(target=self.relaunch_root, daemon=True).start()
        elif (self.s["vpn"] or self.s["block_ipv6"]) and not is_admin():
            # relaunch elevated; settings were just saved so the new window has them
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", *self_cmd(), None, 1) > 32:
                self.closing = True  # the elevated copy takes over; close this one off the JS-call thread
                threading.Thread(target=self.win.destroy, daemon=True).start()
            else:
                self.render("Admin rights needed for VPN / IPv6 block", "red")
        else:
            self.cancelled = False
            self.render("Starting...", "orange")
            threading.Thread(target=self.start, daemon=True).start()

    def start(self):
        try:
            open(LOG, "w").close()
            lines = clean_bridges(self.s["bridges"])
            vpn, cc = self.s["vpn"], COUNTRIES[self.s["country"]]
            self.sid = db("INSERT INTO sessions(start, mode, country, status) VALUES(?,?,?,?)",
                          (now(), "VPN" if vpn else "proxy", self.s["country"], "connecting"))
            if self.s["block_ipv6"]:
                block_ipv6(True)
                self.log("IPv6 blocked (firewall rule)")
            tor, pt = ensure_tor(self.log)
            self.log(f"tor: {tor}, transports: {pt}")
            builtin = builtin_bridges()
            # memory: the bridges that connected last time go first, before any testing
            known = set(lines).union(*builtin.values())
            good = [l for l in self.s.get("last_good", []) if l in known] if lines else []
            if good:
                self.log(f"=== trying last working bridges first ({len(good)}) ===")
                if self.run_tor(tor, pt, good, vpn, cc, "last working"):
                    return  # connected, then the user disconnected (finally: stop)
                if self.cancelled:
                    return
                self.log("last working bridges failed - testing the rest")
            if not lines:  # no bridges configured: plain Tor
                tiers = [("direct Tor", [])]
            else:
                rest = [l for l in lines if l not in good]
                self.status("Testing bridges...", "orange")
                res = probe_all(rest)
                self.log("bridge test: " + ", ".join(f"{l.split()[0]} {res[l] if res[l] is not None else '?'}"
                                                     for l in rest))
                tiers = plan_tiers(rest, res, {k: [l for l in v if l not in good] for k, v in builtin.items()},
                                   self.s.get("stats"), public=self.s.get("community", True))
            for n, (name, tier) in enumerate(tiers, 1):
                if self.cancelled:
                    break
                if tier is None:  # public lists: only fetched when your own bridges all failed
                    self.status("Getting public bridges...", "orange")
                    found = fetch_public(log=self.log)
                    found = {l: v for l, v in found.items() if l not in lines}
                    tier = pick_public(found, probe_all(list(found), 4))
                    if not tier:
                        continue
                    self.add_public(tier, found)
                self.log(f"=== attempt {n}/{len(tiers)}: {name} ({len(tier)} bridges) ===")
                if self.run_tor(tor, pt, tier, vpn, cc, f"{name}, {n}/{len(tiers)}"):
                    break  # it connected; returned because the user disconnected or Tor died
                if self.cancelled:
                    break
            else:
                self.status("Error: no bridge worked (add fresh bridges in Settings)", "red")
        except Exception as e:
            self.log(f"ERROR: {e}")
            self.status(f"Error: {e}", "red")
        finally:
            self.after(0, self.stop)

    def run_tor(self, tor, pt, lines, vpn, cc, label):
        """Run Tor with these bridges. True once it reached 100%; False if it stalled (killed by watchdog)."""
        rc = [f"SocksPort {LISTEN}:{SOCKS}", f"HTTPTunnelPort {LISTEN}:{HTTP}", f"DataDirectory {os.path.join(HOME, 'data')}",
              f"GeoIPFile {geoip()}", f"GeoIPv6File {geoip('geoip6')}",
              "Log notice stdout", "WarnUnsafeSocks 0", "ControlPort auto", "CookieAuthentication 1",
              f"ControlPortWriteToFile {os.path.join(HOME, 'control.port')}",
              f"ClientTransportPlugin meek_lite,obfs4,webtunnel,snowflake exec {pt}"]
        if cc:
            rc += [f"ExitNodes {{{cc}}}", "StrictNodes 1"]
        if vpn:
            rc += [f"DNSPort 127.0.0.1:{DNS_PORT}"]
        if lines:
            rc += ["UseBridges 1"] + [f"Bridge {l}" for l in lines]
        rcp = os.path.join(HOME, "torrc")
        open(rcp, "w", encoding="utf8").write("\n".join(rc) + "\n")
        self.status(f"Connecting... ({label})", "orange")
        # the Linux bundle's tor sits next to its own libevent/openssl
        env = {**os.environ, "LD_LIBRARY_PATH": os.path.dirname(tor)} if not WIN and tor.startswith(HOME) else None
        proc = self.proc = popen([tor, "-f", rcp], env=env)
        state = {"pct": -1, "t": time.time(), "done": False}

        def watchdog():
            while proc.poll() is None and not state["done"]:
                limit = STALL_EARLY if state["pct"] < 75 else STALL_LATE
                if time.time() - state["t"] > limit:
                    self.log(f"no progress for {limit}s at {state['pct']}% - trying next bridges")
                    kill_tree(proc)  # TerminateProcess alone would orphan lyrebird.exe
                    return
                time.sleep(2)
        threading.Thread(target=watchdog, daemon=True).start()

        for l in proc.stdout:
            self.log(l)
            m = re.search(r"Bootstrapped (\d+)%", l)
            if not m:
                continue
            p = int(m.group(1))
            if p > state["pct"]:
                state["pct"], state["t"] = p, time.time()
            if p == 100 and not state["done"]:
                state["done"] = True
                if lines:  # remember what worked so the next connect tries it first
                    self.learn(lines)
                set_proxy(True)
                self.status(f"Connected ({label.split(',')[0]})", "green")
                threading.Thread(target=self.show_exit, args=(8 if vpn else 1,), daemon=True).start()
                threading.Thread(target=self.after_connect, daemon=True).start()
                if vpn and not self.tun:
                    self.status("Starting VPN mode...", "orange")
                    self.tun = True  # placeholder so a repeated 100% doesn't start it twice
                    threading.Thread(target=self.start_vpn, args=(lines,), daemon=True).start()
            elif not self.tun and not state["done"]:
                self.status(f"Bootstrapping {p}% ({label})", "orange")
        self.log("tor exited")
        if not state["done"] and 0 <= state["pct"] < 75 and not self.cancelled:
            self.penalise(lines)  # the bridges never got Tor going (not a bind error, not a strict exit country)
        return state["done"]

    def start_vpn(self, lines):
        try:
            ensure_singbox(self.log)
            cidrs, domains = split_nets(self.s["bypass"])
            if self.s["bypass_ir"]:
                if os.path.exists(geoip()):
                    cidrs += country_nets(geoip(), "IR")
                else:
                    self.log(f"no GeoIP file ({geoip()}): Iranian IPs go through Tor (install tor-geoipdb)")
            mode = self.s["app_mode"]
            cfg = singbox_config(mode, app_names(self.s["apps"]), cidrs, domains, (LOCAL, SOCKS))
            path = os.path.join(HOME, "sing-box.json")
            json.dump(cfg, open(path, "w"), indent=1)
            self.log(f"VPN: mode={mode}, {len(cidrs)} direct IP ranges, {len(domains)} direct domains")
            self.tun = popen([SINGBOX, "run", "-c", path, "-D", HOME], cwd=HOME)
            threading.Thread(target=lambda: [self.log("sing-box: " + re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in self.tun.stdout], daemon=True).start()
            time.sleep(3)
            if self.tun.poll() is not None:
                raise RuntimeError("sing-box exited, see log")
            run("ipconfig", "/flushdns") if WIN else run("resolvectl", "flush-caches")
            self.status({"all": "Connected (whole system via Tor)", "except": "Connected (all apps except list)",
                         "only": "Connected (only listed apps)"}[mode], "green")
        except Exception as e:
            self.log(f"VPN ERROR: {e}")
            self.stop_vpn()
            self.status("Connected (browser proxy only, VPN failed)", "orange")

    def stop_vpn(self):
        t, self.tun = self.tun, None
        if isinstance(t, subprocess.Popen) and t.poll() is None:
            t.terminate()  # sing-box removes its adapter and routes on exit

    def stop(self):
        self.cancelled = True
        self.stop_vpn()
        p, self.proc = self.proc, None
        if p and p.poll() is None:
            kill_tree(p)
        set_proxy(False)
        if self.s["block_ipv6"] or is_admin():
            block_ipv6(False)
        if self.sid:
            db("UPDATE sessions SET end=? WHERE id=?", (now(), self.sid))
            self.sid = None
        self.push(exit=None, speed="", down=None, up=None)
        if self.state_ != "err":
            self.render("Disconnected", "red")

    def relaunch_root(self):
        """Linux: run this app again as root via pkexec (polkit asks for the password); this window waits hidden
        and closes once the root copy has exited, or comes back if the password was refused."""
        keep = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR")
                if k in os.environ]
        keep += [f"GOMMAGE_HOME={HOME}", "PYTHONPATH=" + os.pathsep.join(p for p in sys.path if p)]
        cmd = ["pkexec", "env", *keep, sys.executable] + ([] if FROZEN else [os.path.abspath(__file__)])
        self.win.hide()
        try:
            rc = subprocess.run(cmd).returncode
        except FileNotFoundError:
            rc = 127
        if rc in (126, 127):  # dismissed / not authorised / no pkexec
            self.win.show()
            self.render("Root needed for VPN / IPv6 block (or run: sudo -E python3 gommage.py)", "red")
            return
        self.s = load_settings()  # the root copy learned bridges/stats; don't overwrite them on close
        self.closing = True
        self.win.destroy()

    def give_back(self):
        """Linux: files the root copy made in the user's folder go back to them (tor refuses a foreign DataDirectory)."""
        uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
        if WIN or not uid or os.geteuid() != 0:
            return
        import pwd
        gid = pwd.getpwuid(int(uid)).pw_gid
        for d, _, files in os.walk(HOME):
            for p in [d] + [os.path.join(d, f) for f in files]:
                try:
                    os.chown(p, int(uid), gid, follow_symlinks=False)
                except OSError:
                    pass

    def quit_app(self):
        self.closing = True
        self.save_settings()
        self.stop()
        self.give_back()


if __name__ == "__main__":
    # self-checks of the parsers
    assert clean_bridges("Bridge webtunnel a\n\n# x\n webtunnel b ") == ["webtunnel a", "webtunnel b"]
    assert app_names("C:\\x\\Telegram.exe\n# c\nchrome.exe") == ["Telegram.exe", "chrome.exe"]
    _r = singbox_config("only", ["Telegram.exe"], [], [], ("127.0.0.1", 9050))["route"]
    assert _r["final"] == "direct" and {"process_name": ["Telegram.exe"], "outbound": "tor"} in _r["rules"]
    _r = singbox_config("except", ["x.exe"], ["5.0.0.0/8"], ["ir"], ("127.0.0.1", 9050))["route"]
    assert _r["final"] == "tor" and _r["rules"][1]["process_name"] == TOR_PROCS and _r["rules"][-1]["action"] == "reject"
    apply_ports("0.0.0.0", "9150", "8119")
    assert (LISTEN, LOCAL, SOCKS, HTTP) == ("0.0.0.0", "127.0.0.1", 9150, 8119)
    for bad in (("1.2.3", "9050", "8118"), ("127.0.0.1", "9050", "9050"), ("127.0.0.1", str(DNS_PORT), "8118"), ("127.0.0.1", "x", "1")):
        try:
            apply_ports(*bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    apply_ports("127.0.0.1", "9050", "8118")  # back to defaults before settings are loaded
    assert clean_bridges("a\nb\na") == ["a", "b"]
    assert bridge_target("webtunnel [2001:db8::1]:443 FP url=https://x.de/p ver=1") == ("x.de", 443, True)
    assert bridge_target("obfs4 1.2.3.4:22 FP cert=c") == ("1.2.3.4", 22, False)
    assert bridge_target("snowflake 192.0.2.3:80 FP") is None
    assert bridge_strings({"settings": [{"bridges": {"bridge_strings": ["obfs4 1.2.3.4:1 X", "junk"]}}],
                           "x": ["webtunnel [::1]:443 Y url=https://a"]}) == ["obfs4 1.2.3.4:1 X", "webtunnel [::1]:443 Y url=https://a"]
    _t = plan_tiers(["a", "b", "c", "s"], {"a": 300, "b": False, "c": 40, "s": None}, {"obfs4": ["c", "o1"], "meek": ["m"]})
    assert _t == [("best bridges", ["c", "a"]), ("your snowflake/meek", ["s"]), ("built-in obfs4", ["o1"]), ("built-in meek", ["m"])], _t
    # track record beats raw latency; never-working bridges go last; public lists sit before built-ins
    _fa, _fb = "obfs4 1.1.1.1:1 " + "A" * 40 + " cert=x", "obfs4 2.2.2.2:2 " + "B" * 40 + " cert=x"
    _t = plan_tiers([_fa, _fb], {_fa: 50, _fb: 200}, {"obfs4": ["o"]}, {"A" * 40: [0, 3, 0], "B" * 40: [4, 0, 0]}, public=True)
    assert [n for n, _ in _t] == ["best bridges", "public lists", "built-in obfs4", "bridges that keep failing"], _t
    assert _t[0][1] == [_fb] and _t[1][1] is None and _t[-1][1] == [_fa]
    _ok = "obfs4 1.2.3.4:443 " + "C" * 40 + " cert=" + "a" * 70 + " iat-mode=0"
    _wt = "webtunnel [2001:db8::1]:443 " + "D" * 40 + " url=https://x.example.com/abc ver=0.0.2"
    assert VALID_BRIDGE.fullmatch(_ok) and VALID_BRIDGE.fullmatch(_wt)
    for _bad in (_ok + " ; rm -rf", "obfs4 1.2.3.4:443 xyz cert=a iat-mode=0", "vanilla 1.2.3.4:1 " + "C" * 40, _wt.replace("https", "http")):
        assert not VALID_BRIDGE.fullmatch(_bad), _bad
    assert pick_public({"x": ["a"], "y": ["a", "b"], "z": ["a"]}, {"x": 10, "y": 300, "z": False}) == ["y", "x"]
    assert pick_public({_ok: ["a"], _ok + " ": ["a"]}, {_ok: 5, _ok + " ": 9}) == [_ok]  # same fingerprint once
    assert split_nets("5.6.7.8\n10.0.0.0/8 # lan\nhttps://a.ir/x\n") == (["5.6.7.8/32", "10.0.0.0/8"], ["a.ir"])
    assert app_names("/usr/bin/telegram-desktop") == ["telegram-desktop"]
    if WIN and not is_admin() and "--no-admin" not in sys.argv:
        # VPN mode and the IPv6 block need admin: ask once at launch instead of restarting mid-connect.
        # --no-admin skips this (proxy mode only; toggle() still asks if VPN/IPv6 block is switched on)
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", *self_cmd(), None, 1) > 32:
            sys.exit()
        # UAC declined: carry on without admin (proxy mode still works; toggle() asks again for VPN)
    App().mainloop()
