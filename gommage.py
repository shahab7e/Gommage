"""Gommage: tiny Tor client (Windows, Linux) with custom bridges (webtunnel/obfs4/...), system proxy or whole-system VPN.
Run: python gommage.py   (first run needs the Tor Expert Bundle, or on Linux the system's tor; see ensure_tor)
"""
import base64, ctypes, glob, hashlib, io, ipaddress, json, ntpath, os, queue, re, shutil, signal, socket, sqlite3, ssl, subprocess, sys
import random, tarfile, threading, time, urllib.request, webbrowser, zipfile
from concurrent.futures import ThreadPoolExecutor

import split_engine, killswitch, l2tp

WIN = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)  # running as the PyInstaller exe
APP_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # where ui.html, fonts, assets live
if WIN:
    import winreg
EXE = ".exe" if WIN else ""
VER = "15.0.25"  # ponytail: pinned; bump when Tor ships a new bundle
URL = f"https://dist.torproject.org/torbrowser/{VER}/tor-expert-bundle-{'windows' if WIN else 'linux'}-x86_64-{VER}.tar.gz"
_CLI_HOME = killswitch.parse_home_arg(sys.argv)
if _CLI_HOME:
    HOME = _CLI_HOME
elif WIN:
    HOME = os.path.join(os.environ["APPDATA"], "Gommage")
    OLD_HOME = os.path.join(os.environ["APPDATA"], "TorBridge")  # the app's former name: carry its data over
    if os.path.isdir(OLD_HOME) and not os.path.exists(HOME):
        try:
            os.rename(OLD_HOME, HOME)
        except OSError:
            HOME = OLD_HOME  # old copy still running and holding files; keep using its folder, move it next launch
else:  # GOMMAGE_HOME: set by relaunch_root; under sudo, resolve the desktop user's real home (not /root)
    _xdg = os.environ.get("XDG_CONFIG_HOME")
    if not _xdg or (os.geteuid() == 0 and (os.environ.get("SUDO_UID") or os.environ.get("PKEXEC_UID")) and _xdg.startswith("/root")):
        _xdg = os.path.join(split_engine.resolve_user_home_linux(), ".config")
    HOME = os.environ.get("GOMMAGE_HOME") or os.path.join(_xdg, "Gommage")

_LOCK_FD = None


def ctl_path():
    return os.path.join(os.environ.get("XDG_RUNTIME_DIR") or "/tmp", "gommage-ui.sock")


def make_indicator(on_open, on_quit):
    """Linux tray icon (AppIndicator, which GNOME/Zorin/KDE show); None when the library or a tray host is missing."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import Gtk, AyatanaAppIndicator3 as AI
        if not Gtk.init_check()[0]:
            return None  # no display: creating widgets would abort the process
        ind = AI.Indicator.new_with_path("gommage", "icon", AI.IndicatorCategory.APPLICATION_STATUS,
                                         os.path.join(APP_DIR, "assets"))
        ind.set_title("Gommage")
        menu = Gtk.Menu()
        for n, (label, cb) in enumerate((("Open Gommage", on_open), ("Quit", on_quit))):
            item = Gtk.MenuItem(label=label)
            item.connect("activate", lambda _i, cb=cb: cb())
            menu.append(item)
            if n == 0:
                ind.set_secondary_activate_target(item)
        menu.show_all()
        ind.set_menu(menu)
        ind.set_status(AI.IndicatorStatus.ACTIVE)
        return ind
    except Exception:
        return None


def _tray_for_root_child(keep):
    """The window lives in the root copy, which can't use the user's D-Bus session; so this (user) process owns the tray
    icon and tells the root copy over a socket. Returns a function that stops the tray."""
    done, box = threading.Event(), {}

    def send(cmd):
        c = socket.socket(socket.AF_UNIX)
        try:
            c.settimeout(2)
            c.connect(ctl_path())
            c.sendall(cmd)
        except OSError:
            if cmd == b"quit":
                os._exit(0)  # no root copy to talk to (still at the password prompt): just leave
        finally:
            c.close()

    def loop():
        box["ind"] = make_indicator(lambda: send(b"show"), lambda: send(b"quit"))
        done.set()
        if box["ind"]:
            from gi.repository import Gtk
            Gtk.main()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    done.wait(5)
    if not box.get("ind"):
        return lambda: None
    keep.append("GOMMAGE_TRAY=1")

    def stop():
        from gi.repository import GLib, Gtk
        box["ind"] = None
        GLib.idle_add(Gtk.main_quit)
        t.join(3)
    return stop


def acquire_instance_lock():
    """Linux: one GUI per privilege level (the user's window, the root copy pkexec starts). Without this, a second
    launch ran its own kill_stale_processes() and killed the first one's tor, and they fought over HOME and the ports."""
    global _LOCK_FD
    if WIN:
        return True
    import fcntl
    uid = os.geteuid()
    base = "/run" if uid == 0 else (os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
    try:
        fd = os.open(os.path.join(base, f"gommage-{uid}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    except OSError:
        return True  # can't lock (odd /tmp, read-only /run): better to start than to refuse
    _LOCK_FD = fd  # held for the life of the process; not inherited by pkexec (close_fds)
    return True


def repair_home_owner():
    """Linux, non-root: a root copy that was killed leaves root-owned files in HOME, and then settings/log/torrc can't
    be written. Take them back with one polkit prompt (the root copy normally does it on quit)."""
    if WIN or os.geteuid() == 0 or not os.path.isdir(HOME) or not shutil.which("pkexec"):
        return
    me = os.getuid()
    for d, dirs, files in os.walk(HOME):
        if any(os.lstat(os.path.join(d, n)).st_uid != me for n in dirs + files if os.path.lexists(os.path.join(d, n))) \
                or os.lstat(d).st_uid != me:
            try:
                subprocess.run(["pkexec", "chown", "-R", f"{me}:{os.getgid()}", HOME], timeout=120)
            except (OSError, subprocess.SubprocessError):
                pass
            return


if __name__ == "__main__":
    killswitch.handle_cli_early(sys.argv, HOME, os.path.abspath(__file__))
    if not acquire_instance_lock():
        msg = "Gommage is already running (check the other window, or wait if it is asking for the password)."
        print(msg, file=sys.stderr)
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "Gommage", msg])
        sys.exit(3)
    if not WIN and os.geteuid() != 0 and "--no-root" not in sys.argv and shutil.which("pkexec"):
        # ask for the password once, here, and run the whole app as root: VPN, Kill Switch and IPv6 block then need no
        # further prompts and no window swapping. If it is refused, carry on as a normal user (proxy mode only).
        _keep = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                                 "DBUS_SESSION_BUS_ADDRESS", "XDG_CURRENT_DESKTOP", "LANG") if k in os.environ]
        _keep += [f"GOMMAGE_HOME={HOME}", "PYTHONPATH=" + os.pathsep.join(p for p in sys.path if p)]
        try:
            os.makedirs(HOME, exist_ok=True)
            _out = open(os.path.join(HOME, "root.log"), "w")  # the root copy's errors, readable by you
        except OSError:
            _out = None
        _stop_tray = _tray_for_root_child(_keep)
        _t0 = time.time()
        try:
            _rc = subprocess.run(["pkexec", "env", *_keep, sys.executable] + ([] if FROZEN else [os.path.abspath(__file__)])
                                 + [a for a in sys.argv[1:]], stdout=_out, stderr=subprocess.STDOUT if _out else None).returncode
        except OSError:
            _rc = 127
        if _rc not in (126, 127) and not (_rc != 0 and time.time() - _t0 < 8):  # crashed at once: fall back to a user window
            sys.exit(_rc)
        _stop_tray()  # carrying on in this process: it makes its own tray icon
    repair_home_owner()

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))  # .deb install vendors pywebview here
import webview
if WIN:
    import pystray
    from PIL import Image
VERSION = "1.3.0"  # bump with every release; the app compares it with the latest GitHub release tag
REPO = "shahab7e/Gommage"
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
             "Canada": "ca", "Sweden": "se", "Switzerland": "ch", "Finland": "fi", "Austria": "at",
             "Albania": "al", "Ukraine": "ua"}
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


def kill_stale_processes():
    """Terminate leftover tor/lyrebird/sing-box from a crashed run so ports and TUN adapters aren't held."""
    targets = set(TOR_PROCS + ["sing-box" + EXE])
    mypid = os.getpid()
    if WIN:
        try:
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class PE32(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                            ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
                            ("szExeFile", wintypes.WCHAR * 260)]

            k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE32)]
            k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE32)]
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            k32.TerminateProcess.argtypes = [wintypes.HANDLE, ctypes.c_uint]
            k32.CloseHandle.argtypes = [wintypes.HANDLE]

            snap = k32.CreateToolhelp32Snapshot(0x2, 0)
            if snap and snap != wintypes.HANDLE(-1).value:
                try:
                    pe = PE32(); pe.dwSize = ctypes.sizeof(pe)
                    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
                    home_prefix = os.path.normcase(os.path.abspath(HOME)).rstrip("\\/") + os.sep
                    while ok:
                        pid = pe.th32ProcessID
                        if pid > 4 and pid != mypid and pe.szExeFile.lower() in {t.lower() for t in targets}:
                            h = k32.OpenProcess(0x1001, False, pid)
                            if h:
                                try:
                                    buf = ctypes.create_unicode_buffer(1024); sz = wintypes.DWORD(1024)
                                    if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
                                        if os.path.normcase(buf.value).startswith(home_prefix):
                                            k32.TerminateProcess(h, 1)
                                finally:
                                    k32.CloseHandle(h)
                        ok = k32.Process32NextW(snap, ctypes.byref(pe))
                finally:
                    k32.CloseHandle(snap)
        except Exception:
            pass
    else:
        torrc_marker = os.path.join(HOME, "torrc").encode()
        sb_marker = b"sing-box.json"
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid_s = os.path.basename(pid_dir)
            if not pid_s.isdigit() or int(pid_s) == mypid:
                continue
            try:
                exe = os.path.realpath(os.path.join(pid_dir, "exe"))
                cmd = open(os.path.join(pid_dir, "cmdline"), "rb").read(2048)
            except OSError:
                continue
            if os.path.basename(exe) in targets and (
                exe.startswith(HOME + "/") or torrc_marker in cmd or sb_marker in cmd
            ):
                try:
                    os.kill(int(pid_s), signal.SIGKILL)
                except OSError:
                    pass


kill_stale_tor = kill_stale_processes


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


def free_port(p, taken=(), kind=socket.SOCK_STREAM, host=None):
    """First port >= p that nothing holds (and isn't in `taken`)."""
    bind_host = host or LISTEN
    while p < 65535:
        if p not in taken:
            try:
                with socket.socket(socket.AF_INET, kind) as sk:
                    sk.bind((bind_host, p))
                return p
            except OSError:
                pass
        p += 1
    return p


def apply_ports(listen, socks, http):
    """Validate user-entered listen IP/ports and make them active. Raises ValueError on bad input."""
    global LISTEN, LOCAL, SOCKS, HTTP, DNS_PORT
    ip = ipaddress.IPv4Address(listen.strip())
    s, h = int(socks), int(http)
    DNS_PORT = 9053
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
         "last_good": [], "community": True, "stats": {},
         "ks_mode": "off", "ks_persistent": False, "ks_allow_lan": False, "ks_allow_direct": False}
    try:
        s.update(json.load(open(SETTINGS, encoding="utf8")))
    except (OSError, ValueError):
        for f in (os.path.join(HOME, "bridges.txt"), os.path.join(APP_DIR, "assets", "bridges.txt")):
            try:  # older versions kept only bridges.txt; a fresh install starts from the shipped bridges
                s["bridges"] = open(f, encoding="utf8").read()
                break
            except OSError:
                pass
    s, _ = split_engine.migrate_settings(s)
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
    # the last mirror is our own copy of the same file; it's accepted only if it matches the pinned hash
    for u in (URL, URL.replace("dist.", "archive.").replace("/torbrowser/", "/tor-package-archive/torbrowser/"),
              f"https://github.com/{REPO}/releases/download/tor-{VER}/{os.path.basename(URL)}"):
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


def fetch_bridges(via_proxy=None, log=print, allow_direct=True):
    """Ask the Tor Project (Moat API) for bridges that work in Iran. Tries through Tor, and optionally direct/fronted."""
    body = json.dumps({"country": "ir", "transports": ["obfs4", "webtunnel", "snowflake", "meek"]}).encode()
    routes = ([("via Tor", MOAT, None, via_proxy)] if via_proxy else []) + \
             ([("direct", MOAT, None, None), ("fronted", MOAT_FRONT[0], MOAT_FRONT[1], None)] if allow_direct else [])
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


def latest_version(proxy):
    """Version of the newest GitHub release, e.g. "1.1.0" for tag v1.1.0."""
    o = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}))
    o.addheaders = [("User-Agent", "Gommage")]
    return json.load(o.open(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=30))["tag_name"].lstrip("v")


def newer(a, b):
    """True if version b is newer than a."""
    v = lambda x: tuple(int(n) for n in re.findall(r"\d+", x))
    return v(b) > v(a)


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


def exit_relays(ns):
    """Fingerprints of usable exit relays (Exit + Fast, not BadExit) from GETINFO ns/all."""
    out, fp = [], None
    for line in ns.splitlines():
        if line.startswith("r "):
            fp = base64.b64decode(line.split()[2] + "==").hex().upper()
        elif line.startswith("s ") and fp:
            flags = line.split()
            if "Exit" in flags and "Fast" in flags and "BadExit" not in flags:
                out.append(fp)
    return out


def stale_circuits(status, fp):
    """IDs of built circuits (from GETINFO circuit-status) whose exit isn't relay fp."""
    return [m[1] for m in re.finditer(r"^(?:250[-+]circuit-status=)?(\d+) BUILT (\S+)", status, re.M)
            if m[2].split(",")[-1].split("~")[0].lstrip("$") != fp]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):
        return None  # a 3xx surfaces as HTTPError so we can look at where it points


GOOGLE_AI = ("https://gemini.google.com/app", "https://notebook.google.com/")  # Gemini, NotebookLM


def gemini_ok(proxy):
    """True if every GOOGLE_AI site answers this exit; Google sends 403/429 or a /sorry/ redirect to exits it blocks."""
    o = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}), NoRedirect)
    o.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36")]
    for url in GOOGLE_AI:
        try:
            o.open(url, timeout=20).read(1)
        except urllib.error.HTTPError as e:
            if e.code >= 400 or "/sorry/" in (e.headers.get("Location") or ""):
                return False
    return True


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


def self_cmd(extra_args=""):
    """(program, args) that start this app again without a console window."""
    if FROZEN:
        return sys.executable, extra_args
    exe = sys.executable.replace("python.exe", "pythonw.exe") if WIN else sys.executable
    args = f'"{os.path.abspath(__file__)}"' + (f" {extra_args}" if extra_args else "")
    return exe, args


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
        return {
            "settings": a.s,
            "countries": COUNTRIES,
            "app_modes": APP_MODES,
            "log_path": LOG,
            "windows": WIN,
            "state": a.ui_state,
            "split": a.s.get("split"),
            "ks": a.ks_status(),
            "profiles_builtin": split_engine.BUILTIN_PROFILES,
            "log": open(LOG, encoding="utf8", errors="replace").read()[-20000:] if os.path.exists(LOG) else "",
        }

    def set(self, key, value):
        a = self._app
        push_kw = None
        with a.settings_lock:
            if key == "vpn" and not value and a.s.get("ks_mode", "off") != "off":
                if a.ks.mode != "off" and not is_admin():
                    res = a.unlock_killswitch()
                    if not res.get("ok"):
                        return res
                else:
                    a.s["ks_mode"] = "off"
                    a.s["ks_persistent"] = False
                    if a.ks.mode != "off" and is_admin():
                        a.ks.disarm(force_persistent=True)
                        if a.state_ == "locked" and not a.proc:
                            a.render("Disconnected", "red")
            a.s[key] = value
            if key == "autostart":
                set_autostart(bool(value))
            a.save_settings()
            if key in ("vpn", "ks_mode"):
                push_kw = {
                    "ks": a.ks_status(),
                    "settings": {"vpn": a.s["vpn"], "ks_mode": a.s.get("ks_mode", "off"), "ks_persistent": bool(a.s.get("ks_persistent", False))},
                }
        if push_kw:
            a.push(**push_kw)
        return {"ok": True}

    def toggle(self):
        self._app.toggle()

    def new_identity(self):
        self._app.new_identity()

    def gemini_exit(self):
        self._app.gemini_exit()

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

    def get_split(self):
        return {"split": self._app.s["split"], "ks": self._app.ks_status()}

    def save_split(self, cfg):
        return self._app.save_split(cfg)

    def l2tp_get(self):
        return self._app.l2tp_view()

    def l2tp_save(self, cfg):
        return self._app.save_l2tp(cfg)

    def apply_split(self):
        return self._app.apply_split_live()

    def reset_split(self):
        return self._app.reset_split()

    def discover_apps(self):
        return split_engine.discover_apps(exclude_dir=HOME, home_hint=HOME)

    def pick_app_file(self):
        return self._app.pick_app_dialog(folder=False)

    def pick_app_folder(self):
        return self._app.pick_app_dialog(folder=True)

    def test_rule(self, query):
        return self._app.test_rule(query)

    def live_connections(self):
        return self._app.live_connections()

    def kill_connection(self, cid):
        return bool(self._app.clash and self._app.clash.close_connection(cid))

    def kill_app_connections(self, process_key):
        return self._app.kill_app_connections(process_key)

    def set_killswitch(self, cfg):
        return self._app.set_killswitch(cfg)

    def unlock_killswitch(self):
        return self._app.unlock_killswitch()

    def launch_protected(self, app_id):
        return self._app.launch_protected(app_id)

    def run_leak_audit(self):
        return self._app.run_leak_audit()

    def export_split(self):
        return json.dumps(self._app.s["split"], indent=2)

    def import_split(self, text):
        return self._app.import_split(text)

    def open_update(self):
        webbrowser.open(f"https://github.com/{REPO}/releases/latest")

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
        self.stop_reason = None
        self.state_ = "idle"
        self.ui_state = {}
        self._push_q = queue.Queue()
        self.closing = self.finding = False
        self.starting_vpn = self.reloading_vpn = False
        self.last_newnym = 0.0
        self.lock = threading.RLock()
        self.settings_lock = threading.RLock()
        self.session_gen = 0
        self.clash = self.clash_port = self.clash_secret = None
        self.upstream_dns = None
        self._ir_cidrs = []
        self._applied_sb_shape = None
        self._clash_fails = 0
        self._circ_missing_since = None
        self._ks_tick = 0
        self._l2tp_busy = False
        self._last_exit_fp = None
        self._last_exit_cid = None
        relink_autostart = migrate_old_name()
        self.s = load_settings()
        if relink_autostart and self.s["autostart"]:
            set_autostart(True)
        if self.s["country"] not in COUNTRIES:
            self.s["country"] = "Any"
        self.ks = killswitch.create_killswitch(HOME, self.log)
        self.ks.reconcile_startup(self.s)
        if not WIN and is_admin():
            self.give_back()  # whatever happens to this root copy later, the files are already the user's
            import atexit
            atexit.register(self.give_back)
            for sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, lambda n, _f: (self.give_back(), signal.signal(n, signal.SIG_DFL), os.kill(os.getpid(), n)))
        if "--arm-ks" in sys.argv and is_admin() and self.s.get("ks_mode", "off") != "off":
            try:
                self._arm_ks_locked("Kill Switch armed")
            except Exception as e:
                self.log(f"Kill Switch arm error: {e}")
        if self.ks.locked:
            self.state_ = "locked"
            self.ui_state.update(state="locked", title="Network Locked", sub=self.ks.reason or "Kill Switch active", pct=None, ks=self.ks_status())
        else:
            self.render("Disconnected", "red")
            self.ui_state["ks"] = self.ks_status()
        self.win = webview.create_window("Gommage", os.path.join(APP_DIR, "ui.html"),
                                         js_api=Api(self), width=400, height=780, min_size=(380, 740),
                                         frameless=True, easy_drag=False, background_color="#121419")
        self.win.events.closing += self.on_closing
        if WIN:
            self.win.events.shown += self.round_corners
            self.tray = pystray.Icon("Gommage", Image.open(os.path.join(APP_DIR, "assets", "icon.png")), "Gommage", pystray.Menu(
                pystray.MenuItem("Open", lambda: self.win.show(), default=True),
                pystray.MenuItem("Unlock Kill Switch", lambda: threading.Thread(target=self.unlock_killswitch, daemon=True).start()),
                pystray.MenuItem("Quit", self.quit_from_tray)))
            self.tray.run_detached()
        self.tray_ok = WIN
        if not WIN:
            self._init_linux_tray()
        self.win.events.loaded += self._on_loaded
        threading.Thread(target=self._push_loop, daemon=True).start()
        threading.Thread(target=self.traffic, daemon=True).start()

    def _init_linux_tray(self):
        """Closing the window hides it to the tray (like Windows) when a tray icon exists; otherwise it quits."""
        if is_admin():
            threading.Thread(target=self._jail_watcher, daemon=True).start()
            if os.environ.get("GOMMAGE_TRAY") == "1":
                threading.Thread(target=self._ctl_server, daemon=True).start()
        else:
            self._tray_ind = make_indicator(self.present, self.quit_from_tray)
            self.tray_ok = self._tray_ind is not None

    def _jail_watcher(self):
        """Strict Apps Only: attach_running_to_jail only ran at arm time, so an app started later (closed, then opened
        again) ran outside the jail and connected freely. Sweep /proc and put every matching process in the jail."""
        while not self.closing:
            time.sleep(0.5)
            try:
                if self.ks.mode == "apps" and hasattr(self.ks, "attach_running_to_jail"):
                    apps = [a for a in self.s.get("split", {}).get("apps", [])
                            if a.get("enabled", True) and a.get("action") == "tor_strict"]
                    if apps:
                        self.ks.attach_running_to_jail(apps)
            except Exception:
                pass

    def _ctl_server(self):
        """Root copy: the user's tray process sends 'show' / 'quit' here."""
        path = ctl_path()
        try:
            try:
                os.unlink(path)
            except OSError:
                pass
            srv = socket.socket(socket.AF_UNIX)
            srv.bind(path)
            os.chmod(path, 0o600)
            uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
            if uid and uid.isdigit():
                os.chown(path, int(uid), -1)
            srv.listen(4)
        except OSError as e:
            self.log(f"tray control socket failed: {e}")
            return
        self.tray_ok = True
        while not self.closing:
            try:
                c, _ = srv.accept()
                with c:
                    cmd = c.recv(64).strip()
            except OSError:
                continue
            if cmd == b"show":
                self.present()
            elif cmd == b"quit":
                self.quit_from_tray()
        srv.close()

    def present(self):
        if getattr(self, "_elevating", False):
            return
        self.win.show()
        try:
            from gi.repository import GLib
            from webview.platforms.gtk import BrowserView
            GLib.idle_add(BrowserView.instances[self.win.uid].window.present)
        except Exception:
            pass

    def _hook_linux_drag(self):
        """Linux: a frameless GTK window has no title bar and pywebview's drag region only works on Windows; on Wayland
        the app can't move itself either. Ask the compositor to start the move when the top strip is pressed."""
        if WIN or getattr(self, "_drag_hooked", False):
            return
        self._drag_hooked = True
        try:
            from webview.platforms.gtk import BrowserView
            view = BrowserView.instances[self.win.uid]

            def press(_w, ev):
                if ev.button == 1 and ev.y < 28 and ev.x < view.window.get_size()[0] - 84:
                    view.window.begin_move_drag(ev.button, int(ev.x_root), int(ev.y_root), ev.time)
                    return True
                return False
            view.webview.connect("button-press-event", press)
        except Exception as e:
            self.log(f"window drag unavailable: {e}")

    def _on_loaded(self):
        self._hook_linux_drag()
        if self.s["autoconnect"] or ("--connect" in sys.argv and is_admin()):
            self.after(350, self.toggle)

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

    def _push_loop(self):
        while not self.closing:
            try:
                kw = self._push_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if kw is None or self.closing or not hasattr(self, "win"):
                continue
            try:
                self.win.evaluate_js(f"window.ui && ui({json.dumps(kw)})")
            except Exception:
                pass  # window not ready yet / closing; init() hands over ui_state

    def push(self, **kw):
        self.ui_state.update({k: v for k, v in kw.items() if k != "log"})
        if self.closing or not hasattr(self, "win"):
            return  # evaluate_js would wait forever on a window that is shutting down
        q = getattr(self, "_push_q", None)
        if q is not None:
            q.put(kw)
        else:
            try:
                self.win.evaluate_js(f"window.ui && ui({json.dumps(kw)})")
            except Exception:
                pass

    def render(self, text, color):
        self.state_ = {"green": "on", "orange": "busy", "red": "err" if text.startswith(("Error", "Bad")) else "idle", "locked": "locked"}[color]
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

    def ks_status(self) -> dict:
        st = self.ks.status()
        st["allow_lan"] = bool(self.s.get("ks_allow_lan", False))
        st["allow_direct"] = bool(self.s.get("ks_allow_direct", False))
        st["force_tor_dns"] = bool(self.s.get("split", {}).get("force_tor_dns", True))
        return st

    def _runtime_dir(self) -> str:
        return "/run/gommage" if not WIN else os.path.join(HOME, "runtime")

    def _tor_binary_paths(self, tor: str | None = None, pt: str | None = None) -> list[str]:
        cands = []
        if tor:
            cands.append(tor)
        if pt:
            cands.append(pt)
            pt_dir = os.path.dirname(pt)
            for name in TOR_PROCS:
                p = os.path.join(pt_dir, name)
                if os.path.exists(p):
                    cands.append(p)
        tor_dir = os.path.join(HOME, "tor")
        for p in (os.path.join(tor_dir, "tor" + EXE),
                  os.path.join(tor_dir, "pluggable_transports", "lyrebird" + EXE),
                  os.path.join(tor_dir, "pluggable_transports", "conjure-client" + EXE)):
            if os.path.exists(p):
                cands.append(p)
        return list(dict.fromkeys(split_engine.canonical_path(p) for p in cands if p and os.path.exists(p)))

    def _effective_force_tor_dns(self) -> bool:
        sp = self.s["split"]
        ks_mode = self.s.get("ks_mode", "off")
        ks_strict_no_direct = (ks_mode == "system" and not bool(self.s.get("ks_allow_direct", False)))
        has_strict_apps = any(a.get("enabled", True) and a.get("action") == "tor_strict" for a in sp.get("apps", []))
        return bool(sp.get("force_tor_dns", True)) or ks_strict_no_direct or has_strict_apps

    def _arm_ks_locked(
        self,
        reason: str,
        connecting_hostname_bridge: bool = False,
        tor_paths: list[str] | None = None,
        kill_sockets: bool = True,
    ) -> dict:
        ks_mode = self.s.get("ks_mode", "off")
        if ks_mode == "off":
            return self.ks.disarm(force_persistent=True)
        if tor_paths is None:
            tor_paths = self._tor_binary_paths()
        if ks_mode == "system" and not tor_paths and not self.proc:
            # Ensure tor binaries exist before arming WFP AppId system lock
            tor, pt = ensure_tor(self.log)
            tor_paths = self._tor_binary_paths(tor, pt)
        st = self.ks.arm(
            mode=ks_mode,
            persistent=bool(self.s.get("ks_persistent", False)),
            tor_paths=tor_paths,
            singbox_path=SINGBOX if os.path.exists(SINGBOX) else None,
            split_cfg=self.s["split"],
            allow_lan=bool(self.s.get("ks_allow_lan", False)),
            allow_direct=bool(self.s.get("ks_allow_direct", False)),
            force_tor_dns=self._effective_force_tor_dns(),
            connecting_hostname_bridge=connecting_hostname_bridge,
            tunnel_open=False,
            reason=reason,
            kill_sockets=kill_sockets,
        )
        return st

    def on_tunnel_drop(self, reason: str):
        with self.lock:
            if self.cancelled or self.reloading_vpn or self.state_ == "locked":
                return
            self.log(f"WATCHDOG: {reason}")
            self.stop(reason="crash", drop_reason=reason)

    def traffic(self):
        """Live down/up rate + active health watchdog for Tor circuits and sing-box TUN."""
        last = None
        while True:
            time.sleep(1)
            self._ks_tick += 1
            if self.state_ != "on":
                last = None
                self._clash_fails = 0
                self._circ_missing_since = None
                self._last_exit_fp = None
                self._last_exit_cid = None
                if not WIN and self.ks.mode != "off" and self._ks_tick % 3 == 0:
                    self.push(ks=self.ks_status())
                continue
            if not self.starting_vpn and not self.reloading_vpn:
                if (self.proc and self.proc.poll() is not None) or (
                    self.s.get("vpn") and (self.tun is None or (isinstance(self.tun, subprocess.Popen) and self.tun.poll() is not None))
                ):
                    self.on_tunnel_drop("Tor or VPN process exited unexpectedly")
                    continue
                if self.s.get("vpn") and self.clash:
                    if not self.clash.ping():
                        self._clash_fails += 1
                        if self._clash_fails >= 3:
                            self.on_tunnel_drop("VPN tunnel stopped responding")
                            continue
                    else:
                        self._clash_fails = 0
                if self._ks_tick % 15 == 0 and self.s.get("vpn") and self.l2tp_managed() and not self._l2tp_busy:
                    def _redial():
                        try:
                            if not l2tp.connected():
                                self.log("L2TP: link down, redialing")
                                if self.l2tp_dial():
                                    self.apply_split_live()  # new pppN: rebind sing-box
                        finally:
                            self._l2tp_busy = False
                    self._l2tp_busy = True
                    threading.Thread(target=_redial, daemon=True).start()
            try:
                r = control("GETINFO traffic/read traffic/written circuit-status stream-status")
                cur = (int(re.search(r"traffic/read=(\d+)", r)[1]), int(re.search(r"traffic/written=(\d+)", r)[1]))
            except Exception:
                continue
            if last:
                kw = {"down": cur[0] - last[0], "up": cur[1] - last[1]}
                if not WIN and self.ks.mode != "off" and self._ks_tick % 3 == 0:
                    kw["ks"] = self.ks_status()
                self.push(**kw)
            last = cur

            if not self.starting_vpn and not self.reloading_vpn and not self.finding and self._ks_tick % 3 == 0:
                self._sync_live_exit(r)

            if not self.starting_vpn and not self.reloading_vpn and not self.finding and (time.time() - self.last_newnym >= 15):
                has_general = bool(re.search(r"^(?:250[-+]circuit-status=)?\d+ BUILT .*PURPOSE=GENERAL", r, re.M))
                if has_general:
                    self._circ_missing_since = None
                else:
                    self._circ_missing_since = self._circ_missing_since or time.time()
                    if time.time() - self._circ_missing_since >= 15:
                        self.on_tunnel_drop("Tor circuits lost")
                        continue
            else:
                self._circ_missing_since = None

    # ---------- helpers ----------
    def save_settings(self):
        with self.settings_lock:
            os.makedirs(HOME, exist_ok=True)
            split_engine.sync_legacy_fields(self.s)
            tmp = SETTINGS + ".tmp"
            with open(tmp, "w", encoding="utf8") as f:
                json.dump(self.s, f, indent=1)
            if not WIN:
                os.chmod(tmp, 0o600)  # holds the L2TP password/PSK
            os.replace(tmp, SETTINGS)

    def set_bridges(self, text):
        with self.settings_lock:
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

    def _sync_live_exit(self, status_text: str) -> bool:
        """Update displayed exit IP from the active Tor stream/circuit without a separate proxy hop."""
        circuits: dict[str, str] = {}
        for m in re.finditer(r"^(?:250[-+]circuit-status=)?(\d+)\s+BUILT\s+(\S+).*?PURPOSE=GENERAL\b", status_text, re.M):
            cid, path = m.group(1), m.group(2)
            hops = re.findall(r"\$([0-9A-Fa-f]{40})", path)
            if len(hops) >= 2:
                circuits[cid] = hops[-1].upper()
        if not circuits:
            return False

        chosen_cid = None
        for m in re.finditer(r"^(?:250[-+]stream-status=)?\d+\s+SUCCEEDED\s+(\d+)\s+(\S+)", status_text, re.M):
            cid, target = m.group(1), m.group(2)
            if cid in circuits and not target.startswith(("127.0.0.1:", "localhost:", "[::1]:")):
                chosen_cid = cid
        if not chosen_cid:
            chosen_cid = self._last_exit_cid if self._last_exit_cid in circuits else list(circuits.keys())[-1]

        fp = circuits.get(chosen_cid)
        if not fp:
            return False
        if fp == self._last_exit_fp:
            self._last_exit_cid = chosen_cid
            return True
        try:
            ns = control(f"GETINFO ns/id/{fp}")
            rm = re.search(r"^r\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", ns, re.M)
            if not rm:
                return False
            ip = str(ipaddress.ip_address(rm.group(1)))
            cc = re.search(r"ip-to-country/\S+=(\w+)", control(f"GETINFO ip-to-country/{ip}"))
            self._last_exit_fp = fp
            self._last_exit_cid = chosen_cid
            if self.proc:
                self.push(exit={"ip": ip, "cc": cc.group(1).lower() if cc else ""})
            return True
        except Exception:
            return False

    def show_exit(self, delay=1):
        time.sleep(delay)
        try:
            if self.s.get("vpn") and self._sync_live_exit(control("GETINFO circuit-status stream-status")):
                return
        except Exception:
            pass
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
        if not self.proc and self.ks.mode == "system" and self.ks.locked:
            return self.push(test="Blocked while Whole-System Kill Switch is locked — connect or unlock first")
        self.push(test="looking for fresh bridges…")

        def go():
            via = f"http://{LOCAL}:{HTTP}" if self.proc else None
            cur = clean_bridges(self.s["bridges"])
            found = fetch_public(via, self.log) if self.s.get("community", True) else {}
            if via:  # Tor Project's own API only answers through Tor from Iran
                for l in fetch_bridges(via, self.log, allow_direct=False):
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

    def exit_conf(self):
        """Back to the exit chosen in Settings (undoes a pinned Gemini exit)."""
        cc = COUNTRIES[self.s["country"]]
        control(f"SETCONF ExitNodes={{{cc}}} StrictNodes=1" if cc else "RESETCONF ExitNodes StrictNodes")

    def gemini_exit(self, tries=40):
        """Opt-in: pin the exit to one relay Google doesn't block for Gemini/NotebookLM. New identity undoes it."""
        if self.finding or not self.proc:
            return
        self.finding = True

        def go():
            try:
                exits = exit_relays(control("GETINFO ns/all"))
                random.shuffle(exits)
                for n, fp in enumerate(exits[:tries], 1):
                    if not self.proc:
                        return
                    self.push(gemini=f"{n}/{tries}")
                    control(f"SETCONF ExitNodes=${fp} StrictNodes=1")  # Tor drops circuits through the old exit
                    try:
                        if gemini_ok(f"http://{LOCAL}:{HTTP}"):
                            self.log(f"Gemini and NotebookLM work through exit ${fp}")
                            # the browser keeps its Google connections open on circuits through the old exit; close
                            # them so it reconnects through this one
                            control(*(f"CLOSECIRCUIT {c}" for c in stale_circuits(control("GETINFO circuit-status"), fp)))
                            self.push(gemini="ok")
                            return self.show_exit(0)
                    except Exception as e:
                        self.log(f"Gemini exit ${fp[:8]}: {e}")
                self.log(f"no Gemini exit in {tries} tries")
                self.exit_conf()
                self.push(gemini="fail")
            except Exception as e:
                self.log(f"Gemini exit: {e}")
                self.push(gemini="fail")
            finally:
                self.finding = False
        threading.Thread(target=go, daemon=True).start()

    def new_identity(self):
        def go():
            try:
                self.last_newnym = time.time()
                self.exit_conf()
                control("SIGNAL NEWNYM")
                self.push(exit={"ip": "getting new identity…", "cc": ""}, gemini=None)
                self.show_exit(4)
            except Exception as e:
                self.log(f"NEWNYM failed: {e}")
        threading.Thread(target=go, daemon=True).start()

    def test_bridges(self):
        if not self.proc and self.ks.mode == "system" and self.ks.locked:
            return self.push(test="Blocked while Whole-System Kill Switch is locked — connect or unlock first")
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

    # ---------- advanced split + kill switch API ----------
    def pick_app_dialog(self, folder=False):
        if folder:
            paths = self.win.create_file_dialog(webview.FileDialog.FOLDER, allow_multiple=False)
        else:
            paths = self.win.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=True, file_types=("Programs (*.exe)",) if WIN else ())
        out = []
        for p in paths or ():
            cp = split_engine.canonical_path(p)
            name = os.path.basename(cp.rstrip("\\/")) or cp
            out.append({"name": name, "path": cp, "match_type": "folder" if folder else "path"})
        return out

    def l2tp_managed(self):
        return bool((self.s.get("l2tp") or {}).get("enabled"))

    def l2tp_dial(self):
        """Dial the managed link and point L2TP apps at its interface (Linux: pppN, which can change on redial).
        True when the interface changed, i.e. sing-box needs a restart to bind to it."""
        name = l2tp.up(self.s["l2tp"], self.log)
        if not name or name == self.s["split"].get("l2tp_iface"):
            return False
        with self.settings_lock:
            self.s["split"]["l2tp_iface"] = name
            self.save_settings()
        return True

    def l2tp_view(self):
        c = self.s.get("l2tp") or {}
        return {"enabled": bool(c.get("enabled")), "server": c.get("server", ""), "user": c.get("user", ""),
                "has_password": bool(c.get("password")), "has_psk": bool(c.get("psk")),
                "connected": l2tp.connected(), "missing": l2tp.available(), "windows": WIN}

    def save_l2tp(self, cfg):
        """Blank password/PSK keep the saved ones. Secrets are never returned to the page."""
        if cfg.get("enabled") and (missing := l2tp.available()):
            return {"ok": False, "error": f"L2TP: {missing}"}
        with self.settings_lock:
            old = self.s.get("l2tp") or {}
            c = {"enabled": bool(cfg.get("enabled")), "server": str(cfg.get("server", "")).strip()[:253],
                 "user": str(cfg.get("user", "")).strip()[:256],
                 "password": l2tp.protect(cfg["password"]) if cfg.get("password") else old.get("password", ""),
                 "psk": l2tp.protect(cfg["psk"]) if cfg.get("psk") else old.get("psk", "")}
            self.s["l2tp"] = c
            sp = self.s["split"]
            if c["enabled"]:
                sp["l2tp_iface"] = l2tp.NAME if WIN else l2tp.iface()  # Linux: known once dialed
            elif old.get("enabled"):
                sp["l2tp_iface"] = ""
            self.save_settings()
        if not c["enabled"]:
            threading.Thread(target=l2tp.down, args=(self.log,), daemon=True).start()
        return {"ok": True, "l2tp": self.l2tp_view(), "split": self.s["split"]}

    def save_split(self, cfg):
        with self.settings_lock:
            self.s["split"] = split_engine.validate_split(cfg)
            self.save_settings()
        return {"ok": True, "split": self.s["split"]}

    def reset_split(self):
        with self.settings_lock:
            self.s["split"] = split_engine.default_split()
            self.save_settings()
        return {"ok": True, "split": self.s["split"]}

    def import_split(self, text):
        try:
            sp = split_engine.parse_import_split(text)
            with self.settings_lock:
                self.s["split"] = sp
                self.save_settings()
            return {"ok": True, "split": self.s["split"]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def test_rule(self, q):
        if not self._ir_cidrs and os.path.exists(geoip()):
            try:
                self._ir_cidrs = country_nets(geoip(), "IR")
            except OSError:
                pass
        return split_engine.test_route(
            self.s["split"],
            app_name=str(q.get("app_name") or ""),
            app_path=str(q.get("app_path") or ""),
            host=str(q.get("host") or ""),
            ip=str(q.get("ip") or ""),
            port=int(q.get("port") or 443),
            proto=str(q.get("proto") or "tcp"),
            ir_cidrs=self._ir_cidrs,
            ks_mode=self.s.get("ks_mode", "off"),
            ks_allow_lan=bool(self.s.get("ks_allow_lan", False)),
            ks_allow_direct=bool(self.s.get("ks_allow_direct", False)),
        )

    def live_connections(self):
        if not self.clash or self.state_ != "on":
            return {"total": 0, "up_total": 0, "down_total": 0, "groups": []}
        return self.clash.get_connections()

    def kill_app_connections(self, process_key):
        if not self.clash:
            return 0
        key_cmp = str(process_key or "")
        if WIN:
            key_cmp = key_cmp.lower()
            return self.clash.close_matching_connections(
                lambda c: (((c.get("metadata") or {}).get("processPath") or (c.get("metadata") or {}).get("process") or "System / Unknown").lower() == key_cmp)
            )
        return self.clash.close_matching_connections(
            lambda c: (((c.get("metadata") or {}).get("processPath") or (c.get("metadata") or {}).get("process") or "System / Unknown") == key_cmp)
        )

    def _sb_shape(self):
        sp = self.s["split"]
        return (
            sp.get("default_mode", "all"),
            self._effective_force_tor_dns(),
            bool(sp.get("presets", {}).get("anti_leak", True)),
            self.s.get("ks_mode", "off"),
            bool(self.s.get("ks_allow_lan", False)),
            bool(self.s.get("ks_allow_direct", False)),
            self.upstream_dns,
            sp.get("l2tp_iface", ""),  # adds/removes the l2tp outbound: needs a sing-box restart
        )

    def _spawn_singbox_only(self):
        runtime_dir = self._runtime_dir()
        rules_dir = os.path.join(runtime_dir, "rules")
        os.makedirs(runtime_dir, exist_ok=True)
        if not WIN:
            os.chmod(runtime_dir, 0o700)
        if not self._ir_cidrs and os.path.exists(geoip()):
            self._ir_cidrs = country_nets(geoip(), "IR")
        rules_paths = split_engine.write_rule_sets(rules_dir, self.s["split"], self._ir_cidrs)
        self.clash_port = free_port(19090, (SOCKS, HTTP, DNS_PORT), host="127.0.0.1")
        self.clash_secret = os.urandom(16).hex()
        self.clash = split_engine.ClashClient(self.clash_port, self.clash_secret)
        ks_mode = self.s.get("ks_mode", "off")
        cfg = split_engine.build_singbox_config(
            self.s["split"],
            rules_paths,
            (LOCAL, SOCKS),
            DNS_PORT,
            self._tor_binary_paths(),
            TOR_PROCS,
            self.clash_port,
            self.clash_secret,
            upstream_dns=self.upstream_dns,
            ks_mode=ks_mode,
            ks_allow_lan=bool(self.s.get("ks_allow_lan", False)),
            ks_allow_direct=bool(self.s.get("ks_allow_direct", False)),
        )
        if self.l2tp_managed():
            self.l2tp_dial()  # before the TUN exists, so IPsec setup can't loop into it
        else:
            l2tp.ensure_routes(self.s["split"].get("l2tp_iface", ""), self.log)
        sb_path = os.path.join(runtime_dir, "sing-box.json")
        with open(sb_path, "w", encoding="utf8") as f:
            json.dump(cfg, f, indent=1)
        if not WIN:
            os.chmod(sb_path, 0o600)
        kw = {"cwd": HOME}
        if not WIN and is_admin():
            kw["group"] = killswitch.GOMMAGE_SB_GID
        tun = self.tun = popen([SINGBOX, "run", "-c", sb_path, "-D", HOME], **kw)
        threading.Thread(
            target=lambda: [self.log("sing-box: " + re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in tun.stdout],
            daemon=True,
        ).start()
        deadline = time.time() + 8.0
        luid = None
        while time.time() < deadline:
            if tun.poll() is not None:
                raise RuntimeError("sing-box exited, see log")
            if self.clash.ping():
                if WIN:
                    luid = killswitch.resolve_wintun_luid()
                    if luid:
                        break
                elif os.path.exists("/sys/class/net/Gommage"):
                    break
            time.sleep(0.3)
        if not self.clash.ping():
            raise RuntimeError("sing-box Clash API unresponsive, see log")
        if WIN and not luid:
            luid = killswitch.resolve_wintun_luid()
        if ks_mode != "off":
            self.ks.open_tunnel(wintun_luid=luid, singbox_path=SINGBOX, split_cfg=self.s["split"])
        self._applied_sb_shape = self._sb_shape()
        run("ipconfig", "/flushdns") if WIN else run("resolvectl", "flush-caches")

    def apply_split_live(self):
        if self.l2tp_managed():
            self.l2tp_dial()
        else:
            l2tp.ensure_routes(self.s.get("split", {}).get("l2tp_iface", ""), self.log)
        with self.lock:
            runtime_dir = self._runtime_dir()
            rules_dir = os.path.join(runtime_dir, "rules")
            if not self._ir_cidrs and os.path.exists(geoip()):
                try:
                    self._ir_cidrs = country_nets(geoip(), "IR")
                except OSError:
                    pass
            if not (self.state_ == "on" and self.s.get("vpn") and isinstance(self.tun, subprocess.Popen) and self.tun.poll() is None):
                if self.s.get("ks_mode", "off") != "off" and is_admin():
                    try:
                        self._arm_ks_locked(self.ks.reason or "Kill Switch active")
                    except Exception as e:
                        return {"ok": False, "error": str(e), "ks": self.ks_status()}
                return {"ok": True, "restarted": False, "ks": self.ks_status()}

            need_restart = (self._sb_shape() != self._applied_sb_shape)
            restarted = False
            if not need_restart:
                split_engine.write_rule_sets(rules_dir, self.s["split"], self._ir_cidrs)
                if self.s.get("ks_mode", "off") != "off" and is_admin():
                    luid = killswitch.resolve_wintun_luid() if WIN else None
                    self.ks.arm(
                        mode=self.s["ks_mode"],
                        persistent=bool(self.s.get("ks_persistent", False)),
                        tor_paths=self._tor_binary_paths(),
                        singbox_path=SINGBOX if os.path.exists(SINGBOX) else None,
                        split_cfg=self.s["split"],
                        allow_lan=bool(self.s.get("ks_allow_lan", False)),
                        allow_direct=bool(self.s.get("ks_allow_direct", False)),
                        force_tor_dns=self._effective_force_tor_dns(),
                        tunnel_open=True,
                        wintun_luid=luid,
                        reason="Protected",
                        kill_sockets=False,
                    )
                if self.clash:
                    tightened = {
                        (a.get("path") or a.get("name") or "").lower()
                        for a in self.s["split"].get("apps", [])
                        if a.get("enabled", True) and a.get("action") in ("tor_strict", "tor", "block")
                    }
                    if tightened:
                        self.clash.close_matching_connections(
                            lambda c: "direct" in (c.get("chains") or []) and (
                                ((c.get("metadata") or {}).get("processPath") or "").lower() in tightened
                                or ((c.get("metadata") or {}).get("process") or "").lower() in tightened
                            )
                        )
                run("ipconfig", "/flushdns") if WIN else run("resolvectl", "flush-caches")
            else:
                self.reloading_vpn = True
                try:
                    ks_mode = self.s.get("ks_mode", "off")
                    if ks_mode != "off":
                        if self.ks.mode == "off":
                            self._arm_ks_locked("Applying split rules", kill_sockets=False)
                        else:
                            self.ks.lock_tunnel("Applying split rules")
                    self.stop_vpn()
                    if ks_mode != "off":
                        self._arm_ks_locked("Applying split rules", kill_sockets=False)
                    self._spawn_singbox_only()
                    restarted = True
                except Exception as e:
                    self.log(f"Split live reload error: {e}")
                    self.stop_vpn()
                    if self.s.get("ks_mode", "off") != "off":
                        self.ks.lock_tunnel(f"Reload failed: {e}")
                        self.render(f"Connection Locked (Reload failed: {e})", "locked")
                        self.push(ks=self.ks_status())
                    else:
                        self.stop(reason="crash", drop_reason=f"Split reload failed: {e}")
                    return {"ok": False, "error": str(e), "restarted": False, "ks": self.ks_status()}
                finally:
                    self.reloading_vpn = False
            self.push(ks=self.ks_status())
            return {"ok": True, "restarted": restarted, "ks": self.ks_status()}

    def _elevate_for_action(self, flag: str):
        self.save_settings()
        if not WIN:
            threading.Thread(target=self.relaunch_root, args=([flag],), daemon=True).start()
            return {"ok": True, "elevating": True, "ks": self.ks_status()}
        extra = f'--home "{HOME}" {flag}'.strip()
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", *self_cmd(extra), None, 1) > 32:
            self.closing = True
            if hasattr(self, "_push_q"):
                self._push_q.put(None)
            threading.Thread(target=self.win.destroy, daemon=True).start()
            return {"ok": True, "elevating": True, "ks": self.ks_status()}
        return {"ok": False, "error": "Administrator permission was refused", "ks": self.ks_status()}

    def set_killswitch(self, cfg):
        with self.settings_lock:
            mode = cfg.get("ks_mode", self.s.get("ks_mode", "off"))
            if mode not in ("off", "apps", "system"):
                return {"ok": False, "error": f"Invalid Kill Switch mode: {mode}"}
            if mode == "off" and self.ks.mode != "off" and not is_admin():
                return self.unlock_killswitch()
            prev = (
                self.s.get("ks_mode", "off"),
                bool(self.s.get("ks_persistent", False)),
                bool(self.s.get("ks_allow_lan", False)),
                bool(self.s.get("ks_allow_direct", False)),
                bool(self.s.get("vpn", False)),
                bool(self.s["split"].get("force_tor_dns", True)),
            )
            self.s["ks_mode"] = mode
            if "ks_persistent" in cfg:
                self.s["ks_persistent"] = bool(cfg["ks_persistent"])
            if "ks_allow_lan" in cfg:
                self.s["ks_allow_lan"] = bool(cfg["ks_allow_lan"])
            if "ks_allow_direct" in cfg:
                self.s["ks_allow_direct"] = bool(cfg["ks_allow_direct"])
            if "force_tor_dns" in cfg:
                self.s["split"]["force_tor_dns"] = bool(cfg["force_tor_dns"])
            if mode != "off":
                self.s["vpn"] = True
            else:
                self.s["ks_persistent"] = False
            self.save_settings()

        if mode != "off" and not is_admin():
            res = self._elevate_for_action("--arm-ks")
            if not res.get("ok"):
                with self.settings_lock:
                    (
                        self.s["ks_mode"],
                        self.s["ks_persistent"],
                        self.s["ks_allow_lan"],
                        self.s["ks_allow_direct"],
                        self.s["vpn"],
                        self.s["split"]["force_tor_dns"],
                    ) = prev
                    self.save_settings()
                res["settings"] = self.s
            return res

        try:
            with self.lock:
                if mode == "off":
                    self.ks.disarm(force_persistent=True)
                    if self.state_ == "locked" and not self.proc:
                        self.render("Disconnected", "red")
                elif self.state_ == "on" and isinstance(self.tun, subprocess.Popen) and self.tun.poll() is None:
                    res = self.apply_split_live()
                    if not res.get("ok"):
                        return {**res, "settings": self.s}
                else:
                    self._arm_ks_locked("Kill Switch armed")
                    if self.state_ != "busy":
                        self.render("Network Locked (Kill Switch active)", "locked")
            self.push(ks=self.ks_status(), settings={"vpn": self.s["vpn"], "ks_mode": mode, "ks_persistent": self.s["ks_persistent"]})
            return {"ok": True, "ks": self.ks_status(), "settings": self.s}
        except Exception as e:
            self.log(f"Kill Switch error: {e}")
            return {"ok": False, "error": str(e), "ks": self.ks_status(), "settings": self.s}

    def unlock_killswitch(self):
        if is_admin():
            try:
                self.ks.disarm(force_persistent=True)
            except Exception as e:
                self.log(f"Unlock Kill Switch error: {e}")
                return {"ok": False, "error": str(e), "ks": self.ks_status(), "settings": self.s}
            with self.settings_lock:
                self.s["ks_mode"] = "off"
                self.s["ks_persistent"] = False
                self.save_settings()
            if not self.proc:
                self.render("Disconnected", "red")
            self.push(ks=self.ks_status(), settings={"ks_mode": "off", "ks_persistent": False})
            return {"ok": True, "ks": self.ks_status(), "settings": self.s}

        if not WIN:
            keep = [f"GOMMAGE_HOME={HOME}", "PYTHONPATH=" + os.pathsep.join(p for p in sys.path if p)]
            cmd = ["pkexec", "env", *keep, sys.executable] + ([] if FROZEN else [os.path.abspath(__file__)]) + ["--unlock-killswitch"]
            try:
                rc = subprocess.run(cmd).returncode
            except FileNotFoundError:
                rc = 127
            if rc != 0:
                return {"ok": False, "error": "Root permission required to unlock Kill Switch", "ks": self.ks_status(), "settings": self.s}
        else:
            extra = ("" if FROZEN else f'"{os.path.abspath(__file__)}" ') + f'--unlock-killswitch --elevated --home "{HOME}"'
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, extra.strip(), None, 1) <= 32:
                return {"ok": False, "error": "Administrator permission was refused", "ks": self.ks_status(), "settings": self.s}
            unlocked = False
            for _ in range(30):
                time.sleep(0.2)
                if not killswitch.read_ks_state(HOME).get("armed"):
                    unlocked = True
                    break
            if not unlocked:
                return {"ok": False, "error": "Kill Switch unlock was cancelled or did not complete", "ks": self.ks_status(), "settings": self.s}

        with self.settings_lock:
            self.s["ks_mode"] = "off"
            self.s["ks_persistent"] = False
            self.save_settings()
        self.ks.reconcile_startup(self.s)
        if not self.proc and not self.ks.locked:
            self.render("Disconnected", "red")
        self.push(ks=self.ks_status(), settings={"ks_mode": "off", "ks_persistent": False})
        return {"ok": True, "ks": self.ks_status(), "settings": self.s}

    def launch_protected(self, app_id):
        app = next((a for a in self.s["split"].get("apps", []) if a.get("id") == app_id), None)
        if not app:
            return {"ok": False, "message": "App rule not found"}
        if self.s.get("ks_mode") != "apps" or self.ks.mode != "apps":
            if not is_admin():
                return {"ok": False, "message": "Enable Strict Apps Kill Switch and connect first"}
        ok, msg = killswitch.launch_jailed(app.get("path", ""), os.path.abspath(__file__))
        return {"ok": ok, "message": msg}

    def run_leak_audit(self):
        ks = self.ks_status()
        live = self.ks.probe_live_state()
        sp = self.s["split"]
        checks = []

        # 1. OS Kill Switch Firewall
        if ks["mode"] != "off":
            if live.get("active"):
                fw_detail = f"Active ({live.get('backend')}, mode={ks['mode']}, persistent={ks['persistent']})"
                if live.get("drop_count") is not None:
                    fw_detail += f", {live['drop_count']} leaked packets dropped"
                fw_status = "warn" if ks.get("warnings") else "ok"
                if ks.get("warnings"):
                    fw_detail += f" · {len(ks['warnings'])} warning(s)"
            else:
                fw_detail = "Kill Switch configured but OS firewall rules are not loaded (connect or arm as admin)"
                fw_status = "fail"
            checks.append({"id": "firewall", "title": "OS Kill Switch Firewall", "status": fw_status, "detail": fw_detail, "warnings": ks.get("warnings", [])})
        else:
            checks.append({"id": "firewall", "title": "OS Kill Switch Firewall", "status": "warn", "detail": "Kill Switch is OFF — apps can fall back to clearnet if tunnel drops", "fix_action": "enable_ks"})

        # 2. Tunnel & System Proxy Isolation
        tun_alive = isinstance(self.tun, subprocess.Popen) and self.tun.poll() is None
        tor_alive = bool(self.proc and self.proc.poll() is None)
        clash_ok = bool(self.clash and self.clash.ping())
        if self.state_ == "on" and tor_alive and (not self.s["vpn"] or (tun_alive and clash_ok)):
            exit_ip = (self.ui_state.get("exit") or {}).get("ip") or "pending"
            checks.append({"id": "tunnel", "title": "Tor Tunnel & Proxy Isolation", "status": "ok" if self.s["vpn"] else "warn",
                           "detail": f"Tor active (exit: {exit_ip})" + (" · TUN isolated (OS system proxy off)" if self.s["vpn"] else " · Proxy mode only (non-proxy apps bypass Tor)")})
        elif self.state_ == "locked":
            checks.append({"id": "tunnel", "title": "Tor Tunnel & Proxy Isolation", "status": "ok", "detail": "Tunnel down & OS firewall locked fail-closed (no clearnet leak)"})
        else:
            checks.append({"id": "tunnel", "title": "Tor Tunnel & Proxy Isolation", "status": "warn", "detail": "Not connected"})

        # 3. DNS & IPv6 Seal
        force_dns = bool(sp.get("force_tor_dns", True))
        anti_leak = bool(sp.get("presets", {}).get("anti_leak", True))
        ipv6_sealed = self.s.get("vpn") or self.s.get("block_ipv6") or ks["mode"] != "off"
        if force_dns and anti_leak and ipv6_sealed:
            checks.append({"id": "dns_ipv6", "title": "DNS, IPv6 & WebRTC/DoT Seal", "status": "ok",
                           "detail": "DNS forced via Tor (AAAA/SVCB/HTTPS suppressed), dual-stack IPv6 rejected, STUN/DoT/mDNS blocked"})
        else:
            missing = []
            if not force_dns:
                missing.append("Force Tor DNS off")
            if not anti_leak:
                missing.append("Anti-Leak Shield off")
            if not ipv6_sealed:
                missing.append("IPv6 unblocked")
            checks.append({"id": "dns_ipv6", "title": "DNS, IPv6 & WebRTC/DoT Seal", "status": "warn",
                           "detail": ", ".join(missing), "fix_action": "harden_dns"})

        # 4. Jailed / Strict App Integrity
        strict_apps = [a for a in sp.get("apps", []) if a.get("enabled", True) and a.get("action") == "tor_strict"]
        app_issues = []
        for a in strict_apps:
            if a.get("match_type") == "name" or not a.get("path"):
                app_issues.append(f"{a.get('name')}: path not pinned (name-only cannot be locked by OS firewall)")
        if not WIN and strict_apps and os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
            res = self.ks.attach_running_to_jail(strict_apps) if hasattr(self.ks, "attach_running_to_jail") else {"warnings": []}
            app_issues.extend(res.get("warnings", []))
        if not strict_apps:
            checks.append({"id": "apps", "title": "Strict App Jail Integrity", "status": "ok", "detail": "No per-app Tor-Strict rules configured (Whole-System rules apply)"})
        elif app_issues:
            checks.append({"id": "apps", "title": "Strict App Jail Integrity", "status": "warn", "detail": "; ".join(app_issues[:3])})
        else:
            checks.append({"id": "apps", "title": "Strict App Jail Integrity", "status": "ok", "detail": f"{len(strict_apps)} strict app(s) path-pinned and verified"})

        summary = "fail" if any(c["status"] == "fail" for c in checks) else ("warn" if any(c["status"] == "warn" for c in checks) else "ok")
        return {"summary": summary, "checks": checks}

    def after_connect(self):
        time.sleep(12)
        try:
            ver = latest_version(f"http://{LOCAL}:{HTTP}")
            if newer(VERSION, ver):
                self.push(update=ver)
        except Exception as e:
            self.log(f"update check: {e}")
        self.run_speed()
        if self.proc:  # keep a fresh reserve for next time, fetched safely through Tor
            via = f"http://{LOCAL}:{HTTP}"
            found = {l: ["Tor Project"] for l in fetch_bridges(via, self.log, allow_direct=False)[:10]}
            if self.s.get("community", True) and len(clean_bridges(self.s["bridges"])) < 40:
                for l, v in fetch_public(via, self.log).items():
                    if len(v) > 1:  # in the background only take bridges confirmed by two lists
                        found.setdefault(l, v)
            cur = clean_bridges(self.s["bridges"])
            self.add_public([l for l in found if l not in cur][:15], found)

    def status(self, t, c):
        self.render(t, c)
        if self.sid:
            db("UPDATE sessions SET status=? WHERE id=?", (t, self.sid))

    # ---------- connect / disconnect ----------
    def toggle(self):
        if self.state_ == "busy" and not self.proc:
            return  # still starting up
        self.save_settings()
        if self.proc or self.state_ == "busy":
            self.stop(reason="user")
            return
        try:
            apply_ports(str(self.s["listen"]).strip(), str(self.s["socks"]).strip(), str(self.s["http"]).strip())
        except ValueError as e:
            self.render(f"Bad IP/port: {e}", "red")
            return
        ks_on = self.s.get("ks_mode", "off") != "off"
        if ks_on and not self.s.get("vpn"):
            self.s["vpn"] = True
            self.save_settings()
        need_admin = self.s["vpn"] or self.s["block_ipv6"] or ks_on
        if need_admin and not is_admin() and not WIN:
            threading.Thread(target=self.relaunch_root, args=(["--connect"],), daemon=True).start()
        elif need_admin and not is_admin():
            # relaunch elevated; settings were just saved so the new window has them
            extra = f'--home "{HOME}" --connect'
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", *self_cmd(extra), None, 1) > 32:
                self.closing = True  # the elevated copy takes over; close this one off the JS-call thread
                threading.Thread(target=self.win.destroy, daemon=True).start()
            else:
                self.render("Admin rights needed for VPN / Kill Switch / IPv6 block", "red")
        else:
            self.cancelled = False
            self.stop_reason = None
            self.render("Starting...", "orange")
            threading.Thread(target=self.start, daemon=True).start()

    def start(self, truncate_log=True):
        self.session_gen += 1
        my_gen = self.session_gen
        self.stop_reason = None
        try:
            if truncate_log:
                open(LOG, "w").close()
            lines = clean_bridges(self.s["bridges"])
            ks_mode = self.s.get("ks_mode", "off")
            if ks_mode != "off":
                self.s["vpn"] = True
            vpn, cc = self.s["vpn"], COUNTRIES[self.s["country"]]
            self.sid = db("INSERT INTO sessions(start, mode, country, status) VALUES(?,?,?,?)",
                          (now(), "VPN" if vpn else "proxy", self.s["country"], "connecting"))
            if self.s["block_ipv6"]:
                block_ipv6(True)
                self.log("IPv6 blocked (firewall rule)")
            kill_stale_processes()
            self.port_busy = False
            global SOCKS, HTTP, DNS_PORT  # busy port (Tor Browser, another proxy...) -> use the next free one for this session
            old = (SOCKS, HTTP, DNS_PORT)
            SOCKS = free_port(SOCKS)
            HTTP = free_port(HTTP, (SOCKS,))
            if vpn:
                DNS_PORT = free_port(DNS_PORT, (SOCKS, HTTP), socket.SOCK_DGRAM, host="127.0.0.1")
            if old != (SOCKS, HTTP, DNS_PORT):
                self.log(f"ports busy, using SOCKS {SOCKS}, HTTP {HTTP}, DNS {DNS_PORT} instead of {old}")
            self.upstream_dns = split_engine.detect_upstream_dns() if vpn else None
            tor, pt = ensure_tor(self.log)
            self.give_back()  # a freshly extracted bundle is root's when we're root
            self.log(f"tor: {tor}, transports: {pt}")
            builtin = builtin_bridges()
            tor_paths = self._tor_binary_paths(tor, pt)
            if ks_mode != "off":
                all_cands = lines + [l for v in builtin.values() for l in v]
                has_host_bridge = any((t := bridge_target(l)) is None or t[2] for l in all_cands)
                self._arm_ks_locked("Connecting through Tor", connecting_hostname_bridge=has_host_bridge, tor_paths=tor_paths)
                self.push(ks=self.ks_status())
            # memory: the bridges that connected last time go first, before any testing
            known = set(lines).union(*builtin.values())
            good = [l for l in self.s.get("last_good", []) if l in known] if lines else []
            if good:
                self.log(f"=== trying last working bridges first ({len(good)}) ===")
                if self.run_tor(tor, pt, good, vpn, cc, "last working"):
                    return  # connected, then the user disconnected (finally: stop)
                if self.cancelled:
                    return
                if self.port_busy:
                    return self.status(f"Error: port {SOCKS}/{HTTP} is in use by another program (Tor Browser? "
                                       "another VPN?). Close it or change the ports in Settings", "red")
                self.log("last working bridges failed - testing the rest")
            if not lines:  # no bridges configured: plain Tor
                tiers = [("direct Tor", [])]
            else:
                rest = [l for l in lines if l not in good]
                if ks_mode == "system":
                    res = {l: 100 for l in rest if bridge_target(l) is not None}
                    for l in rest:
                        res.setdefault(l, None)
                    tiers = plan_tiers(rest, res, {k: [l for l in v if l not in good] for k, v in builtin.items()},
                                       self.s.get("stats"), public=False)
                else:
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
                if self.port_busy:
                    self.status(f"Error: port {SOCKS}/{HTTP} is in use by another program (Tor Browser? "
                                "another VPN?). Close it or change the ports in Settings", "red")
                    break
            else:
                self.status("Error: no bridge worked (add fresh bridges in Settings)", "red")
        except Exception as e:
            self.log(f"ERROR: {e}")
            self.status(f"Error: {e}", "red")
        finally:
            if self.session_gen == my_gen and self.stop_reason is None:
                r = "user" if self.cancelled else "crash"
                self.stop(reason=r, drop_reason="Connection failed" if self.state_ == "err" else "Tor stopped unexpectedly")

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
        extra_kw = {"env": env}
        if not WIN and is_admin():
            extra_kw["group"] = killswitch.GOMMAGE_TOR_GID
            _uid = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
            if _uid and _uid.isdigit() and int(_uid) != 0:
                # tor refuses a DataDirectory owned by anyone but the user it runs as; HOME belongs to the desktop user
                # (give_back), so tor runs as them too. The Kill Switch matches on its group, so nothing changes there.
                self.give_back()
                extra_kw["user"] = int(_uid)
        proc = self.proc = popen([tor, "-f", rcp], **extra_kw)
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
            if "WSAEADDRINUSE" in l or "Address already in use" in l:
                self.port_busy = True  # not a bridge problem: another program owns the port
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
                if vpn:
                    set_proxy(False)  # VPN mode must NEVER enable OS HTTP proxy (prevents TUN bypass!)
                    if not self.starting_vpn and not self.tun:
                        self.starting_vpn = True
                        self.status("Starting VPN mode...", "orange")
                        threading.Thread(target=self.start_vpn, args=(lines, label, self.session_gen), daemon=True).start()
                else:
                    set_proxy(True)
                    self.status(f"Connected ({label.split(',')[0]})", "green")
                    threading.Thread(target=self.show_exit, args=(1,), daemon=True).start()
                    threading.Thread(target=self.after_connect, daemon=True).start()
            elif not self.starting_vpn and not self.tun and not state["done"]:
                self.status(f"Bootstrapping {p}% ({label})", "orange")
        self.log("tor exited")
        if not state["done"] and 0 <= state["pct"] < 75 and not self.cancelled:
            self.penalise(lines)  # the bridges never got Tor going (not a bind error, not a strict exit country)
        return state["done"]

    def start_vpn(self, lines, label="VPN", gen=None):
        my_gen = self.session_gen if gen is None else gen
        try:
            ensure_singbox(self.log)
            self.give_back()
            if self.cancelled or self.session_gen != my_gen or not self.proc or self.proc.poll() is not None:
                self.starting_vpn = False
                return
            self._spawn_singbox_only()
            if self.cancelled or self.session_gen != my_gen or not self.proc or self.proc.poll() is not None:
                self.starting_vpn = False
                self.stop_vpn()
                return
            self.starting_vpn = False
            mode_desc = "all via Tor" if self.s["split"].get("default_mode", "all") == "all" else "only listed apps"
            self.status(f"Connected ({mode_desc})", "green")
            self.push(ks=self.ks_status())
            threading.Thread(target=self.show_exit, args=(2,), daemon=True).start()
            threading.Thread(target=self.after_connect, daemon=True).start()
        except Exception as e:
            self.starting_vpn = False
            self.log(f"VPN ERROR: {e}")
            self.stop_vpn()
            if self.cancelled or self.session_gen != my_gen:
                return
            if self.s.get("ks_mode", "off") != "off":
                self.stop(reason="crash", drop_reason=f"VPN failed: {e}")
            else:
                set_proxy(True)
                self.status("Connected (browser proxy only, VPN failed)", "orange")

    def stop_vpn(self):
        t, self.tun = self.tun, None
        self.clash = None
        if isinstance(t, subprocess.Popen) and t.poll() is None:
            t.terminate()  # sing-box removes its adapter and routes on exit
            try:
                t.wait(timeout=5)
            except subprocess.TimeoutExpired:
                t.kill()
        sb_cfg = os.path.join(self._runtime_dir(), "sing-box.json")
        try:
            if os.path.exists(sb_cfg):
                os.remove(sb_cfg)
        except OSError:
            pass

    def stop(self, reason="user", drop_reason="Tunnel dropped"):
        with self.lock:
            if self.state_ == "locked" and reason == "crash" and self.stop_reason == "crash":
                return
            self.stop_reason = reason
            self.cancelled = True
            self.starting_vpn = False
            self.stop_vpn()
            if self.l2tp_managed():
                threading.Thread(target=l2tp.down, args=(self.log,), daemon=True).start()
            p, self.proc = self.proc, None
            if p and p.poll() is None:
                kill_tree(p)
            set_proxy(False)
            if self.sid:
                db("UPDATE sessions SET end=? WHERE id=?", (now(), self.sid))
                self.sid = None
            self.push(exit=None, gemini=None, speed="", down=None, up=None)

            ks_mode = self.s.get("ks_mode", "off")
            ks_persist = bool(self.s.get("ks_persistent", False))
            if ks_mode != "off" and self.ks.mode != "off":
                if reason == "crash":
                    self.ks.lock_tunnel(drop_reason)
                    self.render(f"Connection Locked ({drop_reason})", "locked")
                    self.push(ks=self.ks_status())
                    return
                if reason == "user" and ks_persist:
                    self.ks.lock_tunnel("Persistent Kill Switch locked")
                    self.render("Network Locked (Persistent Kill Switch)", "locked")
                    self.push(ks=self.ks_status())
                    return
                if reason == "quit" and ks_persist:
                    self.ks.lock_tunnel("Persistent Kill Switch active")
                    return
                self.ks.disarm(force_persistent=False)
                self.push(ks=self.ks_status())

            if self.s["block_ipv6"] or is_admin():
                block_ipv6(False)
            if self.state_ != "err":
                self.render("Disconnected", "red")
            self.give_back()  # tor's data dir, log and torrc were made by root

    def relaunch_root(self, extra_flags=()):
        """Linux: run this app again as root via pkexec (polkit asks for the password); this window waits hidden
        and closes once the root copy has exited, or comes back if the password was refused."""
        if getattr(self, "_elevating", False):
            return  # a root copy is already starting or running; a second one would fight it for HOME and ports
        self._elevating = True
        keep = [f"{k}={os.environ[k]}" for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                                "DBUS_SESSION_BUS_ADDRESS", "XDG_CURRENT_DESKTOP", "LANG")
                if k in os.environ]
        keep += [f"GOMMAGE_HOME={HOME}", "PYTHONPATH=" + os.pathsep.join(p for p in sys.path if p)]
        cmd = ["pkexec", "env", *keep, sys.executable] + ([] if FROZEN else [os.path.abspath(__file__)]) + list(extra_flags)
        self.win.hide()
        try:
            # the root copy's stderr (tracebacks, GTK errors) goes to a file the user owns, so a failed start can be diagnosed
            out = open(os.path.join(HOME, "root.log"), "w")
        except OSError:
            out = None
        try:
            rc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT if out else None).returncode
        except FileNotFoundError:
            rc = 127
        finally:
            if out:
                out.close()
            self._elevating = False
        if rc in (126, 127, 3):  # dismissed / not authorised / no pkexec / another root copy already runs
            self.win.show()
            self.render("Gommage is already running as root (find its window)" if rc == 3 else
                        "Root needed for VPN / Kill Switch / IPv6 block (or run: sudo -E python3 gommage.py)", "red")
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

    def on_closing(self):
        """Windows: the close button hides the window to the tray; the tray's Quit (or a relaunch) really closes."""
        if self.tray_ok and not self.closing:
            self.win.hide()
            return False
        self.quit_app()

    def quit_from_tray(self):
        self.closing = True
        self.win.destroy()

    def quit_app(self):
        self.closing = True
        if hasattr(self, "_push_q"):
            self._push_q.put(None)
        if WIN:
            self.tray.stop()
        self.save_settings()
        self.stop(reason="quit")
        self.give_back()


if __name__ == "__main__":
    # self-checks of the parsers and split/killswitch compilers (never invokes sing-box binary unconditionally)
    assert clean_bridges("Bridge webtunnel a\n\n# x\n webtunnel b ") == ["webtunnel a", "webtunnel b"]
    assert app_names("C:\\x\\Telegram.exe\n# c\nchrome.exe") == ["Telegram.exe", "chrome.exe"]
    _legacy = {"app_mode": "only", "apps": "Telegram.exe\nC:\\x\\Signal.exe", "bypass": "5.0.0.0/8 # lan\ndigikala.com", "bypass_ir": False}
    _migrated, _ = split_engine.migrate_settings(_legacy)
    assert _migrated["split"]["default_mode"] == "only" and _migrated["split"]["presets"]["bypass_ir"] is False
    assert len(_migrated["split"]["apps"]) == 2 and _migrated["split"]["apps"][1]["match_type"] == "path"
    assert split_engine.test_route(_migrated["split"], app_name="Telegram.exe", host="example.com")["action"] == "tor"
    assert split_engine.test_route(_migrated["split"], app_name="other.exe", host="example.com")["action"] == "direct"
    _sb_cfg = split_engine.build_singbox_config(
        _migrated["split"], {k: f"/tmp/{k}.json" for k in ("block_apps", "strict_apps_lan", "strict_apps_nolan", "strict_apps_all", "tor_apps", "direct_apps", "block_nets", "block_doms", "tor_nets", "direct_nets", "direct_doms")},
        ("127.0.0.1", 9050), 9053, [], TOR_PROCS, 19090, "sec", upstream_dns="8.8.8.8", ks_mode="system", ks_allow_lan=False, ks_allow_direct=False
    )
    assert _sb_cfg["route"]["final"] == "tor" and _sb_cfg["dns"]["servers"][0]["detour"] == "direct"
    assert _sb_cfg["route"]["rules"][1]["rule_set"] == ["block_apps"] and _sb_cfg["route"]["rules"][2]["action"] == "hijack-dns"
    _l2 = {**_migrated["split"], "default_mode": "all", "l2tp_iface": "MyL2TP", "apps": [{"name": "brave.exe", "match_type": "name", "action": "l2tp"}]}
    assert split_engine.test_route(_l2, app_name="brave.exe", host="example.com", proto="udp")["action"] == "l2tp"
    assert split_engine.test_route({**_l2, "l2tp_iface": ""}, app_name="brave.exe", host="example.com")["action"] != "l2tp"
    _l2_cfg = split_engine.build_singbox_config(_l2, {}, ("127.0.0.1", 9050), 9053, [], TOR_PROCS, 19090, "sec")
    assert {"type": "direct", "tag": "l2tp", "bind_interface": "MyL2TP"} in _l2_cfg["outbounds"]
    _ri = [r.get("rule_set") for r in _l2_cfg["route"]["rules"]]
    assert _ri.index(["l2tp_apps"]) < next(i for i, r in enumerate(_l2_cfg["route"]["rules"]) if r.get("network") == "udp" and "rule_set" not in r)
    assert not any(o["tag"] == "l2tp" for o in split_engine.build_singbox_config(_l2, {}, ("127.0.0.1", 9050), 9053, [], TOR_PROCS, 19090, "sec", ks_mode="system")["outbounds"])
    if WIN:
        killswitch.self_check_abi()
    _nft_s = killswitch.LinuxNftKillSwitch(HOME).build_nft_script("system", tunnel_open=False, allow_lan=False)
    assert "table inet gommage_ks" in _nft_s and "counter drop" in _nft_s and "table inet gommage " not in _nft_s
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
    assert stale_circuits("250+circuit-status=\n7 BUILT $AA~a,$BB~b PURPOSE=GENERAL\n8 BUILT $AA~a,$CC~c\n9 EXTENDED $DD~d\n.",
                          "BB") == ["8"]
    assert newer("1.0.0", "1.0.1") and newer("1.9.0", "1.10.0") and not newer("1.1.0", "1.1.0") and not newer("2.0", "1.9")
    _id = base64.b64encode(bytes.fromhex("AB" * 20)).decode().rstrip("=")
    assert exit_relays(f"r a {_id} x\ns Exit Fast Running\nr b {_id} x\ns BadExit Exit Fast\nr c {_id} x\ns Fast") == ["AB" * 20]
    App().mainloop()
