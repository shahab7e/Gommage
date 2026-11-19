"""Advanced Split Tunneling engine for Gommage (Windows & Linux).

Handles structured split rules, backward-compatible settings migration, pure-stdlib
app discovery, physical upstream DNS detection, sing-box 1.11.15 config and local
rule_set generation, rule simulation, and authenticated Clash API monitoring.
"""
from __future__ import annotations

import copy
import glob
import http.client
import ipaddress
import json
import ntpath
import os
import re
import shlex
import shutil
import struct
import sys
import uuid

try:
    import pwd
except ImportError:
    pwd = None

WIN = sys.platform == "win32"
if WIN:
    import ctypes
    from ctypes import wintypes
    import winreg

SPLIT_VERSION = 1

APP_ACTIONS = ("tor_strict", "tor", "direct", "block")
MATCH_TYPES = ("path", "folder", "name")
NET_KINDS = ("domain_suffix", "domain", "domain_keyword", "ip_cidr", "port")
NET_ACTIONS = ("tor", "direct", "block")

ANTI_LEAK_UDP_PORTS = [3478, 5349, 5353, 5355, 1900, 137, 138, 139]
ANTI_LEAK_PORT_RANGES = ["19302:19309"]
DOT_PORT = 853
DOH_DOMAINS = [
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "freedns.controld.com",
    "doh.cleanbrowsing.org",
]
TELEMETRY_DOMAINS = [
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "app-measurement.com",
    "firebaselogging-pa.googleapis.com",
    "google-analytics.com",
    "doubleclick.net",
    "mixpanel.com",
    "segment.io",
    "amplitude.com",
    "sentry.io",
    "crashlytics.com",
    "metrics.icloud.com",
    "incoming.telemetry.mozilla.org",
]

BUILTIN_PROFILES = {
    "Default": {
        "default_mode": "all",
        "presets": {"bypass_ir": True, "anti_leak": True, "block_telemetry": False},
        "force_tor_dns": True,
    },
    "Strict Privacy": {
        "default_mode": "all",
        "presets": {"bypass_ir": False, "anti_leak": True, "block_telemetry": True},
        "force_tor_dns": True,
    },
    "Only Selected Apps": {
        "default_mode": "only",
        "presets": {"bypass_ir": True, "anti_leak": True, "block_telemetry": False},
        "force_tor_dns": True,
    },
}

_WIN_SYSTEM_SKIP = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "conhost.exe", "winlogon.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "dllhost.exe", "runtimebroker.exe", "searchindexer.exe", "spoolsv.exe",
    "memory compression", "audiodg.exe", "werfault.exe", "wmiprvse.exe",
}
_INSTALLER_NAMES = {"unins000.exe", "uninstall.exe", "uninst.exe", "setup.exe", "installer.exe"}


def _new_id() -> str:
    return uuid.uuid4().hex[:10]


def default_split() -> dict:
    """Return a clean default split tunneling configuration."""
    return {
        "version": SPLIT_VERSION,
        "default_mode": "all",
        "apps": [],
        "net_rules": [],
        "presets": {"bypass_ir": True, "anti_leak": True, "block_telemetry": False},
        "force_tor_dns": True,
        "active_profile": "Default",
        "profiles": {},
    }


def _clean_host(val: str) -> str:
    val = val.strip().lower()
    val = re.sub(r"^\w+://", "", val)
    val = re.sub(r"/.*$", "", val)
    if ":" in val and not val.startswith("["):
        host_part, _, port_part = val.rpartition(":")
        if port_part.isdigit():
            val = host_part
    return val.strip(".")


def split_nets_raw(text: str) -> tuple[list[str], list[str]]:
    """Parse legacy bypass lines into (cidrs, domains), stripping comments and URL schemes."""
    nets, hosts = [], []
    for line in (text or "").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        try:
            nets.append(str(ipaddress.ip_network(line, strict=False)))
        except ValueError:
            h = _clean_host(line)
            if h:
                hosts.append(h)
    return nets, hosts


def _normalize_port_spec(val: str) -> str | None:
    s = val.strip().replace("-", ":").replace(" ", "")
    if not s:
        return None
    if ":" in s:
        parts = s.split(":", 1)
        if parts[0].isdigit() and parts[1].isdigit():
            lo, hi = int(parts[0]), int(parts[1])
            if 1 <= lo <= hi <= 65535:
                return str(lo) if lo == hi else f"{lo}:{hi}"
        return None
    if s.isdigit() and 1 <= int(s) <= 65535:
        return str(int(s))
    return None


def _normalize_net_value(kind: str, val: str) -> str | None:
    raw = str(val or "").split("#")[0].strip()
    if not raw:
        return None
    if kind == "ip_cidr":
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return None
    if kind == "port":
        return _normalize_port_spec(raw)
    if kind in ("domain_suffix", "domain"):
        h = _clean_host(raw)
        return h or None
    if kind == "domain_keyword":
        return raw.lower()
    return None


def infer_net_kind(val: str) -> str:
    """Infer network rule kind from user input string."""
    raw = str(val or "").strip()
    try:
        ipaddress.ip_network(raw, strict=False)
        return "ip_cidr"
    except ValueError:
        pass
    if _normalize_port_spec(raw):
        return "port"
    if raw.startswith("="):
        return "domain"
    return "domain_suffix"


def _validate_app_entry(item: dict) -> dict | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    path = str(item.get("path") or "").strip()
    if not name and path:
        name = ntpath.basename(path.rstrip("\\/")) or path
    if not name and not path:
        return None
    match_type = item.get("match_type")
    if match_type not in MATCH_TYPES:
        match_type = "path" if path else "name"
    action = item.get("action")
    if action not in APP_ACTIONS:
        action = "tor"
    return {
        "id": str(item.get("id") or _new_id()),
        "name": name,
        "path": path,
        "match_type": match_type,
        "action": action,
        "allow_lan": bool(item.get("allow_lan", False)),
        "enabled": bool(item.get("enabled", True)),
    }


def _validate_net_entry(item: dict) -> dict | None:
    if not isinstance(item, dict):
        return None
    kind = item.get("kind")
    if kind not in NET_KINDS:
        kind = infer_net_kind(str(item.get("value") or ""))
    val = _normalize_net_value(kind, str(item.get("value") or "").lstrip("="))
    if not val:
        return None
    action = item.get("action")
    if action not in NET_ACTIONS:
        action = "direct"
    return {
        "id": str(item.get("id") or _new_id()),
        "value": val,
        "kind": kind,
        "action": action,
        "enabled": bool(item.get("enabled", True)),
        "note": str(item.get("note") or "")[:80],
    }


def validate_split(sp: dict, strict: bool = False) -> dict:
    """Normalize and validate a split configuration dict (used on load and import)."""
    if not isinstance(sp, dict):
        if strict:
            raise ValueError("split config must be a JSON object")
        return default_split()

    base = default_split()
    dm = sp.get("default_mode", "all")
    if dm not in ("all", "only"):
        if strict:
            raise ValueError(f"invalid default_mode: {dm!r}")
        dm = "all"
    base["default_mode"] = dm

    presets = sp.get("presets") if isinstance(sp.get("presets"), dict) else {}
    base["presets"] = {
        "bypass_ir": bool(presets.get("bypass_ir", True)),
        "anti_leak": bool(presets.get("anti_leak", True)),
        "block_telemetry": bool(presets.get("block_telemetry", False)),
    }
    base["force_tor_dns"] = bool(sp.get("force_tor_dns", True))
    base["active_profile"] = str(sp.get("active_profile") or "Default")[:48]

    apps_in = sp.get("apps")
    if strict and apps_in is not None and not isinstance(apps_in, list):
        raise ValueError("apps must be a list")
    seen_apps = set()
    for a in apps_in or ():
        va = _validate_app_entry(a)
        if not va:
            continue
        dedup_key = (va["match_type"], (va["path"] or va["name"]).lower())
        if dedup_key not in seen_apps:
            seen_apps.add(dedup_key)
            base["apps"].append(va)

    nets_in = sp.get("net_rules")
    if strict and nets_in is not None and not isinstance(nets_in, list):
        raise ValueError("net_rules must be a list")
    seen_nets = set()
    for r in nets_in or ():
        vr = _validate_net_entry(r)
        if not vr:
            continue
        dedup_key = (vr["kind"], vr["value"].lower(), vr["action"])
        if dedup_key not in seen_nets:
            seen_nets.add(dedup_key)
            base["net_rules"].append(vr)

    profs_in = sp.get("profiles") if isinstance(sp.get("profiles"), dict) else {}
    for pname, pdata in profs_in.items():
        if not isinstance(pname, str) or not pname.strip() or not isinstance(pdata, dict):
            continue
        vp = validate_split({**pdata, "profiles": {}}, strict=False)
        base["profiles"][pname.strip()[:48]] = {
            "default_mode": vp["default_mode"],
            "apps": vp["apps"],
            "net_rules": vp["net_rules"],
            "presets": vp["presets"],
            "force_tor_dns": vp["force_tor_dns"],
        }
    return base


def migrate_settings(s: dict) -> tuple[dict, bool]:
    """Ensure kill-switch and structured split schema exist; migrate legacy keys once.

    Returns (settings_dict, changed_bool).
    """
    changed = False
    ks_defaults = {
        "ks_mode": "off",
        "ks_persistent": False,
        "ks_allow_lan": False,
        "ks_allow_direct": False,
    }
    for k, v in ks_defaults.items():
        if k not in s:
            s[k] = v
            changed = True
    if s["ks_mode"] not in ("off", "apps", "system"):
        s["ks_mode"] = "off"
        changed = True
    if s["ks_mode"] != "off" and not s.get("vpn"):
        s["vpn"] = True
        changed = True

    if not isinstance(s.get("split"), dict) or s["split"].get("version") != SPLIT_VERSION:
        sp = default_split()
        sp["presets"]["bypass_ir"] = bool(s.get("bypass_ir", True))

        legacy_mode = s.get("app_mode", "all")
        if legacy_mode == "only":
            sp["default_mode"] = "only"
            legacy_app_action = "tor"
        elif legacy_mode == "except":
            sp["default_mode"] = "all"
            legacy_app_action = "direct"
        else:
            sp["default_mode"] = "all"
            legacy_app_action = "tor"

        for raw_line in (s.get("apps") or "").splitlines():
            line = raw_line.split("#")[0].strip().strip('"')
            if not line:
                continue
            has_sep = ("/" in line) or ("\\" in line)
            sp["apps"].append({
                "id": _new_id(),
                "name": ntpath.basename(line) if has_sep else line,
                "path": line if has_sep else "",
                "match_type": "path" if has_sep else "name",
                "action": legacy_app_action,
                "allow_lan": False,
                "enabled": True,
            })

        cidrs, domains = split_nets_raw(s.get("bypass", ""))
        for c in cidrs:
            sp["net_rules"].append({"id": _new_id(), "value": c, "kind": "ip_cidr", "action": "direct", "enabled": True, "note": ""})
        for d in domains:
            sp["net_rules"].append({"id": _new_id(), "value": d, "kind": "domain_suffix", "action": "direct", "enabled": True, "note": ""})

        s["split"] = validate_split(sp)
        changed = True
    else:
        validated = validate_split(s["split"])
        if validated != s["split"]:
            s["split"] = validated
            changed = True

    sync_legacy_fields(s)
    return s, changed


def sync_legacy_fields(s: dict) -> None:
    """Keep top-level legacy settings fields coherent with split config."""
    sp = s.get("split")
    if not isinstance(sp, dict):
        return
    s["bypass_ir"] = bool(sp.get("presets", {}).get("bypass_ir", True))


def parse_import_split(text: str) -> dict:
    """Parse and strictly validate an exported split JSON profile string."""
    try:
        raw = json.loads(text)
    except ValueError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
    if isinstance(raw, dict) and "split" in raw and isinstance(raw["split"], dict):
        raw = raw["split"]
    return validate_split(raw, strict=True)


# ---------- path helpers & pure-stdlib app discovery ----------

def canonical_path(path: str) -> str:
    """Normalize an executable or folder path across Windows and Linux."""
    p = str(path or "").strip().strip('"')
    if not p:
        return ""
    if WIN:
        p = os.path.normpath(os.path.expandvars(p))
        if os.path.exists(p):
            try:
                p = os.path.realpath(p)
            except OSError:
                pass
        return p
    p = os.path.expanduser(p)
    try:
        return os.path.realpath(p)
    except OSError:
        return os.path.abspath(p)


def expand_folder_exes(folder: str, max_depth: int = 2, limit: int = 64) -> list[str]:
    """Enumerate real executables in a folder (including versioned app-* subdirs)."""
    root = canonical_path(folder)
    if not root or not os.path.isdir(root):
        return []
    out, seen = [], set()
    root_depth = root.rstrip("\\/").count(os.sep)
    for cur, dirs, files in os.walk(root):
        depth = cur.rstrip("\\/").count(os.sep) - root_depth
        if depth >= max_depth:
            dirs[:] = []
        for fn in sorted(files):
            low = fn.lower()
            if low in _INSTALLER_NAMES or low.startswith("unins"):
                continue
            full = os.path.join(cur, fn)
            if WIN:
                if not low.endswith(".exe"):
                    continue
            else:
                if not os.access(full, os.X_OK):
                    continue
            cp = canonical_path(full)
            key = cp.lower() if WIN else cp
            if key not in seen:
                seen.add(key)
                out.append(cp)
                if len(out) >= limit:
                    return out
    return out


def resolve_user_home_linux() -> str:
    """Return the desktop user's home directory even when running via pkexec/sudo."""
    if not WIN and os.geteuid() == 0 and pwd is not None:
        uid_str = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
        if uid_str and uid_str.isdigit():
            try:
                return pwd.getpwuid(int(uid_str)).pw_dir
            except KeyError:
                pass
    return os.path.expanduser("~")


def _in_dir(path: str, parent: str) -> bool:
    if not path or not parent:
        return False
    a = os.path.normcase(os.path.abspath(path))
    b = os.path.normcase(os.path.abspath(parent)).rstrip("\\/") + os.sep
    return a.startswith(b)


def discover_running_apps(exclude_dir: str = "") -> list[dict]:
    """Discover currently running user applications without third-party dependencies."""
    found: dict[str, dict] = {}
    if WIN:
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260),
                ]

            k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.Process32FirstW.restype = wintypes.BOOL
            k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.Process32NextW.restype = wintypes.BOOL
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
            ]
            k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]

            snap = k32.CreateToolhelp32Snapshot(0x2, 0)
            if snap and snap != wintypes.HANDLE(-1).value:
                try:
                    pe = PROCESSENTRY32W()
                    pe.dwSize = ctypes.sizeof(pe)
                    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
                    while ok:
                        pid = pe.th32ProcessID
                        exe_name = pe.szExeFile
                        if pid > 4 and exe_name.lower() not in _WIN_SYSTEM_SKIP:
                            path = ""
                            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
                            if h:
                                try:
                                    buf = ctypes.create_unicode_buffer(1024)
                                    sz = wintypes.DWORD(1024)
                                    if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
                                        path = buf.value
                                finally:
                                    k32.CloseHandle(h)
                            if not _in_dir(path, exclude_dir):
                                key = (path or exe_name).lower()
                                sandboxed = "msix" if "\\windowsapps\\" in key else None
                                entry = found.setdefault(key, {
                                    "name": exe_name,
                                    "path": path,
                                    "pids": [],
                                    "running": True,
                                    "sandboxed": sandboxed,
                                })
                                entry["pids"].append(int(pid))
                        ok = k32.Process32NextW(snap, ctypes.byref(pe))
                finally:
                    k32.CloseHandle(snap)
        except Exception:
            pass
    else:
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid_s = os.path.basename(pid_dir)
            try:
                exe = os.path.realpath(os.path.join(pid_dir, "exe"))
            except OSError:
                continue
            if _in_dir(exe, exclude_dir):
                continue
            name = os.path.basename(exe)
            if not name:
                continue
            sandboxed = None
            if exe.startswith("/snap/") or "/snap/" in exe:
                sandboxed = "snap"
            elif exe.startswith("/app/"):
                sandboxed = "flatpak"
            else:
                try:
                    cmd = open(os.path.join(pid_dir, "cmdline"), "rb").read(512)
                    if b"flatpak" in cmd:
                        sandboxed = "flatpak"
                except OSError:
                    pass
            entry = found.setdefault(exe, {
                "name": name,
                "path": exe,
                "pids": [],
                "running": True,
                "sandboxed": sandboxed,
            })
            entry["pids"].append(int(pid_s))
    return sorted(found.values(), key=lambda x: (x["name"].lower(), x["path"].lower()))


def _resolve_squirrel_update(exe_path: str) -> str:
    """If a Windows shortcut points to Squirrel Update.exe, try locating app-*\\*.exe."""
    if ntpath.basename(exe_path).lower() != "update.exe":
        return exe_path
    parent = os.path.dirname(exe_path)
    app_dirs = sorted(glob.glob(os.path.join(parent, "app-*")), reverse=True)
    for d in app_dirs:
        exes = [
            f for f in glob.glob(os.path.join(d, "*.exe"))
            if os.path.basename(f).lower() not in _INSTALLER_NAMES and os.path.basename(f).lower() != "update.exe"
        ]
        if exes:
            return exes[0]
    return exe_path


def _decode_utf16z(buf: bytes) -> str:
    """Decode null-terminated UTF-16LE bytes using 2-byte aligned boundaries."""
    end = len(buf) - (len(buf) % 2)
    for j in range(0, end, 2):
        if buf[j] == 0 and buf[j + 1] == 0:
            end = j
            break
    return buf[:end].decode("utf-16-le", "ignore")


def _parse_lnk_target(path: str) -> str | None:
    """Pure-Python MS-SHLLINK (.lnk) target extractor supporting Unicode and EnvDataBlock."""
    try:
        data = open(path, "rb").read(131072)
    except OSError:
        return None
    if len(data) < 76 or data[:4] != b"\x4c\x00\x00\x00":
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    off = 0x4C
    if flags & 0x01:  # HasLinkTargetIDList
        if off + 2 > len(data):
            return None
        off += 2 + struct.unpack_from("<H", data, off)[0]
    if (flags & 0x02) and off + 28 <= len(data):  # HasLinkInfo
        li_size, li_hdr, li_flags = struct.unpack_from("<III", data, off)
        if li_flags & 0x01:  # VolumeIDAndLocalBasePath
            if li_hdr >= 0x24 and off + 36 <= len(data):
                u_off = struct.unpack_from("<I", data, off + 28)[0]
                if u_off and off + u_off < len(data):
                    cand = os.path.expandvars(_decode_utf16z(data[off + u_off:])).strip('"')
                    if cand.lower().endswith(".exe") and os.path.isfile(cand):
                        return _resolve_squirrel_update(cand)
            b_off = struct.unpack_from("<I", data, off + 16)[0]
            if b_off and off + b_off < len(data):
                end = data.find(b"\x00", off + b_off)
                if end != -1:
                    cand = os.path.expandvars(data[off + b_off:end].decode("mbcs", "ignore")).strip('"')
                    if cand.lower().endswith(".exe") and os.path.isfile(cand):
                        return _resolve_squirrel_update(cand)
        off += li_size
    # Skip StringData blocks to reach ExtraData (EnvironmentVariableDataBlock = 0xA0000001)
    for mask in (0x04, 0x08, 0x10, 0x20, 0x40):
        if flags & mask:
            if off + 2 > len(data):
                return None
            chars = struct.unpack_from("<H", data, off)[0]
            off += 2 + chars * (2 if (flags & 0x80) else 1)
    while off + 8 <= len(data):
        blk_size, blk_sig = struct.unpack_from("<II", data, off)
        if blk_size < 4:
            break
        if blk_sig == 0xA0000001 and blk_size >= 788 and off + 788 <= len(data):
            raw_u = data[off + 268:off + 788]
            cand = os.path.expandvars(_decode_utf16z(raw_u)).strip('"')
            if cand.lower().endswith(".exe") and os.path.isfile(cand):
                return _resolve_squirrel_update(cand)
        off += blk_size
    return None


def _parse_desktop_file(path: str) -> dict | None:
    """Parse a Linux .desktop entry into {name, path, sandboxed}."""
    name, exec_line, hidden, dtype = "", "", False, ""
    in_entry = False
    try:
        with open(path, encoding="utf8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("["):
                    in_entry = (line == "[Desktop Entry]")
                    continue
                if not in_entry or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k == "Type":
                    dtype = v.strip()
                elif k in ("NoDisplay", "Hidden") and v.strip().lower() == "true":
                    hidden = True
                elif k == "Name" and not name:
                    name = v.strip()
                elif k == "Exec" and not exec_line:
                    exec_line = v.strip()
    except OSError:
        return None
    if hidden or dtype != "Application" or not exec_line:
        return None
    try:
        tokens = shlex.split(exec_line)
    except ValueError:
        tokens = exec_line.split()
    while tokens and (os.path.basename(tokens[0]) == "env" or ("=" in tokens[0] and not tokens[0].startswith("/"))):
        tokens.pop(0)
    if not tokens:
        return None
    sandboxed = None
    cmd = tokens[0]
    if os.path.basename(cmd) == "flatpak" and "run" in tokens:
        sandboxed = "flatpak"
        target_path = " ".join(tokens[:4])
    else:
        resolved = shutil.which(cmd) or (cmd if os.path.exists(cmd) else "")
        if not resolved:
            return None
        target_path = canonical_path(resolved)
        if "/snap/" in target_path or target_path.startswith("/snap/"):
            sandboxed = "snap"
    return {
        "name": name or os.path.basename(target_path),
        "path": target_path,
        "running": False,
        "sandboxed": sandboxed,
    }


def discover_installed_apps(home_hint: str = "") -> list[dict]:
    """Discover installed desktop applications cleanly on Windows and Linux."""
    found: dict[str, dict] = {}
    if WIN:
        roots = []
        if pd := os.environ.get("PROGRAMDATA"):
            roots.append(os.path.join(pd, "Microsoft", "Windows", "Start Menu", "Programs"))
        appdata = os.environ.get("APPDATA") or (os.path.dirname(home_hint) if home_hint else "")
        if appdata:
            roots.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs"))
        for root in roots:
            if not os.path.isdir(root):
                continue
            for lnk in glob.glob(os.path.join(root, "**", "*.lnk"), recursive=True):
                target = _parse_lnk_target(lnk)
                if not target:
                    continue
                bn = os.path.basename(target).lower()
                if bn in _INSTALLER_NAMES or bn.startswith(("unins", "setup")):
                    continue
                key = target.lower()
                found.setdefault(key, {
                    "name": os.path.splitext(os.path.basename(lnk))[0],
                    "path": target,
                    "running": False,
                    "sandboxed": "msix" if "\\windowsapps\\" in key else None,
                })
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\App Paths") as k:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(k, i)
                            i += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(k, sub) as sk:
                                val, _ = winreg.QueryValueEx(sk, "")
                                cand = os.path.expandvars(str(val).strip().strip('"'))
                                if cand.lower().endswith(".exe") and os.path.isfile(cand):
                                    cand = _resolve_squirrel_update(cand)
                                    bn = os.path.basename(cand).lower()
                                    if bn in _INSTALLER_NAMES or bn.startswith(("unins", "setup")):
                                        continue
                                    key = cand.lower()
                                    found.setdefault(key, {
                                        "name": os.path.splitext(sub)[0],
                                        "path": cand,
                                        "running": False,
                                        "sandboxed": "msix" if "\\windowsapps\\" in key else None,
                                    })
                        except OSError:
                            pass
            except OSError:
                pass
    else:
        uhome = resolve_user_home_linux()
        dirs = [
            "/usr/share/applications",
            os.path.join(uhome, ".local", "share", "applications"),
            "/var/lib/flatpak/exports/share/applications",
            "/var/lib/snapd/desktop/applications",
        ]
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if not fn.endswith(".desktop"):
                    continue
                entry = _parse_desktop_file(os.path.join(d, fn))
                if entry:
                    found.setdefault(entry["path"], entry)
    return sorted(found.values(), key=lambda x: x["name"].lower())


def discover_apps(exclude_dir: str = "", home_hint: str = "") -> dict:
    """Return both running and installed apps, safely swallowing platform errors."""
    try:
        running = discover_running_apps(exclude_dir=exclude_dir)
    except Exception:
        running = []
    try:
        installed = discover_installed_apps(home_hint=home_hint)
    except Exception:
        installed = []
    return {"running": running, "installed": installed}


# ---------- physical upstream DNS discovery ----------

def _valid_physical_dns_v4(token: str) -> str | None:
    try:
        ip = ipaddress.IPv4Address(token.strip())
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return None
    if str(ip).startswith("172.19."):  # Gommage TUN subnet
        return None
    return str(ip)


def detect_upstream_dns() -> str | None:
    """Discover physical interface IPv4 DNS before TUN starts (avoids sing-box 'local' DNS loop)."""
    if WIN:
        try:
            class _GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            iph = ctypes.WinDLL("iphlpapi.dll")
            iph.GetBestInterface.argtypes = [ctypes.c_uint32, ctypes.POINTER(wintypes.DWORD)]
            iph.GetBestInterface.restype = wintypes.DWORD
            iph.ConvertInterfaceIndexToLuid.argtypes = [wintypes.DWORD, ctypes.POINTER(ctypes.c_uint64)]
            iph.ConvertInterfaceIndexToLuid.restype = wintypes.DWORD
            iph.ConvertInterfaceLuidToGuid.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(_GUID)]
            iph.ConvertInterfaceLuidToGuid.restype = wintypes.DWORD

            idx = wintypes.DWORD(0)
            if iph.GetBestInterface(0x01010101, ctypes.byref(idx)) == 0:
                luid = ctypes.c_uint64(0)
                if iph.ConvertInterfaceIndexToLuid(idx, ctypes.byref(luid)) == 0:
                    g = _GUID()
                    if iph.ConvertInterfaceLuidToGuid(ctypes.byref(luid), ctypes.byref(g)) == 0:
                        guid_str = "{" + str(uuid.UUID(bytes_le=bytes(g))).upper() + "}"
                        key_path = rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid_str}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                            for valname in ("NameServer", "DhcpNameServer"):
                                try:
                                    raw, _ = winreg.QueryValueEx(k, valname)
                                    for part in str(raw).replace(",", " ").split():
                                        if ok := _valid_physical_dns_v4(part):
                                            return ok
                                except OSError:
                                    pass
        except Exception:
            pass
        # Fallback: scan active interfaces with a configured gateway
        try:
            root = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root) as k:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    with winreg.OpenKey(k, sub) as sk:
                        has_gw = False
                        for gw_k in ("DefaultGateway", "DhcpDefaultGateway"):
                            try:
                                gw, _ = winreg.QueryValueEx(sk, gw_k)
                                if gw and any(str(x).strip() and str(x).strip() != "0.0.0.0" for x in (gw if isinstance(gw, list) else [gw])):
                                    has_gw = True
                                    break
                            except OSError:
                                pass
                        if not has_gw:
                            continue
                        for valname in ("NameServer", "DhcpNameServer"):
                            try:
                                raw, _ = winreg.QueryValueEx(sk, valname)
                                for part in str(raw).replace(",", " ").split():
                                    if ok := _valid_physical_dns_v4(part):
                                        return ok
                            except OSError:
                                pass
        except Exception:
            pass
        return None

    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path, encoding="utf8", errors="replace") as f:
                for line in f:
                    parts = line.split("#", 1)[0].split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        if ok := _valid_physical_dns_v4(parts[1]):
                            return ok
        except OSError:
            pass
    return None


# ---------- sing-box 1.11.15 local rule_set + config compiler ----------

def _or_rules(buckets: dict[str, list], sentinel_key: str, sentinel_val: str) -> list[dict]:
    """Emit one dict per non-empty bucket so sing-box ORs conditions instead of ANDing."""
    rules = [{k: v} for k, v in buckets.items() if v]
    return rules if rules else [{sentinel_key: [sentinel_val]}]


def compile_app_rules(apps: list[dict], action: str, lan_filter: bool | None = None) -> list[dict]:
    """Compile matching app policies into sing-box headless rules."""
    names, paths, regexes = [], [], []
    for a in apps:
        if not a.get("enabled", True) or a.get("action") != action:
            continue
        if lan_filter is not None and bool(a.get("allow_lan", False)) != lan_filter:
            continue
        mt = a.get("match_type", "path")
        path = a.get("path", "")
        name = a.get("name", "")
        if mt == "folder" and path:
            sep = "\\" if WIN else "/"
            norm = os.path.normpath(os.path.expandvars(path)) if WIN else path
            norm = norm.rstrip("\\/") + sep
            pat = ("(?i)^" if WIN else "^") + re.escape(norm)
            if pat not in regexes:
                regexes.append(pat)
        elif mt == "path" and path:
            cp = canonical_path(path)
            if cp and cp not in paths:
                paths.append(cp)
        elif name:
            bn = ntpath.basename(name)
            if bn and bn not in names:
                names.append(bn)
    return _or_rules(
        {"process_name": names, "process_path": paths, "process_path_regex": regexes},
        "process_name",
        "__gommage_none__",
    )


def compile_net_rules(
    net_rules: list[dict],
    action: str,
    extra_cidrs: tuple[str, ...] | list[str] = (),
    extra_domains: tuple[str, ...] | list[str] = (),
    extra_ports: tuple[int, ...] | list[int] = (),
    extra_port_ranges: tuple[str, ...] | list[str] = (),
    domain_only: bool = False,
) -> list[dict]:
    """Compile network rules into sing-box headless rules (separating each match field)."""
    buckets: dict[str, list] = {
        "domain_suffix": list(dict.fromkeys(extra_domains)),
        "domain": [],
        "domain_keyword": [],
    }
    if not domain_only:
        buckets["ip_cidr"] = list(dict.fromkeys(extra_cidrs))
        buckets["port"] = list(dict.fromkeys(extra_ports))
        buckets["port_range"] = list(dict.fromkeys(extra_port_ranges))

    for r in net_rules:
        if not r.get("enabled", True) or r.get("action") != action:
            continue
        kind = r.get("kind")
        val = r.get("value")
        if not kind or not val:
            continue
        if domain_only and kind not in ("domain_suffix", "domain", "domain_keyword"):
            continue
        if kind == "port":
            norm = _normalize_port_spec(str(val))
            if not norm:
                continue
            if ":" in norm:
                if norm not in buckets["port_range"]:
                    buckets["port_range"].append(norm)
            else:
                p = int(norm)
                if p not in buckets["port"]:
                    buckets["port"].append(p)
        elif kind in buckets:
            if val not in buckets[kind]:
                buckets[kind].append(val)

    return _or_rules(buckets, "domain", "invalid.gommage.internal")


def _write_inplace(path: str, payload: dict) -> None:
    """Write rule_set JSON in-place so sing-box fsnotify inode watchers keep firing."""
    data = json.dumps(payload, indent=1)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def write_rule_sets(rules_dir: str, split_cfg: dict, ir_cidrs: list[str] = ()) -> dict[str, str]:
    """Write all 11 local sing-box 1.11 source rule_sets and return {tag: path}."""
    os.makedirs(rules_dir, exist_ok=True)
    if not WIN:
        try:
            os.chmod(rules_dir, 0o700)
        except OSError:
            pass
    sp = validate_split(split_cfg)
    apps = sp["apps"]
    nets = sp["net_rules"]
    presets = sp["presets"]

    extra_block_doms = TELEMETRY_DOMAINS if presets.get("block_telemetry") else ()
    extra_direct_doms = ["ir"] if presets.get("bypass_ir") else ()
    extra_direct_cidrs = list(ir_cidrs) if presets.get("bypass_ir") else ()

    payloads = {
        "block_apps": {"version": 2, "rules": compile_app_rules(apps, "block")},
        "strict_apps_lan": {"version": 2, "rules": compile_app_rules(apps, "tor_strict", lan_filter=True)},
        "strict_apps_nolan": {"version": 2, "rules": compile_app_rules(apps, "tor_strict", lan_filter=False)},
        "strict_apps_all": {"version": 2, "rules": compile_app_rules(apps, "tor_strict")},
        "tor_apps": {"version": 2, "rules": compile_app_rules(apps, "tor")},
        "direct_apps": {"version": 2, "rules": compile_app_rules(apps, "direct")},
        "block_nets": {"version": 2, "rules": compile_net_rules(nets, "block", extra_domains=extra_block_doms)},
        "block_doms": {"version": 2, "rules": compile_net_rules(nets, "block", extra_domains=extra_block_doms, domain_only=True)},
        "tor_nets": {"version": 2, "rules": compile_net_rules(nets, "tor")},
        "direct_nets": {"version": 2, "rules": compile_net_rules(nets, "direct", extra_cidrs=extra_direct_cidrs, extra_domains=extra_direct_doms)},
        "direct_doms": {"version": 2, "rules": compile_net_rules(nets, "direct", extra_domains=extra_direct_doms, domain_only=True)},
    }
    paths = {}
    for tag, obj in payloads.items():
        fp = os.path.join(rules_dir, f"{tag}.json")
        _write_inplace(fp, obj)
        paths[tag] = fp
    return paths


def build_singbox_config(
    split_cfg: dict,
    rules_paths: dict[str, str],
    socks_addr: tuple[str, int],
    dns_port: int,
    tor_proc_paths: list[str],
    tor_proc_names: list[str],
    clash_port: int,
    clash_secret: str,
    upstream_dns: str | None = None,
    ks_mode: str = "off",
    ks_allow_lan: bool = False,
    ks_allow_direct: bool = False,
) -> dict:
    """Build a verified sing-box 1.11.15 configuration with strict leak-proof precedence."""
    sp = validate_split(split_cfg)
    ks_strict_no_direct = (ks_mode == "system" and not ks_allow_direct)
    ks_block_lan_global = (ks_mode == "system" and not ks_allow_lan)
    has_strict_apps = any(a.get("enabled", True) and a.get("action") == "tor_strict" for a in sp["apps"])
    force_tor_dns = bool(sp.get("force_tor_dns", True)) or ks_strict_no_direct or has_strict_apps

    dns_servers = [
        {"tag": "tor-dns", "address": f"udp://127.0.0.1:{dns_port}", "detour": "direct", "strategy": "ipv4_only"},
        {"tag": "empty-dns", "address": "rcode://success"},
        {"tag": "block-dns", "address": "rcode://refused"},
    ]
    dns_rules = [
        {"rule_set": ["block_doms"], "server": "block-dns"},
        {"query_type": ["AAAA", "HTTPS", "SVCB"], "server": "empty-dns"},
    ]
    if upstream_dns and not force_tor_dns and not ks_strict_no_direct:
        dns_servers.append({"tag": "direct-dns", "address": f"udp://{upstream_dns}:53", "detour": "direct"})
        dns_rules.append({"rule_set": ["direct_doms"], "server": "direct-dns"})

    rules: list[dict] = []
    # 1. Tor & pluggable transports must never loop into TUN
    clean_tor_paths = [canonical_path(p) for p in (tor_proc_paths or ()) if p]
    if clean_tor_paths:
        rules.append({"process_path": list(dict.fromkeys(clean_tor_paths)), "outbound": "direct"})
    elif tor_proc_names:
        rules.append({"process_name": list(tor_proc_names), "outbound": "direct"})

    # 2. Blocked apps MUST precede hijack-dns so they cannot leak via DNS
    rules.append({"rule_set": ["block_apps"], "action": "reject", "method": "drop"})

    # 3. DNS hijack
    rules.append({"protocol": "dns", "action": "hijack-dns"})

    # 4-9. Tor-Strict apps (strictly above bypass_ir / direct_nets / global ip_is_private!)
    if not ks_block_lan_global:
        rules.append({"rule_set": ["strict_apps_lan"], "ip_is_private": True, "outbound": "direct"})
        rules.append({"rule_set": ["strict_apps_nolan"], "ip_is_private": True, "action": "reject", "method": "drop"})
    else:
        rules.append({"rule_set": ["strict_apps_all"], "ip_is_private": True, "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["strict_apps_all"], "ip_version": 6, "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["strict_apps_all"], "network": "udp", "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["strict_apps_all"], "port": [DOT_PORT], "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["strict_apps_all"], "domain_suffix": DOH_DOMAINS, "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["strict_apps_all"], "outbound": "tor"})

    # 10. Blocked domains / IPs / ports
    rules.append({"rule_set": ["block_nets"], "action": "reject", "method": "drop"})

    # 11. Explicit Tor domains / IPs / ports
    rules.append({"rule_set": ["tor_nets"], "ip_version": 6, "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["tor_nets"], "network": "udp", "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["tor_nets"], "outbound": "tor"})

    # 12. Direct apps (skipped under strict Whole-System Kill Switch)
    if not ks_strict_no_direct:
        rules.append({"rule_set": ["direct_apps"], "outbound": "direct"})

    # 13. Private/LAN IPs (skipped if Whole-System Kill Switch blocks LAN)
    if not ks_block_lan_global:
        rules.append({"ip_is_private": True, "outbound": "direct"})

    # 14. Direct domains / CIDRs + Iranian IPs (skipped under strict Whole-System Kill Switch)
    if not ks_strict_no_direct:
        rules.append({"rule_set": ["direct_nets"], "outbound": "direct"})

    # 15. Anti-Leak Shield (scoped to tor_apps in "only" mode so direct apps' voice/LAN are preserved)
    if sp["presets"].get("anti_leak", True):
        if sp["default_mode"] == "only" and not ks_strict_no_direct:
            rules.append({"rule_set": ["tor_apps"], "port": ANTI_LEAK_UDP_PORTS + [DOT_PORT], "action": "reject", "method": "drop"})
            rules.append({"rule_set": ["tor_apps"], "port_range": ANTI_LEAK_PORT_RANGES, "action": "reject", "method": "drop"})
        else:
            rules.append({"port": ANTI_LEAK_UDP_PORTS + [DOT_PORT], "action": "reject", "method": "drop"})
            rules.append({"port_range": ANTI_LEAK_PORT_RANGES, "action": "reject", "method": "drop"})

    # 16. Standard Tor-routed apps
    rules.append({"rule_set": ["tor_apps"], "ip_version": 6, "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["tor_apps"], "network": "udp", "action": "reject", "method": "drop"})
    rules.append({"rule_set": ["tor_apps"], "outbound": "tor"})

    # 17. Default policy
    if sp["default_mode"] == "all" or ks_strict_no_direct:
        rules.append({"ip_version": 6, "action": "reject", "method": "drop"})
        rules.append({"network": "udp", "action": "reject", "method": "drop"})
        final_outbound = "tor"
    else:
        final_outbound = "direct"

    rule_sets = [
        {"tag": tag, "type": "local", "format": "source", "path": path}
        for tag, path in rules_paths.items()
    ]

    return {
        "log": {"level": "warn"},
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{clash_port}",
                "secret": clash_secret,
                "access_control_allow_origin": ["http://127.0.0.1"],
                "access_control_allow_private_network": False,
            }
        },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "tor-dns",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun",
                "interface_name": "Gommage",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": True,
                "strict_route": True,
                "stack": "gvisor",
                "sniff": True,
                "sniff_override_destination": True,
            }
        ],
        "outbounds": [
            {"type": "socks", "tag": "tor", "server": socks_addr[0], "server_port": int(socks_addr[1]), "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "find_process": True,
            "rule_set": rule_sets,
            "rules": rules,
            "final": final_outbound,
        },
    }


# ---------- rule simulator (exact parity with build_singbox_config) ----------

def _app_matches(app: dict, q_name: str, q_path: str) -> bool:
    mt = app.get("match_type", "path")
    aname = (app.get("name") or "").lower()
    apath = (app.get("path") or "")
    if mt == "folder" and apath and q_path:
        sep = "\\" if WIN else "/"
        prefix = (os.path.normpath(apath) if WIN else apath).rstrip("\\/") + sep
        cmp_p = os.path.normpath(q_path) if WIN else q_path
        return (cmp_p.lower().startswith(prefix.lower())) if WIN else cmp_p.startswith(prefix)
    if mt == "path" and apath and q_path:
        if WIN:
            return os.path.normpath(q_path).lower() == os.path.normpath(apath).lower()
        return q_path == apath
    if q_name and aname:
        return q_name.lower() == aname
    if q_path and aname:
        return ntpath.basename(q_path).lower() == aname
    return False


def _find_matching_app(apps: list[dict], action: str, q_name: str, q_path: str) -> dict | None:
    for a in apps:
        if a.get("enabled", True) and a.get("action") == action and _app_matches(a, q_name, q_path):
            return a
    return None


def _match_net(net_rules: list[dict], action: str, host: str, ip_obj, port: int | None, extra_doms=(), extra_cidrs=()) -> str | None:
    h = _clean_host(host)
    for d in extra_doms:
        if h and (h == d or h.endswith("." + d)):
            return f"domain_suffix:{d}"
    if ip_obj is not None:
        for c in extra_cidrs:
            try:
                if ip_obj in ipaddress.ip_network(c, strict=False):
                    return f"ip_cidr:{c}"
            except ValueError:
                pass
    for r in net_rules:
        if not r.get("enabled", True) or r.get("action") != action:
            continue
        k, v = r["kind"], r["value"]
        if k == "domain_suffix" and h and (h == v or h.endswith("." + v)):
            return f"domain_suffix:{v}"
        if k == "domain" and h and h == v:
            return f"domain:{v}"
        if k == "domain_keyword" and h and v in h:
            return f"domain_keyword:{v}"
        if k == "ip_cidr" and ip_obj is not None:
            try:
                if ip_obj in ipaddress.ip_network(v, strict=False):
                    return f"ip_cidr:{v}"
            except ValueError:
                pass
        if k == "port" and port is not None:
            if ":" in v:
                lo, hi = map(int, v.split(":"))
                if lo <= port <= hi:
                    return f"port:{v}"
            elif port == int(v):
                return f"port:{v}"
    return None


def test_route(
    split_cfg: dict,
    app_name: str = "",
    app_path: str = "",
    host: str = "",
    ip: str = "",
    port: int = 443,
    proto: str = "tcp",
    ir_cidrs: list[str] | tuple[str, ...] = (),
    ks_mode: str = "off",
    ks_allow_lan: bool = False,
    ks_allow_direct: bool = False,
) -> dict:
    """Simulate sing-box routing decision using the exact rule precedence."""
    sp = validate_split(split_cfg)
    apps, nets, presets = sp["apps"], sp["net_rules"], sp["presets"]
    ks_strict_no_direct = (ks_mode == "system" and not ks_allow_direct)
    ks_block_lan_global = (ks_mode == "system" and not ks_allow_lan)

    q_name = app_name.strip() or (ntpath.basename(app_path.strip()) if app_path.strip() else "")
    q_path = app_path.strip()
    q_host = _clean_host(host)
    q_proto = (proto or "tcp").lower()
    q_port = int(port) if str(port).isdigit() else None
    ip_obj = None
    if ip.strip():
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
        except ValueError:
            pass
    elif q_host:
        try:
            ip_obj = ipaddress.ip_address(q_host)
            q_host = ""
        except ValueError:
            pass

    is_priv = bool(ip_obj and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local))
    is_v6 = bool(ip_obj and ip_obj.version == 6)

    if _find_matching_app(apps, "block", q_name, q_path):
        return {"action": "block", "reason": "Blocked app rule (precedes DNS hijack)"}

    if sa := _find_matching_app(apps, "tor_strict", q_name, q_path):
        if is_priv:
            if sa.get("allow_lan") and not ks_block_lan_global:
                return {"action": "direct", "reason": "Strict app LAN exception (allow_lan)"}
            return {"action": "block", "reason": "Strict app private/LAN IP blocked"}
        if is_v6:
            return {"action": "block", "reason": "Strict app IPv6 blocked"}
        if q_proto == "udp":
            return {"action": "block", "reason": "Strict app UDP/QUIC/WebRTC blocked"}
        if q_port == DOT_PORT or any(q_host == d or q_host.endswith("." + d) for d in DOH_DOMAINS):
            return {"action": "block", "reason": "Strict app DoT/DoH bypass blocked"}
        return {"action": "tor_strict", "reason": "Strict app forced via Tor (overrides direct/IR rules)"}

    extra_block = TELEMETRY_DOMAINS if presets.get("block_telemetry") else ()
    if m := _match_net(nets, "block", q_host, ip_obj, q_port, extra_doms=extra_block):
        return {"action": "block", "reason": f"Blocked network rule ({m})"}

    if m := _match_net(nets, "tor", q_host, ip_obj, q_port):
        if is_v6 or q_proto == "udp":
            return {"action": "block", "reason": f"Tor network rule ({m}) rejects IPv6/UDP"}
        return {"action": "tor", "reason": f"Tor network rule ({m})"}

    if not ks_strict_no_direct and _find_matching_app(apps, "direct", q_name, q_path):
        return {"action": "direct", "reason": "Direct app rule"}

    if is_priv and not ks_block_lan_global:
        return {"action": "direct", "reason": "Private/LAN IP direct"}

    if not ks_strict_no_direct:
        extra_d = ["ir"] if presets.get("bypass_ir") else ()
        if m := _match_net(nets, "direct", q_host, ip_obj, q_port, extra_doms=extra_d, extra_cidrs=ir_cidrs if presets.get("bypass_ir") else ()):
            return {"action": "direct", "reason": f"Direct network rule ({m})"}

    if presets.get("anti_leak", True) and q_port is not None:
        if sp["default_mode"] != "only" or ks_strict_no_direct or _find_matching_app(apps, "tor", q_name, q_path):
            if q_port in ANTI_LEAK_UDP_PORTS or q_port == DOT_PORT or (19302 <= q_port <= 19309):
                return {"action": "block", "reason": f"Anti-Leak Shield blocked port {q_port}"}

    if _find_matching_app(apps, "tor", q_name, q_path):
        if is_v6 or q_proto == "udp":
            return {"action": "block", "reason": "Tor app rule rejects IPv6/UDP"}
        return {"action": "tor", "reason": "Tor app rule"}

    if sp["default_mode"] == "all" or ks_strict_no_direct:
        if is_v6 or q_proto == "udp":
            return {"action": "block", "reason": "Default Tor policy rejects IPv6/UDP"}
        return {"action": "tor", "reason": "Default mode: All via Tor"}

    return {"action": "direct", "reason": "Default mode: Direct"}


# ---------- authenticated Clash API client ----------

class ClashClient:
    """Direct loopback HTTP client for sing-box Clash API (bypasses OS system proxy)."""

    def __init__(self, port: int, secret: str):
        self.port = int(port)
        self.secret = secret

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)
        headers = {"Authorization": f"Bearer {self.secret}"}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf8")
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if not data:
                return resp.status, None
            try:
                return resp.status, json.loads(data.decode("utf8", "replace"))
            except ValueError:
                return resp.status, None
        finally:
            conn.close()

    def ping(self) -> bool:
        try:
            code, _ = self._req("GET", "/version")
            return 200 <= code < 300
        except (OSError, http.client.HTTPException):
            return False

    def get_connections(self, limit: int = 150) -> dict:
        try:
            code, data = self._req("GET", "/connections")
        except (OSError, http.client.HTTPException):
            return {"total": 0, "up_total": 0, "down_total": 0, "groups": []}
        if code != 200 or not isinstance(data, dict):
            return {"total": 0, "up_total": 0, "down_total": 0, "groups": []}
        conns = data.get("connections") or []
        groups: dict[str, dict] = {}
        for c in conns[:limit]:
            meta = c.get("metadata") or {}
            ppath = meta.get("processPath") or ""
            pname = meta.get("process") or (ntpath.basename(ppath) if ppath else "System / Unknown")
            key = (ppath or pname).lower() if WIN else (ppath or pname)
            chains = c.get("chains") or []
            route = "direct" if "direct" in chains else ("block" if "reject" in chains else "tor")
            g = groups.setdefault(key, {
                "key": key,
                "name": pname,
                "path": ppath,
                "count": 0,
                "upload": 0,
                "download": 0,
                "routes": set(),
                "items": [],
            })
            g["count"] += 1
            g["upload"] += int(c.get("upload") or 0)
            g["download"] += int(c.get("download") or 0)
            g["routes"].add(route)
            g["items"].append({
                "id": c.get("id", ""),
                "host": meta.get("host") or meta.get("sniffHost") or "",
                "ip": meta.get("destinationIP") or "",
                "port": meta.get("destinationPort") or "",
                "network": (meta.get("network") or "tcp").upper(),
                "route": route,
                "rule": c.get("rule") or "",
                "upload": int(c.get("upload") or 0),
                "download": int(c.get("download") or 0),
            })
        out_groups = []
        for g in groups.values():
            g["routes"] = sorted(g["routes"])
            out_groups.append(g)
        out_groups.sort(key=lambda x: (-x["count"], -(x["upload"] + x["download"]), x["name"].lower()))
        return {
            "total": len(conns),
            "up_total": int(data.get("uploadTotal") or 0),
            "down_total": int(data.get("downloadTotal") or 0),
            "groups": out_groups,
        }

    def close_connection(self, cid: str) -> bool:
        try:
            code, _ = self._req("DELETE", f"/connections/{cid}")
            return 200 <= code < 300
        except (OSError, http.client.HTTPException):
            return False

    def close_all_connections(self) -> bool:
        try:
            code, _ = self._req("DELETE", "/connections")
            return 200 <= code < 300
        except (OSError, http.client.HTTPException):
            return False

    def close_matching_connections(self, predicate) -> int:
        try:
            code, data = self._req("GET", "/connections")
        except (OSError, http.client.HTTPException):
            return 0
        if code != 200 or not isinstance(data, dict):
            return 0
        closed = 0
        for c in (data.get("connections") or []):
            if predicate(c):
                if cid := c.get("id"):
                    if self.close_connection(cid):
                        closed += 1
        return closed
