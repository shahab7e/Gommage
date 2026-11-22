"""Managed L2TP/IPsec for Gommage.

Windows: drives Windows' own L2TP client (a hidden per-user profile with split tunneling, dialed with rasdial).
Linux:   drives NetworkManager's L2TP plugin (network-manager-l2tp) through nmcli.
Either way it is dialed before the TUN comes up, plus the routes that let it live beside sing-box.
Secrets: DPAPI-encrypted on Windows (only this Windows account can decrypt them); on Linux they sit in the
settings file, which is kept owner-only (0600). They never leave this machine.
"""
import base64
import ctypes
import os
import re
import shutil
import subprocess
import sys
import tempfile

WIN = sys.platform == "win32"
NAME = "Gommage-L2TP"
NOFLASH = 0x08000000 if WIN else 0


# ---------- secrets ----------
if WIN:
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32, _kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    src, out = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _BLOB()
    fn = _crypt32.CryptProtectData if encrypt else _crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(out)):  # 0x1 = UI_FORBIDDEN
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _kernel32.LocalFree(out.pbData)


def protect(text: str) -> str:
    if not text:
        return ""
    # ponytail: Linux has no per-user secret store we can rely on under pkexec; the 0600 settings file is the guard
    return base64.b64encode(_dpapi(text.encode("utf8"), True) if WIN else text.encode("utf8")).decode()


def unprotect(blob: str) -> str:
    if not blob:
        return ""
    raw = base64.b64decode(blob)
    return (_dpapi(raw, False) if WIN else raw).decode("utf8")


# ---------- helpers ----------
def _q(s: str) -> str:
    """PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


def _ps(script: str):
    # script goes in on stdin, so secrets never appear in a process command line
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "-"], input=script,
                          capture_output=True, text=True, creationflags=NOFLASH)


def _sh(*cmd, input=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, input=input, timeout=90)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def available() -> str:
    """'' when managed L2TP can work here, else what is missing."""
    if WIN:
        return ""
    if not shutil.which("nmcli"):
        return "NetworkManager (nmcli) is not installed"
    if not any(os.path.exists(p) for p in ("/usr/lib/NetworkManager/VPN/nm-l2tp-service.name",
                                             "/etc/NetworkManager/VPN/nm-l2tp-service.name")):
        return "install it first: sudo apt install network-manager-l2tp"
    return ""


def connected(name: str = NAME) -> bool:
    if WIN:
        r = subprocess.run(["rasdial"], capture_output=True, text=True, creationflags=NOFLASH)
        return any(l.strip().lower() == name.lower() for l in r.stdout.splitlines())
    r = _sh("nmcli", "-t", "-f", "NAME", "connection", "show", "--active")
    return name in r.stdout.splitlines()


def iface() -> str:
    """Network interface the managed link uses (Windows: the profile name; Linux: pppN while connected)."""
    if WIN:
        return NAME
    r = _sh("nmcli", "-g", "IP4.ADDRESS,GENERAL.IP-IFACE", "connection", "show", NAME)
    m = re.search(r"\b(ppp\d+)\b", r.stdout)
    return m[1] if m else ""


last_error = ""  # why the last managed dial failed, shown in the UI ("" once connected)
_ERR_HINT = {"789": "IPsec rejected (check the pre-shared key)", "691": "wrong username or password",
             "809": "server unreachable (UDP 500/4500 blocked?)", "868": "server name not found"}


def ensure_routes(ifname: str, log=print, server: str = ""):
    """Routes so a split-tunnel L2TP link works beside the TUN:
    1. its server goes out the real NIC: IPsec/L2TP must never enter sing-box (re-sourced ports kill the link).
       Needs no interface, so it is set BEFORE dialing, else the dial itself loops into the TUN (error 789);
    2. a default route on the L2TP interface at a far worse metric, else bind_interface gets 'network unreachable';
       its interface metric goes far back too, so Windows stops asking the link's DNS first (10 s per lookup).
    Neither steals traffic: sing-box's routes and the NIC's default still win for everything else."""
    ip = _resolve(server) if server else ""
    if WIN:
        return _ensure_routes_win(ifname, ip, log)
    out = []
    if ip and f"to {ip} lookup main" not in _sh("ip", "rule", "show").stdout:
        # sing-box's policy rules sit before the main table, so a /32 there isn't enough: send it to main first
        r = _sh("ip", "rule", "add", "to", ip, "lookup", "main", "priority", "100")
        if r.returncode:
            out.append(f"server rule: {r.stderr.strip()}")
    if ifname and "default" not in _sh("ip", "route", "show", "dev", ifname).stdout:
        r = _sh("ip", "route", "add", "default", "dev", ifname, "metric", "9000")
        if r.returncode:
            out.append(f"adapter route: {r.stderr.strip()}")
    if out:
        log(f"L2TP '{ifname or server}': {' | '.join(out)[:300]}")


def _resolve(host: str) -> str:
    import socket
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return ""


def _ensure_routes_win(ifname: str, ip: str, log):
    r = _ps(
        f"$n={_q(ifname)}; $ip={_q(ip)}; $err=@();"
        # manual mode (user's own VPN): find its server from the profile
        "if(-not $ip -and $n){ try{ $srv=(Get-VpnConnection -Name $n -ErrorAction Stop).ServerAddress;"
        " $ip=([Net.Dns]::GetHostAddresses($srv)|?{$_.AddressFamily -eq 'InterNetwork'}|select -First 1).IPAddressToString }catch{} };"
        "if($ip){ try{"
        " $gw=Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4|?{$_.InterfaceAlias -notin @($n,'Gommage') -and $_.NextHop -ne '0.0.0.0'}"
        "|sort {$_.RouteMetric+(Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric}|select -First 1;"
        " if($gw -and -not (Get-NetRoute -DestinationPrefix ($ip+'/32') -ErrorAction SilentlyContinue)){"
        "  New-NetRoute -DestinationPrefix ($ip+'/32') -InterfaceIndex $gw.ifIndex -NextHop $gw.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null }"
        "}catch{ $err+=('server route: '+$_) } };"
        "if($n){ try{ $i=(Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction Stop).ifIndex;"
        " if(-not (Get-NetRoute -InterfaceIndex $i -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue)){"
        "  New-NetRoute -InterfaceIndex $i -DestinationPrefix 0.0.0.0/0 -RouteMetric 9000 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null };"
        " Set-NetIPInterface -InterfaceIndex $i -InterfaceMetric 9000 -ErrorAction Stop"
        "}catch{ $err+=('adapter route (is it connected?): '+$_) } };"
        "if($err){ Write-Output ($err -join ' | ') }"
    )
    out = (r.stdout + r.stderr).strip()
    if out:
        log(f"L2TP '{ifname or ip}': {out[:300]}")


# ---------- managed connection ----------
def up(cfg: dict, log=print) -> str:
    """(Re)create the hidden profile from cfg, dial it, set routes. Returns the interface name, '' on failure."""
    global last_error
    if missing := available():
        last_error = missing
        log(f"L2TP: {missing}")
        return ""
    if connected():
        last_error = ""
        ensure_routes(iface(), log, cfg.get("server", ""))
        return iface()
    try:
        pw, psk = unprotect(cfg.get("password", "")), unprotect(cfg.get("psk", ""))
    except (OSError, ValueError):
        last_error = "saved password/PSK can't be decrypted; enter them again"
        log(f"L2TP: {last_error}")
        return ""
    if not (cfg.get("server") and cfg.get("user") and pw and psk):
        last_error = "server, username, password and PSK are all needed"
        log(f"L2TP: {last_error}")
        return ""
    ensure_routes("", log, cfg["server"])  # server bypass first: the dial must not go into the TUN
    err = _up_win(cfg, pw, psk, log) if WIN else _up_linux(cfg, pw, psk, log)
    if err:
        last_error = err
        return ""
    last_error = ""
    log(f"L2TP: connected to {cfg['server']}")
    name = iface()
    ensure_routes(name, log, cfg["server"])
    return name


def _up_win(cfg, pw, psk, log) -> str:
    r = _ps(
        f"Remove-VpnConnection -Name {_q(NAME)} -Force -ErrorAction SilentlyContinue;"
        f"Add-VpnConnection -Name {_q(NAME)} -ServerAddress {_q(cfg['server'])} -TunnelType L2tp -L2tpPsk {_q(psk)}"
        " -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -SplitTunneling -Force -ErrorAction Stop"
    )
    if r.returncode:
        log(f"L2TP: profile not created: {r.stderr.strip()[:300]}")
        return "profile not created (see log)"
    # ponytail: rasdial takes the password as an argument (visible to same-user processes for ~a second);
    # the RasDial API via ctypes would avoid that if it ever matters
    r = subprocess.run(["rasdial", NAME, cfg["user"], pw], capture_output=True, text=True, creationflags=NOFLASH)
    if r.returncode:
        log(f"L2TP: dial failed (code {r.returncode}): {r.stdout.strip().splitlines()[-1:] or ''}")
        return f"error {r.returncode}: " + _ERR_HINT.get(str(r.returncode), "dial failed (see log)")
    return ""


def _up_linux(cfg, pw, psk, log) -> str:
    _sh("nmcli", "connection", "delete", NAME)
    # secrets are not stored in the profile (flags=2): they come from a 0600 file at dial time, never argv
    data = (f"gateway={cfg['server']}, user={cfg['user']}, ipsec-enabled=yes, password-flags=2, "
            "ipsec-psk-flags=2, refuse-eap=yes, refuse-pap=yes, refuse-chap=yes, refuse-mschap=yes, require-mppe=no")
    r = _sh("nmcli", "connection", "add", "type", "vpn", "con-name", NAME, "vpn-type", "l2tp",
            "vpn.data", data, "ipv4.never-default", "yes", "ipv4.ignore-auto-dns", "yes", "ipv6.method", "disabled",
            "connection.autoconnect", "no")
    if r.returncode:
        log(f"L2TP: profile not created: {r.stderr.strip()[:300]}")
        return "profile not created (see log)"
    fd, path = tempfile.mkstemp(prefix="gommage-l2tp-")
    try:
        with os.fdopen(fd, "w") as f:  # mkstemp makes it 0600
            f.write(f"vpn.secrets.password:{pw}\nvpn.secrets.ipsec-psk:{psk}\n")
        r = _sh("nmcli", "--wait", "60", "connection", "up", NAME, "passwd-file", path)
    finally:
        os.remove(path)
    if r.returncode:
        log(f"L2TP: dial failed: {(r.stderr or r.stdout).strip()[:300]}")
        return "dial failed (see log)"
    return ""


def down(log=print):
    if not connected():
        return
    if WIN:
        subprocess.run(["rasdial", NAME, "/disconnect"], capture_output=True, creationflags=NOFLASH)
    else:
        _sh("nmcli", "connection", "down", NAME)
    log("L2TP: disconnected")


if __name__ == "__main__":
    assert unprotect(protect("p@ss'w\"0rd ۱۲۳")) == "p@ss'w\"0rd ۱۲۳" and protect("") == "" == unprotect("")
    assert _q("a'b") == "'a''b'"
    print("l2tp ok")
