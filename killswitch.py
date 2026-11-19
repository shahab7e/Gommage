"""OS-level Fail-Closed Kill Switch engine for Gommage (Windows WFP & Linux nftables).

Windows: Dual-handle Windows Filtering Platform (fwpuclnt.dll via ctypes)
  - Session mode: FWPM_SESSION_FLAG_DYNAMIC (auto-clears on crash/reboot).
  - Persistent mode: FWPM_FILTER_FLAG_PERSISTENT base lock + dynamic TUN LUID permit
    (never combines PERSISTENT | BOOTTIME, preventing FWP_E_INVALID_FLAGS and bricking).

Linux: Dedicated `table inet gommage_ks` via nftables + dedicated skgid for Tor/sing-box
  + cgroup v2 `gommage_jail` for per-app jailing + optional systemd persistence +
  iptables fallback + race-free `--exec-jailed` launcher.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid

try:
    import pwd
except ImportError:
    pwd = None

import split_engine

WIN = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)

STATE_DISARMED = "disarmed"
STATE_LOCKED = "locked"
STATE_OPEN = "open"

GOMMAGE_TOR_GID = 64998
GOMMAGE_SB_GID = 64999
NFT_TABLE = "gommage_ks"
JAIL_CGROUP = "/sys/fs/cgroup/gommage_jail"
PERSIST_NFT = "/etc/gommage-killswitch.nft"
PERSIST_UNIT = "/etc/systemd/system/gommage-killswitch.service"
IPT_CHAIN = "GOMMAGE_KS"

if WIN:
    import ctypes
    from ctypes import wintypes


# ---------- shared state & recovery docs ----------

def _chown_for_desktop_user(path: str) -> None:
    if WIN or os.geteuid() != 0 or pwd is None:
        return
    uid_s = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if not uid_s or not uid_s.isdigit():
        return
    try:
        uid = int(uid_s)
        gid = pwd.getpwuid(uid).pw_gid
        os.chown(path, uid, gid, follow_symlinks=False)
    except (OSError, KeyError):
        pass


def state_path(home: str) -> str:
    return os.path.join(home, "ks_state.json")


def read_ks_state(home: str) -> dict:
    default = {
        "armed": False,
        "mode": "off",
        "persistent": False,
        "locked": False,
        "reason": "",
        "updated": 0,
    }
    try:
        data = json.load(open(state_path(home), encoding="utf8"))
        if isinstance(data, dict):
            default.update(data)
    except (OSError, ValueError):
        pass
    return default


def write_ks_state(home: str, armed: bool, mode: str, persistent: bool, locked: bool, reason: str = "") -> dict:
    os.makedirs(home, exist_ok=True)
    payload = {
        "armed": bool(armed),
        "mode": mode,
        "persistent": bool(persistent),
        "locked": bool(locked),
        "reason": reason,
        "updated": int(time.time()),
    }
    p = state_path(home)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf8") as f:
        json.dump(payload, f, indent=1)
    if not WIN:
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
    os.replace(tmp, p)
    _chown_for_desktop_user(p)
    return payload


def write_recovery_guide(home: str) -> None:
    os.makedirs(home, exist_ok=True)
    p = os.path.join(home, "UNLOCK-KILLSWITCH.txt")
    if WIN:
        if FROZEN:
            cmd = f'"{sys.executable}" --unlock-killswitch --home "{home}"'
        else:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gommage.py")
            cmd = f'"{sys.executable}" "{script}" --unlock-killswitch --home "{home}"'
        txt = (
            "Gommage Persistent Kill Switch — Emergency Unlock Guide\n"
            "=======================================================\n\n"
            "1. From the Gommage window:\n"
            "   Click the red 'Unlock' button on the Home screen banner.\n\n"
            "2. From Command Prompt / PowerShell (Administrator or standard):\n"
            f"   {cmd}\n"
        )
    else:
        txt = (
            "Gommage Persistent Kill Switch — Emergency Unlock Guide\n"
            "=======================================================\n\n"
            "1. From the Gommage window:\n"
            "   Click the red 'Unlock' button on the Home screen banner.\n\n"
            "2. From a terminal (headless / recovery):\n"
            "   sudo gommage --unlock-killswitch\n\n"
            "3. Raw OS commands (works even if Gommage is uninstalled):\n"
            f"   sudo nft delete table inet {NFT_TABLE} 2>/dev/null || true\n"
            "   sudo systemctl disable --now gommage-killswitch.service 2>/dev/null || true\n"
            f"   sudo rm -f {PERSIST_UNIT} {PERSIST_NFT}\n"
        )
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf8") as f:
        f.write(txt)
    if not WIN:
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
    os.replace(tmp, p)
    _chown_for_desktop_user(p)


def remove_recovery_guide(home: str) -> None:
    p = os.path.join(home, "UNLOCK-KILLSWITCH.txt")
    try:
        if os.path.exists(p):
            os.remove(p)
    except OSError:
        pass


# ---------- Windows WFP Kill Switch ----------

if WIN:
    GOMMAGE_PROVIDER_GUID = uuid.UUID("7f4c9a12-8b3d-4e51-9a2c-6d1e8f3b5a01")
    GOMMAGE_SUBLAYER_GUID = uuid.UUID("7f4c9a12-8b3d-4e51-9a2c-6d1e8f3b5a02")

    FWPM_LAYER_ALE_AUTH_CONNECT_V4 = uuid.UUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
    FWPM_LAYER_ALE_AUTH_CONNECT_V6 = uuid.UUID("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = uuid.UUID("e1cd9fe7-f4b5-4273-96c0-592e487b8650")
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = uuid.UUID("a3b42c97-9f04-4672-b87e-cee9c483257f")

    FWPM_CONDITION_ALE_APP_ID = uuid.UUID("d78e1e87-8644-4ea5-9437-d809ecefc971")
    FWPM_CONDITION_IP_LOCAL_INTERFACE = uuid.UUID("4cd62a49-59c3-4969-b7f3-bda5d32890a4")
    FWPM_CONDITION_FLAGS = uuid.UUID("632ce23b-5167-435c-86d7-e903684aa80c")
    FWPM_CONDITION_IP_REMOTE_ADDRESS = uuid.UUID("b235ae9a-1d64-49b8-a44c-5ff3d9095045")
    FWPM_CONDITION_IP_LOCAL_PORT = uuid.UUID("0c1ba1af-5765-453f-af22-a8f791ac775b")
    FWPM_CONDITION_IP_REMOTE_PORT = uuid.UUID("c35a604d-d22b-4e1a-91b4-68f674ee674b")
    FWPM_CONDITION_IP_PROTOCOL = uuid.UUID("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7")

    FWP_UINT8 = 1
    FWP_UINT16 = 2
    FWP_UINT32 = 3
    FWP_UINT64 = 4
    FWP_BYTE_BLOB_TYPE = 12
    FWP_V4_ADDR_MASK = 0x100
    FWP_V6_ADDR_MASK = 0x101

    FWP_MATCH_EQUAL = 0
    FWP_MATCH_FLAGS_ALL_SET = 6
    FWP_MATCH_NOT_EQUAL = 10

    FWP_ACTION_BLOCK = 0x00001001
    FWP_ACTION_PERMIT = 0x00001002

    FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001
    FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
    FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001
    FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001
    FWPM_FILTER_FLAG_PERSISTENT = 0x00000001
    RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF

    FWP_E_PROVIDER_NOT_FOUND = 0x80320005
    FWP_E_SUBLAYER_NOT_FOUND = 0x80320007
    FWP_E_ALREADY_EXISTS = 0x80320009
    FWP_E_FILTER_NOT_FOUND = 0x80320003
    FWP_E_IN_USE = 0x8032000A

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_uint32),
            ("Data2", ctypes.c_uint16),
            ("Data3", ctypes.c_uint16),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class FWP_BYTE_BLOB(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
        _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]

    class FWP_V6_ADDR_AND_MASK(ctypes.Structure):
        _fields_ = [("addr", ctypes.c_ubyte * 16), ("prefixLength", ctypes.c_uint8)]

    class FWP_VALUE_UNION(ctypes.Union):
        _fields_ = [
            ("uint8", ctypes.c_uint8),
            ("uint16", ctypes.c_uint16),
            ("uint32", ctypes.c_uint32),
            ("uint64", ctypes.POINTER(ctypes.c_uint64)),
            ("int8", ctypes.c_int8),
            ("int16", ctypes.c_int16),
            ("int32", ctypes.c_int32),
            ("int64", ctypes.POINTER(ctypes.c_int64)),
            ("byteBlob", ctypes.POINTER(FWP_BYTE_BLOB)),
            ("v4AddrMask", ctypes.POINTER(FWP_V4_ADDR_AND_MASK)),
            ("v6AddrMask", ctypes.POINTER(FWP_V6_ADDR_AND_MASK)),
            ("ptr", ctypes.c_void_p),
        ]

    class FWP_VALUE0(ctypes.Structure):
        _fields_ = [("type", ctypes.c_uint32), ("value", FWP_VALUE_UNION)]

    class FWPM_DISPLAY_DATA0(ctypes.Structure):
        _fields_ = [("name", wintypes.LPWSTR), ("description", wintypes.LPWSTR)]

    class FWPM_SESSION0(ctypes.Structure):
        _fields_ = [
            ("sessionKey", GUID),
            ("displayData", FWPM_DISPLAY_DATA0),
            ("flags", ctypes.c_uint32),
            ("txnWaitTimeoutInMSec", ctypes.c_uint32),
            ("processId", ctypes.c_uint32),
            ("sid", ctypes.c_void_p),
            ("username", wintypes.LPWSTR),
            ("kernelMode", wintypes.BOOL),
        ]

    class FWPM_PROVIDER0(ctypes.Structure):
        _fields_ = [
            ("providerKey", GUID),
            ("displayData", FWPM_DISPLAY_DATA0),
            ("flags", ctypes.c_uint32),
            ("providerData", FWP_BYTE_BLOB),
            ("serviceName", wintypes.LPWSTR),
        ]

    class FWPM_SUBLAYER0(ctypes.Structure):
        _fields_ = [
            ("subLayerKey", GUID),
            ("displayData", FWPM_DISPLAY_DATA0),
            ("flags", ctypes.c_uint32),
            ("providerKey", ctypes.POINTER(GUID)),
            ("providerData", FWP_BYTE_BLOB),
            ("weight", ctypes.c_uint16),
        ]

    class FWPM_FILTER_CONDITION0(ctypes.Structure):
        _fields_ = [
            ("fieldKey", GUID),
            ("matchType", ctypes.c_uint32),
            ("conditionValue", FWP_VALUE0),
        ]

    class FWPM_ACTION0(ctypes.Structure):
        _fields_ = [("type", ctypes.c_uint32), ("filterType", GUID)]

    class _FILTER_CTX(ctypes.Union):
        _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]

    class FWPM_FILTER0(ctypes.Structure):
        _fields_ = [
            ("filterKey", GUID),
            ("displayData", FWPM_DISPLAY_DATA0),
            ("flags", ctypes.c_uint32),
            ("providerKey", ctypes.POINTER(GUID)),
            ("providerData", FWP_BYTE_BLOB),
            ("layerKey", GUID),
            ("subLayerKey", GUID),
            ("weight", FWP_VALUE0),
            ("numFilterConditions", ctypes.c_uint32),
            ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
            ("action", FWPM_ACTION0),
            ("ctx", _FILTER_CTX),
            ("reserved", ctypes.POINTER(GUID)),
            ("filterId", ctypes.c_uint64),
            ("effectiveWeight", FWP_VALUE0),
        ]

    class FWPM_FILTER_ENUM_TEMPLATE0(ctypes.Structure):
        _fields_ = [
            ("providerKey", ctypes.POINTER(GUID)),
            ("layerKey", GUID),
            ("enumType", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("providerContextTemplate", ctypes.c_void_p),
            ("numFilterConditions", ctypes.c_uint32),
            ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
            ("actionMask", ctypes.c_uint32),
            ("calloutKey", ctypes.POINTER(GUID)),
        ]

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [
            ("dwAddr", ctypes.c_uint32),
            ("dwIndex", wintypes.DWORD),
            ("dwMask", ctypes.c_uint32),
            ("dwBCastAddr", ctypes.c_uint32),
            ("dwReasmSize", ctypes.c_uint32),
            ("unused1", ctypes.c_uint16),
            ("wType", ctypes.c_uint16),
        ]

    def _to_guid(u: uuid.UUID) -> GUID:
        return GUID.from_buffer_copy(u.bytes_le)

    def _guid_eq(g_ptr, target_u: uuid.UUID) -> bool:
        if not g_ptr:
            return False
        return bytes(g_ptr.contents) == target_u.bytes_le

    _FW = None
    _IPH = None

    def _wfp():
        global _FW
        if _FW is not None:
            return _FW
        fw = ctypes.WinDLL("fwpuclnt.dll")
        fw.FwpmEngineOpen0.argtypes = [wintypes.LPCWSTR, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(FWPM_SESSION0), ctypes.POINTER(wintypes.HANDLE)]
        fw.FwpmEngineOpen0.restype = ctypes.c_uint32
        fw.FwpmEngineClose0.argtypes = [wintypes.HANDLE]
        fw.FwpmEngineClose0.restype = ctypes.c_uint32
        fw.FwpmTransactionBegin0.argtypes = [wintypes.HANDLE, ctypes.c_uint32]
        fw.FwpmTransactionBegin0.restype = ctypes.c_uint32
        fw.FwpmTransactionCommit0.argtypes = [wintypes.HANDLE]
        fw.FwpmTransactionCommit0.restype = ctypes.c_uint32
        fw.FwpmTransactionAbort0.argtypes = [wintypes.HANDLE]
        fw.FwpmTransactionAbort0.restype = ctypes.c_uint32
        fw.FwpmProviderAdd0.argtypes = [wintypes.HANDLE, ctypes.POINTER(FWPM_PROVIDER0), ctypes.c_void_p]
        fw.FwpmProviderAdd0.restype = ctypes.c_uint32
        fw.FwpmProviderDeleteByKey0.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID)]
        fw.FwpmProviderDeleteByKey0.restype = ctypes.c_uint32
        fw.FwpmSubLayerAdd0.argtypes = [wintypes.HANDLE, ctypes.POINTER(FWPM_SUBLAYER0), ctypes.c_void_p]
        fw.FwpmSubLayerAdd0.restype = ctypes.c_uint32
        fw.FwpmSubLayerDeleteByKey0.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID)]
        fw.FwpmSubLayerDeleteByKey0.restype = ctypes.c_uint32
        fw.FwpmFilterAdd0.argtypes = [wintypes.HANDLE, ctypes.POINTER(FWPM_FILTER0), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
        fw.FwpmFilterAdd0.restype = ctypes.c_uint32
        fw.FwpmFilterDeleteById0.argtypes = [wintypes.HANDLE, ctypes.c_uint64]
        fw.FwpmFilterDeleteById0.restype = ctypes.c_uint32
        fw.FwpmFilterCreateEnumHandle0.argtypes = [wintypes.HANDLE, ctypes.POINTER(FWPM_FILTER_ENUM_TEMPLATE0), ctypes.POINTER(wintypes.HANDLE)]
        fw.FwpmFilterCreateEnumHandle0.restype = ctypes.c_uint32
        fw.FwpmFilterEnum0.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_uint32, ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0))), ctypes.POINTER(ctypes.c_uint32)]
        fw.FwpmFilterEnum0.restype = ctypes.c_uint32
        fw.FwpmFilterDestroyEnumHandle0.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        fw.FwpmFilterDestroyEnumHandle0.restype = ctypes.c_uint32
        fw.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        fw.FwpmFreeMemory0.restype = None
        fw.FwpmGetAppIdFromFileName0.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FWP_BYTE_BLOB))]
        fw.FwpmGetAppIdFromFileName0.restype = ctypes.c_uint32
        _FW = fw
        return _FW

    def _iph():
        global _IPH
        if _IPH is not None:
            return _IPH
        iph = ctypes.WinDLL("iphlpapi.dll")
        iph.GetIpAddrTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        iph.GetIpAddrTable.restype = wintypes.DWORD
        iph.ConvertInterfaceIndexToLuid.argtypes = [wintypes.DWORD, ctypes.POINTER(ctypes.c_uint64)]
        iph.ConvertInterfaceIndexToLuid.restype = wintypes.DWORD
        iph.ConvertInterfaceAliasToLuid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_uint64)]
        iph.ConvertInterfaceAliasToLuid.restype = ctypes.c_uint32
        _IPH = iph
        return _IPH

    def self_check_abi() -> None:
        """Assert exact MSVC x64 struct sizes for WFP ctypes structures."""
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            return
        expected = {
            GUID: 16,
            FWP_BYTE_BLOB: 16,
            FWP_V4_ADDR_AND_MASK: 8,
            FWP_V6_ADDR_AND_MASK: 17,
            FWP_VALUE0: 16,
            FWPM_DISPLAY_DATA0: 16,
            FWPM_SESSION0: 72,
            FWPM_PROVIDER0: 64,
            FWPM_SUBLAYER0: 72,
            FWPM_FILTER_CONDITION0: 40,
            FWPM_ACTION0: 20,
            FWPM_FILTER0: 200,
            FWPM_FILTER_ENUM_TEMPLATE0: 72,
            MIB_IPADDRROW: 24,
        }
        for cls, sz in expected.items():
            assert ctypes.sizeof(cls) == sz, f"{cls.__name__} size {ctypes.sizeof(cls)} != {sz}"

    def resolve_wintun_luid(alias: str = "Gommage", tun_ip: str = "172.19.0.1") -> int | None:
        """Resolve active Wintun interface LUID by IP address first (beats stale 'Gommage 2'), then alias."""
        try:
            iph = _iph()
            target_nbo = int.from_bytes(ipaddress.IPv4Address(tun_ip).packed, "little")
            sz = wintypes.DWORD(0)
            iph.GetIpAddrTable(None, ctypes.byref(sz), False)
            if sz.value >= 4:
                buf = ctypes.create_string_buffer(sz.value)
                if iph.GetIpAddrTable(buf, ctypes.byref(sz), False) == 0:
                    n = ctypes.c_uint32.from_buffer(buf).value
                    if 4 + n * ctypes.sizeof(MIB_IPADDRROW) <= sz.value:
                        rows = (MIB_IPADDRROW * n).from_buffer(buf, 4)
                        for row in rows:
                            if row.dwAddr == target_nbo:
                                luid = ctypes.c_uint64(0)
                                if iph.ConvertInterfaceIndexToLuid(row.dwIndex, ctypes.byref(luid)) == 0:
                                    return int(luid.value)
            luid = ctypes.c_uint64(0)
            if iph.ConvertInterfaceAliasToLuid(alias, ctypes.byref(luid)) == 0:
                return int(luid.value)
        except Exception:
            pass
        return None

    def get_app_id_bytes(exe_path: str) -> bytes | None:
        """Convert executable path to WFP FWP_BYTE_BLOB payload bytes (freed via FwpmFreeMemory0)."""
        if not exe_path or not os.path.isfile(exe_path):
            return None
        fw = _wfp()
        ptr = ctypes.POINTER(FWP_BYTE_BLOB)()
        rc = fw.FwpmGetAppIdFromFileName0(exe_path, ctypes.byref(ptr))
        if rc != 0 or not ptr:
            return None
        try:
            return bytes(ptr.contents.data[:ptr.contents.size])
        finally:
            vp = ctypes.c_void_p(ctypes.addressof(ptr.contents))
            fw.FwpmFreeMemory0(ctypes.byref(vp))


class WinWFPKillSwitch:
    """Windows Filtering Platform (WFP) dual-handle Kill Switch."""

    def __init__(self, home: str, log=print):
        self.home = home
        self.log = log
        self.dyn_handle = None
        self.base_filter_ids: list[int] = []
        self.dyn_filter_ids: list[int] = []
        self.mode = "off"
        self.persistent = False
        self.locked = False
        self.reason = ""
        self.warnings: list[str] = []
        self._last_args: dict = {}

    def capabilities(self) -> dict:
        return {"backend": "wfp", "has_wfp": True, "can_per_app": True, "can_persistent": True}

    def _open_engine(self, dynamic: bool) -> wintypes.HANDLE:
        fw = _wfp()
        sess = FWPM_SESSION0()
        sess.displayData.name = "Gommage Kill Switch"
        sess.flags = FWPM_SESSION_FLAG_DYNAMIC if dynamic else 0
        h = wintypes.HANDLE()
        rc = fw.FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT, None, ctypes.byref(sess), ctypes.byref(h))
        if rc != 0:
            raise OSError(f"FwpmEngineOpen0 failed: 0x{rc:08X}")
        return h

    def _ensure_provider_and_sublayer(self, h: wintypes.HANDLE, persistent: bool) -> None:
        fw = _wfp()
        prov = FWPM_PROVIDER0()
        prov.providerKey = _to_guid(GOMMAGE_PROVIDER_GUID)
        prov.displayData.name = "Gommage Kill Switch"
        prov.displayData.description = "Gommage anti-leak network firewall"
        prov.flags = FWPM_PROVIDER_FLAG_PERSISTENT if persistent else 0
        rc = fw.FwpmProviderAdd0(h, ctypes.byref(prov), None)
        if rc not in (0, FWP_E_ALREADY_EXISTS):
            raise OSError(f"FwpmProviderAdd0 failed: 0x{rc:08X}")

        prov_guid = _to_guid(GOMMAGE_PROVIDER_GUID)
        sub = FWPM_SUBLAYER0()
        sub.subLayerKey = _to_guid(GOMMAGE_SUBLAYER_GUID)
        sub.displayData.name = "Gommage Kill Switch Sublayer"
        sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT if persistent else 0
        sub.providerKey = ctypes.pointer(prov_guid)
        sub.weight = 0xFFFF
        rc = fw.FwpmSubLayerAdd0(h, ctypes.byref(sub), None)
        if rc not in (0, FWP_E_ALREADY_EXISTS):
            raise OSError(f"FwpmSubLayerAdd0 failed: 0x{rc:08X}")

    def _enum_provider_filter_ids(self, h: wintypes.HANDLE, persistent_only: bool | None = None) -> list[int]:
        fw = _wfp()
        eh = wintypes.HANDLE()
        rc = fw.FwpmFilterCreateEnumHandle0(h, None, ctypes.byref(eh))
        if rc != 0:
            raise OSError(f"FwpmFilterCreateEnumHandle0 failed: 0x{rc:08X}")
        ids: list[int] = []
        try:
            while True:
                entries = ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0))()
                count = ctypes.c_uint32(0)
                rc = fw.FwpmFilterEnum0(h, eh, 128, ctypes.byref(entries), ctypes.byref(count))
                if rc != 0:
                    raise OSError(f"FwpmFilterEnum0 failed: 0x{rc:08X}")
                try:
                    for i in range(count.value):
                        flt = entries[i].contents
                        if _guid_eq(flt.providerKey, GOMMAGE_PROVIDER_GUID):
                            is_p = bool(flt.flags & FWPM_FILTER_FLAG_PERSISTENT)
                            if persistent_only is None or is_p == persistent_only:
                                ids.append(int(flt.filterId))
                finally:
                    if entries:
                        vp = ctypes.c_void_p(ctypes.cast(entries, ctypes.c_void_p).value)
                        fw.FwpmFreeMemory0(ctypes.byref(vp))
                if count.value < 128:
                    break
        finally:
            fw.FwpmFilterDestroyEnumHandle0(h, eh)
        return ids

    def _add_filter(
        self,
        h: wintypes.HANDLE,
        layer: uuid.UUID,
        action_type: int,
        weight: int,
        name: str,
        conditions: list[tuple],
        persistent: bool,
    ) -> int:
        """Add one WFP filter; keeps all ctypes condition backing buffers alive through the call."""
        fw = _wfp()
        keepalive: list = []

        prov_guid = _to_guid(GOMMAGE_PROVIDER_GUID)
        keepalive.append(prov_guid)

        cond_arr = (FWPM_FILTER_CONDITION0 * len(conditions))() if conditions else None
        for idx, (field_uuid, match_type, val_type, val_data) in enumerate(conditions):
            c = cond_arr[idx]
            c.fieldKey = _to_guid(field_uuid)
            c.matchType = match_type
            c.conditionValue.type = val_type
            if val_type == FWP_UINT8:
                c.conditionValue.value.uint8 = int(val_data)
            elif val_type == FWP_UINT16:
                c.conditionValue.value.uint16 = int(val_data)
            elif val_type == FWP_UINT32:
                c.conditionValue.value.uint32 = int(val_data)
            elif val_type == FWP_UINT64:
                u64 = ctypes.c_uint64(int(val_data))
                keepalive.append(u64)
                c.conditionValue.value.uint64 = ctypes.pointer(u64)
            elif val_type == FWP_BYTE_BLOB_TYPE:
                buf = (ctypes.c_ubyte * len(val_data)).from_buffer_copy(val_data)
                blob = FWP_BYTE_BLOB(size=len(val_data), data=buf)
                keepalive.extend((buf, blob))
                c.conditionValue.value.byteBlob = ctypes.pointer(blob)
            elif val_type == FWP_V4_ADDR_MASK:
                net_ip, net_mask = val_data
                am = FWP_V4_ADDR_AND_MASK(addr=int(net_ip), mask=int(net_mask))
                keepalive.append(am)
                c.conditionValue.value.v4AddrMask = ctypes.pointer(am)
            elif val_type == FWP_V6_ADDR_MASK:
                ip6_bytes, prefix = val_data
                arr16 = (ctypes.c_ubyte * 16).from_buffer_copy(ip6_bytes)
                am6 = FWP_V6_ADDR_AND_MASK(addr=arr16, prefixLength=int(prefix))
                keepalive.extend((arr16, am6))
                c.conditionValue.value.v6AddrMask = ctypes.pointer(am6)

        flt = FWPM_FILTER0()
        flt.displayData.name = name
        flt.flags = FWPM_FILTER_FLAG_PERSISTENT if persistent else 0
        flt.providerKey = ctypes.pointer(prov_guid)
        flt.layerKey = _to_guid(layer)
        flt.subLayerKey = _to_guid(GOMMAGE_SUBLAYER_GUID)
        flt.weight.type = FWP_UINT8
        flt.weight.value.uint8 = int(weight)
        flt.numFilterConditions = len(conditions)
        if cond_arr is not None:
            keepalive.append(cond_arr)
            flt.filterCondition = cond_arr
        flt.action.type = action_type

        fid = ctypes.c_uint64(0)
        rc = fw.FwpmFilterAdd0(h, ctypes.byref(flt), None, ctypes.byref(fid))
        if rc != 0:
            raise OSError(f"FwpmFilterAdd0 ({name}) failed: 0x{rc:08X}")
        return int(fid.value)

    def _resolve_strict_and_blocked_app_ids(self, split_cfg: dict) -> tuple[list[tuple[bytes, bool, str]], list[tuple[bytes, str]], list[str]]:
        strict_ids, blocked_ids, warnings = [], [], []
        seen_strict, seen_blocked = set(), set()
        for app in split_cfg.get("apps", []):
            if not app.get("enabled", True):
                continue
            action = app.get("action")
            if action not in ("tor_strict", "block"):
                continue
            mt = app.get("match_type", "path")
            raw_path = app.get("path", "")
            paths: list[str] = []
            if mt == "folder" and raw_path:
                paths = split_engine.expand_folder_exes(raw_path)
                if not paths:
                    warnings.append(f"No executables found in folder for {app.get('name')}")
            elif mt == "path" and raw_path:
                cp = split_engine.canonical_path(raw_path)
                if os.path.isfile(cp):
                    paths = [cp]
                else:
                    warnings.append(f"Executable missing on disk: {raw_path}")
            else:
                warnings.append(f"'{app.get('name')}' uses name-only matching; select its .exe path for OS Kill Switch lock")
                continue

            for p in paths:
                blob = get_app_id_bytes(p)
                if not blob:
                    warnings.append(f"WFP cannot lock Store/protected path: {p}")
                    continue
                if action == "tor_strict":
                    if blob not in seen_strict:
                        seen_strict.add(blob)
                        strict_ids.append((blob, bool(app.get("allow_lan", False)), os.path.basename(p)))
                else:
                    if blob not in seen_blocked:
                        seen_blocked.add(blob)
                        blocked_ids.append((blob, os.path.basename(p)))
        return strict_ids, blocked_ids, warnings

    def _emit_base_filters(
        self,
        h: wintypes.HANDLE,
        mode: str,
        tor_blobs: list[tuple[bytes, str]],
        strict_ids: list[tuple[bytes, bool, str]],
        blocked_ids: list[tuple[bytes, str]],
        allow_lan: bool,
        persistent: bool,
        track_ids: list[int] | None,
    ) -> None:
        v4_layers = (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
        all_layers = (
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        )

        def add(*args):
            fid = self._add_filter(h, *args, persistent=persistent)
            if track_ids is not None:
                track_ids.append(fid)

        lan_cidrs = [
            (int(ipaddress.IPv4Network(c).network_address), int(ipaddress.IPv4Network(c).netmask))
            for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]

        if mode == "system":
            # Weight 15: Loopback, DHCPv4, and Tor/PT binaries
            for lyr in all_layers:
                add(lyr, FWP_ACTION_PERMIT, 15, "Gommage-Loopback", [
                    (FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_CONDITION_FLAG_IS_LOOPBACK),
                ])
            add(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 15, "Gommage-DHCP", [
                (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, 17),
                (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, 67),
            ])
            add(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWP_ACTION_PERMIT, 15, "Gommage-DHCP-Recv", [
                (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, 17),
                (FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL, FWP_UINT16, 68),
            ])
            for blob, bname in tor_blobs:
                for lyr in all_layers:
                    add(lyr, FWP_ACTION_PERMIT, 15, f"Gommage-Tor-{bname}", [
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                    ])
            if allow_lan:
                for net_val in lan_cidrs:
                    for lyr in v4_layers:
                        add(lyr, FWP_ACTION_PERMIT, 8, "Gommage-LAN", [
                            (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, FWP_V4_ADDR_MASK, net_val),
                        ])
            # Weight 1: Catch-all block
            for lyr in all_layers:
                add(lyr, FWP_ACTION_BLOCK, 1, "Gommage-System-Block", [])

        elif mode == "apps":
            for blob, app_lan, aname in strict_ids:
                for lyr in all_layers:
                    add(lyr, FWP_ACTION_PERMIT, 15, f"Gommage-AppLoopback-{aname}", [
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                        (FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_CONDITION_FLAG_IS_LOOPBACK),
                    ])
                if app_lan:
                    for net_val in lan_cidrs:
                        for lyr in v4_layers:
                            add(lyr, FWP_ACTION_PERMIT, 8, f"Gommage-AppLAN-{aname}", [
                                (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                                (FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL, FWP_V4_ADDR_MASK, net_val),
                            ])
                for lyr in all_layers:
                    add(lyr, FWP_ACTION_BLOCK, 1, f"Gommage-AppBlock-{aname}", [
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                    ])
            for blob, aname in blocked_ids:
                for lyr in all_layers:
                    add(lyr, FWP_ACTION_BLOCK, 1, f"Gommage-HardBlock-{aname}", [
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                    ])

    def _emit_dynamic_overlay(
        self,
        tunnel_open: bool,
        wintun_luid: int | None,
        singbox_blob: bytes | None,
        strict_ids: list[tuple[bytes, bool, str]],
        mode: str,
        force_tor_dns: bool,
        connecting_hostname_bridge: bool,
    ) -> None:
        fw = _wfp()
        if self.dyn_handle is None:
            self.dyn_handle = self._open_engine(dynamic=True)
        h = self.dyn_handle
        if not self.persistent:
            self._ensure_provider_and_sublayer(h, persistent=False)

        # Remove previous dynamic overlay filters cleanly in a single transaction
        rc = fw.FwpmTransactionBegin0(h, 0)
        if rc != 0:
            raise OSError(f"FwpmTransactionBegin0 failed: 0x{rc:08X}")
        try:
            for fid in self.dyn_filter_ids:
                fw.FwpmFilterDeleteById0(h, fid)
            self.dyn_filter_ids.clear()

            def add_dyn(layer, action_type, weight, name, conds):
                fid = self._add_filter(h, layer, action_type, weight, name, conds, persistent=False)
                self.dyn_filter_ids.append(fid)

            if tunnel_open and wintun_luid:
                if mode == "system":
                    for lyr in (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4):
                        add_dyn(lyr, FWP_ACTION_PERMIT, 15, "Gommage-TUN-V4", [
                            (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL, FWP_UINT64, wintun_luid),
                        ])
                    if singbox_blob:
                        for lyr in (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4):
                            add_dyn(lyr, FWP_ACTION_PERMIT, 13, "Gommage-SingBox-V4", [
                                (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, singbox_blob),
                            ])
                elif mode == "apps":
                    for blob, _, aname in strict_ids:
                        for lyr in (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4):
                            add_dyn(lyr, FWP_ACTION_PERMIT, 15, f"Gommage-AppTUN-{aname}", [
                                (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, blob),
                                (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL, FWP_UINT64, wintun_luid),
                            ])

                # Close Windows Dnscache / SMHNR non-TUN DNS leaks on port 53 & 853
                if force_tor_dns:
                    if mode == "apps":
                        for lyr in (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6):
                            add_dyn(lyr, FWP_ACTION_PERMIT, 15, "Gommage-Apps-Loopback-DNS", [
                                (FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_CONDITION_FLAG_IS_LOOPBACK),
                            ])
                        if singbox_blob:
                            add_dyn(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 13, "Gommage-Apps-SingBox-DNS", [
                                (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, singbox_blob),
                            ])
                    for proto in (17, 6):
                        for port in (53, 853):
                            add_dyn(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, 12, f"Gommage-BlockNonTunDNS-{proto}-{port}", [
                                (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_NOT_EQUAL, FWP_UINT64, wintun_luid),
                                (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, proto),
                                (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, port),
                            ])
                            add_dyn(FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, 12, f"Gommage-BlockNonTunDNS6-{proto}-{port}", [
                                (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, proto),
                                (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, port),
                            ])
            elif mode == "system" and connecting_hostname_bridge:
                svchost = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "svchost.exe")
                if sv_blob := get_app_id_bytes(svchost):
                    add_dyn(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 14, "Gommage-BridgeBootstrapDNS", [
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, sv_blob),
                        (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, 17),
                        (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL, FWP_UINT16, 53),
                    ])

            rc = fw.FwpmTransactionCommit0(h)
            if rc != 0:
                raise OSError(f"FwpmTransactionCommit0 failed: 0x{rc:08X}")
        except Exception:
            fw.FwpmTransactionAbort0(h)
            raise

    def arm(
        self,
        mode: str,
        persistent: bool,
        tor_paths: list[str],
        singbox_path: str | None,
        split_cfg: dict,
        allow_lan: bool = False,
        allow_direct: bool = False,
        force_tor_dns: bool = True,
        connecting_hostname_bridge: bool = False,
        tunnel_open: bool = False,
        wintun_luid: int | None = None,
        reason: str = "Connecting",
        kill_sockets: bool = True,
    ) -> dict:
        if mode == "off":
            self.disarm(force_persistent=True)
            return self.status()

        self._last_args = {
            "mode": mode,
            "persistent": persistent,
            "tor_paths": list(tor_paths),
            "singbox_path": singbox_path,
            "split_cfg": split_cfg,
            "allow_lan": allow_lan,
            "allow_direct": allow_direct,
            "force_tor_dns": force_tor_dns,
        }

        tor_blobs = []
        for p in tor_paths:
            if b := get_app_id_bytes(p):
                tor_blobs.append((b, os.path.basename(p)))
        singbox_blob = get_app_id_bytes(singbox_path) if singbox_path else None
        strict_ids, blocked_ids, warnings = self._resolve_strict_and_blocked_app_ids(split_cfg)
        self.warnings = warnings

        fw = _wfp()
        if not persistent:
            if self.dyn_handle is not None and not self.persistent:
                # Session-mode live re-arm: atomically swap base filters inside one transaction (zero unguarded gap)
                h = self.dyn_handle
                rc = fw.FwpmTransactionBegin0(h, 0)
                if rc != 0:
                    raise OSError(f"FwpmTransactionBegin0 failed: 0x{rc:08X}")
                try:
                    for fid in self.base_filter_ids:
                        fw.FwpmFilterDeleteById0(h, fid)
                    self.base_filter_ids.clear()
                    self._ensure_provider_and_sublayer(h, persistent=False)
                    self._emit_base_filters(h, mode, tor_blobs, strict_ids, blocked_ids, allow_lan, persistent=False, track_ids=self.base_filter_ids)
                    rc = fw.FwpmTransactionCommit0(h)
                    if rc != 0:
                        raise OSError(f"FwpmTransactionCommit0 failed: 0x{rc:08X}")
                except Exception:
                    fw.FwpmTransactionAbort0(h)
                    raise
            else:
                # Close dynamic handle BEFORE cleaning persistent provider/sublayer (prevents FWP_E_IN_USE)
                if self.dyn_handle is not None:
                    fw.FwpmEngineClose0(self.dyn_handle)
                    self.dyn_handle = None
                    self.dyn_filter_ids.clear()
                    self.base_filter_ids.clear()
                self._cleanup_persistent_only()
                self.dyn_handle = self._open_engine(dynamic=True)
                h = self.dyn_handle
                rc = fw.FwpmTransactionBegin0(h, 0)
                if rc != 0:
                    raise OSError(f"FwpmTransactionBegin0 failed: 0x{rc:08X}")
                try:
                    self._ensure_provider_and_sublayer(h, persistent=False)
                    self._emit_base_filters(h, mode, tor_blobs, strict_ids, blocked_ids, allow_lan, persistent=False, track_ids=self.base_filter_ids)
                    rc = fw.FwpmTransactionCommit0(h)
                    if rc != 0:
                        raise OSError(f"FwpmTransactionCommit0 failed: 0x{rc:08X}")
                except Exception:
                    fw.FwpmTransactionAbort0(h)
                    raise
            remove_recovery_guide(self.home)
        else:
            # Close dynamic session handle before creating persistent provider/sublayer (prevents FWP_E_LIFETIME_MISMATCH)
            if self.dyn_handle is not None and not self.persistent:
                fw.FwpmEngineClose0(self.dyn_handle)
                self.dyn_handle = None
                self.dyn_filter_ids.clear()
                self.base_filter_ids.clear()
            # Persistent base filters in non-dynamic transaction (zero unguarded gap when already persistent!)
            ph = self._open_engine(dynamic=False)
            try:
                rc = fw.FwpmTransactionBegin0(ph, 0)
                if rc != 0:
                    raise OSError(f"FwpmTransactionBegin0 failed: 0x{rc:08X}")
                try:
                    self._ensure_provider_and_sublayer(ph, persistent=True)
                    for old_fid in self._enum_provider_filter_ids(ph, persistent_only=True):
                        fw.FwpmFilterDeleteById0(ph, old_fid)
                    self._emit_base_filters(ph, mode, tor_blobs, strict_ids, blocked_ids, allow_lan, persistent=True, track_ids=None)
                    rc = fw.FwpmTransactionCommit0(ph)
                    if rc != 0:
                        raise OSError(f"FwpmTransactionCommit0 failed: 0x{rc:08X}")
                except Exception:
                    fw.FwpmTransactionAbort0(ph)
                    raise
            finally:
                fw.FwpmEngineClose0(ph)
            write_recovery_guide(self.home)

        self.mode = mode
        self.persistent = bool(persistent)
        self.locked = not tunnel_open
        self.reason = reason

        self._emit_dynamic_overlay(
            tunnel_open=tunnel_open,
            wintun_luid=wintun_luid,
            singbox_blob=singbox_blob,
            strict_ids=strict_ids,
            mode=mode,
            force_tor_dns=force_tor_dns,
            connecting_hostname_bridge=connecting_hostname_bridge,
        )
        write_ks_state(self.home, True, mode, persistent, self.locked, reason)
        return self.status()

    def open_tunnel(self, wintun_luid: int | None = None, singbox_path: str | None = None, split_cfg: dict | None = None) -> dict:
        if self.mode == "off":
            return self.status()
        if singbox_path:
            self._last_args["singbox_path"] = singbox_path
        if split_cfg is not None:
            self._last_args["split_cfg"] = split_cfg
        luid = wintun_luid or resolve_wintun_luid()
        if not luid:
            raise RuntimeError("Wintun interface LUID not found; keeping Kill Switch locked")
        strict_ids, _, warnings = self._resolve_strict_and_blocked_app_ids(self._last_args.get("split_cfg") or {})
        self.warnings = warnings
        sb_blob = get_app_id_bytes(self._last_args.get("singbox_path") or "")
        self.locked = False
        self.reason = "Protected"
        self._emit_dynamic_overlay(
            tunnel_open=True,
            wintun_luid=luid,
            singbox_blob=sb_blob,
            strict_ids=strict_ids,
            mode=self.mode,
            force_tor_dns=bool(self._last_args.get("force_tor_dns", True)),
            connecting_hostname_bridge=False,
        )
        write_ks_state(self.home, True, self.mode, self.persistent, False, self.reason)
        return self.status()

    def lock_tunnel(self, reason: str = "Tunnel locked", connecting_hostname_bridge: bool = False) -> dict:
        if self.mode == "off":
            return self.status()
        strict_ids, _, _ = self._resolve_strict_and_blocked_app_ids(self._last_args.get("split_cfg") or {})
        self.locked = True
        self.reason = reason
        self._emit_dynamic_overlay(
            tunnel_open=False,
            wintun_luid=None,
            singbox_blob=None,
            strict_ids=strict_ids,
            mode=self.mode,
            force_tor_dns=bool(self._last_args.get("force_tor_dns", True)),
            connecting_hostname_bridge=connecting_hostname_bridge,
        )
        write_ks_state(self.home, True, self.mode, self.persistent, True, reason)
        return self.status()

    def _cleanup_persistent_only(self) -> None:
        fw = _wfp()
        ph = self._open_engine(dynamic=False)
        try:
            rc = fw.FwpmTransactionBegin0(ph, 0)
            if rc != 0:
                raise OSError(f"FwpmTransactionBegin0 failed: 0x{rc:08X}")
            try:
                for fid in self._enum_provider_filter_ids(ph, persistent_only=None):
                    rc = fw.FwpmFilterDeleteById0(ph, fid)
                    if rc not in (0, FWP_E_FILTER_NOT_FOUND):
                        raise OSError(f"FwpmFilterDeleteById0 failed: 0x{rc:08X}")
                sub_g = _to_guid(GOMMAGE_SUBLAYER_GUID)
                prov_g = _to_guid(GOMMAGE_PROVIDER_GUID)
                rc = fw.FwpmSubLayerDeleteByKey0(ph, ctypes.byref(sub_g))
                if rc not in (0, FWP_E_SUBLAYER_NOT_FOUND):
                    raise OSError(f"FwpmSubLayerDeleteByKey0 failed: 0x{rc:08X}")
                rc = fw.FwpmProviderDeleteByKey0(ph, ctypes.byref(prov_g))
                if rc not in (0, FWP_E_PROVIDER_NOT_FOUND):
                    raise OSError(f"FwpmProviderDeleteByKey0 failed: 0x{rc:08X}")
                rc = fw.FwpmTransactionCommit0(ph)
                if rc != 0:
                    raise OSError(f"FwpmTransactionCommit0 failed: 0x{rc:08X}")
            except Exception:
                fw.FwpmTransactionAbort0(ph)
                raise
        finally:
            fw.FwpmEngineClose0(ph)

    def disarm(self, force_persistent: bool = True) -> dict:
        fw = _wfp()
        if self.dyn_handle is not None:
            try:
                fw.FwpmEngineClose0(self.dyn_handle)
            except Exception:
                pass
            self.dyn_handle = None
            self.dyn_filter_ids.clear()
            self.base_filter_ids.clear()
        if force_persistent:
            self._cleanup_persistent_only()
            remove_recovery_guide(self.home)
        self.mode = "off"
        self.persistent = False
        self.locked = False
        self.reason = ""
        self.warnings = []
        write_ks_state(self.home, False, "off", False, False, "")
        return self.status()

    def probe_live_state(self) -> dict:
        st = read_ks_state(self.home)
        try:
            fw = _wfp()
            h = self._open_engine(dynamic=True)
            try:
                fids = self._enum_provider_filter_ids(h)
                return {
                    "active": len(fids) > 0,
                    "filter_count": len(fids),
                    "drop_count": None,
                    "backend": "wfp",
                    "error": None,
                }
            finally:
                fw.FwpmEngineClose0(h)
        except Exception as e:
            return {
                "active": bool(st.get("armed") and st.get("persistent")),
                "filter_count": None,
                "drop_count": None,
                "backend": "wfp",
                "error": str(e),
            }

    def reconcile_startup(self, settings: dict) -> dict:
        st = read_ks_state(self.home)
        live = self.probe_live_state()
        if live.get("active") or (settings.get("ks_persistent") and st.get("armed")):
            self.mode = st.get("mode") or settings.get("ks_mode", "off")
            if self.mode == "off":
                self.mode = "system"
            self.persistent = bool(st.get("persistent", settings.get("ks_persistent")))
            self.locked = True
            self.reason = st.get("reason") or "Persistent Kill Switch active"
        else:
            if st.get("armed"):
                # Session filters cleared after reboot/crash
                write_ks_state(self.home, False, "off", False, False, "")
            self.mode = "off"
            self.persistent = False
            self.locked = False
            self.reason = ""
            self.warnings = []
        return self.status()

    def status(self) -> dict:
        return {
            "armed": self.mode != "off",
            "mode": self.mode,
            "persistent": self.persistent,
            "locked": self.locked,
            "reason": self.reason,
            "warnings": list(self.warnings),
            "drop_count": None,
            "caps": self.capabilities(),
        }


# ---------- Linux nftables + skgid + cgroup v2 Kill Switch ----------

def _run_cmd(cmd: list[str], input_text: str | None = None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, input=input_text, capture_output=True, text=True)
    except FileNotFoundError:
        return None


def _systemd_resolve_uid() -> int | None:
    if pwd is None:
        return None
    for name in ("systemd-resolve", "systemd-resolved"):
        try:
            return pwd.getpwnam(name).pw_uid
        except KeyError:
            pass
    return None


def _proc_matches_app(exe_real: str, app: dict) -> bool:
    mt = app.get("match_type", "path")
    ap = app.get("path", "")
    an = (app.get("name") or "").lower()
    if mt == "folder" and ap:
        prefix = ap.rstrip("/") + "/"
        return exe_real.startswith(prefix)
    if mt == "path" and ap:
        return exe_real == split_engine.canonical_path(ap)
    if an:
        return os.path.basename(exe_real).lower() == an
    return False


class LinuxNftKillSwitch:
    """Linux runtime + persistent nftables Kill Switch with cgroup v2 app jail."""

    def __init__(self, home: str, log=print):
        self.home = home
        self.log = log
        self.mode = "off"
        self.persistent = False
        self.locked = False
        self.reason = ""
        self.warnings: list[str] = []
        self._last_args: dict = {}

    def capabilities(self) -> dict:
        return {
            "backend": "nft" if shutil.which("nft") else ("iptables" if shutil.which("iptables") else "none"),
            "has_nft": bool(shutil.which("nft")),
            "has_iptables": bool(shutil.which("iptables")),
            "has_cgroupv2": os.path.exists("/sys/fs/cgroup/cgroup.controllers"),
            "has_ss": bool(shutil.which("ss")),
            "has_systemctl": bool(shutil.which("systemctl")),
            "can_per_app": bool(shutil.which("nft") and os.path.exists("/sys/fs/cgroup/cgroup.controllers")),
            "can_persistent": bool(shutil.which("nft") and shutil.which("systemctl")),
        }

    def build_nft_script(
        self,
        mode: str,
        tunnel_open: bool,
        allow_lan: bool = False,
        force_tor_dns: bool = True,
        connecting_hostname_bridge: bool = False,
        resolve_uid: int | None = None,
    ) -> str:
        """Build an atomic nftables ruleset for `table inet gommage_ks`."""
        lines = [
            f"add table inet {NFT_TABLE}",
            f"flush table inet {NFT_TABLE}",
            f"table inet {NFT_TABLE} {{",
        ]
        if mode == "system":
            lines.append("  chain output {")
            lines.append("    type filter hook output priority -10; policy drop;")
            lines.append('    oifname "lo" accept')
            lines.append("    udp sport 68 udp dport 67 accept")
            lines.append(f"    meta skgid {GOMMAGE_TOR_GID} accept")
            if tunnel_open:
                lines.append(f"    meta skgid {GOMMAGE_SB_GID} accept")
                lines.append('    oifname "Gommage" meta nfproto ipv4 accept')
            elif connecting_hostname_bridge and resolve_uid is not None:
                lines.append(f"    meta skuid {int(resolve_uid)} udp dport 53 accept")
            if force_tor_dns:
                lines.append('    meta l4proto { udp, tcp } th dport { 53, 853 } oifname != "Gommage" oifname != "lo" counter drop')
            if allow_lan:
                lines.append("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept")
            lines.append("    counter drop")
            lines.append("  }")
        elif mode == "apps":
            lines.append("  chain output {")
            lines.append("    type filter hook output priority -10; policy accept;")
            if tunnel_open:
                lines.append('    socket cgroupv2 level 1 "gommage_jail" oifname "lo" accept')
                lines.append('    socket cgroupv2 level 1 "gommage_jail" oifname "Gommage" meta nfproto ipv4 accept')
                if force_tor_dns and resolve_uid is not None:
                    lines.append(f'    meta skuid {int(resolve_uid)} oifname != "Gommage" oifname != "lo" meta l4proto {{ udp, tcp }} th dport {{ 53, 853 }} counter drop')
            else:
                lines.append('    socket cgroupv2 level 1 "gommage_jail" oifname "lo" ip daddr != 127.0.0.53 accept')
                lines.append('    socket cgroupv2 level 1 "gommage_jail" oifname "lo" ip6 daddr ::1 accept')
            if force_tor_dns:
                lines.append('    socket cgroupv2 level 1 "gommage_jail" meta l4proto { udp, tcp } th dport { 53, 853 } oifname != "Gommage" oifname != "lo" counter drop')
            if allow_lan:
                lines.append('    socket cgroupv2 level 1 "gommage_jail" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept')
            lines.append('    socket cgroupv2 level 1 "gommage_jail" counter drop')
            lines.append("  }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _apply_iptables_fallback(self, tunnel_open: bool, allow_lan: bool) -> None:
        """Runtime fallback for `system` mode when nftables is unavailable."""
        for tool in ("iptables", "ip6tables"):
            _run_cmd([tool, "-D", "OUTPUT", "-j", IPT_CHAIN])
            _run_cmd([tool, "-F", IPT_CHAIN])
            _run_cmd([tool, "-X", IPT_CHAIN])
            _run_cmd([tool, "-N", IPT_CHAIN])
            _run_cmd([tool, "-A", IPT_CHAIN, "-o", "lo", "-j", "ACCEPT"])
            _run_cmd([tool, "-A", IPT_CHAIN, "-m", "owner", "--gid-owner", str(GOMMAGE_TOR_GID), "-j", "ACCEPT"])
            if tool == "iptables":
                _run_cmd([tool, "-A", IPT_CHAIN, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"])
                if tunnel_open:
                    _run_cmd([tool, "-A", IPT_CHAIN, "-m", "owner", "--gid-owner", str(GOMMAGE_SB_GID), "-j", "ACCEPT"])
                    _run_cmd([tool, "-A", IPT_CHAIN, "-o", "Gommage", "-j", "ACCEPT"])
                if allow_lan:
                    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
                        _run_cmd([tool, "-A", IPT_CHAIN, "-d", net, "-j", "ACCEPT"])
            _run_cmd([tool, "-A", IPT_CHAIN, "-j", "DROP"])
            _run_cmd([tool, "-I", "OUTPUT", "1", "-j", IPT_CHAIN])

    def _clear_iptables_fallback(self) -> None:
        for tool in ("iptables", "ip6tables"):
            while (r := _run_cmd([tool, "-D", "OUTPUT", "-j", IPT_CHAIN])) and r.returncode == 0:
                pass
            _run_cmd([tool, "-F", IPT_CHAIN])
            _run_cmd([tool, "-X", IPT_CHAIN])

    def _apply_rules(self, mode: str, tunnel_open: bool, allow_lan: bool, force_tor_dns: bool, connecting_hostname_bridge: bool) -> None:
        caps = self.capabilities()
        if mode == "apps":
            if not caps["has_nft"] or not caps["has_cgroupv2"]:
                raise RuntimeError("Linux Strict Apps Kill Switch requires nftables and unified cgroup v2")
            os.makedirs(JAIL_CGROUP, exist_ok=True)
        if caps["has_nft"]:
            script = self.build_nft_script(
                mode=mode,
                tunnel_open=tunnel_open,
                allow_lan=allow_lan,
                force_tor_dns=force_tor_dns,
                connecting_hostname_bridge=connecting_hostname_bridge,
                resolve_uid=_systemd_resolve_uid(),
            )
            r = _run_cmd(["nft", "-f", "-"], input_text=script)
            if not r or r.returncode != 0:
                raise RuntimeError(f"nftables load failed: {r.stderr if r else 'nft missing'}")
        elif mode == "system" and caps["has_iptables"]:
            self._apply_iptables_fallback(tunnel_open, allow_lan)
        else:
            raise RuntimeError("Neither nftables nor iptables is available for Kill Switch")

    def _install_persistent_unit(self, mode: str, allow_lan: bool, force_tor_dns: bool) -> None:
        nft_bin = shutil.which("nft")
        if not nft_bin or not shutil.which("systemctl"):
            raise RuntimeError("Persistent Kill Switch on Linux requires nftables and systemd")
        boot_script = self.build_nft_script(
            mode=mode,
            tunnel_open=False,
            allow_lan=allow_lan,
            force_tor_dns=force_tor_dns,
            connecting_hostname_bridge=False,
            resolve_uid=_systemd_resolve_uid(),
        )
        with open(PERSIST_NFT, "w", encoding="utf8") as f:
            f.write(boot_script)
        os.chmod(PERSIST_NFT, 0o644)
        unit = (
            "[Unit]\n"
            "Description=Gommage Persistent Kill Switch\n"
            "DefaultDependencies=no\n"
            "Before=network-pre.target\n"
            "Wants=network-pre.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            f"ExecStartPre=/bin/mkdir -p {JAIL_CGROUP}\n"
            f"ExecStart={nft_bin} -f {PERSIST_NFT}\n"
            f"ExecStop={nft_bin} delete table inet {NFT_TABLE}\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        with open(PERSIST_UNIT, "w", encoding="utf8") as f:
            f.write(unit)
        os.chmod(PERSIST_UNIT, 0o644)
        _run_cmd(["systemctl", "daemon-reload"])
        _run_cmd(["systemctl", "enable", "gommage-killswitch.service"])

    def kill_stale_sockets(self) -> None:
        if not shutil.which("ss"):
            return
        _run_cmd(["ss", "-4", "-K", "state", "established", "not", "dst", "127.0.0.0/8"])
        _run_cmd(["ss", "-6", "-K", "state", "established", "not", "dst", "::1"])

    def attach_running_to_jail(self, strict_apps: list[dict]) -> dict:
        """Move matching running PIDs into gommage_jail; return jailed + unjailed audit info."""
        jailed, warnings = [], []
        if not strict_apps or not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
            return {"jailed_pids": jailed, "warnings": warnings}
        if os.geteuid() == 0:
            os.makedirs(JAIL_CGROUP, exist_ok=True)
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid_s = os.path.basename(pid_dir)
            try:
                exe = os.path.realpath(os.path.join(pid_dir, "exe"))
                cg = open(os.path.join(pid_dir, "cgroup"), encoding="utf8", errors="replace").read()
            except OSError:
                continue
            if not any(_proc_matches_app(exe, a) for a in strict_apps):
                continue
            if "gommage_jail" in cg:
                jailed.append({"pid": int(pid_s), "exe": exe})
                continue
            if os.geteuid() == 0:
                try:
                    open(os.path.join(JAIL_CGROUP, "cgroup.procs"), "w").write(pid_s + "\n")
                    jailed.append({"pid": int(pid_s), "exe": exe})
                    warnings.append(f"{os.path.basename(exe)} (PID {pid_s}) was already running before lock; pre-existing UDP sockets may bypass cgroup until restarted via Launch Protected")
                except OSError:
                    warnings.append(f"Could not jail running {os.path.basename(exe)} (PID {pid_s}); use Launch Protected")
            else:
                warnings.append(f"{os.path.basename(exe)} (PID {pid_s}) is running outside gommage_jail")
        return {"jailed_pids": jailed, "warnings": warnings}

    def arm(
        self,
        mode: str,
        persistent: bool,
        tor_paths: list[str],
        singbox_path: str | None,
        split_cfg: dict,
        allow_lan: bool = False,
        allow_direct: bool = False,
        force_tor_dns: bool = True,
        connecting_hostname_bridge: bool = False,
        tunnel_open: bool = False,
        wintun_luid: int | None = None,
        reason: str = "Connecting",
        kill_sockets: bool = True,
    ) -> dict:
        if mode == "off":
            self.disarm(force_persistent=True)
            return self.status()

        self._last_args = {
            "mode": mode,
            "persistent": persistent,
            "split_cfg": split_cfg,
            "allow_lan": allow_lan,
            "allow_direct": allow_direct,
            "force_tor_dns": force_tor_dns,
        }
        if not persistent:
            # Remove systemd persistence BEFORE loading live rules (keep_live=True skips --now so ExecStop doesn't delete our table)
            self._remove_persistent_unit(keep_live=True)
            remove_recovery_guide(self.home)

        self._apply_rules(mode, tunnel_open, allow_lan, force_tor_dns, connecting_hostname_bridge)

        warnings = []
        if mode == "system" and not tunnel_open and kill_sockets:
            self.kill_stale_sockets()
        elif mode == "apps":
            strict_apps = [a for a in split_cfg.get("apps", []) if a.get("enabled", True) and a.get("action") == "tor_strict"]
            res = self.attach_running_to_jail(strict_apps)
            warnings.extend(res["warnings"])

        if persistent:
            self._install_persistent_unit(mode, allow_lan, force_tor_dns)
            write_recovery_guide(self.home)

        self.mode = mode
        self.persistent = bool(persistent)
        self.locked = not tunnel_open
        self.reason = reason
        self.warnings = warnings
        write_ks_state(self.home, True, mode, persistent, self.locked, reason)
        return self.status()

    def open_tunnel(self, wintun_luid: int | None = None, singbox_path: str | None = None, split_cfg: dict | None = None) -> dict:
        if self.mode == "off":
            return self.status()
        if split_cfg is not None:
            self._last_args["split_cfg"] = split_cfg
        self._apply_rules(
            self.mode,
            tunnel_open=True,
            allow_lan=bool(self._last_args.get("allow_lan", False)),
            force_tor_dns=bool(self._last_args.get("force_tor_dns", True)),
            connecting_hostname_bridge=False,
        )
        self.locked = False
        self.reason = "Protected"
        write_ks_state(self.home, True, self.mode, self.persistent, False, self.reason)
        return self.status()

    def lock_tunnel(self, reason: str = "Tunnel locked", connecting_hostname_bridge: bool = False) -> dict:
        if self.mode == "off":
            return self.status()
        self._apply_rules(
            self.mode,
            tunnel_open=False,
            allow_lan=bool(self._last_args.get("allow_lan", False)),
            force_tor_dns=bool(self._last_args.get("force_tor_dns", True)),
            connecting_hostname_bridge=connecting_hostname_bridge,
        )
        self.locked = True
        self.reason = reason
        write_ks_state(self.home, True, self.mode, self.persistent, True, reason)
        return self.status()

    def _remove_persistent_unit(self, keep_live: bool = False) -> None:
        had_unit = os.path.exists(PERSIST_UNIT)
        has_ctl = bool(shutil.which("systemctl"))
        if has_ctl and had_unit:
            cmd = ["systemctl", "disable"] + ([] if keep_live else ["--now"]) + ["gommage-killswitch.service"]
            _run_cmd(cmd)
        for p in (PERSIST_UNIT, PERSIST_NFT):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        if has_ctl and had_unit:
            _run_cmd(["systemctl", "daemon-reload"])

    def disarm(self, force_persistent: bool = True) -> dict:
        if shutil.which("nft"):
            _run_cmd(["nft", "delete", "table", "inet", NFT_TABLE])
        self._clear_iptables_fallback()
        if force_persistent:
            self._remove_persistent_unit(keep_live=False)
            remove_recovery_guide(self.home)
        self.mode = "off"
        self.persistent = False
        self.locked = False
        self.reason = ""
        self.warnings = []
        write_ks_state(self.home, False, "off", False, False, "")
        return self.status()

    def probe_live_state(self) -> dict:
        st = read_ks_state(self.home)
        caps = self.capabilities()
        if os.geteuid() != 0:
            return {
                "active": bool((st.get("armed") and st.get("persistent")) or os.path.exists(PERSIST_NFT)),
                "filter_count": None,
                "drop_count": None,
                "backend": caps["backend"],
                "error": None,
            }
        if caps["has_nft"]:
            r = _run_cmd(["nft", "list", "table", "inet", NFT_TABLE])
            if r and r.returncode == 0:
                drops = sum(int(m) for m in re.findall(r"counter packets (\d+) bytes \d+ drop", r.stdout))
                return {
                    "active": True,
                    "filter_count": r.stdout.count("\n"),
                    "drop_count": drops,
                    "backend": "nft",
                    "error": None,
                }
            return {"active": False, "filter_count": 0, "drop_count": 0, "backend": "nft", "error": None}
        return {
            "active": bool(st.get("armed")),
            "filter_count": None,
            "drop_count": None,
            "backend": caps["backend"],
            "error": None,
        }

    def reconcile_startup(self, settings: dict) -> dict:
        st = read_ks_state(self.home)
        live = self.probe_live_state()
        if live.get("active") or os.path.exists(PERSIST_NFT) or (settings.get("ks_persistent") and st.get("armed")):
            self.mode = st.get("mode") or settings.get("ks_mode", "off")
            if self.mode == "off":
                self.mode = "system"
            self.persistent = bool(st.get("persistent", settings.get("ks_persistent")) or os.path.exists(PERSIST_NFT))
            self.locked = True
            self.reason = st.get("reason") or "Kill Switch active"
        else:
            if st.get("armed"):
                write_ks_state(self.home, False, "off", False, False, "")
            self.mode = "off"
            self.persistent = False
            self.locked = False
            self.reason = ""
            self.warnings = []
        return self.status()

    def status(self) -> dict:
        live = self.probe_live_state()
        return {
            "armed": self.mode != "off",
            "mode": self.mode,
            "persistent": self.persistent,
            "locked": self.locked,
            "reason": self.reason,
            "warnings": list(self.warnings),
            "drop_count": live.get("drop_count"),
            "caps": self.capabilities(),
        }


# ---------- factory + Linux jailed launcher + headless CLI ----------

def create_killswitch(home: str, log=print):
    return WinWFPKillSwitch(home, log) if WIN else LinuxNftKillSwitch(home, log)


def launch_jailed(exe_path: str, gommage_script: str) -> tuple[bool, str]:
    """Linux: spawn a desktop app directly inside /sys/fs/cgroup/gommage_jail as desktop user."""
    if WIN:
        return False, "Launch Protected is Linux-only (on Windows, launch normally; WFP locks by executable path)"
    if os.geteuid() != 0:
        return False, "Connect in VPN mode (elevated) first to jail processes"
    uid_s = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if not uid_s or not uid_s.isdigit():
        return False, "Desktop user UID unknown; start Gommage from desktop session via pkexec"
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        return False, "Linux cgroup v2 is not mounted on /sys/fs/cgroup"
    if not exe_path or not os.path.isfile(exe_path):
        return False, f"Executable not found: {exe_path}"
    cmd = [sys.executable] + ([] if FROZEN else [gommage_script]) + ["--exec-jailed", uid_s, exe_path]
    subprocess.Popen(cmd, start_new_session=True)
    return True, f"Launched {os.path.basename(exe_path)} inside cgroup jail"


def exec_jailed_cli(uid_str: str, exe_path: str) -> None:
    """Race-free child pre-exec: join cgroup v2 as root, drop privileges cleanly, exec app."""
    if WIN or pwd is None:
        sys.exit(1)
    if os.geteuid() != 0:
        sys.exit(1)
    os.makedirs(JAIL_CGROUP, exist_ok=True)
    with open(os.path.join(JAIL_CGROUP, "cgroup.procs"), "w", encoding="utf8") as f:
        f.write(f"{os.getpid()}\n")
    pw = pwd.getpwuid(int(uid_str))
    os.setgroups(os.getgrouplist(pw.pw_name, pw.pw_gid))
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    env = os.environ.copy()
    env["HOME"] = pw.pw_dir
    env["USER"] = pw.pw_name
    env["LOGNAME"] = pw.pw_name
    if not env.get("DBUS_SESSION_BUS_ADDRESS") and env.get("XDG_RUNTIME_DIR"):
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={env['XDG_RUNTIME_DIR']}/bus"
    os.execvpe(exe_path, [exe_path], env)


def _win_notify(msg: str, is_err: bool = False) -> None:
    if sys.stdout:
        print(msg)
    if FROZEN or sys.stdout is None:
        flags = 0x10 if is_err else 0x40
        ctypes.windll.user32.MessageBoxW(0, msg, "Gommage Kill Switch", flags)


def parse_home_arg(argv: list[str]) -> str | None:
    for i, a in enumerate(argv[1:], 1):
        if a == "--home" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--home="):
            return a.split("=", 1)[1]
    return None


def handle_cli_early(argv: list[str], home: str, gommage_script: str = "") -> None:
    """Run headless recovery/jail commands BEFORE importing GUI libraries (webview/pystray/PIL)."""
    if "--exec-jailed" in argv:
        idx = argv.index("--exec-jailed")
        if idx + 2 < len(argv):
            exec_jailed_cli(argv[idx + 1], argv[idx + 2])
        sys.exit(1)

    if "--unlock-killswitch" not in argv:
        return

    if WIN:
        is_adm = bool(ctypes.windll.shell32.IsUserAnAdmin())
        if not is_adm:
            if "--elevated" in argv:
                _win_notify("Administrator permission is required to unlock the Kill Switch.", is_err=True)
                sys.exit(1)
            extra = ("" if FROZEN else f'"{gommage_script}" ') + f'--unlock-killswitch --elevated --home "{home}"'
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, extra.strip(), None, 1)
            sys.exit(0 if rc > 32 else 1)
        try:
            WinWFPKillSwitch(home).disarm(force_persistent=True)
            _win_notify("Gommage Kill Switch unlocked and persistent firewall rules removed.")
            sys.exit(0)
        except Exception as e:
            _win_notify(f"Failed to unlock Kill Switch: {e}", is_err=True)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("Root permission is required. Run: sudo gommage --unlock-killswitch", file=sys.stderr)
            sys.exit(1)
        try:
            LinuxNftKillSwitch(home).disarm(force_persistent=True)
            print("Gommage Kill Switch unlocked and persistent firewall rules removed.")
            sys.exit(0)
        except Exception as e:
            print(f"Failed to unlock Kill Switch: {e}", file=sys.stderr)
            sys.exit(1)
