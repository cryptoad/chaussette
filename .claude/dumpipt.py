import ctypes
import socket
import struct
from typing import Iterable, List

# Constants from linux/netfilter_ipv4/ip_tables.h and linux/netfilter.h.
SOL_IP = socket.SOL_IP
IPT_BASE_CTL = 64
IPT_SO_GET_INFO = IPT_BASE_CTL
IPT_SO_GET_ENTRIES = IPT_BASE_CTL + 1
XT_TABLE_MAXNAMELEN = 32
XT_EXTENSION_MAXNAMELEN = 29
NF_IP_NUMHOOKS = 5
IFNAMSIZ = 16
NF_DROP = 0
NF_ACCEPT = 1
NF_QUEUE = 3
NF_REPEAT = 4
NF_STOP = 5
NF_RETURN = -NF_REPEAT - 1

# Hook names correspond to NF_INET_* values.
HOOK_NAMES = [
    "PREROUTING",
    "LOCAL_IN",
    "FORWARD",
    "LOCAL_OUT",
    "POSTROUTING",
]


class IPTGetinfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]


class IPTGetEntriesHeader(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        ("entrytable", ctypes.c_ubyte * 0),
    ]


class IPTIP(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_uint32),
        ("dst", ctypes.c_uint32),
        ("smask", ctypes.c_uint32),
        ("dmask", ctypes.c_uint32),
        ("iniface", ctypes.c_char * IFNAMSIZ),
        ("outiface", ctypes.c_char * IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("invflags", ctypes.c_uint8),
    ]


class XTCounters(ctypes.Structure):
    _fields_ = [("pcnt", ctypes.c_uint64), ("bcnt", ctypes.c_uint64)]


class IPTEntry(ctypes.Structure):
    _fields_ = [
        ("ip", IPTIP),
        ("nfcache", ctypes.c_uint),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint),
        ("counters", XTCounters),
    ]


class XTEntryMatch(ctypes.Structure):
    _fields_ = [
        ("match_size", ctypes.c_uint16),
        ("name", ctypes.c_char * XT_EXTENSION_MAXNAMELEN),
        ("revision", ctypes.c_uint8),
    ]


class XTEntryTarget(ctypes.Structure):
    _fields_ = [
        ("target_size", ctypes.c_uint16),
        ("name", ctypes.c_char * XT_EXTENSION_MAXNAMELEN),
        ("revision", ctypes.c_uint8),
    ]


class XTStandardTarget(ctypes.Structure):
    _fields_ = [("target", XTEntryTarget), ("verdict", ctypes.c_int32)]


VERDICTS = {
    -NF_DROP - 1: "DROP",
    -NF_ACCEPT - 1: "ACCEPT",
    -NF_QUEUE - 1: "QUEUE",
    -NF_REPEAT - 1: "REPEAT",
    -NF_STOP - 1: "STOP",
    NF_RETURN: "RETURN",
}


def _decode_addr(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def _decode_iface(name: Iterable[int]) -> str:
    raw = bytes(name)
    return raw.split(b"\0", 1)[0].decode(errors="ignore")


def _decode_target(entry_data: memoryview, target_offset: int) -> str:
    tgt = XTEntryTarget.from_buffer(entry_data, target_offset)
    name = tgt.name.split(b"\0", 1)[0].decode(errors="ignore")
    if not name:
        std = XTStandardTarget.from_buffer(entry_data, target_offset)
        return VERDICTS.get(std.verdict, f"verdict {std.verdict}")
    return name


def _decode_matches(entry_data: memoryview, target_offset: int) -> List[str]:
    matches = []
    offset = ctypes.sizeof(IPTEntry)
    while offset < target_offset:
        match = XTEntryMatch.from_buffer(entry_data, offset)
        name = match.name.split(b"\0", 1)[0].decode(errors="ignore")
        matches.append(name)
        offset += match.match_size
    return matches


def _describe_entry(entry: IPTEntry, entry_bytes: memoryview) -> str:
    ip = entry.ip
    parts = []
    if ip.proto:
        parts.append(f"proto={ip.proto}")
    if ip.smask:
        parts.append(f"src={_decode_addr(ip.src)}/{_decode_addr(ip.smask)}")
    if ip.dmask:
        parts.append(f"dst={_decode_addr(ip.dst)}/{_decode_addr(ip.dmask)}")
    iniface = _decode_iface(ip.iniface)
    if iniface:
        parts.append(f"in={iniface}")
    outiface = _decode_iface(ip.outiface)
    if outiface:
        parts.append(f"out={outiface}")
    matches = _decode_matches(entry_bytes, entry.target_offset)
    target = _decode_target(entry_bytes, entry.target_offset)
    parts.append(f"target={target}")
    if matches:
        parts.append(f"matches={','.join(matches)}")
    return ", ".join(parts)


def main() -> None:
    # Must run as root with CAP_NET_RAW/CAP_NET_ADMIN (gVisor: pass --net-raw).
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        info = IPTGetinfo()
        info.name = b"nat"
        buf_len = ctypes.c_uint(ctypes.sizeof(info))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.getsockopt(
            s.fileno(), SOL_IP, IPT_SO_GET_INFO, ctypes.byref(info), ctypes.byref(buf_len)
        ) != 0:
            raise OSError(ctypes.get_errno(), "getsockopt IPT_SO_GET_INFO failed")

        header_size = ctypes.sizeof(IPTGetEntriesHeader)
        entries_buf = ctypes.create_string_buffer(header_size + info.size)
        entries = IPTGetEntriesHeader.from_buffer(entries_buf)
        entries.name = info.name
        entries.size = info.size

        buf_len = ctypes.c_uint(ctypes.sizeof(entries_buf))
        if libc.getsockopt(
            s.fileno(), SOL_IP, IPT_SO_GET_ENTRIES, ctypes.byref(entries), ctypes.byref(buf_len)
        ) != 0:
            raise OSError(ctypes.get_errno(), "getsockopt IPT_SO_GET_ENTRIES failed")

    entry_data = (ctypes.c_ubyte * info.size).from_buffer(entries_buf, header_size)
    print(f"Table {info.name.decode()} has {info.num_entries} entries ({info.size} bytes)")

    hook_map = {}
    for idx, off in enumerate(info.hook_entry):
        if info.valid_hooks & (1 << idx):
            hook_map.setdefault(off, []).append(f"{HOOK_NAMES[idx]} start")
    for idx, off in enumerate(info.underflow):
        if info.valid_hooks & (1 << idx):
            hook_map.setdefault(off, []).append(f"{HOOK_NAMES[idx]} underflow")

    offset = 0
    while offset < info.size:
        view = memoryview(entry_data)[offset:]
        entry = IPTEntry.from_buffer(view)
        annotations = hook_map.get(offset)
        desc = _describe_entry(entry, view)
        if annotations:
            print(f"[{offset:5d}] {'; '.join(annotations)}")
        print(f"[{offset:5d}] {desc}")
        offset += entry.next_offset


if __name__ == "__main__":
    main()
