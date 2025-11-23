#!/usr/bin/env python3
"""
Dump iptables (IPv4) entries in a human-readable form inside a gVisor container.

The script queries IPT_SO_GET_INFO and IPT_SO_GET_ENTRIES directly through a raw
IPv4 socket. It prints table metadata and each rule's matches and target,
including the decoded standard verdicts (ACCEPT, DROP, RETURN, etc.).

Run inside a gVisor sandbox with --net-raw or otherwise ensure CAP_NET_RAW and
CAP_NET_ADMIN are present.
"""
import ctypes
import ipaddress
import socket
import struct
from typing import Iterable, List, Tuple

# Constants from linux/netfilter_ipv4/ip_tables.h and x_tables.h
SOL_IP = socket.SOL_IP
IPT_SO_GET_INFO = 64
IPT_SO_GET_ENTRIES = IPT_SO_GET_INFO + 1
XT_TABLE_MAXNAMELEN = 32
XT_EXTENSION_MAXNAMELEN = 29
NF_INET_NUMHOOKS = 5
XT_STANDARD_TARGET = b""  # "standard" target has an empty name.
XT_ERROR_TARGET = b"ERROR"

HOOK_NAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

VERDICT_STRINGS = {
    -1: "DROP",
    -2: "ACCEPT",
    -3: "QUEUE",
    -4: "REPEAT",
    -5: "STOP",
    -6: "RETURN",
}


class IPTGetinfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]


class IPTGetEntries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        ("_pad", ctypes.c_uint),
    ]


class IPTIP(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_uint32),
        ("dst", ctypes.c_uint32),
        ("smask", ctypes.c_uint32),
        ("dmask", ctypes.c_uint32),
        ("iniface", ctypes.c_char * socket.IFNAMSIZ),
        ("outiface", ctypes.c_char * socket.IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("flags", ctypes.c_ubyte),
        ("invflags", ctypes.c_ubyte),
    ]


class XTCounters(ctypes.Structure):
    _fields_ = [
        ("pcnt", ctypes.c_uint64),
        ("bcnt", ctypes.c_uint64),
    ]


class IPTEntry(ctypes.Structure):
    _fields_ = [
        ("ip", IPTIP),
        ("nfcache", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint32),
        ("counters", XTCounters),
    ]


def _decode_ip(addr: int, mask: int) -> str:
    ip = ipaddress.IPv4Address(addr)
    if mask == 0:
        return "any"
    prefix = ipaddress.IPv4Network((0, mask)).prefixlen
    return f"{ip}/{prefix}"


def _decode_iface(raw_name: bytes, raw_mask: Iterable[int]) -> str:
    name = raw_name.split(b"\0", 1)[0].decode() if raw_name else ""
    mask_bytes = bytes(raw_mask)
    if not name or all(b == 0 for b in mask_bytes):
        return "*"
    masked = "".join(ch if mask_bytes[i] else "?" for i, ch in enumerate(name))
    return masked


def _read_matches(payload: bytes, start: int, end: int) -> List[Tuple[str, bytes]]:
    matches: List[Tuple[str, bytes]] = []
    offset = start
    header_size = 2 + XT_EXTENSION_MAXNAMELEN + 1
    while offset + header_size <= end:
        (match_size,) = struct.unpack_from("<H", payload, offset)
        name = payload[offset + 2 : offset + 2 + XT_EXTENSION_MAXNAMELEN]
        name = name.split(b"\0", 1)[0]
        revision = payload[offset + 2 + XT_EXTENSION_MAXNAMELEN]
        data_start = offset + header_size
        data_end = offset + match_size
        if match_size == 0 or data_end > end:
            break
        matches.append((f"{name.decode()}(rev {revision})", payload[data_start:data_end]))
        offset = data_end
    return matches


def _decode_verdict(value: int) -> str:
    if value == 0xFFFFFFFF:
        return "CONTINUE"
    return VERDICT_STRINGS.get(value, str(value))


def _read_target(payload: bytes, offset: int) -> Tuple[str, str, bytes]:
    header_size = 2 + XT_EXTENSION_MAXNAMELEN + 1
    (target_size,) = struct.unpack_from("<H", payload, offset)
    name = payload[offset + 2 : offset + 2 + XT_EXTENSION_MAXNAMELEN]
    name = name.split(b"\0", 1)[0]
    revision = payload[offset + 2 + XT_EXTENSION_MAXNAMELEN]
    data_start = offset + header_size
    data_end = offset + target_size
    data = payload[data_start:data_end]

    if name == XT_STANDARD_TARGET and len(data) >= 4:
        (verdict,) = struct.unpack_from("<i", data)
        verdict = _decode_verdict(verdict)
        return "standard", verdict, data[4:]
    if name == XT_ERROR_TARGET:
        return "error", data.decode(errors="replace"), b""
    return name.decode() or "unknown", f"rev {revision}", data


def _print_entry(index: int, offset: int, entry: IPTEntry, matches, target_desc):
    ip = entry.ip
    src = _decode_ip(ip.src, ip.smask)
    dst = _decode_ip(ip.dst, ip.dmask)
    iniface = _decode_iface(ip.iniface, ip.iniface_mask)
    outiface = _decode_iface(ip.outiface, ip.outiface_mask)
    target_name, target_detail, target_data = target_desc
    print(f"[{index}] offset={offset} next={entry.next_offset} target_off={entry.target_offset}")
    print(f"     src={src} dst={dst} proto={ip.proto} in={iniface} out={outiface}")
    if matches:
        print("     matches:")
        for name, data in matches:
            print(f"       - {name} ({len(data)} bytes of data)")
    print(f"     target={target_name}: {target_detail}")
    if target_data:
        print(f"       raw target data: {target_data.hex()}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        info = IPTGetinfo()
        info.name = b"nat"
        info_len = ctypes.c_uint(ctypes.sizeof(info))
        if ctypes.CDLL("libc.so.6").getsockopt(
            s.fileno(), SOL_IP, IPT_SO_GET_INFO, ctypes.byref(info), ctypes.byref(info_len)
        ) != 0:
            raise OSError(ctypes.get_errno(), "getsockopt IPT_SO_GET_INFO failed")

        entries_buf = ctypes.create_string_buffer(info.size)
        entries = IPTGetEntries.from_buffer(entries_buf)
        entries.name = info.name
        entries.size = info.size
        buf_len = ctypes.c_uint(entries_buf._length_)
        if ctypes.CDLL("libc.so.6").getsockopt(
            s.fileno(), SOL_IP, IPT_SO_GET_ENTRIES, entries_buf, ctypes.byref(buf_len)
        ) != 0:
            raise OSError(ctypes.get_errno(), "getsockopt IPT_SO_GET_ENTRIES failed")

    print(f"Table: {entries.name.decode()} valid_hooks=0x{info.valid_hooks:x}")
    for i, (hook, under) in enumerate(zip(info.hook_entry, info.underflow)):
        print(f"  {HOOK_NAMES[i]}: entry_offset={hook} underflow_offset={under}")
    print(f"Entries: {info.num_entries} total_bytes={info.size}\n")

    payload = entries_buf.raw[: entries.size]
    offset = ctypes.sizeof(IPTGetEntries)
    index = 0
    while offset < len(payload):
        entry = IPTEntry.from_buffer_copy(payload, offset)
        target_offset = offset + entry.target_offset
        matches = _read_matches(payload, offset + ctypes.sizeof(IPTEntry), target_offset)
        target = _read_target(payload, target_offset)
        _print_entry(index, offset, entry, matches, target)
        offset += entry.next_offset
        index += 1


if __name__ == "__main__":
    main()
