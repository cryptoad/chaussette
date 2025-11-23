#!/usr/bin/env python3
"""Minimal iptables dumper for gVisor debugging.

This script queries IPT_SO_GET_INFO and IPT_SO_GET_ENTRIES for a set of
iptables tables, starting with the nat table. It requires CAP_NET_RAW or
CAP_NET_ADMIN (for gVisor, pass --net-raw).
"""

import ctypes
import ipaddress
import os
import socket
from errno import ENOMEM

# Constants from linux/netfilter_ipv4/ip_tables.h.
SOL_IP = socket.SOL_IP
IPT_SO_GET_INFO = 64  # IPT_BASE_CTL
IPT_SO_GET_ENTRIES = IPT_SO_GET_INFO + 1
XT_TABLE_MAXNAMELEN = 32
NF_IP_NUMHOOKS = 5
IFNAMSIZ = 16
XT_EXTENSION_MAXNAMELEN = 29


class IPTGetinfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]


class IPTGetEntries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        ("entrytable", ctypes.c_ubyte * 0),
    ]


class XTCounters(ctypes.Structure):
    _fields_ = [
        ("pcnt", ctypes.c_uint64),
        ("bcnt", ctypes.c_uint64),
    ]


class IPTIP(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_uint32),
        ("dst", ctypes.c_uint32),
        ("smsk", ctypes.c_uint32),
        ("dmsk", ctypes.c_uint32),
        ("iniface", ctypes.c_char * IFNAMSIZ),
        ("outiface", ctypes.c_char * IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("invflags", ctypes.c_uint8),
    ]


class IPTEntry(ctypes.Structure):
    _fields_ = [
        ("ip", IPTIP),
        ("nfcache", ctypes.c_uint),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint),
        ("counters", XTCounters),
    ]


class XTEntryTarget(ctypes.Structure):
    _fields_ = [
        ("target_size", ctypes.c_uint16),
        ("name", ctypes.c_char * XT_EXTENSION_MAXNAMELEN),
        ("revision", ctypes.c_uint8),
    ]


libc = ctypes.CDLL("libc.so.6", use_errno=True)


def _getsockopt(sock, level, optname, optval):
    """Wrapper for getsockopt that raises OSError on failure."""
    buflen = ctypes.c_uint(ctypes.sizeof(optval))
    if libc.getsockopt(sock.fileno(), level, optname, ctypes.byref(optval), ctypes.byref(buflen)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return optval


def _get_info(sock, table_name):
    info = IPTGetinfo()
    info.name = table_name
    return _getsockopt(sock, SOL_IP, IPT_SO_GET_INFO, info)


def _get_entries(sock, table_name, size, num_entries):
    header_size = ctypes.sizeof(IPTGetEntries)
    counters_size = num_entries * ctypes.sizeof(XTCounters)

    # The kernel may append xt_counters after the entry table. Allocate space
    # for those counters up front; otherwise IPT_SO_GET_ENTRIES can fail with
    # ENOMEM if info.size does not account for the counters region.
    buf = ctypes.create_string_buffer(header_size + size + counters_size)
    entries = IPTGetEntries.from_buffer(buf)
    entries.name = table_name
    entries.size = size

    buflen = ctypes.c_uint(len(buf))
    ret = libc.getsockopt(sock.fileno(), SOL_IP, IPT_SO_GET_ENTRIES, ctypes.byref(entries), ctypes.byref(buflen))
    if ret != 0:
        errno = ctypes.get_errno()
        # If we somehow still sized the buffer too small, retry with the size
        # requested by the kernel (stored in entries.size).
        if errno == ENOMEM and entries.size > size:
            return _get_entries(sock, table_name, entries.size, num_entries)
        raise OSError(errno, os.strerror(errno))

    return bytes(buf)[header_size:header_size + size]


def _ipv4(addr):
    return ipaddress.IPv4Address(socket.ntohl(addr))


def _format_cidr(addr, mask):
    if mask == 0:
        return "any"

    try:
        prefix = ipaddress.IPv4Network((int(_ipv4(addr)), int(_ipv4(mask))), strict=False).prefixlen
        return f"{_ipv4(addr)}/{prefix}"
    except ValueError:
        return f"{_ipv4(addr)} mask {_ipv4(mask)}"


def _format_iface(name_bytes, mask_bytes):
    mask = bytes(mask_bytes)
    if not any(mask):
        return "any"

    name = bytes(name_bytes).split(b"\0", 1)[0].decode(errors="replace")
    if all(b == 0xFF for b in mask):
        return name or "any"

    return f"{name or 'any'} (mask {mask.hex()})"


def _format_proto(proto):
    if proto == 0:
        return "any"

    common = {
        1: "icmp",
        6: "tcp",
        17: "udp",
    }
    return common.get(proto, str(proto))


def _decode_entries(raw_entries, info):
    hook_names = {
        0: "PREROUTING",
        1: "LOCAL_IN",
        2: "FORWARD",
        3: "LOCAL_OUT",
        4: "POSTROUTING",
    }

    hook_offsets = {info.hook_entry[i]: hook_names[i] for i in range(NF_IP_NUMHOOKS) if info.valid_hooks & (1 << i)}
    underflows = {info.underflow[i]: hook_names[i] for i in range(NF_IP_NUMHOOKS) if info.valid_hooks & (1 << i)}

    readable = []
    offset = 0
    index = 0

    while offset < len(raw_entries):
        entry = IPTEntry.from_buffer_copy(raw_entries[offset:])

        if entry.next_offset == 0:
            readable.append(f"{offset:04x}: malformed entry with next_offset=0")
            break

        target_offset = offset + entry.target_offset
        target = XTEntryTarget.from_buffer_copy(raw_entries[target_offset:])
        target_name = bytes(target.name).split(b"\0", 1)[0].decode(errors="replace")

        if offset in hook_offsets:
            readable.append(f"[{hook_offsets[offset]} chain]")

        src = _format_cidr(entry.ip.src, entry.ip.smsk)
        dst = _format_cidr(entry.ip.dst, entry.ip.dmsk)
        proto = _format_proto(entry.ip.proto)
        iniface = _format_iface(entry.ip.iniface, entry.ip.iniface_mask)
        outiface = _format_iface(entry.ip.outiface, entry.ip.outiface_mask)

        readable.append(
            f"{index:02d} @ {offset:04x}: src {src} dst {dst} proto {proto} in {iniface} out {outiface} -> {target_name}"
        )

        if offset in underflows:
            readable.append(f"[{underflows[offset]} underflow]")

        offset += entry.next_offset
        index += 1

    return readable


def _hexdump(data, width=16):
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{offset:08x}: {hex_bytes}")
    return "\n".join(lines) if lines else "<empty>"


def dump_table(sock, table):
    table_bytes = table.encode()
    try:
        info = _get_info(sock, table_bytes)
    except OSError as e:
        print(f"{table}: failed to get info: {e}")
        return

    print(f"{table}: entries={info.num_entries}, bytes={info.size}")

    try:
        raw_entries = _get_entries(sock, table_bytes, info.size, info.num_entries)
    except OSError as e:
        print(f"{table}: failed to get entries: {e}")
        return

    for line in _decode_entries(raw_entries, info):
        print(line)

    print("\nRaw entries:")
    print(_hexdump(raw_entries))
    print()


def main():
    tables = ["nat", "filter", "mangle", "raw", "security"]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        for table in tables:
            dump_table(sock, table)


if __name__ == "__main__":
    main()
