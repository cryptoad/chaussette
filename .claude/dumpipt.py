#!/usr/bin/env python3
"""
Dump IPv4/IPv6 iptables from a gVisor container using IPT_SO_GET_INFO/ENTRIES.

The tool opens RAW sockets (requires --net-raw) and walks the kernel tables
without external helpers. It mirrors the uapi structures with ``ctypes`` and
prints a readable, chain-oriented summary for every table that exists.
"""
from __future__ import annotations

import ctypes
import os
import socket
import struct
from typing import List, Mapping, MutableMapping, Sequence, Tuple

# Constants from <linux/netfilter*.h>.
XT_TABLE_MAXNAMELEN = 32
XT_EXTENSION_MAXNAMELEN = 29
XT_ALIGN = ctypes.alignment(
    type(
        "_xt_align",
        (ctypes.Structure,),
        {
            "_fields_": [
                ("u8", ctypes.c_uint8),
                ("u16", ctypes.c_uint16),
                ("u32", ctypes.c_uint32),
                ("u64", ctypes.c_uint64),
            ]
        },
    )
)

IPT_SO_GET_INFO = 64
IPT_SO_GET_ENTRIES = 65
IP6T_SO_GET_INFO = 64
IP6T_SO_GET_ENTRIES = 65

NF_INET_NUMHOOKS = 5
HOOK_NAMES = ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]

# ctypes definitions mirroring the kernel headers.


class IPTIP(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_uint32),
        ("dst", ctypes.c_uint32),
        ("smsk", ctypes.c_uint32),
        ("dmsk", ctypes.c_uint32),
        ("iniface", ctypes.c_char * socket.IFNAMSIZ),
        ("outiface", ctypes.c_char * socket.IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("invflags", ctypes.c_uint8),
    ]


class IP6TIP6(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_ubyte * 16),
        ("dst", ctypes.c_ubyte * 16),
        ("smsk", ctypes.c_ubyte * 16),
        ("dmsk", ctypes.c_ubyte * 16),
        ("iniface", ctypes.c_char * socket.IFNAMSIZ),
        ("outiface", ctypes.c_char * socket.IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * socket.IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("tos", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("invflags", ctypes.c_uint8),
    ]


class XtCounters(ctypes.Structure):
    _fields_ = [("pcnt", ctypes.c_uint64), ("bcnt", ctypes.c_uint64)]


class IPTEntryBase(ctypes.Structure):
    _fields_ = [
        ("ip", IPTIP),
        ("nfcache", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint32),
        ("counters", XtCounters),
    ]


class IP6TEntryBase(ctypes.Structure):
    _fields_ = [
        ("ip", IP6TIP6),
        ("nfcache", ctypes.c_uint32),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint32),
        ("counters", XtCounters),
    ]


class IPTGetInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint32),
        ("hook_entry", ctypes.c_uint32 * NF_INET_NUMHOOKS),
        ("underflow", ctypes.c_uint32 * NF_INET_NUMHOOKS),
        ("num_entries", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
    ]


class IPTGetEntries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
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


class XTErrorTarget(ctypes.Structure):
    _fields_ = [
        ("target", XTEntryTarget),
        ("errorname", ctypes.c_char * (XT_EXTENSION_MAXNAMELEN + 1)),
    ]


def _align(length: int) -> int:
    return (length + (XT_ALIGN - 1)) & ~(XT_ALIGN - 1)


def _inet_ntop4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def _inet_ntop6(raw: Sequence[int]) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(raw))


def _matches(entry_bytes: memoryview, target_offset: int) -> List[str]:
    results: List[str] = []
    offset = ctypes.sizeof(IPTEntryBase)
    while offset < target_offset:
        header = XTEntryMatch.from_buffer_copy(entry_bytes, offset)
        name = header.name.split(b"\0", 1)[0].decode() or "(standard)"
        results.append(name)
        offset += _align(header.match_size)
    return results


def _parse_target(entry_bytes: memoryview, target_offset: int) -> Tuple[str, str]:
    target = XTEntryTarget.from_buffer_copy(entry_bytes, target_offset)
    name = target.name.split(b"\0", 1)[0].decode()
    target_name = name or "standard"
    description = ""

    if name == "":
        std = XTStandardTarget.from_buffer_copy(entry_bytes, target_offset)
        verdict = std.verdict
        verdict_map = {
            -4: "RETURN",
            0: "DROP",
            1: "ACCEPT",
            3: "QUEUE",
            4: "REPEAT",
            5: "STOP",
        }
        description = verdict_map.get(verdict, f"JUMP {verdict}")
    elif name == "ERROR":
        err = XTErrorTarget.from_buffer_copy(entry_bytes, target_offset)
        error_name = err.errorname.split(b"\0", 1)[0].decode()
        description = f"error: {error_name}"
    return target_name, description


def _entry_ip_repr(ip: IPTIP, ipv6: bool) -> str:
    if ipv6:
        src = _inet_ntop6(ip.src)
        dst = _inet_ntop6(ip.dst)
        smsk = _inet_ntop6(ip.smsk)
        dmsk = _inet_ntop6(ip.dmsk)
    else:
        src = _inet_ntop4(ip.src)
        dst = _inet_ntop4(ip.dst)
        smsk = _inet_ntop4(ip.smsk)
        dmsk = _inet_ntop4(ip.dmsk)
    src_mask = f"{src}/{smsk}"
    dst_mask = f"{dst}/{dmsk}"
    proto = ip.proto
    return f"src {src_mask} dst {dst_mask} proto {proto}"


def _table_info(sock: socket.socket, level: int, opt: int, name: str) -> IPTGetInfo | None:
    req = IPTGetInfo()
    req.name = name.encode()
    try:
        data = ctypes.create_string_buffer(ctypes.sizeof(req))
        ctypes.memmove(data, ctypes.byref(req), ctypes.sizeof(req))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        optlen = ctypes.c_uint(ctypes.sizeof(data))
        if libc.getsockopt(sock.fileno(), level, opt, data, ctypes.byref(optlen)) != 0:
            return None
        ctypes.memmove(ctypes.byref(req), data, ctypes.sizeof(req))
        return req
    except OSError:
        return None


def _table_entries(sock: socket.socket, level: int, opt: int, name: str, size: int) -> bytes | None:
    header = IPTGetEntries()
    header.name = name.encode()
    header.size = size
    buffer_size = ctypes.sizeof(header) + size
    data = ctypes.create_string_buffer(buffer_size)
    ctypes.memmove(data, ctypes.byref(header), ctypes.sizeof(header))
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    optlen = ctypes.c_uint(buffer_size)
    if libc.getsockopt(sock.fileno(), level, opt, data, ctypes.byref(optlen)) != 0:
        return None
    return data.raw[: optlen.value]


def _chain_boundaries(
    info: IPTGetInfo, entries: bytes, entry_cls: type[IPTEntryBase]
) -> Mapping[int, str]:
    starts: MutableMapping[int, str] = {}
    for idx, offset in enumerate(info.hook_entry):
        if info.valid_hooks & (1 << idx):
            starts[offset] = HOOK_NAMES[idx]
    offset = 0
    data = memoryview(entries)
    size = info.size
    while offset < size:
        entry = entry_cls.from_buffer_copy(data, offset)
        target_name, desc = _parse_target(data[offset : offset + entry.next_offset], entry.target_offset)
        if target_name == "ERROR" and desc.startswith("error: "):
            starts[offset] = desc.split(": ", 1)[1]
        offset += entry.next_offset
    return dict(sorted(starts.items()))


def _dump_table(ipv6: bool, name: str):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    level = socket.IPPROTO_IPV6 if ipv6 else socket.SOL_IP
    info_opt = IP6T_SO_GET_INFO if ipv6 else IPT_SO_GET_INFO
    entries_opt = IP6T_SO_GET_ENTRIES if ipv6 else IPT_SO_GET_ENTRIES

    with socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        info = _table_info(sock, level, info_opt, name)
        if info is None:
            return
        entries = _table_entries(sock, level, entries_opt, name, info.size)
        if entries is None:
            return

    print(f"Table {name} ({'IPv6' if ipv6 else 'IPv4'})")
    entry_cls = IP6TEntryBase if ipv6 else IPTEntryBase
    boundaries = _chain_boundaries(
        info, entries[ctypes.sizeof(IPTGetEntries) :], entry_cls
    )
    data = memoryview(entries)[ctypes.sizeof(IPTGetEntries) :]

    offset = 0
    chain_indices = sorted(boundaries.keys()) + [info.size]
    chain_lookup = {o: boundaries[o] for o in boundaries}
    chain_idx = 0
    current_chain = chain_lookup.get(chain_indices[chain_idx], "?")
    chain_end = chain_indices[chain_idx + 1] if chain_idx + 1 < len(chain_indices) else info.size
    print(f" Chain {current_chain}")
    while offset < info.size:
        if offset >= chain_end and chain_idx + 1 < len(chain_indices) - 0:
            chain_idx += 1
            current_chain = chain_lookup.get(chain_indices[chain_idx], current_chain)
            chain_end = chain_indices[chain_idx + 1] if chain_idx + 1 < len(chain_indices) else info.size
            print(f" Chain {current_chain}")
        entry = entry_cls.from_buffer_copy(data, offset)
        entry_bytes = data[offset : offset + entry.next_offset]
        match_names = _matches(entry_bytes, entry.target_offset)
        target_name, target_desc = _parse_target(entry_bytes, entry.target_offset)
        ip_repr = _entry_ip_repr(entry.ip, ipv6)
        match_text = f" matches: {', '.join(match_names)}" if match_names else ""
        extra = f" ({target_desc})" if target_desc else ""
        print(
            f"  [offset {offset:04d}] {ip_repr}{match_text} -> {target_name}{extra}"
        )
        offset += entry.next_offset


TABLES = ["filter", "nat", "mangle", "raw", "security"]


def main():
    for ipv6 in (False, True):
        for table in TABLES:
            try:
                _dump_table(ipv6, table)
            except PermissionError:
                print(f"Skipping {table} {'IPv6' if ipv6 else 'IPv4'} (permissions)")
            except OSError as exc:
                if exc.errno in (socket.ENOPROTOOPT, getattr(socket, "EAFNOSUPPORT", 97)):
                    continue
                print(f"Failed to read {table} {'IPv6' if ipv6 else 'IPv4'}: {exc}")


if __name__ == "__main__":
    main()
