#!/usr/bin/env python3
"""Dump iptables/ip6tables rules via kernel GET_INFO/GET_ENTRIES calls.

The script mirrors the logic of iptables-save, but only relies on the raw
kernel socket API exposed by gVisor when launched with `--net-raw`. It queries
both IPv4 and IPv6 tables using IPT_SO_GET_INFO / IPT_SO_GET_ENTRIES (and their
IPv6 counterparts) and prints every chain with its rules in a readable format.
"""

import errno
import ipaddress
import os
import socket
import struct
import sys
import ctypes
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


# Constants from linux headers (uapi).
XT_TABLE_MAXNAMELEN = 32
XT_EXTENSION_MAXNAMELEN = 29
IFNAMSIZ = 16
NF_INET_NUMHOOKS = 5

# Socket option numbers for iptables (ipv4/ipv6 share the same values).
IPT_BASE_CTL = 64
IPT_SO_GET_INFO = IPT_BASE_CTL
IPT_SO_GET_ENTRIES = IPT_BASE_CTL + 1

HOOK_NAMES = ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]

TABLES = ["filter", "nat", "mangle", "raw", "security"]


libc = ctypes.CDLL(None, use_errno=True)


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
    ]


@dataclass
class Rule:
    chain: str
    description: str
    matches: List[str]
    target: str
    packets: int
    bytes: int


def _getsockopt(fd: int, level: int, opt: int, buf: ctypes.Array) -> None:
    """Invoke libc getsockopt with the provided buffer.

    Python's socket.getsockopt cannot pass input buffers, so we delegate to
    libc to preserve the in/out semantics required by iptables.
    """

    optlen = ctypes.c_uint(ctypes.sizeof(buf))
    res = libc.getsockopt(fd, level, opt, ctypes.byref(buf), ctypes.byref(optlen))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _align8(size: int) -> int:
    return (size + 7) & ~7


def _format_ipv4(addr: int, mask: int, invert: bool) -> str:
    network = ipaddress.IPv4Network((addr, mask), strict=False)
    prefix = "! " if invert else ""
    return f"{prefix}{network.with_prefixlen}"


def _format_ipv6(addr: bytes, mask: bytes, invert: bool) -> str:
    network = ipaddress.IPv6Network((addr, mask), strict=False)
    prefix = "! " if invert else ""
    return f"{prefix}{network.with_prefixlen}"


def _decode_matches(data: memoryview, start: int, end: int) -> List[str]:
    matches = []
    pos = start
    while pos < end:
        match_size, raw_name, revision = struct.unpack_from("=H29sB", data, pos)
        name = raw_name.split(b"\0", 1)[0].decode() or "(unknown)"
        matches.append(f"{name}(rev {revision})")
        pos += _align8(match_size)
    return matches


def _decode_target(data: memoryview, offset: int) -> str:
    target_size, raw_name, revision = struct.unpack_from("=H29sB", data, offset)
    name = raw_name.split(b"\0", 1)[0].decode() or "(unknown)"
    return f"{name}(rev {revision})"


def _parse_ipv4_entries(blob: bytes, chain_map: Dict[int, str], end_map: Dict[str, int]) -> List[Rule]:
    fmt = struct.Struct("=4I16s16s16s16sHBBIHHIQQ")
    data = memoryview(blob)
    rules: List[Rule] = []
    offset = 0
    current_chain: Optional[str] = None
    current_end: Optional[int] = None

    while offset < len(blob):
        if offset in chain_map:
            current_chain = chain_map[offset]
            current_end = end_map.get(current_chain)

        (
            src,
            dst,
            smsk,
            dmsk,
            iniface,
            iniface_mask,
            outiface,
            outiface_mask,
            proto,
            flags,
            invflags,
            nfcache,
            target_offset,
            next_offset,
            comefrom,
            pcnt,
            bcnt,
        ) = fmt.unpack_from(data, offset)

        chain = current_chain or "(unknown)"
        matches = _decode_matches(data, offset + fmt.size, offset + target_offset)
        target = _decode_target(data, offset + target_offset)

        src_str = _format_ipv4(src, smsk, bool(invflags & 0x08))
        dst_str = _format_ipv4(dst, dmsk, bool(invflags & 0x10))
        proto_desc = f"proto {proto}" if proto else "proto any"
        rule_desc = f"{src_str} -> {dst_str} ({proto_desc})"

        rules.append(
            Rule(
                chain=chain,
                description=rule_desc,
                matches=matches,
                target=target,
                packets=pcnt,
                bytes=bcnt,
            )
        )

        offset += next_offset
        if current_chain and current_end is not None and offset > current_end:
            current_chain = None
            current_end = None

    return rules


def _parse_ipv6_entries(blob: bytes, chain_map: Dict[int, str], end_map: Dict[str, int]) -> List[Rule]:
    fmt = struct.Struct("=16s16s16s16s16s16s16s16sHBBBxxxIHHIQQ")
    data = memoryview(blob)
    rules: List[Rule] = []
    offset = 0
    current_chain: Optional[str] = None
    current_end: Optional[int] = None

    while offset < len(blob):
        if offset in chain_map:
            current_chain = chain_map[offset]
            current_end = end_map.get(current_chain)

        (
            src,
            dst,
            smsk,
            dmsk,
            iniface,
            outiface,
            iniface_mask,
            outiface_mask,
            proto,
            tos,
            flags,
            invflags,
            nfcache,
            target_offset,
            next_offset,
            comefrom,
            pcnt,
            bcnt,
        ) = fmt.unpack_from(data, offset)

        chain = current_chain or "(unknown)"
        matches = _decode_matches(data, offset + fmt.size, offset + target_offset)
        target = _decode_target(data, offset + target_offset)

        src_str = _format_ipv6(src, smsk, bool(invflags & 0x08))
        dst_str = _format_ipv6(dst, dmsk, bool(invflags & 0x10))
        proto_desc = f"proto {proto}" if proto else "proto any"
        rule_desc = f"{src_str} -> {dst_str} ({proto_desc})"

        rules.append(
            Rule(
                chain=chain,
                description=rule_desc,
                matches=matches,
                target=target,
                packets=pcnt,
                bytes=bcnt,
            )
        )

        offset += next_offset
        if current_chain and current_end is not None and offset > current_end:
            current_chain = None
            current_end = None

    return rules


def _chain_maps(valid_hooks: int, hook_entry: Iterable[int], underflow: Iterable[int]) -> (Dict[int, str], Dict[str, int]):
    starts: Dict[int, str] = {}
    ends: Dict[str, int] = {}
    for idx, name in enumerate(HOOK_NAMES):
        if valid_hooks & (1 << idx):
            starts[hook_entry[idx]] = name
            ends[name] = underflow[idx]
    return starts, ends


def _dump_family(family_name: str, af: int, level: int) -> None:
    print(f"=== {family_name} ===")
    with socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        fd = sock.fileno()
        for table in TABLES:
            info = IPTGetinfo()
            info.name = table.encode()
            try:
                _getsockopt(fd, level, IPT_SO_GET_INFO, info)
            except OSError as exc:
                if exc.errno not in (errno.EPERM, errno.ENOENT, errno.EINVAL):
                    print(f"[WARN] table {table}: {exc}")
                continue

            if info.num_entries == 0:
                print(f"Table {table}: (empty)")
                continue

            entries_buf = (ctypes.c_ubyte * (ctypes.sizeof(IPTGetEntries) + info.size))()
            entries = IPTGetEntries.from_buffer(entries_buf)
            entries.name = table.encode()
            entries.size = info.size
            _getsockopt(fd, level, IPT_SO_GET_ENTRIES, entries)

            blob = bytes(entries_buf)[ctypes.sizeof(IPTGetEntries) : ctypes.sizeof(IPTGetEntries) + info.size]
            starts, ends = _chain_maps(info.valid_hooks, info.hook_entry, info.underflow)

            parser = _parse_ipv4_entries if af == socket.AF_INET else _parse_ipv6_entries
            rules = parser(blob, starts, ends)

            print(f"Table {table}:")
            for rule in rules:
                match_desc = ", ".join(rule.matches) if rule.matches else "(no matches)"
                print(
                    f"  Chain {rule.chain}: {rule.description}\n"
                    f"    target: {rule.target}\n"
                    f"    matches: {match_desc}\n"
                    f"    counters: {rule.packets} packets / {rule.bytes} bytes"
                )
    print()


def main() -> int:
    try:
        _dump_family("IPv4", socket.AF_INET, socket.SOL_IP)
        _dump_family("IPv6", socket.AF_INET6, socket.SOL_IPV6)
    except PermissionError:
        print("This tool must run with --net-raw or equivalent CAP_NET_RAW privileges.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
