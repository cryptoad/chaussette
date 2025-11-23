#!/usr/bin/env python3
"""Dump IPv4 and IPv6 iptables rules using IPT_SO_GET_INFO/ENTRIES.

This script must run inside a gVisor container started with --net-raw so that
raw sockets can issue the iptables getsockopt calls. It prints each table and
chain along with decoded rule criteria, counters, and targets.
"""
import ctypes
import ipaddress
import os
import socket
import struct
from typing import Dict, Iterable, List, Optional, Tuple

# Constants shared between IPv4 and IPv6.
XT_EXTENSION_MAXNAMELEN = 29
XT_TABLE_MAXNAMELEN = 32
NF_INET_NUMHOOKS = 5

# Socket options.
IPT_SO_GET_INFO = 64
IPT_SO_GET_ENTRIES = 65
IP6T_SO_GET_INFO = 64
IP6T_SO_GET_ENTRIES = 65

# Entry sizes taken from pkg/abi/linux/netfilter*.go.
SIZE_OF_IPT_ENTRY = 112
SIZE_OF_IP6T_ENTRY = 168

# Structure formats.
IPT_GETINFO_FMT = "<32sI5I5III"
IPT_GETINFO_SIZE = struct.calcsize(IPT_GETINFO_FMT)
IPT_GETENTRIES_HDR_FMT = "<32sI"
IPT_GETENTRIES_HDR_SIZE = struct.calcsize(IPT_GETENTRIES_HDR_FMT)

# Standard verdict mapping mirrors pkg/abi/linux/netfilter.go.
STANDARD_VERDICTS = {
    -1: "DROP",  # -NF_DROP - 1
    -2: "ACCEPT",  # -NF_ACCEPT - 1
    -4: "QUEUE",  # -NF_QUEUE - 1
    -5: "RETURN",  # NF_RETURN
}

HOOK_NAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

libc = ctypes.CDLL(None)
libc.getsockopt.argtypes = [
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint),
]


def _raw_getsockopt(sock: socket.socket, level: int, optname: int, buffer: bytearray) -> bytes:
    """Invoke getsockopt with an input/output buffer."""
    length = ctypes.c_uint(len(buffer))
    buf = (ctypes.c_char * len(buffer)).from_buffer(buffer)
    res = libc.getsockopt(sock.fileno(), level, optname, buf, ctypes.byref(length))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return bytes(buf[: length.value])


def _read_table_names(path: str) -> List[str]:
    """Return all table names from /proc."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def _decode_ip(addr: bytes, mask: bytes) -> str:
    """Format an IP address and mask as CIDR, or 'any'."""
    if len(addr) == 4:
        ip = ipaddress.IPv4Address(addr)
    else:
        ip = ipaddress.IPv6Address(addr)
    if all(b == 0 for b in mask):
        return "any"
    prefix = sum(bin(b).count("1") for b in mask)
    return f"{ip}/{prefix}"


def _decode_iface(name: bytes, mask: bytes) -> str:
    """Decode an interface name plus mask used by iptables."""
    if all(b == 0 for b in mask):
        return "*"
    base = name.split(b"\0", 1)[0].decode(errors="ignore")
    if all(b == 0xFF for b in mask):
        return base or "*"
    # Show wildcarded characters where the mask is not 0xFF.
    padded = base.ljust(len(mask), "?")
    return "".join(ch if m == 0xFF else "?" for ch, m in zip(padded, mask)).rstrip("?")


def _parse_target(target: bytes) -> str:
    """Return a human readable description of a target blob."""
    if len(target) < 2:
        return "<invalid>"
    target_size = struct.unpack_from("<H", target, 0)[0]
    name_bytes = target[2 : 2 + XT_EXTENSION_MAXNAMELEN]
    name = name_bytes.split(b"\0", 1)[0].decode(errors="ignore")
    payload = target[32:target_size]
    if not name:
        if len(payload) >= 4:
            verdict = struct.unpack_from("<i", payload, 0)[0]
            if verdict in STANDARD_VERDICTS:
                return STANDARD_VERDICTS[verdict]
            return f"JUMP offset {verdict}"
        return "standard"
    if payload:
        return f"{name} (rev {target[2 + XT_EXTENSION_MAXNAMELEN]})"
    return name


def _iter_entries(data: bytes, entry_size: int) -> Iterable[Tuple[int, Dict[str, object]]]:
    """Yield (offset, entry) pairs from a get_entries blob."""
    offset = 0
    while offset + entry_size <= len(data):
        entry_data = data[offset:]
        if entry_size == SIZE_OF_IPT_ENTRY:
            unpacked = struct.unpack_from(
                "<4s4s4s4s16s16s16s16sHBBIHHIQQ", entry_data, 0
            )
            ip_fields = unpacked[:10]
            proto = ip_fields[8]
            flags = ip_fields[9]
            invflags = unpacked[10]
            nfcache, target_offset, next_offset, _, packets, bytes_ = unpacked[11:]
        else:
            unpacked = struct.unpack_from(
                "<16s16s16s16s16s16s16s16sHBBB3xIHHI4xQQ", entry_data, 0
            )
            ip_fields = unpacked[:10]
            proto = ip_fields[8]
            flags = ip_fields[9]
            invflags = unpacked[10]
            nfcache, target_offset, next_offset, _, packets, bytes_ = unpacked[11:]
        target = entry_data[target_offset:next_offset]
        yield (
            offset,
            {
                "src": ip_fields[0],
                "dst": ip_fields[1],
                "src_mask": ip_fields[2],
                "dst_mask": ip_fields[3],
                "in_iface": ip_fields[4],
                "out_iface": ip_fields[5],
                "in_iface_mask": ip_fields[6],
                "out_iface_mask": ip_fields[7],
                "proto": proto,
                "flags": flags,
                "invflags": invflags,
                "target": target,
                "match_len": max(0, target_offset - entry_size),
                "packets": packets,
                "bytes": bytes_,
                "next_offset": next_offset,
            },
        )
        if next_offset <= 0:
            break
        offset += next_offset


def _format_entry(entry: Dict[str, object], ipv6: bool) -> str:
    """Pretty print a single entry."""
    src = _decode_ip(entry["src"], entry["src_mask"])
    dst = _decode_ip(entry["dst"], entry["dst_mask"])
    in_if = _decode_iface(entry["in_iface"], entry["in_iface_mask"])
    out_if = _decode_iface(entry["out_iface"], entry["out_iface_mask"])
    proto = entry["proto"]
    proto_str = "any" if proto == 0 else str(proto)
    target_desc = _parse_target(entry["target"])
    match_len = entry["match_len"]
    pieces = [
        f"src {src}",
        f"dst {dst}",
        f"in {in_if}",
        f"out {out_if}",
        f"proto {proto_str}",
        f"target {target_desc}",
    ]
    if match_len:
        pieces.append(f"matches {match_len}B")
    pieces.append(f"packets {entry['packets']}")
    pieces.append(f"bytes {entry['bytes']}")
    return ", ".join(pieces)


def _dump_table(sock: socket.socket, level: int, opt_info: int, opt_entries: int, name: str, ipv6: bool) -> None:
    """Fetch and print all rules for a single table."""
    info_buf = bytearray(IPT_GETINFO_SIZE)
    name_bytes = name.encode()
    info_buf[: len(name_bytes)] = name_bytes
    info_raw = _raw_getsockopt(sock, level, opt_info, info_buf)
    info = struct.unpack(IPT_GETINFO_FMT, info_raw)
    valid_hooks = info[1]
    hook_entry = list(info[2:7])
    underflow = list(info[7:12])
    num_entries = info[12]
    size = info[13]

    entries_buf = bytearray(IPT_GETENTRIES_HDR_SIZE + size)
    struct.pack_into(IPT_GETENTRIES_HDR_FMT, entries_buf, 0, name_bytes, size)
    entries_raw = _raw_getsockopt(sock, level, opt_entries, entries_buf)
    entries = entries_raw[IPT_GETENTRIES_HDR_SIZE:]

    hook_offsets = {}
    underflow_offsets = {}
    for idx, hook_name in enumerate(HOOK_NAMES):
        if valid_hooks & (1 << idx):
            hook_offsets.setdefault(hook_entry[idx], []).append(hook_name)
            underflow_offsets.setdefault(underflow[idx], []).append(hook_name)

    print(f"Table {name} ({'IPv6' if ipv6 else 'IPv4'})")
    print(f"  Entries: {num_entries}, Size: {size} bytes")
    for offset, entry in _iter_entries(entries, SIZE_OF_IP6T_ENTRY if ipv6 else SIZE_OF_IPT_ENTRY):
        if offset in hook_offsets:
            chain_name = "/".join(hook_offsets[offset])
            print(f"\nChain {chain_name} (offset {offset})")
        line = _format_entry(entry, ipv6)
        prefix = f"  [{offset:05d}] "
        print(prefix + line)
        if offset in underflow_offsets:
            policy = _parse_target(entry["target"])
            print(f"    Policy for {','.join(underflow_offsets[offset])}: {policy}")
    print()


def main() -> None:
    families = [
        (
            socket.AF_INET,
            socket.SOL_IP,
            IPT_SO_GET_INFO,
            IPT_SO_GET_ENTRIES,
            "/proc/net/ip_tables_names",
            False,
        ),
        (
            socket.AF_INET6,
            socket.SOL_IPV6,
            IP6T_SO_GET_INFO,
            IP6T_SO_GET_ENTRIES,
            "/proc/net/ip6_tables_names",
            True,
        ),
    ]

    for family, level, opt_info, opt_entries, name_file, ipv6 in families:
        tables = _read_table_names(name_file)
        if not tables:
            continue
        with socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
            for table in tables:
                _dump_table(sock, level, opt_info, opt_entries, table, ipv6)


if __name__ == "__main__":
    main()
