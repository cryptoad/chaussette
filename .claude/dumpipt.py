#!/usr/bin/env python3
import ctypes
import os
import socket
from errno import ENOMEM
import struct

SOL_IP = socket.SOL_IP
IPT_SO_GET_INFO = 64
IPT_SO_GET_ENTRIES = IPT_SO_GET_INFO + 1
XT_TABLE_MAXNAMELEN = 32
NF_IP_NUMHOOKS = 5

# iptables structures ---------------------------------------------------------

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

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# ---------------------------------------------------------------------------

def _getsockopt(sock, level, optname, optval):
    buflen = ctypes.c_uint(ctypes.sizeof(optval))
    if libc.getsockopt(sock.fileno(), level, optname,
                       ctypes.byref(optval), ctypes.byref(buflen)) != 0:
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

    buf = ctypes.create_string_buffer(header_size + size + counters_size)
    entries = IPTGetEntries.from_buffer(buf)
    entries.name = table_name
    entries.size = size

    buflen = ctypes.c_uint(len(buf))
    if libc.getsockopt(sock.fileno(), SOL_IP, IPT_SO_GET_ENTRIES,
                       ctypes.byref(entries), ctypes.byref(buflen)) != 0:
        errno = ctypes.get_errno()
        if errno == ENOMEM and entries.size > size:
            return _get_entries(sock, table_name, entries.size, num_entries)
        raise OSError(errno, os.strerror(errno))

    return bytes(buf)[header_size:header_size + size]

# ---------------------------------------------------------------------------
# Human-readable parsers
# ---------------------------------------------------------------------------

IPT_ENTRY_FMT = "IIIIIIII"  # struct ipt_entry without matches/target
IPT_ENTRY_FIXED_SIZE = struct.calcsize(IPT_ENTRY_FMT)

XT_ENTRY_TARGET_FMT = "HH"  # target header
XT_ENTRY_TARGET_SIZE = struct.calcsize(XT_ENTRY_TARGET_FMT)

def parse_ip(entry):
    """Return human-readable ip source/destination info."""
    src, dst, smask, dmask, proto = struct.unpack("4s4sIIII", entry[:24])[0:5]
    s = socket.inet_ntoa(src)
    d = socket.inet_ntoa(dst)
    return f"{s}/{smask} -> {d}/{dmask}, proto={proto}"

def parse_tcp_match(data):
    try:
        # struct xt_tcp
        # u_int16_t spts[2], dpts[2]; u_int8_t options, flg_mask, flg_cmp, invflags
        spt_min, spt_max, dpt_min, dpt_max, opts, mask, cmp_, inv = struct.unpack(
            "!HHHHBBBB", data[:12]
        )
        return f"tcp sport {spt_min}-{spt_max} dport {dpt_min}-{dpt_max}"
    except:
        return "<tcp match unreadable>"

def parse_udp_match(data):
    try:
        spt_min, spt_max, dpt_min, dpt_max = struct.unpack("!HHHH", data[:8])
        return f"udp sport {spt_min}-{spt_max} dport {dpt_min}-{dpt_max}"
    except:
        return "<udp match unreadable>"

def parse_icmp_match(data):
    try:
        icmp_type, icmp_code = struct.unpack("!BB", data[:2])
        return f"icmp type={icmp_type} code={icmp_code}"
    except:
        return "<icmp match unreadable>"

def parse_target(name, data):
    name = name.decode().strip("\x00")
    if name == "ACCEPT":
        return "ACCEPT"
    if name == "DROP":
        return "DROP"
    if name == "RETURN":
        return "RETURN"
    if name == "DNAT":
        # struct xt_nat_tginfo
        try:
            ip = socket.inet_ntoa(data[0:4])
            port = struct.unpack("!H", data[4:6])[0]
            return f"DNAT to {ip}:{port}"
        except:
            pass
    if name == "SNAT":
        try:
            ip = socket.inet_ntoa(data[0:4])
            port = struct.unpack("!H", data[4:6])[0]
            return f"SNAT to {ip}:{port}"
        except:
            pass
    return f"{name} (raw: {data.hex()})"

# ---------------------------------------------------------------------------

def decode_entries(raw):
    """Decode all ipt_entry records from the raw buffer."""
    pos = 0
    rules = []
    total = len(raw)

    while pos < total:
        # Read struct ipt_entry header
        header = raw[pos:pos + IPT_ENTRY_FIXED_SIZE]
        if len(header) < IPT_ENTRY_FIXED_SIZE:
            break

        fields = struct.unpack(IPT_ENTRY_FMT, header)
        target_offset = fields[6]
        next_offset = fields[7]

        entry_block = raw[pos:pos + next_offset]
        ip_part = entry_block[:IPT_ENTRY_FIXED_SIZE]

        matches_part = entry_block[IPT_ENTRY_FIXED_SIZE:target_offset]
        target_block = entry_block[target_offset:next_offset]

        # Parse target header
        t_u16 = struct.unpack("HH", target_block[:4])
        t_size = t_u16[0]
        t_name = target_block[4:36]

        t_data = target_block[36:t_size]

        rule_desc = []

        # IP part
        rule_desc.append(parse_ip(ip_part))

        # Matches
        mp = matches_part
        while len(mp) >= 4:
            m_size = struct.unpack("H", mp[:2])[0]
            m_name = mp[4:32].rstrip(b"\x00")
            payload = mp[32:m_size]
            name = m_name.decode()

            if name == "tcp":
                rule_desc.append(parse_tcp_match(payload))
            elif name == "udp":
                rule_desc.append(parse_udp_match(payload))
            elif name == "icmp":
                rule_desc.append(parse_icmp_match(payload))
            else:
                rule_desc.append(f"match {name}: {payload.hex()}")

            mp = mp[m_size:]

        # Target
        rule_desc.append("→ " + parse_target(t_name, t_data))

        rules.append("\n    ".join(rule_desc))
        pos += next_offset

    return rules


# ---------------------------------------------------------------------------

def dump_table(sock, table):
    table_bytes = table.encode()
    try:
        info = _get_info(sock, table_bytes)
    except OSError as e:
        print(f"{table}: failed to get info: {e}")
        return

    print(f"\n### TABLE {table.upper()} ###")
    print(f"{info.num_entries} entries, {info.size} bytes\n")

    try:
        raw_entries = _get_entries(sock, table_bytes, info.size, info.num_entries)
    except OSError as e:
        print(f"{table}: failed to get entries: {e}")
        return

    rules = decode_entries(raw_entries)
    if not rules:
        print("(empty)")
    else:
        for i, r in enumerate(rules, 1):
            print(f"Rule {i}:\n    {r}\n")

def main():
    tables = ["nat", "filter", "mangle", "raw", "security"]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        for table in tables:
            dump_table(sock, table)

if __name__ == "__main__":
    main()
