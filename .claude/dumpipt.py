#!/usr/bin/env python3
import socket
import ctypes
import os
import struct

# --------------------------------------------------------------------
# Constants (from linux/netfilter_ipv4/ip_tables.h / x_tables.h)
# --------------------------------------------------------------------

SOL_IP = socket.SOL_IP

IPT_BASE_CTL = 64
IPT_SO_GET_INFO    = IPT_BASE_CTL          # 64
IPT_SO_GET_ENTRIES = IPT_BASE_CTL + 1      # 65

XT_TABLE_MAXNAMELEN      = 32
XT_EXTENSION_MAXNAMELEN  = 29
NF_IP_NUMHOOKS           = 5
IFNAMSIZ                 = 16

HOOK_NAMES_BY_TABLE = {
    "filter": {
        1: "INPUT",
        2: "FORWARD",
        3: "OUTPUT",
    },
    "nat": {
        0: "PREROUTING",
        1: "INPUT",
        3: "OUTPUT",
        4: "POSTROUTING",
    },
    "mangle": {
        0: "PREROUTING",
        1: "INPUT",
        2: "FORWARD",
        3: "OUTPUT",
        4: "POSTROUTING",
    },
    "raw": {
        0: "PREROUTING",
        3: "OUTPUT",
    },
}

# --------------------------------------------------------------------
# Structures – match kernel layout
# --------------------------------------------------------------------

class IPTGetinfo(ctypes.Structure):
    _fields_ = [
        ("name",        ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry",  ctypes.c_uint * NF_IP_NUMHOOKS),
        ("underflow",   ctypes.c_uint * NF_IP_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size",        ctypes.c_uint),
    ]

class IPTGetEntries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        # ipt_entry[] follows
    ]

class IptIp(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_uint32),
        ("dst", ctypes.c_uint32),
        ("smsk", ctypes.c_uint32),
        ("dmsk", ctypes.c_uint32),
        ("iniface", ctypes.c_char * IFNAMSIZ),
        ("iniface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("outiface", ctypes.c_char * IFNAMSIZ),
        ("outiface_mask", ctypes.c_ubyte * IFNAMSIZ),
        ("proto", ctypes.c_uint16),
        ("flags", ctypes.c_uint8),
        ("invflags", ctypes.c_uint8),
    ]

class XtCounters(ctypes.Structure):
    _fields_ = [
        ("pcnt", ctypes.c_uint64),
        ("bcnt", ctypes.c_uint64),
    ]

class IptEntry(ctypes.Structure):
    _fields_ = [
        ("ip", IptIp),
        ("nfcache", ctypes.c_uint),
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint),
        ("counters", XtCounters),
        # followed by matches + target
    ]

IPT_ENTRY_SIZE = ctypes.sizeof(IptEntry)

# --------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------

def ntoa(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def proto_name(p):
    if p == 0:
        return "any"
    if p == 1:
        return "icmp"
    if p == 6:
        return "tcp"
    if p == 17:
        return "udp"
    return str(p)

def clean_c_string(arr):
    raw = bytes(arr)
    return raw.split(b"\x00", 1)[0].decode(errors="ignore")

# --------------------------------------------------------------------
# Kernel calls – EXACTLY modeled on your PoC
# --------------------------------------------------------------------

def get_table_info(sock, table):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    info = IPTGetinfo()
    info.name = table.encode()  # <-- exactly like your PoC
    buf_len = ctypes.c_uint(ctypes.sizeof(info))

    rc = libc.getsockopt(
        sock.fileno(),
        SOL_IP,
        IPT_SO_GET_INFO,
        ctypes.byref(info),
        ctypes.byref(buf_len),
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"IPT_SO_GET_INFO failed: {os.strerror(err)}")

    return info


def get_table_entries(sock, table, size):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    hdr = IPTGetEntries()
    hdr.name = table.encode()
    hdr.size = size

    total = ctypes.sizeof(IPTGetEntries) + size
    buf = ctypes.create_string_buffer(total)
    ctypes.memmove(buf, ctypes.byref(hdr), ctypes.sizeof(hdr))

    buf_len = ctypes.c_uint(total)

    rc = libc.getsockopt(
        sock.fileno(),
        SOL_IP,
        IPT_SO_GET_ENTRIES,
        buf,
        ctypes.byref(buf_len),
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"IPT_SO_GET_ENTRIES failed: {os.strerror(err)}")

    return buf.raw[:buf_len.value]

# --------------------------------------------------------------------
# Decoding: matches and target
# --------------------------------------------------------------------

def decode_matches(blob, start, end, indent):
    pos = start
    while pos + 32 <= end:
        try:
            match_size = struct.unpack_from("H", blob, pos)[0]
        except struct.error:
            return
        if match_size == 0 or pos + match_size > end:
            return
        # struct xt_entry_match.user:
        #   __u16 match_size;
        #   char name[29];
        #   __u8 revision;
        _, name_bytes, rev = struct.unpack_from("H29sB", blob, pos)
        mname = name_bytes.split(b"\x00", 1)[0].decode(errors="ignore")
        print(indent + f"match {mname} (size={match_size}, rev={rev})")
        pos += match_size

def decode_target(blob, off, indent):
    if off + 32 > len(blob):
        print(indent + "target: <truncated>")
        return

    target_size, = struct.unpack_from("H", blob, off)
    if target_size < 32 or off + target_size > len(blob):
        print(indent + f"target: <invalid size {target_size}>")
        return

    _, name_bytes, rev = struct.unpack_from("H29sB", blob, off)
    tname = name_bytes.split(b"\x00", 1)[0].decode(errors="ignore")
    print(indent + f"target {tname} (size={target_size}, rev={rev})")

    # standard target: first 4 bytes of data is an int verdict
    if tname == "standard" and target_size >= 36:
        verdict, = struct.unpack_from("i", blob, off + 32)
        print(indent + f"  verdict raw = {verdict}")

# --------------------------------------------------------------------
# Rule + chain decoding
# --------------------------------------------------------------------

def build_offset_to_chain(info, table):
    hooks = HOOK_NAMES_BY_TABLE.get(table, {})
    mp = {}
    for hook_idx in range(NF_IP_NUMHOOKS):
        off = info.hook_entry[hook_idx]
        if off == 0 and hook_idx not in hooks:
            continue
        name = hooks.get(hook_idx, f"HOOK{hook_idx}")
        mp[off] = name
    return mp

def decode_entry(blob, off, idx):
    if off + IPT_ENTRY_SIZE > len(blob):
        print("  [!] truncated entry")
        return None

    entry = IptEntry.from_buffer_copy(blob, off)
    ip = entry.ip

    src = ntoa(ip.src)
    dst = ntoa(ip.dst)
    sm = ntoa(ip.smsg) if hasattr(ip, "smsg") else ntoa(ip.smsk)  # guard in case of typo
    dm = ntoa(ip.dmsg) if hasattr(ip, "dmsg") else ntoa(ip.dmsk)

    inif = clean_c_string(ip.iniface)
    outif = clean_c_string(ip.outiface)

    proto = proto_name(ip.proto)

    print(f"Rule #{idx}: offset={off}, next={entry.next_offset}, target_off={entry.target_offset}")
    print(f"    src={src}/{sm}  dst={dst}/{dm}")
    print(f"    in={inif or '*'}  out={outif or '*'}  proto={proto}")
    print(f"    counters: pkts={entry.counters.pcnt} bytes={entry.counters.bcnt}")

    matches_start = off + IPT_ENTRY_SIZE
    target_start  = off + entry.target_offset

    if matches_start < target_start:
        print("    matches:")
        decode_matches(blob, matches_start, target_start, "        ")
    else:
        print("    matches: none")

    print("    target:")
    decode_target(blob, target_start, "        ")

    return entry.next_offset

def walk_entries(blob, info, table):
    header_size = ctypes.sizeof(IPTGetEntries)
    end = len(blob)
    off = header_size

    offset_to_chain = build_offset_to_chain(info, table)

    idx = 0
    while off + 4 <= end:
        rel_off = off - header_size
        if rel_off in offset_to_chain:
            cname = offset_to_chain[rel_off]
            print("")
            print(f"=== Chain {cname} (offset {rel_off}) ===")

        next_off = decode_entry(blob, off, idx)
        if not next_off:
            break

        off += next_off
        idx += 1

        if off >= end:
            break

# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------

def main():
    table = "nat"   # or "filter", "mangle", "raw", "security"

    # Use the same kind of socket as your PoC
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        print(f"[+] Querying table '{table}'")

        try:
            info = get_table_info(s, table)
        except OSError as e:
            print("[-] IPT_SO_GET_INFO error:", e)
            return

        raw_name = bytes(info.name)
        tname = raw_name.split(b"\x00", 1)[0].decode(errors="ignore")

        print("Table name:", tname)
        print("Entries:", info.num_entries)
        print("Size:", info.size)
        print("Hook entry offsets:", list(info.hook_entry))
        print("Underflow offsets:", list(info.underflow))

        try:
            blob = get_table_entries(s, table, info.size)
        except OSError as e:
            print("[-] IPT_SO_GET_ENTRIES error:", e)
            return

    print("\n[+] Decoding entries:\n")
    walk_entries(blob, info, table)


if __name__ == "__main__":
    main()
