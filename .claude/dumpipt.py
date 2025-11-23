#!/usr/bin/env python3
import ctypes
import socket
import struct

IP_SO_GET_INFO = 65
IP_SO_GET_ENTRIES = 66

XT_TABLE_MAXNAMELEN = 32
NF_INET_NUMHOOKS = 5

# ---------------------------------------------------------
#   struct ipt_getinfo
# ---------------------------------------------------------

class ipt_getinfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]

# ---------------------------------------------------------
#   struct ipt_get_entries  (header only)
# ---------------------------------------------------------

class ipt_get_entries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        # followed by entries[]
    ]

# ---------------------------------------------------------

def get_table_info(name):
    """Return ipt_getinfo for the given table."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # kernel wants exactly sizeof(ipt_getinfo) bytes
    req = ctypes.create_string_buffer(ctypes.sizeof(ipt_getinfo))
    # copy table name
    ctypes.memmove(req, name.encode(), len(name))

    try:
        data = s.getsockopt(socket.IPPROTO_IP, IP_SO_GET_INFO, req)
    finally:
        s.close()

    return ipt_getinfo.from_buffer_copy(data)


def dump_table_entries(name, size):
    """Return raw iptables bytes for entries."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Build header for ipt_get_entries
    hdr = ipt_get_entries()
    hdr.name = name.encode()
    hdr.size = size

    hdr_buf = ctypes.string_buffer(ctypes.sizeof(hdr) + size)
    ctypes.memmove(hdr_buf, ctypes.addressof(hdr), ctypes.sizeof(hdr))

    try:
        raw = s.getsockopt(socket.IPPROTO_IP, IP_SO_GET_ENTRIES, hdr_buf)
    finally:
        s.close()

    return raw


def walk_raw_entries(raw):
    """Walk the rule list (struct ipt_entry blobs)."""
    off = XT_TABLE_MAXNAMELEN + 4   # name + size (bytes 0–35)
    total = len(raw)

    print(f"[+] Total bytes: {total}")

    while off < total:
        # ipt_entry: target_offset(2), next_offset(2), comefrom(4), counters(16)
        if off + 24 > total:
            print("[-] Entry truncated at end")
            break

        (target_off, next_off) = struct.unpack_from("HH", raw, off)
        print(f"Rule at offset={off}: next_offset={next_off}, target_offset={target_off}")

        if next_off == 0:
            print("[-] Invalid next_offset=0, stopping")
            break

        off += next_off


def main():
    table = "filter"

    print(f"[+] Dumping iptables table: {table}")

    info = get_table_info(table)
    print("[+] Table info:")
    print(f"    num_entries = {info.num_entries}")
    print(f"    size        = {info.size}")
    print(f"    valid_hooks = 0x{info.valid_hooks:x}")
    print("    hook_entry  =", list(info.hook_entry))
    print("    underflow   =", list(info.underflow))

    print("\n[+] Fetching entries...")
    raw = dump_table_entries(table, info.size)

    print("[+] Walking entry list:")
    walk_raw_entries(raw)

if __name__ == "__main__":
    main()
