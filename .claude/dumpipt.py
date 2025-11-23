#!/usr/bin/env python3
import ctypes
import socket
import struct

IP_SO_GET_INFO    = 65
IP_SO_GET_ENTRIES = 66

XT_TABLE_MAXNAMELEN = 32
NF_INET_NUMHOOKS    = 5

# ---------------------------------------------------------
#                   STRUCT DEFINITIONS
# ---------------------------------------------------------

class ipt_getinfo(ctypes.Structure):
    _fields_ = [
        ("name",       ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("underflow",  ctypes.c_uint * NF_INET_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size",        ctypes.c_uint),
    ]

class ipt_get_entries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        # followed by entries[] which we fetch manually
    ]

# size of struct ipt_entry header before matches/target
IPT_ENTRY_FIXED_SIZE = 8 + 16   # target_off(2) + next_off(2) + comefrom(4) + counters(16)


# ---------------------------------------------------------
#                   HELPERS
# ---------------------------------------------------------

def get_table_info(name):
    """Call IP_SO_GET_INFO and return ipt_getinfo."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Kernel ignores input buffer contents, but needs correct size
    buflen = ctypes.sizeof(ipt_getinfo)

    try:
        raw = s.getsockopt(socket.IPPROTO_IP, IP_SO_GET_INFO, buflen)
    finally:
        s.close()

    if len(raw) != buflen:
        raise RuntimeError("Kernel returned incorrect struct size")

    info = ipt_getinfo.from_buffer_copy(raw)
    return info


def get_table_entries(name, size):
    """Call IP_SO_GET_ENTRIES and return raw bytes of entries[]."""

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Build minimal ipt_get_entries header
    hdr = ipt_get_entries()
    hdr.name = name.encode()
    hdr.size = size

    # Kernel expects a buffer containing struct + space for entries
    buf = ctypes.string_buffer(ctypes.sizeof(ipt_get_entries) + size)

    # Copy header into start of buffer
    ctypes.memmove(buf, ctypes.addressof(hdr), ctypes.sizeof(hdr))

    try:
        # Kernel overwrites buffer with struct + entries[]
        raw = s.getsockopt(socket.IPPROTO_IP, IP_SO_GET_ENTRIES, buf)
    finally:
        s.close()

    # raw now contains:
    # struct ipt_get_entries + entries[]
    return raw


def walk_entries(blob):
    """Walk raw ipt_entry list and print offsets."""
    # The entries start immediately after ipt_get_entries header
    off = ctypes.sizeof(ipt_get_entries)
    end = len(blob)

    print(f"[+] Total returned bytes: {end}")

    while off < end:
        if off + 4 > end:
            print("[-] Truncated ipt_entry header, stopping")
            break

        # target_offset, next_offset
        target_off, next_off = struct.unpack_from("HH", blob, off)

        print(f"Rule @ offset {off:5d}: next_off={next_off:3d}, target_off={target_off:3d}")

        if next_off == 0:
            print("[-] Invalid next_offset=0; stopping")
            break

        off += next_off


# ---------------------------------------------------------
#                   MAIN
# ---------------------------------------------------------

def main():
    table = "filter"

    print(f"[+] Requesting info for table '{table}'")

    info = get_table_info(table)

    print("[+] Table info:")
    print(f"    num_entries = {info.num_entries}")
    print(f"    size        = {info.size}")
    print(f"    valid_hooks = 0x{info.valid_hooks:x}")
    print(f"    hook_entry  = {list(info.hook_entry)}")
    print(f"    underflow   = {list(info.underflow)}")

    print("\n[+] Fetching table entries…")
    blob = get_table_entries(table, info.size)

    print("[+] Walking entries:")
    walk_entries(blob)


if __name__ == "__main__":
    main()
