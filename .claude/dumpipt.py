#!/usr/bin/env python3
import ctypes
import socket
import struct
import os

# --------------------------------------------------------------------
# Netfilter constants (from linux/netfilter_ipv4/ip_tables.h)
# --------------------------------------------------------------------

IPT_BASE_CTL = 64

IPT_SO_SET_REPLACE        = IPT_BASE_CTL
IPT_SO_SET_ADD_COUNTERS   = IPT_BASE_CTL + 1

IPT_SO_GET_INFO           = IPT_BASE_CTL          # 64
IPT_SO_GET_ENTRIES        = IPT_BASE_CTL + 1      # 65
IPT_SO_GET_REVISION_MATCH = IPT_BASE_CTL + 2
IPT_SO_GET_REVISION_TARGET= IPT_BASE_CTL + 3

XT_TABLE_MAXNAMELEN = 32
NF_INET_NUMHOOKS    = 5  # PREROUTING=0, INPUT=1, FORWARD=2, OUTPUT=3, POSTROUTING=4

# --------------------------------------------------------------------
# Struct definitions
# --------------------------------------------------------------------

class ipt_getinfo(ctypes.Structure):
    _fields_ = [
        ("name",        ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry",  ctypes.c_uint * NF_INET_NUMHOOKS),
        ("underflow",   ctypes.c_uint * NF_INET_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size",        ctypes.c_uint),
    ]


class ipt_get_entries(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("size", ctypes.c_uint),
        # followed in memory by entries[]
    ]

# --------------------------------------------------------------------
# libc.getsockopt binding
# --------------------------------------------------------------------

libc = ctypes.CDLL(None, use_errno=True)

libc.getsockopt.argtypes = [
    ctypes.c_int,                     # sockfd
    ctypes.c_int,                     # level
    ctypes.c_int,                     # optname
    ctypes.c_void_p,                  # optval
    ctypes.POINTER(ctypes.c_uint),    # optlen (socklen_t*)
]
libc.getsockopt.restype = ctypes.c_int

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

def get_table_info(table_name: str) -> ipt_getinfo:
    """Call IPT_SO_GET_INFO to get ipt_getinfo for a given table."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = s.fileno()

    info = ipt_getinfo()
    ctypes.memset(ctypes.byref(info), 0, ctypes.sizeof(info))

    enc = table_name.encode()
    if len(enc) >= XT_TABLE_MAXNAMELEN:
        raise ValueError("Table name too long")
    ctypes.memmove(info.name, enc, len(enc))

    optlen = ctypes.c_uint(ctypes.sizeof(info))

    rc = libc.getsockopt(
        fd,
        socket.IPPROTO_IP,
        IPT_SO_GET_INFO,
        ctypes.byref(info),
        ctypes.byref(optlen),
    )

    s.close()

    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))

    if optlen.value != ctypes.sizeof(info):
        raise RuntimeError(f"Unexpected ipt_getinfo size {optlen.value}")

    return info


def get_table_entries(table_name: str, size: int) -> bytes:
    """Call IPT_SO_GET_ENTRIES to get raw entries[] blob for a given table."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = s.fileno()

    total = ctypes.sizeof(ipt_get_entries) + size
    buf = ctypes.create_string_buffer(total)

    # Initialize header
    hdr = ipt_get_entries()
    ctypes.memset(ctypes.byref(hdr), 0, ctypes.sizeof(hdr))

    enc = table_name.encode()
    if len(enc) >= XT_TABLE_MAXNAMELEN:
        raise ValueError("Table name too long")
    ctypes.memmove(hdr.name, enc, len(enc))
    hdr.size = size

    # Copy header into start of buffer
    ctypes.memmove(buf, ctypes.byref(hdr), ctypes.sizeof(hdr))

    optlen = ctypes.c_uint(total)

    rc = libc.getsockopt(
        fd,
        socket.IPPROTO_IP,
        IPT_SO_GET_ENTRIES,
        ctypes.cast(buf, ctypes.c_void_p),
        ctypes.byref(optlen),
    )

    s.close()

    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))

    return buf.raw[:optlen.value]


def walk_entries(blob: bytes) -> None:
    """
    Walk the ipt_entry list and print offsets.

    Layout of returned blob:
      struct ipt_get_entries  (we provided header, kernel fills / reuses it)
      followed by contiguous struct ipt_entry records.

    ipt_entry starts with:
      __u16 target_offset;
      __u16 next_offset;
      __u32 comefrom;
      struct xt_counters counters;
      ... matches ...
      ... target ...
    """
    header_size = ctypes.sizeof(ipt_get_entries)
    end = len(blob)
    off = header_size

    print(f"[+] Raw blob size: {end} bytes")
    print(f"[+] Entries start at offset {header_size}")

    idx = 0
    while off + 4 <= end:
        # target_offset, next_offset are the first 4 bytes of ipt_entry
        target_offset, next_offset = struct.unpack_from("HH", blob, off)

        print(f"  Rule #{idx}: offset={off}, next_offset={next_offset}, target_offset={target_offset}")

        if next_offset == 0:
            print("    [!] next_offset == 0, stopping (corrupt or end).")
            break

        off += next_offset
        idx += 1

        if off >= end:
            break


# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------

def main():
    table = "filter"  # you can change this to "nat", "mangle", "raw", "security" if supported

    print(f"[+] Getting iptables info for table '{table}'")

    try:
        info = get_table_info(table)
    except OSError as e:
        print(f"[-] getsockopt(IPT_SO_GET_INFO) failed: {e}")
        print("    This usually means the kernel / sandbox does not support "
              "the legacy iptables getsockopt API (common in gVisor / some container runtimes).")
        return

    tname = info.name.split(b"\x00", 1)[0].decode(errors="ignore")

    print("[+] Table info:")
    print(f"    name        = {tname}")
    print(f"    num_entries = {info.num_entries}")
    print(f"    size        = {info.size}")
    print(f"    valid_hooks = 0x{info.valid_hooks:x}")
    print(f"    hook_entry  = {list(info.hook_entry)}")
    print(f"    underflow   = {list(info.underflow)}")

    print("\n[+] Fetching entries with IPT_SO_GET_ENTRIES...")

    try:
        blob = get_table_entries(table, info.size)
    except OSError as e:
        print(f"[-] getsockopt(IPT_SO_GET_ENTRIES) failed: {e}")
        return

    print("[+] Walking ipt_entry list:\n")
    walk_entries(blob)


if __name__ == "__main__":
    main()
