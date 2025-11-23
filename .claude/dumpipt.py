#!/usr/bin/env python3
import socket, ctypes, os, struct

# --------------------------------------------------------------------
# Constants from linux/netfilter_ipv4/ip_tables.h
# --------------------------------------------------------------------

SOL_IP = socket.SOL_IP

IPT_BASE_CTL = 64
IPT_SO_GET_INFO = IPT_BASE_CTL          # = 64
IPT_SO_GET_ENTRIES = IPT_BASE_CTL + 1   # = 65

XT_TABLE_MAXNAMELEN = 32
NF_IP_NUMHOOKS = 5                       # PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING

# --------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------

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
        # followed in memory by `entries[]`
    ]

# --------------------------------------------------------------------
# Load libc and define getsockopt
# --------------------------------------------------------------------

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.getsockopt.argtypes = [
    ctypes.c_int, ctypes.c_int, ctypes.c_int,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)
]
libc.getsockopt.restype = ctypes.c_int

# --------------------------------------------------------------------
# Get Table Info
# --------------------------------------------------------------------

def get_table_info(sock, table: str) -> IPTGetinfo:
    """Retrieve iptables table metadata via IPT_SO_GET_INFO."""
    info = IPTGetinfo()
    ctypes.memset(ctypes.byref(info), 0, ctypes.sizeof(info))

    # Copy table name
    enc = table.encode()
    ctypes.memmove(info.name, enc, len(enc))

    optlen = ctypes.c_uint(ctypes.sizeof(info))

    rc = libc.getsockopt(
        sock.fileno(),
        SOL_IP,
        IPT_SO_GET_INFO,
        ctypes.byref(info),
        ctypes.byref(optlen)
    )

    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"IPT_SO_GET_INFO failed: {os.strerror(err)}")

    return info

# --------------------------------------------------------------------
# Get Table Entries
# --------------------------------------------------------------------

def get_table_entries(sock, table: str, size: int) -> bytes:
    """Retrieve raw iptables entries via IPT_SO_GET_ENTRIES."""

    # Build header
    hdr = IPTGetEntries()
    ctypes.memset(ctypes.byref(hdr), 0, ctypes.sizeof(hdr))

    enc = table.encode()
    ctypes.memmove(hdr.name, enc, len(enc))
    hdr.size = size

    # Allocate buffer: header + all entries
    total = ctypes.sizeof(IPTGetEntries) + size
    buf = ctypes.create_string_buffer(total)

    # Copy header into the beginning of buffer
    ctypes.memmove(buf, ctypes.byref(hdr), ctypes.sizeof(hdr))

    optlen = ctypes.c_uint(total)

    rc = libc.getsockopt(
        sock.fileno(),
        SOL_IP,
        IPT_SO_GET_ENTRIES,
        ctypes.cast(buf, ctypes.c_void_p),
        ctypes.byref(optlen)
    )

    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"IPT_SO_GET_ENTRIES failed: {os.strerror(err)}")

    # Return exactly the bytes written
    return buf.raw[:optlen.value]

# --------------------------------------------------------------------
# Walk through ipt_entry list
# --------------------------------------------------------------------

def walk_entries(blob: bytes):
    """Walk the ipt_entry chain and print rule offsets & sizes."""

    header_size = ctypes.sizeof(IPTGetEntries)
    off = header_size
    end = len(blob)

    print(f"[+] Entries start after {header_size} bytes")
    print(f"[+] Total blob size: {end} bytes")

    idx = 0
    while off + 4 <= end:
        # ipt_entry begins with:
        # __u16 target_offset;
        # __u16 next_offset;
        target_off, next_off = struct.unpack_from("HH", blob, off)

        print(f"  Rule {idx}: offset={off}, next_off={next_off}, target_off={target_off}")

        if next_off == 0:
            print("    [!] next_offset=0: end or corruption")
            break

        off += next_off
        idx += 1

        if off >= end:
            break

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

def main():
    table = "nat"    # change to filter/nat/mangle/raw/security

    # Raw IPv4 socket (any protocol will do: ICMP is fine)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:

        print(f"[+] Querying table: {table}")

        info = get_table_info(s, table)

        print("[+] Table metadata:")
        print(f"    name        = {info.name.split(b'\\x00')[0].decode()}")
        print(f"    num_entries = {info.num_entries}")
        print(f"    size        = {info.size}")
        print(f"    valid_hooks = 0x{info.valid_hooks:x}")
        print(f"    hook_entry  = {list(info.hook_entry)}")
        print(f"    underflow   = {list(info.underflow)}")

        print("\n[+] Retrieving ipt_entry blob...")
        blob = get_table_entries(s, table, info.size)

    print("\n[+] Walking entries:\n")
    walk_entries(blob)


if __name__ == "__main__":
    main()
