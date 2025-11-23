#!/usr/bin/env python3
import ctypes
import socket
import struct
import subprocess
import time
import errno
import os

#
# Constants from Linux netfilter/xtables headers
#
IPT_SO_SET_REPLACE = 64
NF_INET_NUMHOOKS = 5   # PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING
XT_TABLE_MAXNAMELEN = 32

# ---------------------- structs -------------------------
#
# struct xt_counters { uint64_t pcnt, bcnt; }
#
class xt_counters(ctypes.Structure):
    _fields_ = [
        ("pcnt", ctypes.c_ulonglong),
        ("bcnt", ctypes.c_ulonglong),
    ]

#
# struct ipt_entry (empty rule)
# Minimal rule with no matches and a default verdict = CONTINUE (0)
#
class ipt_entry(ctypes.Structure):
    _fields_ = [
        ("target_offset", ctypes.c_uint16),
        ("next_offset", ctypes.c_uint16),
        ("comefrom", ctypes.c_uint),
        ("counters", xt_counters),
        # No fields beyond counters; padding will be added manually
    ]

#
# struct ipt_replace
#
class ipt_replace(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_INET_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_INET_NUMHOOKS),
        # Followed by struct ipt_entry entries[] in memory
    ]

# ----------------------------------------------------------

def get_default_gateway():
    """Parse /proc/net/route to determine the default gateway and interface."""
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.split()
            iface, dst, gw, flags = fields[0], fields[1], fields[2], int(fields[3], 16)
            if dst == "00000000" and (flags & 2):
                gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
                return iface, gw_ip
    raise RuntimeError("No default route found")

# ----------------------------------------------------------

def build_empty_filter_table():
    """
    Build an ipt_replace that flushes the FILTER table completely.
    The FILTER table has hooks: INPUT=0, FORWARD=1, OUTPUT=2.
    We install one empty rule per hook (minimal valid table).
    """
    table_name = b"filter"
    num_entries = 3  # INPUT, FORWARD, OUTPUT

    # Build three minimal ipt_entry structs
    entries = []
    entry_bin_list = []

    for _ in range(num_entries):
        e = ipt_entry()
        e.target_offset = ctypes.sizeof(ipt_entry)
        e.next_offset = ctypes.sizeof(ipt_entry)
        e.comefrom = 0
        e.counters = xt_counters(0, 0)

        entry_bin = bytes(e)
        entries.append(e)
        entry_bin_list.append(entry_bin)

    data_entries = b"".join(entry_bin_list)
    total_size = ctypes.sizeof(ipt_replace) + len(data_entries)

    rep = ipt_replace()
    rep.name = table_name
    rep.valid_hooks = (1 << 0) | (1 << 1) | (1 << 2)  # INPUT, FORWARD, OUTPUT
    rep.num_entries = num_entries
    rep.size = total_size

    # Hook entry indexes: INPUT=0, FORWARD=1, OUTPUT=2
    rep.hook_entry = (0, 1 * ctypes.sizeof(ipt_entry), 2 * ctypes.sizeof(ipt_entry), 0, 0)
    rep.underflow = rep.hook_entry

    # Build final buffer for setsockopt(): header + entries
    buf = bytes(rep) + data_entries
    return buf

# ----------------------------------------------------------

def flush_iptables_raw():
    """Flush FILTER table using raw SO_SET_REPLACE netfilter call."""
    print("[+] Building empty filter table…")
    buf = build_empty_filter_table()

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    try:
        print("[+] Sending IPT_SO_SET_REPLACE...")
        s.setsockopt(socket.IPPROTO_IP, IPT_SO_SET_REPLACE, buf)
        print("[+] Success: FILTER table flushed")
    except OSError as e:
        print(f"[-] Failed to replace iptables: {e}")
    finally:
        s.close()

# ----------------------------------------------------------

def connect_test(ip, port, timeout=0.5):
    """Return ('open'|'closed'|'timeout', errno) for the port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
        s.close()

        if rc == 0:
            return "open", rc
        if rc == errno.ECONNREFUSED:
            return "closed", rc
        return f"err_{rc}", rc

    except socket.timeout:
        return "timeout", None
    except Exception as e:
        return "exc", str(e)

# ----------------------------------------------------------

def main():
    if os.geteuid() != 0:
        print("Must be root.")
        return

    iface, gw = get_default_gateway()
    print(f"[+] Default gateway: {gw} via {iface}")

    # 1. Flush iptables
    flush_iptables_raw()

    # 2. Test gateway ports
    ports = [22, 53, 80, 443, 2024, 2379, 3306]
    print(f"\n[+] Testing connectivity to {gw}…\n")

    for p in ports:
        status, info = connect_test(gw, p)
        print(f"Port {p:5d}: {status:10s}  ({info})")

    print("\nDone.\n")

# ----------------------------------------------------------

if __name__ == "__main__":
    main()
