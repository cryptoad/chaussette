#!/usr/bin/env python3
import socket
import struct
import os
import time

ICMPV6_NS = 135
ICMPV6_NA = 136

TIMEOUT = 2.0

# ============================================================

def get_iface():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            if line.split()[1] == "00000000":
                return line.split()[0]
    raise RuntimeError("no iface")

def get_self_ipv6(iface):
    addrs = []
    with open("/proc/net/if_inet6") as f:
        for line in f:
            addr_hex, idx, plen, scope, flags, ifname = line.split()
            if ifname != iface:
                continue
            addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(addr_hex))
            if addr.startswith("fe80::"):
                addrs.append(addr)
    return addrs

def make_socket(iface):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.settimeout(TIMEOUT)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    return s

# ============================================================
# ND logic
# ============================================================

def solicited_node_multicast(addr):
    b = socket.inet_pton(socket.AF_INET6, addr)
    last3 = b[-3:]
    return "ff02::1:ff%02x:%02x%02x" % (last3[0], last3[1], last3[2])

def send_ns(sock, iface, target):
    target_bin = socket.inet_pton(socket.AF_INET6, target)

    # Type, code, checksum, reserved
    pkt = struct.pack("!BBHI", ICMPV6_NS, 0, 0, 0) + target_bin

    group = solicited_node_multicast(target)

    sock.sendto(pkt, (group, 0, 0, socket.if_nametoindex(iface)))

def recv_na(sock, self_addrs):
    found = []

    start = time.time()
    while time.time() - start < TIMEOUT:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            break

        if data[0] == ICMPV6_NA:
            src = addr[0]
            if src not in self_addrs:
                found.append(src)

    return list(set(found))

# ============================================================
# Simple target generation
# ============================================================

def mutate_targets(base):
    parts = base.split(":")
    last = int(parts[-1], 16)

    out = []
    for i in range(-32, 33):
        v = (last + i) & 0xffff
        parts[-1] = f"{v:x}"
        out.append(":".join(parts))

    return list(set(out))

# ============================================================
# Main
# ============================================================

def main():
    if os.geteuid() != 0:
        print("run as root")
        return

    iface = get_iface()
    self_addrs = get_self_ipv6(iface)

    print(f"[+] iface: {iface}")
    print(f"[+] self IPv6: {self_addrs}")

    if not self_addrs:
        print("[-] no IPv6 addr")
        return

    base = self_addrs[0]

    sock = make_socket(iface)

    print("\n[+] sending neighbor solicitations...")

    targets = mutate_targets(base)

    for t in targets:
        send_ns(sock, iface, t)

    found = recv_na(sock, self_addrs)

    print("\n[+] results:")
    if found:
        for x in found:
            print("[FOUND]", x)
    else:
        print("[-] no neighbors discovered")

    print("\nDone.")

if __name__ == "__main__":
    main()
