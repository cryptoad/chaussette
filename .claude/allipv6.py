#!/usr/bin/env python3
import socket
import struct
import os
import time

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY   = 129

TIMEOUT = 2.0

# ============================================================
# Helpers
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
            parts = line.strip().split()
            addr_hex, idx, plen, scope, flags, ifname = parts
            if ifname != iface:
                continue

            # only link-local (scope == 0x20)
            if scope != "20":
                continue

            # convert hex -> IPv6
            addr = ":".join(addr_hex[i:i+4] for i in range(0,32,4))
            addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(addr_hex))
            addrs.append(addr)

    return addrs

def join_multicast(sock, iface, group):
    idx = socket.if_nametoindex(iface)
    mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", idx)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

def make_socket(iface):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.settimeout(TIMEOUT)

    # bind to iface
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())

    # receive pktinfo
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)

    # hops
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)

    return s

# ============================================================
# ICMPv6
# ============================================================

def send_echo(sock, iface, target):
    ident = os.getpid() & 0xffff
    seq = 1
    pkt = struct.pack("!BBHHH", ICMPV6_ECHO_REQUEST, 0, 0, ident, seq) + b"X"

    sock.sendto(pkt, (target, 0, 0, socket.if_nametoindex(iface)))
    return ident

def recv_loop(sock, ident, self_addrs):
    start = time.time()
    while time.time() - start < TIMEOUT:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            return None

        t = data[0]
        src = addr[0]

        # ignore own echo request
        if t == ICMPV6_ECHO_REQUEST:
            continue

        # ignore self responses
        if src in self_addrs:
            continue

        if t == ICMPV6_ECHO_REPLY:
            r_ident = struct.unpack("!H", data[4:6])[0]
            if r_ident == ident:
                return ("ECHO_REPLY", addr)

        if t == 134:
            return ("ROUTER_ADVERT", addr)

        if t == 136:
            return ("NEIGHBOR_ADVERT", addr)

        return (f"type={t}", addr)

    return None

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

    sock = make_socket(iface)

    # join multicast groups
    join_multicast(sock, iface, "ff02::1")
    join_multicast(sock, iface, "ff02::2")

    tests = [
        ("all-nodes", "ff02::1"),
        ("all-routers", "ff02::2"),
    ]

    for name, target in tests:
        print(f"\n--- {name} ({target}%{iface}) ---")

        ident = send_echo(sock, iface, target)
        res = recv_loop(sock, ident, self_addrs)

        if res:
            print("[+] response:", res)
        else:
            print("[-] no response")

    print("\n[+] passive listen (5s)...")
    start = time.time()
    while time.time() - start < 5:
        try:
            data, addr = sock.recvfrom(2048)
            if addr[0] not in self_addrs:
                print("[*] unsolicited:", data[0], addr)
        except socket.timeout:
            pass

    print("\nDone.")

if __name__ == "__main__":
    main()
