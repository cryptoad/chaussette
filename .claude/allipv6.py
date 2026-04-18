#!/usr/bin/env python3
import socket
import struct
import subprocess
import os
import time

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY   = 129

TIMEOUT = 2.0

def get_iface():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.strip().split()
            if fields[1] == "00000000":
                return fields[0]
    raise RuntimeError("no iface")

def join_multicast(sock, iface, group):
    idx = socket.if_nametoindex(iface)
    mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", idx)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

def icmpv6_socket(iface):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.settimeout(TIMEOUT)

    idx = socket.if_nametoindex(iface)

    # bind to iface
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())

    # receive pktinfo
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)

    # multicast hops
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)

    return s

def send_echo(sock, iface, target):
    ident = os.getpid() & 0xffff
    seq = 1
    pkt = struct.pack("!BBHHH", ICMPV6_ECHO_REQUEST, 0, 0, ident, seq) + b"X"

    sock.sendto(pkt, (target, 0, 0, socket.if_nametoindex(iface)))
    return ident

def recv_loop(sock, ident):
    start = time.time()
    while time.time() - start < TIMEOUT:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            return None

        t = data[0]

        # ignore our own echo request
        if t == ICMPV6_ECHO_REQUEST:
            continue

        if t == ICMPV6_ECHO_REPLY:
            r_ident = struct.unpack("!H", data[4:6])[0]
            if r_ident == ident:
                return ("ECHO_REPLY", addr)

        # router advert (bonus signal)
        if t == 134:
            return ("ROUTER_ADVERT", addr)

        # neighbor advert
        if t == 136:
            return ("NEIGHBOR_ADVERT", addr)

        return (f"type={t}", addr)

    return None

def main():
    if os.geteuid() != 0:
        print("run as root")
        return

    iface = get_iface()
    print(f"[+] iface: {iface}")

    sock = icmpv6_socket(iface)

    # join multicast groups
    join_multicast(sock, iface, "ff02::1")  # all nodes
    join_multicast(sock, iface, "ff02::2")  # all routers

    tests = [
        ("all-nodes", "ff02::1"),
        ("all-routers", "ff02::2"),
    ]

    for name, target in tests:
        print(f"\n--- {name} ({target}%{iface}) ---")

        ident = send_echo(sock, iface, target)
        res = recv_loop(sock, ident)

        if res:
            print("[+] response:", res)
        else:
            print("[-] no response")

    print("\n[+] passive listen (5s for RA/NA)...")
    start = time.time()
    while time.time() - start < 5:
        try:
            data, addr = sock.recvfrom(2048)
            print("[*] unsolicited:", data[0], addr)
        except socket.timeout:
            pass

if __name__ == "__main__":
    main()
