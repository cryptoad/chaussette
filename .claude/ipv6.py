#!/usr/bin/env python3
import socket
import struct
import random
import fcntl
import os
import time


def get_default_gateway():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            iface, dest, gw, flags, _, _, _, _, _, _, _ = line.split()
            if dest == "00000000":
                gw_hex = bytes.fromhex(gw)
                return socket.inet_ntoa(gw_hex[::-1]), iface
    raise RuntimeError("No default gateway found")


def get_iface_hwaddr(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(
        s.fileno(), 0x8927, struct.pack('256s', iface.encode()[:15])
    )
    return info[18:24]


def get_source_ip():
    ips = os.popen("hostname -I").read().strip().split()
    for ip in ips:
        if "." in ip and not ip.startswith("127."):
            return ip
    raise RuntimeError("Could not determine IPv4 from hostname -I")


def sniff_gateway_mac(sock, gateway_ip, timeout=3):
    gw_ip_raw = socket.inet_aton(gateway_ip)
    end = time.time() + timeout
    sock.settimeout(0.3)

    print(f"[+] Sniffing traffic to learn MAC for {gateway_ip} ...")

    while time.time() < end:
        try:
            pkt = sock.recv(2048)
        except socket.timeout:
            continue

        if len(pkt) < 34:
            continue

        src_mac = pkt[6:12]
        ethertype = pkt[12:14]

        if ethertype != b"\x08\x00":  # IPv4 only
            continue

        ip_src = pkt[26:30]
        ip_dst = pkt[30:34]

        if ip_src == gw_ip_raw:
            print("[+] Learned gateway MAC (source match)")
            return src_mac

        if ip_dst == gw_ip_raw:
            print("[+] Learned gateway MAC (destination match)")
            return src_mac

    raise RuntimeError("Could not discover gateway MAC via passive sniffing")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def build_syn_packet(src_mac, dst_mac, src_ip, dst_ip, sport, dport, seq):
    eth = dst_mac + src_mac + b"\x08\x00"

    ver_ihl = 0x45
    total_len = 20 + 20
    ident = random.randint(0, 65535)

    ip_header = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, 0,
        total_len, ident, 0,
        64, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )

    flags = (5 << 12) | 0x002  # SYN
    tcp_header = struct.pack("!HHLLHHHH",
        sport, dport, seq, 0,
        flags, 1024, 0, 0
    )

    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_sum = checksum(pseudo + tcp_header)

    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_sum) + tcp_header[18:]

    return eth + ip_header + tcp_header


def main():
    gw_ip, iface = get_default_gateway()
    print(f"[+] Default gateway: {gw_ip} via {iface}")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))

    src_ip = get_source_ip()
    src_mac = get_iface_hwaddr(iface)
    print(f"[+] Source MAC={src_mac.hex(':')} IP={src_ip}")

    gw_mac = sniff_gateway_mac(sock, gw_ip)
    print(f"[+] Gateway MAC = {gw_mac.hex(':')}")

    ports = [22, 53, 80, 443] + list(range(10000, 10200))
    ports = ports[:200]

    sport = random.randint(20000, 60000)
    seq = random.randint(0, 2**32 - 1)

    print("[+] Sending SYN packets ...")
    for p in ports:
        pkt = build_syn_packet(src_mac, gw_mac, src_ip, gw_ip, sport, p, seq)
        sock.send(pkt)

    print("[+] Listening for replies ...")
    sock.settimeout(0.25)
    deadline = time.time() + 2
    open_ports = set()

    while time.time() < deadline:
        try:
            data = sock.recv(2048)
        except socket.timeout:
            continue

        if data[12:14] != b"\x08\x00":
            continue

        iphdr = data[14:34]
        if iphdr[9] != 6:
            continue

        src = socket.inet_ntoa(iphdr[12:16])
        if src != gw_ip:
            continue

        tcp = data[34:54]
        sport_r, dport_r, _, _, flags = struct.unpack("!HHLLH", tcp[:14])
        if dport_r != sport:
            continue

        if flags & 0x012 == 0x012:
            print(f"    [+] OPEN: {sport_r}")
            open_ports.add(sport_r)

    print("\nScan complete.")
    if open_ports:
        for p in sorted(open_ports):
            print("Open port:", p)
    else:
        print("No open ports found.")


if __name__ == "__main__":
    main()
