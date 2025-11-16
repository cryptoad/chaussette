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
            if dest == "00000000":  # default route
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
    # Parse hostname -I output
    ips = os.popen("hostname -I").read().strip().split()
    for ip in ips:
        if "." in ip and not ip.startswith("127."):
            return ip
    raise RuntimeError("Could not determine source IPv4")

def arp_resolve(sock, src_mac, src_ip, target_ip):
    broadcast = b"\xff"*6
    eth = broadcast + src_mac + b"\x08\x06"

    arp = struct.pack("!HHBBH6s4s6s4s",
        1, 0x0800,
        6, 4,
        1,
        src_mac,
        socket.inet_aton(src_ip),
        b"\x00"*6,
        socket.inet_aton(target_ip)
    )

    sock.send(eth + arp)
    sock.settimeout(2)

    while True:
        pkt = sock.recv(2048)
        if pkt[12:14] == b"\x08\x06" and pkt[20:22] == b"\x00\x02":
            sender_ip = socket.inet_ntoa(pkt[28:32])
            if sender_ip == target_ip:
                return pkt[22:28]

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

    offset_res_flags = (5 << 12) | 0x002  # SYN flag
    tcp_header = struct.pack("!HHLLHHHH",
        sport, dport, seq, 0,
        offset_res_flags, 1024, 0, 0
    )

    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_sum = checksum(pseudo + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_sum) + tcp_header[18:]

    return eth + ip_header + tcp_header

def main():
    gw_ip, iface = get_default_gateway()
    print(f"[+] Default gateway: {gw_ip} on {iface}")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))

    src_mac = get_iface_hwaddr(iface)
    src_ip = get_source_ip()

    print(f"[+] Local MAC: {src_mac.hex(':')}  IP: {src_ip}")
    print(f"[+] Resolving ARP for gateway {gw_ip} ...")

    gw_mac = arp_resolve(sock, src_mac, src_ip, gw_ip)
    print(f"[+] Gateway MAC: {gw_mac.hex(':')}")

    ports = [22, 53, 80, 443] + list(range(10000, 10200))
    ports = ports[:200]

    sport = random.randint(20000, 60000)
    seq = random.randint(0, 2**32 - 1)

    print("[+] Sending SYN packets...")
    for p in ports:
        pkt = build_syn_packet(src_mac, gw_mac, src_ip, gw_ip, sport, p, seq)
        sock.send(pkt)

    print("[+] Listening for replies...")
    sock.settimeout(0.25)

    open_ports = set()
    deadline = time.time() + 2

    while time.time() < deadline:
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break

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
            print(f"    [+] OPEN: {sport_r} (SYN-ACK)")
            open_ports.add(sport_r)

    print("\nScan complete.")
    if open_ports:
        for p in sorted(open_ports):
            print(f"Open port: {p}")
    else:
        print("No open ports detected.")

if __name__ == "__main__":
    main()
