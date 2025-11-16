#!/usr/bin/env python3
import socket
import struct
import random
import fcntl
import os
import time
import sys

# ------------------------------
# Helpers
# ------------------------------

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

def arp_resolve(sock, src_mac, src_ip, target_ip):
    """
    Returns MAC address of target_ip
    """
    broadcast = b"\xff"*6
    eth = broadcast + src_mac + b"\x08\x06"

    # ARP request
    arp = struct.pack("!HHBBH6s4s6s4s",
        1,  # Ethernet
        0x0800,  # IPv4
        6, 4,
        1,  # request
        src_mac,
        socket.inet_aton(src_ip),
        b"\x00"*6,
        socket.inet_aton(target_ip)
    )

    sock.send(eth + arp)

    # listen for ARP reply
    sock.settimeout(2)
    while True:
        pkt = sock.recv(2048)
        if pkt[12:14] == b"\x08\x06" and pkt[20:22] == b"\x00\x02":
            sender_ip = socket.inet_ntoa(pkt[28:32])
            if sender_ip == target_ip:
                return pkt[22:28]  # sender MAC


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


# ------------------------------
# TCP SYN scan
# ------------------------------

def build_syn_packet(src_mac, dst_mac, src_ip, dst_ip, sport, dport, seq):
    # Ethernet
    eth = dst_mac + src_mac + b"\x08\x00"

    # IP header
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + 20
    ident = random.randint(0, 65535)
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    ip_checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    ip_header = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, ip_checksum, src, dst
    )

    # TCP header (checksum later)
    offset_res_flags = (5 << 12) | 0x002  # SYN
    window = 1024
    urg = 0

    tcp_header = struct.pack("!HHLLHHHH",
        sport, dport, seq, 0,
        offset_res_flags, window, 0, urg
    )

    # TCP checksum
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(tcp_header))
    tcp_checksum = checksum(pseudo + tcp_header)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

    return eth + ip_header + tcp_header


def main():
    gw_ip, iface = get_default_gateway()
    print(f"[+] Default gateway: {gw_ip} via {iface}")

    # Raw AF_PACKET socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))

    # local IP
    src_ip = socket.gethostbyname(socket.gethostname())
    # fallback: fetch from interface if hostname isn't routable
    if src_ip.startswith("127."):
        src_ip = os.popen(f"ip -4 addr show {iface}").read().split("inet ")[1].split("/")[0]

    src_mac = get_iface_hwaddr(iface)
    print(f"[+] Our MAC: {src_mac.hex(':')}, IP: {src_ip}")

    print(f"[+] Resolving MAC of {gw_ip}...")
    gw_mac = arp_resolve(sock, src_mac, src_ip, gw_ip)
    print(f"[+] Gateway MAC: {gw_mac.hex(':')}")

    # ports to scan
    ports = [20,21,22,23,25,53,80,110,139,143,443,445,3389] + list(range(10000,10200))
    # trim to ~200
    ports = ports[:200]

    sport = random.randint(20000, 60000)
    seq = random.randint(0, 2**32 - 1)

    print("[+] Sending SYNs…")
    for p in ports:
        pkt = build_syn_packet(src_mac, gw_mac, src_ip, gw_ip, sport, p, seq)
        sock.send(pkt)

    print("[+] Waiting for replies...")
    sock.settimeout(0.25)  # short timeout due to possible drops

    open_ports = set()

    deadline = time.time() + 2  # 2 seconds total listen
    while time.time() < deadline:
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break

        # IP packet?
        if data[12:14] != b"\x08\x00":
            continue

        # Extract IP header
        iphdr = data[14:34]
        proto = iphdr[9]
        if proto != 6:  # TCP only
            continue

        src = socket.inet_ntoa(iphdr[12:16])
        dst = socket.inet_ntoa(iphdr[16:20])

        if src != gw_ip:
            continue

        # extract TCP
        tcp = data[34:54]
        sport_r, dport_r, seq_r, ack_r, flags = struct.unpack("!HHLLH", tcp[:14])

        if dport_r != sport:
            continue

        # SYN-ACK or RST
        if flags & 0x012 == 0x012:
            print(f"    [+] Port {sport_r} OPEN (SYN-ACK)")
            open_ports.add(sport_r)
        elif flags & 0x004:
            # RST means closed
            pass

    print("\n=== Scan complete ===")
    if open_ports:
        for p in sorted(open_ports):
            print(f"Open: {p}")
    else:
        print("No open ports detected")

if __name__ == "__main__":
    main()
