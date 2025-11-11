#!/usr/bin/env python3
"""
arp_scan_auto_iface.py - ARP scanner (no 3rd-party libs) that auto-selects
the single non-loopback interface at runtime (Linux-only).

Usage:
    sudo python3 arp_scan_auto_iface.py --network 192.168.1.0/24 --timeout 3.0
"""
import argparse
import fcntl
import ipaddress
import socket
import struct
import time
import select
import os
from typing import Dict, Tuple, List

SIOCGIFHWADDR = 0x8927
SIOCGIFADDR   = 0x8915

def find_first_non_lo_iface() -> str:
    """
    Return the first interface name that's not 'lo'. Uses /sys/class/net if available,
    otherwise falls back to socket.if_nameindex().
    """
    # Primary method: /sys/class/net (Linux)
    try:
        net_dirs = os.listdir("/sys/class/net")
        # Preserve order returned by kernel; choose first that is not 'lo'
        for ifname in net_dirs:
            if ifname == "lo":
                continue
            # skip virtual/ifaces without operstate? we still accept them
            return ifname
    except Exception:
        pass

    # Fallback method: use socket.if_nameindex()
    try:
        for idx, ifname in socket.if_nameindex():
            if ifname == "lo":
                continue
            return ifname
    except Exception:
        pass

    raise SystemExit("Could not find a non-loopback interface on this system")

def ifname_to_bytes(ifname: str) -> bytes:
    return ifname.encode('utf-8')[:15].ljust(16, b'\x00')

def get_iface_mac(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('16sH14s', ifname.encode('utf-8'), 0, b'')
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    finally:
        s.close()
    mac = res[18:24]
    return ':'.join(f'{b:02x}' for b in mac)

def get_iface_ipv4(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname.encode('utf-8'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    finally:
        s.close()
    ip_bytes = res[20:24]
    return socket.inet_ntoa(ip_bytes)

def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))

def ip_str_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)

def build_arp_request(src_mac: bytes, src_ip: bytes, target_ip: bytes) -> bytes:
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    ethertype = struct.pack('!H', 0x0806)  # ARP
    eth_hdr = dst_mac + src_mac + ethertype

    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    opcode = 1  # request
    target_mac = b'\x00' * 6
    arp_payload = struct.pack('!HHBBH6s4s6s4s',
                              htype, ptype, hlen, plen, opcode,
                              src_mac, src_ip, target_mac, target_ip)
    return eth_hdr + arp_payload

def parse_arp_reply(frame: bytes) -> Tuple[str, str]:
    if len(frame) < 14 + 28:
        return "", ""
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype != 0x0806:
        return "", ""
    arp = frame[14:14+28]
    htype, ptype, hlen, plen, opcode = struct.unpack('!HHBBH', arp[:8])
    if opcode != 2:
        return "", ""
    sender_mac = arp[8:14]
    sender_ip = arp[14:18]
    mac_str = ':'.join(f'{b:02x}' for b in sender_mac)
    ip_str = socket.inet_ntoa(sender_ip)
    return ip_str, mac_str

def send_arp_requests(iface: str, src_mac: str, src_ip: str, targets: List[str]) -> None:
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw.bind((iface, 0))
    src_mac_b = mac_str_to_bytes(src_mac)
    src_ip_b = ip_str_to_bytes(src_ip)

    for t in targets:
        pkt = build_arp_request(src_mac_b, src_ip_b, ip_str_to_bytes(t))
        raw.send(pkt)
    raw.close()

def listen_for_replies(iface: str, timeout: float) -> Dict[str, str]:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.setblocking(0)

    end = time.time() + timeout
    results: Dict[str, str] = {}
    while time.time() < end:
        remaining = end - time.time()
        r, _, _ = select.select([sock], [], [], remaining)
        if not r:
            break
        frame = sock.recv(65536)
        ip, mac = parse_arp_reply(frame)
        if ip and mac:
            results[ip] = mac
    sock.close()
    return results

def expand_targets_from_network(network: str) -> List[str]:
    net = ipaddress.ip_network(network, strict=False)
    return [str(ip) for ip in net.hosts()]

def arp_scan(network: str, timeout: float = 3.0) -> Dict[str, str]:
    if os.geteuid() != 0:
        raise SystemExit("Root privileges required (run with sudo)")

    iface = find_first_non_lo_iface()
    try:
        my_mac = get_iface_mac(iface)
    except Exception as e:
        raise SystemExit(f"Could not obtain MAC for iface {iface}: {e}")
    try:
        my_ip = get_iface_ipv4(iface)
    except Exception as e:
        raise SystemExit(f"Could not obtain IPv4 for iface {iface}: {e}")

    print(f"[+] Using interface {iface} - IP {my_ip}  MAC {my_mac}")
    targets = expand_targets_from_network(network)
    print(f"[+] Scanning {len(targets)} hosts ... (timeout {timeout}s)")

    send_arp_requests(iface, my_mac, my_ip, targets)
    results = listen_for_replies(iface, timeout)
    return results

def main():
    parser = argparse.ArgumentParser(description="ARP scanner (no 3rd-party libs). Auto-selects the first non-loopback interface.")
    parser.add_argument('--network', required=True, help='Network to scan, e.g. 192.168.1.0/24 or single IP 10.0.0.5')
    parser.add_argument('--timeout', type=float, default=3.0, help='How many seconds to wait for replies')
    args = parser.parse_args()

    net = args.network
    if '/' not in net:
        net = f'{net}/32'

    found = arp_scan(net, timeout=args.timeout)
    print("Discovered hosts:")
    for ip, mac in sorted(found.items(), key=lambda t: t[0]):
        print(f"  {ip} -> {mac}")

if __name__ == '__main__':
    main()
