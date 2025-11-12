#!/usr/bin/env python3
# Send an ARP request to discover the MAC address of the default gateway.
# Linux only. Must run as root.

import socket
import struct
import fcntl
import os
import time
import binascii

SIOCGIFADDR = 0x8915       # Get interface IP address
SIOCGIFHWADDR = 0x8927     # Get interface MAC address


def get_default_gateway():
    """Return (interface, gateway_ip) for the default route."""
    with open("/proc/net/route", "r") as f:
        for line in f.readlines()[1:]:
            fields = line.strip().split()
            iface, dest, gateway, flags = fields[0], fields[1], fields[2], fields[3]
            if dest == "00000000":  # default route
                gw_ip = socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
                return iface, gw_ip
    raise RuntimeError("Default gateway not found in /proc/net/route")


def get_iface_ip(iface):
    """Get IPv4 address assigned to interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', iface[:15].encode('utf-8'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    finally:
        s.close()
    ip = struct.unpack('!I', res[20:24])[0]
    return socket.inet_ntoa(struct.pack('!I', ip))


def get_iface_mac(iface):
    """Get MAC address of interface (works even inside containers)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', iface[:15].encode('utf-8'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    finally:
        s.close()
    mac_bytes = res[18:24]
    return ':'.join('%02x' % b for b in mac_bytes)


def mac_str_to_bytes(mac_str):
    return binascii.unhexlify(mac_str.replace(":", ""))


def ip_str_to_bytes(ip_str):
    return socket.inet_aton(ip_str)


def build_arp_request(src_mac, src_ip, target_ip):
    """Build a raw Ethernet frame with ARP request payload."""
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # broadcast
    eth_type = struct.pack('!H', 0x0806)   # ARP
    eth_hdr = dst_mac + src_mac + eth_type

    htype = struct.pack('!H', 1)           # Ethernet
    ptype = struct.pack('!H', 0x0800)      # IPv4
    hlen = struct.pack('!B', 6)
    plen = struct.pack('!B', 4)
    opcode = struct.pack('!H', 1)          # request

    arp_hdr = (
        htype + ptype + hlen + plen + opcode +
        src_mac + src_ip +
        b'\x00' * 6 + ip_str_to_bytes(target_ip)
    )

    return eth_hdr + arp_hdr


def parse_arp_reply(frame, expected_ip):
    """Parse ARP reply and return (sender_mac, sender_ip) if matching expected_ip."""
    if len(frame) < 42:
        return None, None
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype != 0x0806:
        return None, None
    arp = frame[14:42]
    htype, ptype, hlen, plen, opcode = struct.unpack('!HHBBH', arp[:8])
    if opcode != 2:
        return None, None
    sender_mac = arp[8:14]
    sender_ip = socket.inet_ntoa(arp[14:18])
    if sender_ip == expected_ip:
        return sender_mac, sender_ip
    return None, None


def main(timeout=5.0):
    iface, gw_ip = get_default_gateway()
    print(f"Default interface: {iface}, gateway: {gw_ip}")

    iface_ip = get_iface_ip(iface)
    iface_mac = get_iface_mac(iface)
    print(f"Local IP: {iface_ip}")
    print(f"Local MAC: {iface_mac}")

    src_mac_b = mac_str_to_bytes(iface_mac)
    src_ip_b = ip_str_to_bytes(iface_ip)
    packet = build_arp_request(src_mac_b, src_ip_b, gw_ip)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
    s.bind((iface, 0))

    print(f"Sending ARP request for {gw_ip} ...")
    s.send(packet)

    end = time.time() + timeout
    while time.time() < end:
        frame = s.recv(65535)
        mac_bytes, sender_ip = parse_arp_reply(frame, gw_ip)
        if mac_bytes:
            mac_str = ':'.join(f'{b:02x}' for b in mac_bytes)
            print(f"Gateway {sender_ip} is at {mac_str}")
            s.close()
            return mac_str

    s.close()
    raise TimeoutError(f"No ARP reply from {gw_ip} within {timeout} seconds")


if __name__ == "__main__":
    try:
        mac = main()
    except Exception as e:
        print("Error:", e)
