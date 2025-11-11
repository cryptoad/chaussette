#!/usr/bin/env python3
"""
arp_lookup_proxy.py

Usage: run as root. Reads HTTP_PROXY env var and performs an ARP request
for the proxy IP using raw sockets, printing the resolved MAC address.

Author: ChatGPT (example)
"""
import os
import socket
import struct
import fcntl
import time
import sys
from urllib.parse import urlparse

# ioctl constants
SIOCGIFCONF = 0x8912
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

def parse_http_proxy_env():
    env = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not env:
        raise SystemExit("HTTP_PROXY not set in environment")
    # allow bare ip:port or full URL
    if "://" not in env:
        env = "http://" + env
    p = urlparse(env)
    host = p.hostname
    port = p.port
    if not host:
        raise SystemExit("Could not parse proxy host from HTTP_PROXY")
    return host, port

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def mac_str_to_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(':'))

def bytes_to_mac(b):
    return ':'.join(f"{x:02x}" for x in b)

def get_local_ip_for_dest(dest_ip):
    """Create UDP socket to dest and read local socket name to learn source IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # use an unlikely port; doesn't send packets on connect for UDP
        s.connect((dest_ip, 9))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

def get_interfaces():
    """Return list of (ifname, ip_str, mac_str) for interfaces that have IPv4 addrs."""
    max_bytes = 4096
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array_bytes = None
    # build buffer for SIOCGIFCONF
    buf = struct.pack('iL', max_bytes, 0)
    import array
    names = array.array('b', b'\0' * max_bytes)
    # call ioctl
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFCONF, struct.pack('iL', max_bytes, names.buffer_info()[0]))
    except OSError as e:
        raise SystemExit(f"Could not call ioctl SIOCGIFCONF: {e}")
    # parse returned buffer length
    out_bytes = struct.unpack('iL', res)[0]
    raw = names.tobytes()[:out_bytes]
    interfaces = []
    entry_size = 40  # typical size on Linux for ifreq (depends; 40 is common)
    for i in range(0, len(raw), entry_size):
        entry = raw[i:i+entry_size]
        if len(entry) < 16:
            continue
        ifname = entry[:16].split(b'\0', 1)[0].decode('utf-8', errors='ignore')
        ip_bytes = entry[20:24]
        ip_str = socket.inet_ntoa(ip_bytes)
        # get hwaddr
        try:
            hw = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname.encode('utf-8')))
            mac = ':'.join(f"{b:02x}" for b in hw[18:24])
        except OSError:
            mac = None
        interfaces.append((ifname, ip_str, mac))
    s.close()
    return interfaces

def find_interface_by_ip(local_ip):
    ifaces = get_interfaces()
    for ifname, ip, mac in ifaces:
        if ip == local_ip:
            return ifname, ip, mac
    return None

def build_arp_request(src_mac_bytes, src_ip_bytes, target_ip_bytes):
    # Ethernet header: DST(6) SRC(6) ETHERTYPE(2)
    dst_mac = b'\xff' * 6
    ethertype = struct.pack('!H', 0x0806)  # ARP
    eth_hdr = dst_mac + src_mac_bytes + ethertype
    # ARP payload:
    # htype(2)=1, ptype(2)=0x0800, hlen(1)=6, plen(1)=4, opcode(2)=1 (request)
    arp_hdr = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
    sender_mac = src_mac_bytes
    sender_ip = src_ip_bytes
    target_mac = b'\x00' * 6
    target_ip = target_ip_bytes
    arp_payload = arp_hdr + sender_mac + sender_ip + target_mac + target_ip
    return eth_hdr + arp_payload

def send_arp_and_listen(ifname, src_mac, src_ip, target_ip, timeout=3.0):
    # open raw AF_PACKET socket bound to interface
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
    try:
        raw.bind((ifname, 0))
    except PermissionError:
        raise SystemExit("Must run as root to bind AF_PACKET raw socket")
    src_mac_bytes = mac_str_to_bytes(src_mac)
    src_ip_bytes = ip_to_bytes(src_ip)
    target_ip_bytes = ip_to_bytes(target_ip)
    frame = build_arp_request(src_mac_bytes, src_ip_bytes, target_ip_bytes)
    raw.send(frame)
    # listen loop for reply
    end = time.time() + timeout
    while time.time() < end:
        raw.settimeout(end - time.time())
        try:
            packet = raw.recv(65535)
        except socket.timeout:
            break
        # parse ethernet header
        if len(packet) < 42:
            continue
        eth_proto = struct.unpack('!H', packet[12:14])[0]
        if eth_proto != 0x0806:  # ARP
            continue
        arp = packet[14:14+28]
        (htype, ptype, hlen, plen, opcode) = struct.unpack('!HHBBH', arp[:8])
        if opcode != 2:  # ARP reply
            continue
        sender_mac = arp[8:14]
        sender_ip = socket.inet_ntoa(arp[14:18])
        target_ip_received = socket.inet_ntoa(arp[24:28])
        if sender_ip == target_ip and target_ip_received == src_ip:
            return bytes_to_mac(sender_mac)
    return None

def get_iface_mac_from_sys(ifname):
    try:
        path = f"/sys/class/net/{ifname}/address"
        with open(path, 'r') as f:
            return f.read().strip().lower()
    except Exception:
        return None

def main():
    proxy_ip, proxy_port = parse_http_proxy_env()
    print(f"Proxy IP: {proxy_ip} Port: {proxy_port}")
    try:
        local_ip = get_local_ip_for_dest(proxy_ip)
    except Exception as e:
        raise SystemExit(f"Could not determine local IP for route to {proxy_ip}: {e}")
    print(f"Local IP used to reach proxy: {local_ip}")

    iface_info = find_interface_by_ip(local_ip)
    if not iface_info:
        raise SystemExit(f"Could not find interface with IP {local_ip}")
    ifname, if_ip, if_mac = iface_info
    # if ioctl didn't give mac, try sysfs
    if not if_mac or if_mac == '00:00:00:00:00:00':
        if_mac = get_iface_mac_from_sys(ifname)
    if not if_mac:
        raise SystemExit(f"Could not determine MAC for interface {ifname}")

    print(f"Using interface: {ifname} MAC: {if_mac}")

    print(f"Sending ARP request for {proxy_ip} on {ifname}...")
    resolved = send_arp_and_listen(ifname, if_mac, local_ip, proxy_ip, timeout=4.0)
    if resolved:
        print(f"Resolved {proxy_ip} -> {resolved}")
    else:
        print(f"No ARP reply for {proxy_ip} received (timeout).")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
