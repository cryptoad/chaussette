#!/usr/bin/env python3
"""
ARP scan using the IPv4 from `hostname -I`.

- Picks the first IPv4 address returned by `hostname -I`.
- Finds the interface that has that address.
- Scans the /24 that contains that IP (all host addresses).
- Uses AF_PACKET raw sockets with explicit EtherType to avoid Errno 95.
- No 3rd-party libraries. Linux only. Must be run as root.
"""
import os
import sys
import socket
import struct
import fcntl
import ipaddress
import time
import select
from typing import Dict, List, Tuple

# ioctls
SIOCGIFHWADDR = 0x8927
SIOCGIFADDR   = 0x8915

ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003

def run_cmd_hostname_I() -> List[str]:
    """Return whitespace-separated tokens from `hostname -I`"""
    try:
        out = os.popen("hostname -I").read().strip()
    except Exception:
        out = ""
    if not out:
        return []
    return out.split()

def pick_first_ipv4(addrs: List[str]) -> str:
    for a in addrs:
        try:
            socket.inet_aton(a)
            # valid IPv4
            if a != "127.0.0.1":
                return a
        except OSError:
            continue
    raise SystemExit("No IPv4 address found from `hostname -I`")

def ifname_to_bytes(ifname: str) -> bytes:
    return ifname.encode('utf-8')[:15].ljust(16, b'\x00')

def get_iface_ipv4(ifname: str) -> str:
    """Return IPv4 address assigned to interface (raises on failure)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('256s', ifname.encode('utf-8'))
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    finally:
        s.close()
    ip_bytes = res[20:24]
    return socket.inet_ntoa(ip_bytes)

def get_iface_mac(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('16sH14s', ifname.encode('utf-8'), 0, b'')
        res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    finally:
        s.close()
    mac = res[18:24]
    return ':'.join(f'{b:02x}' for b in mac)

def find_iface_for_ip(ipv4: str) -> str:
    """
    Iterate interfaces from /sys/class/net (fallback to socket.if_nameindex),
    calling ioctl to obtain their IPv4, and match to ipv4. Returns interface name.
    """
    # primary source: /sys/class/net
    if os.path.isdir("/sys/class/net"):
        for ifname in os.listdir("/sys/class/net"):
            if ifname == "lo":
                continue
            try:
                addr = get_iface_ipv4(ifname)
            except OSError:
                continue
            if addr == ipv4:
                return ifname
    # fallback: socket.if_nameindex()
    try:
        for _, ifname in socket.if_nameindex():
            if ifname == "lo":
                continue
            try:
                addr = get_iface_ipv4(ifname)
            except OSError:
                continue
            if addr == ipv4:
                return ifname
    except Exception:
        pass
    raise SystemExit(f"Could not find interface for IP {ipv4}")

def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))

def ip_str_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)

def build_arp_request(src_mac: bytes, src_ip: bytes, target_ip: bytes) -> bytes:
    # Ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    ethertype = struct.pack('!H', ETH_P_ARP)
    eth_hdr = dst_mac + src_mac + ethertype
    # ARP payload: htype=1, ptype=0x0800, hlen=6, plen=4, opcode=1 (request)
    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    opcode = 1
    target_mac = b'\x00'*6
    arp_payload = struct.pack('!HHBBH6s4s6s4s',
                              htype, ptype, hlen, plen, opcode,
                              src_mac, src_ip, target_mac, target_ip)
    return eth_hdr + arp_payload

def parse_arp_reply(frame: bytes) -> Tuple[str, str]:
    """
    Parse Ethernet+ARP reply and return (ip_str, mac_str) for the sender.
    Returns ("", "") if not an ARP reply.
    """
    if len(frame) < 14 + 28:
        return "", ""
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype != ETH_P_ARP:
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

def expand_targets_from_ip_ipv4_cidr(ipv4: str, cidr: int = 24) -> List[str]:
    net = ipaddress.ip_network(f"{ipv4}/{cidr}", strict=False)
    return [str(ip) for ip in net.hosts()]

def send_arp_requests(iface: str, src_mac: str, src_ip: str, targets: list[str]) -> None:
    """
    Create AF_PACKET socket with ETH_P_ARP and send ARP requests via send().
    Some kernels/interfaces reject sendto() with (iface, proto), so we just bind + send().
    """
    proto = socket.htons(ETH_P_ARP)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, proto)
    try:
        raw.bind((iface, 0))
    except Exception as e:
        raw.close()
        raise SystemExit(f"Failed to bind AF_PACKET socket to {iface}: {e}")

    src_mac_b = mac_str_to_bytes(src_mac)
    src_ip_b = ip_str_to_bytes(src_ip)

    for t in targets:
        pkt = build_arp_request(src_mac_b, src_ip_b, ip_str_to_bytes(t))
        # Just send() after binding – no sendto() arguments
        try:
            raw.send(pkt)
        except OSError as e:
            print(f"[!] send() failed for {t}: {e}")
    raw.close()

def listen_for_replies(iface: str, timeout: float = 3.0) -> Dict[str, str]:
    """
    Listen for ARP replies using ETH_P_ALL so we capture frames reliably.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((iface, 0))
    except Exception as e:
        sock.close()
        raise SystemExit(f"Failed to bind sniff socket to {iface}: {e}")
    sock.setblocking(0)
    end = time.time() + timeout
    results: Dict[str, str] = {}
    while time.time() < end:
        remaining = end - time.time()
        r, _, _ = select.select([sock], [], [], remaining)
        if not r:
            break
        try:
            frame = sock.recv(65536)
        except Exception:
            continue
        ip, mac = parse_arp_reply(frame)
        if ip and mac:
            results[ip] = mac
    sock.close()
    return results

def main():
    if os.geteuid() != 0:
        print("This script must be run as root (or with CAP_NET_RAW). Exiting.", file=sys.stderr)
        sys.exit(1)

    addrs = run_cmd_hostname_I()
    if not addrs:
        raise SystemExit("`hostname -I` returned no addresses.")
    my_ipv4 = pick_first_ipv4(addrs)
    print(f"[+] Picked IPv4 from hostname -I: {my_ipv4}")

    iface = find_iface_for_ip(my_ipv4)
    print(f"[+] Found interface for IP {my_ipv4}: {iface}")

    try:
        my_mac = get_iface_mac(iface)
    except Exception as e:
        raise SystemExit(f"Could not get MAC for interface {iface}: {e}")
    print(f"[+] Interface {iface} MAC: {my_mac}")

    targets = expand_targets_from_ip_ipv4_cidr(my_ipv4, cidr=24)
    print(f"[+] Scanning /24: {len(targets)} hosts (this excludes network & broadcast) ...")

    # send ARP requests then listen for replies
    send_arp_requests(iface, my_mac, my_ipv4, targets)
    results = listen_for_replies(iface, timeout=4.0)

    print("[+] ARP scan results:")
    for ip in sorted(results.keys(), key=lambda x: tuple(map(int, x.split('.')))):
        print(f"    {ip} -> {results[ip]}")

    if not results:
        print("No replies received. Possible reasons: interface issue, off-LAN targets, firewall, or running in a restricted environment (container/WSL).")

if __name__ == "__main__":
    main()
