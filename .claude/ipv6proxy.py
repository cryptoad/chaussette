#!/usr/bin/env python3
"""
Read HTTP_PROXY from env, ARP the target IP to get MAC (scapy),
build IPv6 link-local from MAC (EUI-64), then try TCP connect to that IPv6:15004.
Linux-only (uses scapy/AF_PACKET and socket.if_nametoindex for scope id).
Run as root.
"""
import os
import sys
import socket
import ipaddress
from urllib.parse import urlparse

from scapy.all import srp, Ether, ARP, conf

def parse_http_proxy_env():
    # accept HTTP_PROXY or http_proxy
    val = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    if not val:
        raise SystemExit("HTTP_PROXY (or http_proxy) not set in environment")
    # Accept forms:
    # - http://1.2.3.4:8080
    # - 1.2.3.4:8080
    # - 1.2.3.4
    # - http://[fe80::abcd%eth0]:8080  (unlikely here, but keep simple)
    parsed = urlparse(val if '://' in val else f'//{val}', scheme='')  # treat "1.2.3.4:8080" as netloc
    host = parsed.hostname or parsed.path  # path fallback if urlparse put it there
    port = parsed.port
    if not host:
        raise SystemExit(f"Could not parse host from HTTP_PROXY='{val}'")
    return host, port

def mac_str_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':','').replace('-',''))

def mac_to_eui64(mac_bytes):
    """
    Convert 6-byte MAC to 8-byte EUI-64 per RFC:
     1) flip the universal/local bit (bit 1 of the first octet -> xor 0x02)
     2) insert 0xff,0xfe in the middle
    """
    if len(mac_bytes) != 6:
        raise ValueError("MAC must be 6 bytes")
    b = bytearray(mac_bytes)
    b[0] ^= 0x02  # flip U/L bit
    eui = bytes(b[0:3]) + b'\xff\xfe' + bytes(b[3:6])
    return eui  # 8 bytes

def eui64_to_ipv6_linklocal(eui64_bytes):
    """
    Build the 16-byte IPv6 address for fe80::/64 + eui64
    """
    if len(eui64_bytes) != 8:
        raise ValueError("EUI-64 must be 8 bytes")
    ip_bytes = b'\xfe\x80' + (b'\x00' * 6) + eui64_bytes
    return ipaddress.IPv6Address(int.from_bytes(ip_bytes, 'big'))

def find_iface_for_target(target_ip):
    """
    Use scapy's routing table to determine outgoing interface for target_ip.
    Returns interface name (e.g. 'eth0').
    """
    # conf.route.route returns (dest, gateway, iface)
    route = conf.route.route(target_ip)
    if route and len(route) >= 3:
        return route[2]
    return None

def do_arp_get_mac(target_ip, iface=None, timeout=2):
    """
    Send an ARP who-has via scapy and return MAC string (like 'aa:bb:cc:dd:ee:ff') or None.
    """
    # send a single ARP request as Ether broadcast / ARP(pdst=target_ip)
    # srp returns (ans, unans)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
    ans, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False)
    if ans and len(ans) > 0:
        # first reply
        reply = ans[0][1]
        return reply.hwsrc.lower()
    return None

def try_connect_ipv6(addr: ipaddress.IPv6Address, port=15004, iface_name=None, timeout=5):
    """
    Attempt TCP connect to IPv6 address (link-local). For link-local we must provide scope id (interface index).
    Returns True if connected, else False and an exception message.
    """
    family = socket.AF_INET6
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if addr.is_link_local and iface_name:
            # need zone index (interface index)
            try:
                scope_id = socket.if_nametoindex(iface_name)
            except OSError as e:
                return False, f"Could not get index for interface '{iface_name}': {e}"
            sockaddr = (str(addr), port, 0, scope_id)
        else:
            sockaddr = (str(addr), port)
        s.connect(sockaddr)
        s.close()
        return True, "Connected"
    except Exception as e:
        return False, str(e)

def main():
    if os.geteuid() != 0:
        print("Warning: this script should be run as root (required for raw/ARP). Continuing may fail.", file=sys.stderr)

    target_ip, target_port = parse_http_proxy_env()
    print(f"Parsed HTTP_PROXY -> IP: {target_ip}  Port: {target_port}")

    # ensure target_ip is IPv4 (we use ARP)
    try:
        socket.inet_aton(target_ip)
    except OSError:
        raise SystemExit("Target from HTTP_PROXY does not look like an IPv4 address; this script expects an IPv4 IP.")

    # determine outgoing interface
    iface = find_iface_for_target(target_ip)
    if not iface:
        print("Could not determine outgoing interface for target IP; falling back to None (scapy will pick one).")
    else:
        print(f"Using interface '{iface}' to reach {target_ip}")

    print(f"Sending ARP request for {target_ip} ...")
    mac = do_arp_get_mac(target_ip, iface=iface, timeout=3)
    if not mac:
        raise SystemExit("No ARP reply received. The target might be off-LAN or not responding to ARP.")

    print(f"Got MAC for {target_ip}: {mac}")

    # convert MAC -> EUI-64 -> link-local IPv6
    mac_bytes = mac_str_to_bytes(mac)
    eui64 = mac_to_eui64(mac_bytes)
    ipv6_ll = eui64_to_ipv6_linklocal(eui64)
    print(f"Constructed link-local IPv6 (unscoped): {ipv6_ll.compressed}")

    # If link-local we must include zone id on connect; determine iface index
    if iface is None:
        # try to choose interface from conf.iface
        iface = conf.iface
        print(f"No route-found iface; using scapy.conf.iface='{iface}'")

    print(f"Attempting TCP connect to [{ipv6_ll.compressed}]:15004 on interface '{iface}' ...")
    ok, msg = try_connect_ipv6(ipv6_ll, port=15004, iface_name=iface, timeout=5)
    if ok:
        print("SUCCESS: Connected to link-local IPv6 on port 15004")
    else:
        print(f"Connect failed: {msg}")

if __name__ == "__main__":
    main()
