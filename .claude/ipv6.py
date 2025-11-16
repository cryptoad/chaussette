#!/usr/bin/env python3
import subprocess
import socket
import struct
import fcntl
import os
import time

ETH_P_ARP = 0x0806  # ARP ethertype
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

SCAN_PORTS = list(range(1, 201))  # ~200 "known" ports (1-200)
SCAN_TIMEOUT = 0.15               # seconds per port (adjust if needed)
ARP_SNIFF_TIMEOUT = 5.0           # seconds to wait for ARP reply


def get_local_ipv4_from_hostname():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    for token in out.split():
        if "." in token and not token.startswith("127."):
            return token
    raise RuntimeError("No non-loopback IPv4 address found from hostname -I")


def get_iface_ipv4(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    ip = socket.inet_ntoa(res[20:24])
    s.close()
    return ip


def get_default_gateway_for_ip(local_ip):
    """
    Parse /proc/net/route to find the default gateway for the interface
    whose IPv4 address matches local_ip.
    """
    with open("/proc/net/route", "r") as f:
        lines = f.readlines()[1:]  # skip header

    routes = [l.strip().split() for l in lines if l.strip()]

    # First try to match interface IP to the local_ip
    for fields in routes:
        iface, dest_hex, gw_hex, flags_hex = fields[0], fields[1], fields[2], fields[3]
        flags = int(flags_hex, 16)
        # Destination 0.0.0.0 and GATEWAY flag
        if dest_hex != "00000000" or not (flags & 0x2):
            continue
        try:
            iface_ip = get_iface_ipv4(iface)
        except OSError:
            continue
        if iface_ip == local_ip:
            gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
            return iface, gw

    # Fallback: first default route
    for fields in routes:
        iface, dest_hex, gw_hex, flags_hex = fields[0], fields[1], fields[2], fields[3]
        flags = int(flags_hex, 16)
        if dest_hex != "00000000" or not (flags & 0x2):
            continue
        gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
        return iface, gw

    raise RuntimeError("No default gateway found in /proc/net/route")


def get_local_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    s.close()
    mac = res[18:24]
    return mac  # 6 bytes


def bytes_to_mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def trigger_arp_to_gateway(gw_ip, iface):
    """
    Send a dummy UDP packet to the gateway to ensure the kernel
    generates ARP traffic we can sniff.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Binding to the interface is optional but can help
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        except OSError:
            pass
        s.settimeout(1.0)
        # Port doesn't matter; packet will likely be dropped by gateway anyway
        s.sendto(b"\x00", (gw_ip, 9))
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def sniff_gateway_mac(iface, gw_ip, timeout=ARP_SNIFF_TIMEOUT):
    """
    Use an AF_PACKET RAW socket to sniff ARP replies and extract
    the MAC for the gateway IP.
    """
    # Open raw socket bound to interface, ARP protocol
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((iface, 0))
    s.settimeout(timeout)

    start = time.time()
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            break
        s.settimeout(remaining)
        try:
            pkt, addr = s.recvfrom(65535)
        except socket.timeout:
            break

        if len(pkt) < 42:
            continue

        eth_type = struct.unpack("!H", pkt[12:14])[0]
        if eth_type != ETH_P_ARP:
            continue

        arp = pkt[14:]
        if len(arp) < 28:
            continue

        htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", arp[:8])
        # We want ARP reply (oper == 2), IPv4, MAC length 6, IP length 4
        if oper != 2 or ptype != 0x0800 or hlen != 6 or plen != 4:
            continue

        sha = arp[8:14]   # sender hardware address
        spa = arp[14:18]  # sender protocol address (IPv4)
        spa_str = socket.inet_ntoa(spa)

        if spa_str == gw_ip:
            s.close()
            return sha

    s.close()
    return None


def mac_to_ipv6_link_local(mac_bytes):
    """
    Convert a 6-byte MAC to an IPv6 link-local address using EUI-64:
      fe80::xxxx:xxxx:xxxx:xxxx
    """
    if len(mac_bytes) != 6:
        raise ValueError("MAC must be 6 bytes")

    mac = bytearray(mac_bytes)
    # Flip the U/L bit
    mac[0] ^= 0x02

    eui64 = bytearray(8)
    eui64[0:3] = mac[0:3]
    eui64[3:5] = b"\xff\xfe"
    eui64[5:8] = mac[3:6]

    # Format as standard IPv6 link-local
    parts = [
        0xfe80,
        (eui64[0] << 8) | eui64[1],
        (eui64[2] << 8) | eui64[3],
        (eui64[4] << 8) | eui64[5],
        (eui64[6] << 8) | eui64[7],
    ]
    # Compress zero groups minimally; here we just use standard formatting, no clever compression
    addr = ":".join(f"{p:x}" for p in parts)
    return addr


def scan_ipv6_ports(addr, iface, ports, timeout=SCAN_TIMEOUT):
    """
    Perform a simple TCP connect scan on the given IPv6 link-local address.
    """
    print(f"\n[+] Scanning IPv6 {addr}%{iface} on {len(ports)} ports...")
    scope_id = socket.if_nametoindex(iface)

    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(timeout)
            # (address, port, flowinfo, scope_id)
            res = s.connect_ex((addr, port, 0, scope_id))
            s.close()
            if res == 0:
                print(f"  [OPEN] {port}")
                open_ports.append(port)
        except Exception:
            # Treat errors as closed/filtered and continue
            continue

    print("\nScan complete.")
    if open_ports:
        print("Open ports:", ", ".join(str(p) for p in open_ports))
    else:
        print("No open ports detected (within timeout constraints).")


def main():
    if os.geteuid() != 0:
        print("This script must be run as root (for raw AF_PACKET socket).")
        return

    local_ip = get_local_ipv4_from_hostname()
    iface, gw_ip = get_default_gateway_for_ip(local_ip)

    print(f"[+] Local IPv4:      {local_ip}")
    print(f"[+] Interface:       {iface}")
    print(f"[+] Gateway IPv4:    {gw_ip}")

    local_mac = get_local_mac(iface)
    print(f"[+] Local MAC:       {bytes_to_mac_str(local_mac)}")

    print("\n[+] Triggering ARP to gateway and sniffing for its MAC...")
    trigger_arp_to_gateway(gw_ip, iface)
    gw_mac = sniff_gateway_mac(iface, gw_ip)

    if not gw_mac:
        print("[-] Failed to discover gateway MAC via ARP sniffing.")
        return

    print(f"[+] Gateway MAC:     {bytes_to_mac_str(gw_mac)}")

    # Build IPv6 link-local addresses from MACs
    local_ll = mac_to_ipv6_link_local(local_mac)
    gw_ll = mac_to_ipv6_link_local(gw_mac)

    print(f"\n[+] Local link-local IPv6 (derived):   {local_ll}%{iface}")
    print(f"[+] Gateway link-local IPv6 (derived): {gw_ll}%{iface}")

    # Now scan ~200 ports on the gateway's IPv6 link-local
    scan_ipv6_ports(gw_ll, iface, SCAN_PORTS, timeout=SCAN_TIMEOUT)


if __name__ == "__main__":
    main()
