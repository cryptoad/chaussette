#!/usr/bin/env python3
import subprocess
import socket
import struct
import fcntl
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ETH_P_IP = 0x0800
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

COMMON_TCP_PORTS = [
    20, 21, 22, 23, 25,
    53, 67, 68, 69,
    80, 110, 111, 119, 123,
    135, 137, 138, 139,
    143, 161, 162,
    389, 443, 445, 465, 514, 587,
    631, 636, 873, 993, 995,
    1080, 1433, 1521, 2049,
    2181, 2379, 2380,
    3306, 3389, 3690, 4443, 4500,
    5000, 5001, 5432, 5672,
    5900, 6080, 6081, 6379,
    6443, 6667, 7001,
    8000, 8008, 8080,
    8443, 8883, 9000, 9001,
    9092, 11211,
    15004
]

SCAN_PORTS = COMMON_TCP_PORTS
SCAN_TIMEOUT = 0.2
SNIFF_TIMEOUT = 5.0


def get_local_ipv4_from_hostname():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    for token in out.split():
        if "." in token and not token.startswith("127."):
            return token
    raise RuntimeError("No non-loopback IPv4 address found")


def get_iface_ipv4(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    ip = socket.inet_ntoa(res[20:24])
    s.close()
    return ip


def get_default_gateway_for_ip(local_ip):
    with open("/proc/net/route", "r") as f:
        lines = f.readlines()[1:]

    routes = [l.strip().split() for l in lines if l.strip()]

    for fields in routes:
        iface, dest_hex, gw_hex, flags_hex = fields[0], fields[1], fields[2], fields[3]
        flags = int(flags_hex, 16)
        if dest_hex != "00000000" or not (flags & 0x2):
            continue
        try:
            iface_ip = get_iface_ipv4(iface)
        except OSError:
            continue
        if iface_ip == local_ip:
            gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
            return iface, gw

    for fields in routes:
        iface, dest_hex, gw_hex, flags_hex = fields[0], fields[1], fields[2], fields[3]
        flags = int(flags_hex, 16)
        if dest_hex != "00000000" or not (flags & 0x2):
            continue
        gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
        return iface, gw

    raise RuntimeError("No default gateway found")


def get_local_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    s.close()
    return res[18:24]


def bytes_to_mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def sniff_gateway_mac(iface, gw_ip, timeout=SNIFF_TIMEOUT):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.bind((iface, 0))
    s.settimeout(timeout)

    gw_bytes = socket.inet_aton(gw_ip)
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

        if len(pkt) < 34:
            continue

        eth_src = pkt[6:12]
        eth_dst = pkt[0:6]

        ip_hdr = pkt[14:]
        if ip_hdr[0] >> 4 != 4:
            continue

        src_ip = ip_hdr[12:16]
        dst_ip = ip_hdr[16:20]

        if src_ip == gw_bytes:
            s.close()
            return eth_src, True

        if dst_ip == gw_bytes:
            s.close()
            return eth_dst, False

    s.close()
    return None, None


def mac_to_ipv6_link_local(mac_bytes):
    mac = bytearray(mac_bytes)
    mac[0] ^= 0x02

    eui64 = bytearray(8)
    eui64[0:3] = mac[0:3]
    eui64[3:5] = b"\xff\xfe"
    eui64[5:8] = mac[3:6]

    parts = [
        (eui64[0] << 8) | eui64[1],
        (eui64[2] << 8) | eui64[3],
        (eui64[4] << 8) | eui64[5],
        (eui64[6] << 8) | eui64[7],
    ]
    addr = ":".join(f"{p:x}" for p in parts)
    return f"fe80::{addr}"


# -------------------------------------------------------------
#   PARALLEL SCANNING
# -------------------------------------------------------------
def scan_one_port(scoped_addr, scope_id, port, timeout):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((scoped_addr, port, 0, scope_id))
        s.close()
        if r == 0:
            return port, None  # open
        return None, None
    except Exception as e:
        return None, type(e).__name__


def scan_ipv6_ports(addr, iface, ports, timeout=SCAN_TIMEOUT, workers=100):
    print(f"\n[+] Scanning IPv6 {addr}%{iface}...")
    scope_id = socket.if_nametoindex(iface)
    scoped_addr = f"{addr}%{iface}"

    exception_types = set()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(scan_one_port, scoped_addr, scope_id, port, timeout): port
            for port in ports
        }

        for fut in as_completed(futures):
            port = futures[fut]
            open_port, exc = fut.result()
            if open_port:
                print(f"  [OPEN] {open_port}")
            if exc:
                exception_types.add(exc)

    if exception_types:
        print("\n[!] Exceptions encountered:")
        for t in sorted(exception_types):
            print("   -", t)
    else:
        print("\n[+] No exceptions encountered.")


def main():
    if os.geteuid() != 0:
        print("Must be root")
        return

    local_ip = get_local_ipv4_from_hostname()
    iface, gw_ip = get_default_gateway_for_ip(local_ip)

    print(f"[+] Local IP: {local_ip}")
    print(f"[+] IFACE:    {iface}")
    print(f"[+] GW IPv4:  {gw_ip}")

    local_mac = get_local_mac(iface)
    print(f"[+] Local MAC:   {bytes_to_mac_str(local_mac)}")

    print("[+] Sniffing packets to find gateway MAC...")
    gw_mac, from_src = sniff_gateway_mac(iface, gw_ip)

    if not gw_mac:
        print("[-] Could not discover gateway MAC")
        return

    print(f"[+] GW MAC:      {bytes_to_mac_str(gw_mac)} (from {'source' if from_src else 'dest'})")

    local_ll = mac_to_ipv6_link_local(local_mac)
    gw_ll = mac_to_ipv6_link_local(gw_mac)

    print(f"[+] Local LL IPv6: {local_ll}%{iface}")
    print(f"[+] GW LL IPv6:    {gw_ll}%{iface}")

    scan_ipv6_ports(gw_ll, iface, SCAN_PORTS)


if __name__ == "__main__":
    main()
