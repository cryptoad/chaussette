#!/usr/bin/env python3
import subprocess
import socket
import struct
import fcntl
import os
import time

ETH_P_IP = 0x0800
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

COMMON_TCP_PORTS = [
    20, 21,             # FTP
    22,                 # SSH
    23,                 # Telnet
    25,                 # SMTP
    53,                 # DNS (TCP)
    67, 68,             # DHCP
    69,                 # TFTP
    80,                 # HTTP
    110,                # POP3
    111,                # RPCbind
    119,                # NNTP
    123,                # NTP
    135, 137, 138, 139, # NetBIOS / SMB
    143,                # IMAP
    161, 162,           # SNMP
    389,                # LDAP
    443,                # HTTPS
    445,                # SMB
    465,                # SMTPS
    514,                # Syslog
    587,                # SMTP Submission
    631,                # IPP / CUPS
    636,                # LDAPS
    873,                # rsync
    993, 995,           # IMAPs / POP3s
    1080,               # SOCKS proxy
    1433, 1521,         # MSSQL / Oracle
    2049,               # NFS
    2181,               # Zookeeper
    2379, 2380,         # etcd
    3306,               # MySQL
    3389,               # RDP
    3690,               # SVN
    4443,               # HTTPS alt
    4500,               # IPsec NAT-T
    5000, 5001,         # misc services
    5432,               # PostgreSQL
    5672,               # RabbitMQ
    5900,               # VNC
    6080, 6081,         # noVNC
    6379,               # Redis
    6443,               # Kubernetes API
    6667,               # IRC
    7001,               # WebLogic
    8000, 8008, 8080,   # HTTP alt
    8443,               # HTTPS alt
    8883,               # MQTT over TLS
    9000, 9001,         # misc services
    9092,               # Kafka
    11211,              # Memcached
    15004               # <– your custom port
]

SCAN_PORTS = COMMON_TCP_PORTS
SCAN_TIMEOUT = 0.15
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
        0xfe80,
        (eui64[0] << 8) | eui64[1],
        (eui64[2] << 8) | eui64[3],
        (eui64[4] << 8) | eui64[5],
        (eui64[6] << 8) | eui64[7],
    ]
    addr = ":".join(f"{p:x}" for p in parts)
    return addr


def scan_ipv6_ports(addr, iface, ports, timeout=SCAN_TIMEOUT):
    print(f"\n[+] Scanning IPv6 {addr}%{iface}...")
    scope_id = socket.if_nametoindex(iface)

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((addr, port, 0, scope_id))
            s.close()
            if r == 0:
                print(f"  [OPEN] {port}")
        except:
            pass


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
