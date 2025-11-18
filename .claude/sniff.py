#!/usr/bin/env python3
import socket
import struct
import time
import subprocess
import sys

PROTO_NAMES = {
    1:  "ICMP",
    2:  "IGMP",
    4:  "IP-in-IP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

def get_local_ips():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    return set(out.split())

LOCAL_IPS = get_local_ips()
print("Local IPs:", LOCAL_IPS)

def mac_addr(raw):
    return ":".join(f"{b:02x}" for b in raw)

def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0

    # ETH_P_ALL = 3 (network byte order)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print(f"\nCapturing ANY IPv4 protocol for {duration} seconds...\n")
    end = time.time() + duration

    # === Aggregation structures ===
    ip_to_mac = {}                     # "1.2.3.4" → "aa:bb:cc:dd:ee:ff"
    protocol_ports = {}               # proto → set of (src_port, dst_port)

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)
        if len(packet) < 34:
            continue

        # Ethernet header
        dst_mac = mac_addr(packet[0:6])
        src_mac = mac_addr(packet[6:12])
        eth_type = struct.unpack("!H", packet[12:14])[0]

        if eth_type != 0x0800:  # IPv4 only
            continue

        # IP header
        ip_start = 14
        if len(packet) < ip_start + 20:
            continue

        ip_header = packet[ip_start:ip_start+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version = iph[0] >> 4
        ihl = (iph[0] & 0x0F) * 4
        protocol = iph[6]

        if version != 4:
            continue

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        # Skip local↔local
        if src_ip in LOCAL_IPS and dst_ip in LOCAL_IPS:
            continue

        # Record IP→MAC (first seen)
        if src_ip not in ip_to_mac:
            ip_to_mac[src_ip] = src_mac
        if dst_ip not in ip_to_mac:
            ip_to_mac[dst_ip] = dst_mac

        # Extract ports for TCP/UDP
        if protocol in (6, 17):  # TCP or UDP
            l4_start = ip_start + ihl
            if len(packet) >= l4_start + 4:
                src_port, dst_port = struct.unpack("!HH", packet[l4_start:l4_start+4])
                protocol_ports.setdefault(protocol, set()).add((src_port, dst_port))
        else:
            # For other protocols track that they were seen; no ports
            protocol_ports.setdefault(protocol, set())

    # === Summary Output ===

    print("\n=== Unique IP → MAC mappings seen ===")
    for ip, mac in ip_to_mac.items():
        print(f"{ip:15s}  {mac}")

    print("\n=== Protocols and ports seen ===")
    for proto, ports in protocol_ports.items():
        name = PROTO_NAMES.get(proto, f"PROTO-{proto}")
        if proto in (6, 17):
            print(f"{name} ({proto}):")
            for sp, dp in sorted(ports):
                print(f"    {sp} → {dp}")
        else:
            print(f"{name} ({proto}) (no ports)")

    print("\nDone.\n")

if __name__ == "__main__":
    main()
