#!/usr/bin/env python3
import socket
import struct
import time
import subprocess
import sys

DISPLAY_LEN = 128

def get_local_ips():
    """Return a set of all local IPs from hostname -I."""
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    return set(out.split())

LOCAL_IPS = get_local_ips()
print("Local IPs:", LOCAL_IPS)

def mac_addr(raw):
    """Convert 6-byte binary MAC to human-readable form."""
    return ":".join(f"{b:02x}" for b in raw)

def hexdump(data):
    data = data[:DISPLAY_LEN]
    hex_bytes = data.hex()
    byte_list = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]
    lines = []

    for i in range(0, len(byte_list), 16):
        lines.append(" ".join(byte_list[i:i+16]))

    return "\n".join(lines)

def main():
    # Parse duration argument
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print(f"\nCapturing TCP/UDP packets for {duration} seconds...\n")
    end = time.time() + duration

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)
        if len(packet) < 34:
            continue

        # --- Ethernet header ---
        dst_mac = mac_addr(packet[0:6])
        src_mac = mac_addr(packet[6:12])
        eth_type = struct.unpack("!H", packet[12:14])[0]

        if eth_type != 0x0800:  # Only IPv4
            continue

        # --- IP header ---
        ip_start = 14
        ip_header = packet[ip_start:ip_start+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        ihl = (iph[0] & 0x0F) * 4
        protocol = iph[6]  # 6 = TCP, 17 = UDP

        if protocol not in (6, 17):
            continue

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        proto_name = "TCP" if protocol == 6 else "UDP"
        print(f"\n[{proto_name}] {src_ip} ({src_mac})  →  {dst_ip} ({dst_mac})")

        # Only display content if it is local traffic
        if src_ip in LOCAL_IPS or dst_ip in LOCAL_IPS:
            continue

        # --- Extract IP layer and above ---
        ip_and_up = packet[ip_start:]

        print(f"--- Showing first {DISPLAY_LEN} bytes of IP-layer data ---")
        print(hexdump(ip_and_up))

    print("\nDone.")

if __name__ == "__main__":
    main()
