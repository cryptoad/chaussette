#!/usr/bin/env python3
import socket
import struct
import time

TARGET_PORT = 15004
DISPLAY_LEN = 128

def hexdump(data):
    data = data[:DISPLAY_LEN]
    hex_bytes = data.hex()
    byte_list = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]

    lines = []
    for i in range(0, len(byte_list), 16):   # 16 bytes per line
        lines.append(" ".join(byte_list[i:i+16]))

    return "\n".join(lines)

def main():
    # Raw Ethernet socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print(f"Capturing TCP packets to port {TARGET_PORT} for 10 seconds...\n")
    end = time.time() + 10

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)

        # Must contain at least Ethernet(14) + IP
        if len(packet) < 34:
            continue

        # --- Ethernet type ---
        eth_type = struct.unpack("!H", packet[12:14])[0]
        if eth_type != 0x0800:  # IPv4 only
            continue

        # --- Parse IP header ---
        ip_header_start = 14
        ip_header = packet[ip_header_start:ip_header_start+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        ihl = (iph[0] & 0x0F) * 4
        protocol = iph[6]

        if protocol != 6:   # not TCP
            continue

        # --- Parse TCP header ---
        tcp_start = ip_header_start + ihl
        if len(packet) < tcp_start + 20:
            continue

        tcp_header = packet[tcp_start:tcp_start+20]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        dst_port = tcph[1]

        if dst_port != TARGET_PORT:
            continue

        # --- Extract IP layer and above ---
        ip_and_up = packet[ip_header_start:]

        print(f"\n=== TCP Packet to {TARGET_PORT} "
              f"(IP layer size: {len(ip_and_up)} bytes) ===")
        print(hexdump(ip_and_up))

    print("\nDone.")

if __name__ == "__main__":
    main()
