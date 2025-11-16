#!/usr/bin/env python3
import socket
import time

def hexdump(data):
    # limit to first 48 bytes
    data = data[:48]

    hex_bytes = data.hex()
    byte_list = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]

    lines = []
    for i in range(0, len(byte_list), 16):  # 16 bytes per line
        line = " ".join(byte_list[i:i+16])
        lines.append(line)

    return "\n".join(lines)

def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Capturing packets for 3 seconds...\n")
    end = time.time() + 3

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)
        print(f"\n=== Packet ({len(packet)} bytes, showing first 48) ===")
        print(hexdump(packet))

    print("\nDone.")

if __name__ == "__main__":
    main()
