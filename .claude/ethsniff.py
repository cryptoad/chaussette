#!/usr/bin/env python3
import socket
import time

def hexdump(data):
    out_lines = []
    hex_bytes = data.hex()

    # hex_bytes is a continuous string like "aabbcc..."
    # Convert into groups of 2 chars ("aa", "bb", ...)
    bytes_list = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]

    # 16 bytes per line
    for i in range(0, len(bytes_list), 16):
        line_bytes = bytes_list[i:i+16]
        out_lines.append(" ".join(line_bytes))

    return "\n".join(out_lines)

def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Capturing packets for 5 seconds...\n")
    end = time.time() + 5

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)
        print(f"\n=== Packet ({len(packet)} bytes) ===")
        print(hexdump(packet))

    print("\nDone.")

if __name__ == "__main__":
    main()
