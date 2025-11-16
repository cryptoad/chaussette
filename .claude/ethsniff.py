#!/usr/bin/env python3
import socket
import time
import textwrap

def hexdump(data):
    hexstr = data.hex()
    # group hex bytes: "aa bb cc ..."
    grouped = " ".join(textwrap.wrap(hexstr, 2))
    # split into lines of 16 bytes
    lines = textwrap.wrap(grouped, 16 * 3)  # "xx "*16 = 48 chars (+ spaces)
    return "\n".join(lines)

def main():
    # Raw AF_PACKET socket to capture all Ethernet frames
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
