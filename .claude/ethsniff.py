#!/usr/bin/env python3
import socket
import time

def main():
    # Create a raw AF_PACKET socket to capture all Ethernet frames
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Capturing packets for 10 seconds...")
    end = time.time() + 10

    while time.time() < end:
        packet, addr = sock.recvfrom(65535)
        print(f"Captured packet: {len(packet)} bytes")

    print("Done.")

if __name__ == "__main__":
    main()
