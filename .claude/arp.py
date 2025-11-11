#!/usr/bin/env python3
"""
Scan /24 for MAC addresses without 3rd-party libs.
Method: provoke kernel ARP by sending UDP datagrams, then read /proc/net/arp.

Notes:
- Works best when your container can send L2 ARP requests; in heavy sandboxes (gVisor) it may fail.
- No raw sockets used (no root required).
"""

import subprocess
import socket
import time
import sys
import re

def get_ip_from_hostname_I():
    try:
        out = subprocess.check_output(["hostname", "-I"], stderr=subprocess.DEVNULL, text=True).strip()
        if not out:
            return None
        # choose first IPv4-looking token
        for token in out.split():
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
                return token
    except Exception:
        return None

def get_default_ipv4():
    # fallback: make UDP socket to public server to learn our source IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't actually send network traffic (no connect handshake) but sets local addr
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def parse_arp_table():
    arp = {}
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.read().splitlines()
    except Exception:
        return arp
    if not lines:
        return arp
    # header: IP address       HW type     Flags       HW address            Mask     Device
    for line in lines[1:]:
        cols = line.split()
        if len(cols) >= 6:
            ip = cols[0]
            mac = cols[3]
            dev = cols[5]
            # ignore incomplete entries
            if mac != "00:00:00:00:00:00" and re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', mac, re.I):
                arp[ip] = (mac.lower(), dev)
    return arp

def probe_subnet(base3, port=65212, timeout=0.01):
    """Send a small UDP packet to each host in base3.* (1..254)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    # we don't need to receive; kernel will try ARP on sendto
    for i in range(1, 255):
        ip = f"{base3}.{i}"
        try:
            sock.sendto(b'', (ip, port))
        except BlockingIOError:
            # non-blocking might raise this; that's fine
            pass
        except OSError:
            # network unreachable, etc. keep going
            pass
    # small pause to let kernel populate the ARP cache
    time.sleep(0.15)
    sock.close()

def main():
    ip = get_ip_from_hostname_I()
    if not ip:
        ip = get_default_ipv4()
    if not ip:
        print("Could not determine a usable IPv4 address (hostname -I failed and fallback failed).", file=sys.stderr)
        sys.exit(1)

    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        print(f"Address from hostname -I is not IPv4: {ip!r}", file=sys.stderr)
        sys.exit(1)

    octets = ip.split(".")
    base3 = ".".join(octets[:3])
    print(f"Local IP: {ip}  -> scanning subnet: {base3}.0/24")
    print("Probing hosts (this sends harmless UDP datagrams)...")

    probe_subnet(base3)

    arp = parse_arp_table()
    found = {ip: (mac, dev) for ip, (mac, dev) in arp.items() if ip.startswith(base3 + ".")}
    if not found:
        print("No MAC addresses discovered in ARP cache for this /24. Possible reasons:")
        print("- Kernel ARP requests blocked by container/sandbox")
        print("- Hosts didn't respond (down) or ARP cache was flushed")
        sys.exit(0)

    print("\nDiscovered MAC addresses in /24:")
    for host in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac, dev = found[host]
        print(f"{host}\t{mac}\tiface={dev}")

if __name__ == "__main__":
    main()
