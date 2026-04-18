#!/usr/bin/env python3
import socket
import struct
import fcntl
import subprocess
import os
import time

SIOCGIFHWADDR = 0x8927

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY   = 129

# ============================================================
# Helpers
# ============================================================

def get_local_ipv4():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    for x in out.split():
        if "." in x and not x.startswith("127."):
            return x
    raise RuntimeError("no ipv4")

def get_default_iface():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.strip().split()
            if fields[1] == "00000000":
                return fields[0]
    raise RuntimeError("no iface")

def get_iface_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    s.close()
    return res[18:24]

def mac_to_ll(mac):
    mac = bytearray(mac)
    mac[0] ^= 0x02
    eui = mac[:3] + b'\xff\xfe' + mac[3:]
    parts = [(eui[i]<<8) | eui[i+1] for i in range(0,8,2)]
    return "fe80::" + ":".join(f"{p:x}" for p in parts)

# ============================================================
# ICMPv6
# ============================================================

def icmpv6_echo(iface, target):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.settimeout(1.0)

    ident = int(time.time()) & 0xffff
    pkt = struct.pack("!BBHHH", ICMPV6_ECHO_REQUEST, 0, 0, ident, 1) + b"X"

    s.sendto(pkt, (target, 0, 0, socket.if_nametoindex(iface)))

    try:
        data, addr = s.recvfrom(2048)
        if data[0] == ICMPV6_ECHO_REPLY:
            return True, f"reply from {addr}"
        return False, f"type={data[0]}"
    except socket.timeout:
        return False, "timeout"

def udp_probe(iface, target):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(1.0)

    try:
        s.sendto(b"X", (target, 55555, 0, socket.if_nametoindex(iface)))
        data, addr = s.recvfrom(2048)
        return True, f"udp resp {addr}"
    except socket.timeout:
        return False, "no response"
    except Exception as e:
        return False, str(e)

# ============================================================
# Main
# ============================================================

def main():
    if os.geteuid() != 0:
        print("run as root")
        return

    ip = get_local_ipv4()
    iface = get_default_iface()
    mac = get_iface_mac(iface)

    print(f"[+] Local IPv4: {ip}")
    print(f"[+] IFACE:      {iface}")
    print(f"[+] IFACE MAC:  {':'.join(f'{x:02x}' for x in mac)}")

    # In this environment: next-hop MAC == everything
    target_ll = mac_to_ll(mac)

    print(f"[+] Using synthetic next-hop LL: {target_ll}%{iface}")

    tests = [
        ("ICMPv6 Echo (self-derived)", icmpv6_echo),
        ("ICMPv6 all-nodes", lambda i,t: icmpv6_echo(i,"ff02::1")),
        ("ICMPv6 all-routers", lambda i,t: icmpv6_echo(i,"ff02::2")),
        ("UDP probe", udp_probe),
    ]

    for name, fn in tests:
        print(f"\n--- {name} ---")
        ok, info = fn(iface, target_ll)
        print("Result:", "OK" if ok else "FAIL")
        print("Info:  ", info)

if __name__ == "__main__":
    main()
