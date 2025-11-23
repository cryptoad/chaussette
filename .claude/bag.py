#!/usr/bin/env python3
import subprocess
import socket
import struct
import fcntl
import os
import time
import errno
import threading
from concurrent.futures import ThreadPoolExecutor

ETH_P_IP = 0x0800
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

SCAN_TIMEOUT = 0.3
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
ICMPV6_NS = 135
ICMPV6_NA = 136
ICMPV6_TIME_EXCEEDED = 3
ICMPV6_DEST_UNREACH = 1

# ============================================================
#                Utility functions (unchanged)
# ============================================================

def get_local_ipv4_from_hostname():
    out = subprocess.check_output(["hostname","-I"],text=True).strip()
    for tok in out.split():
        if "." in tok and not tok.startswith("127."):
            return tok
    raise RuntimeError("No IPv4 address detected")

def get_iface_ipv4(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    s.close()
    return socket.inet_ntoa(res[20:24])

def get_default_gateway_for_ip(local_ip):
    with open("/proc/net/route","r") as f:
        lines = f.readlines()[1:]
    for line in lines:
        fields = line.strip().split()
        iface, dst, gw, flags = fields[0], fields[1], fields[2], int(fields[3],16)
        if dst=="00000000" and (flags & 0x2):
            try:
                if get_iface_ipv4(iface) == local_ip:
                    return iface, socket.inet_ntoa(struct.pack("<L",int(gw,16)))
            except OSError:
                pass
    for line in lines:
        fields=line.strip().split()
        iface, dst, gw, flags = fields[0], fields[1], fields[2], int(fields[3],16)
        if dst=="00000000" and (flags & 0x2):
            return iface, socket.inet_ntoa(struct.pack("<L",int(gw,16)))
    raise RuntimeError("No gateway found")

def get_local_mac(iface):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    s.close()
    return res[18:24]

def bytes_to_mac_str(b):
    return ":".join(f"{x:02x}" for x in b)

def sniff_gateway_mac(iface, gw_ip, timeout=4.0):
    """Identical to your working version, requires AF_PACKET."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.bind((iface,0))
    s.settimeout(timeout)
    gw_bytes = socket.inet_aton(gw_ip)
    start = time.time()

    while True:
        if time.time()-start > timeout:
            break
        try:
            pkt,_ = s.recvfrom(65535)
        except socket.timeout:
            break
        if len(pkt)<34: continue
        ip_hdr = pkt[14:]
        if ip_hdr[0]>>4 != 4: continue
        src_ip = ip_hdr[12:16]
        dst_ip = ip_hdr[16:20]
        if src_ip == gw_bytes:
            s.close()
            return pkt[6:12], True
        if dst_ip == gw_bytes:
            s.close()
            return pkt[0:6], False
    s.close()
    return None,None

def mac_to_ipv6_link_local(mac):
    mac = bytearray(mac)
    mac[0] ^= 0x02
    eui = bytearray(8)
    eui[0:3] = mac[0:3]
    eui[3:5] = b'\xff\xfe'
    eui[5:8] = mac[3:6]
    parts = [
        (eui[0]<<8)|eui[1],
        (eui[2]<<8)|eui[3],
        (eui[4]<<8)|eui[5],
        (eui[6]<<8)|eui[7]
    ]
    return "fe80::" + ":".join(f"{p:x}" for p in parts)

# ============================================================
#                    ICMPv6 helper
# ============================================================

def checksum(data):
    s = 0
    if len(data) % 2 == 1:
        data += b'\x00'
    for i in range(0,len(data),2):
        s += (data[i]<<8) + data[i+1]
    while s>0xffff:
        s = (s & 0xffff) + (s>>16)
    return (~s) & 0xffff

def build_ipv6_pseudo(src, dst, payload):
    return (socket.inet_pton(AF_INET6, src) +
            socket.inet_pton(AF_INET6, dst) +
            struct.pack("!I3xB", len(payload), 58))

# ============================================================
#              ICMPv6 reachability probes
# ============================================================

def icmpv6_echo(iface, target_ll):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, socket.if_nametoindex(iface))
        s.settimeout(1.0)

        ident = int(time.time()) & 0xffff
        seq = 1
        payload = b"HELLO"

        pkt = struct.pack("!BBHHH", ICMPV6_ECHO_REQUEST, 0, 0, ident, seq) + payload

        # Kernel fills checksum; no need to compute manually.
        s.sendto(pkt, (target_ll,0,0,socket.if_nametoindex(iface)))

        try:
            data, addr = s.recvfrom(2048)
            t, code = data[0], data[1]
            if t == ICMPV6_ECHO_REPLY:
                return True, f"Got Echo Reply from {addr}"
            return False, f"Got ICMPv6 type={t} code={code}"
        except socket.timeout:
            return False, "No reply"
    except Exception as e:
        return False, str(e)

def icmpv6_multicast_probe(iface, group):
    """Ping all-nodes or all-routers multicast"""
    return icmpv6_echo(iface, group)

def send_udp_probe(iface, target_ll, port=54321):
    """Send UDP and see if ICMP DestUnreach returns."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.bind(("",0,0,socket.if_nametoindex(iface)))
        try:
            s.sendto(b"X", (target_ll, port, 0, socket.if_nametoindex(iface)))
            data, addr = s.recvfrom(2048)
            return True, f"Got UDP response: {data}"
        except socket.timeout:
            return False, "No UDP response or ICMP unreachable"
    except Exception as e:
        return False, str(e)

def neighbor_solicit(iface, target_ll):
    """Send Neighbor Solicitation to target LL."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.settimeout(1.0)

        # Build NS
        target_bin = socket.inet_pton(socket.AF_INET6, target_ll)
        # Type, code, checksum, reserved
        hdr = struct.pack("!BBHI", ICMPV6_NS, 0, 0, 0) + target_bin
        s.sendto(hdr, (target_ll,0,0,socket.if_nametoindex(iface)))

        try:
            data, addr = s.recvfrom(2048)
            if data[0] == ICMPV6_NA:
                return True, f"Got NA from {addr}"
            return False, f"Got ICMPv6 type={data[0]}"
        except socket.timeout:
            return False, "No NA"
    except Exception as e:
        return False, str(e)

def solicit_node_multicast(addr):
    """Generate FF02::1:FFxx:xxxx from LL address."""
    b = socket.inet_pton(socket.AF_INET6, addr)
    last3 = b[-3:]
    return "ff02::1:ff%02x:%02x%02x" % (last3[0], last3[1], last3[2])

# ============================================================
#                          Main
# ============================================================

def main():
    if os.geteuid() != 0:
        print("Must run as root")
        return

    local_ip = get_local_ipv4_from_hostname()
    iface, gw_ip = get_default_gateway_for_ip(local_ip)

    print(f"[+] Local IPv4: {local_ip}")
    print(f"[+] IFACE:      {iface}")
    print(f"[+] GW IPv4:    {gw_ip}")

    print("[+] Sniffing to discover GW MAC...")
    gw_mac, _ = sniff_gateway_mac(iface, gw_ip)
    if not gw_mac:
        print("[-] Could not discover GW MAC")
        return

    print(f"[+] GW MAC:     {bytes_to_mac_str(gw_mac)}")

    gw_ll = mac_to_ipv6_link_local(gw_mac)
    print(f"[+] GW LL IPv6: {gw_ll}%{iface}")

    print("\n================ REACHABILITY TESTS ================")

    tests = [
        ("ICMPv6 Echo", icmpv6_echo, (iface, gw_ll)),
        ("Multicast FF02::1", icmpv6_multicast_probe, (iface, "ff02::1")),
        ("Multicast FF02::2 (routers)", icmpv6_multicast_probe, (iface, "ff02::2")),
        ("Neighbor Solicitation (direct)", neighbor_solicit, (iface, gw_ll)),
        ("Solicited-node multicast NS", neighbor_solicit,
            (iface, solicit_node_multicast(gw_ll))),
        ("UDP high-port probe", send_udp_probe, (iface, gw_ll)),
    ]

    for name, func, args in tests:
        print(f"\n--- {name} ---")
        try:
            ok, info = func(*args)
            print(f"Result: {'SUCCESS' if ok else 'FAIL'}")
            print(f"Info:   {info}")
        except Exception as e:
            print(f"EXC: {e}")

    print("\n====================================================")
    print("Done.")

if __name__=="__main__":
    main()
