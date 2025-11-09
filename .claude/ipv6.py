#!/usr/bin/env python3
import os
import socket
import struct

def parse_if_inet6(path="/proc/net/if_inet6"):
    """Return a list of IPv6 interfaces from /proc/net/if_inet6."""
    interfaces = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) != 6:
                    continue
                addr_hex, idx, plen, scope, flags, ifname = parts
                addr = ":".join(addr_hex[i:i+4] for i in range(0, 32, 4))
                interfaces.append({
                    "ifname": ifname,
                    "addr": addr,
                    "plen": int(plen, 16),
                    "scope": int(scope, 16),
                    "flags": int(flags, 16),
                })
    except Exception as e:
        print(f"[!] Could not read {path}: {e}")
    return interfaces

def parse_ipv6_routes(path="/proc/net/ipv6_route"):
    """Parse IPv6 routing table (for debugging or discovery)."""
    routes = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                dst_hex, dst_len, src_hex, src_len, gw_hex, metric, refcnt, use, flags, ifname = parts[:10]
                dst = ":".join(dst_hex[i:i+4] for i in range(0, 32, 4))
                gw = ":".join(gw_hex[i:i+4] for i in range(0, 32, 4))
                routes.append({
                    "ifname": ifname,
                    "dst": dst,
                    "dst_len": int(dst_len, 16),
                    "gateway": gw,
                    "metric": int(metric, 16),
                })
    except Exception as e:
        print(f"[!] Could not read {path}: {e}")
    return routes

def ping_multicast(ifname):
    """Try to send an IPv6 multicast ping to ff02::1 on a given interface."""
    print(f"[*] Pinging ff02::1 on {ifname}...")
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.settimeout(2)
        if_idx = socket.if_nametoindex(ifname)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, if_idx)

        icmp_type, icmp_code, ident, seq = 128, 0, os.getpid() & 0xffff, 1
        pseudo = struct.pack("!BBHHH", icmp_type, icmp_code, 0, ident, seq)
        s.sendto(pseudo, ("ff02::1", 0, 0, if_idx))
        try:
            while True:
                data, addr = s.recvfrom(1024)
                print(f"    ↳ Response from {addr[0]}")
        except socket.timeout:
            print("    (no replies)")
        s.close()
    except PermissionError:
        print("    [!] No permission for raw ICMPv6 sockets (CAP_NET_RAW missing).")
    except Exception as e:
        print(f"    [!] Error sending multicast ping: {e}")

def main():
    print("=== IPv6 Interfaces ===")
    interfaces = parse_if_inet6()
    if not interfaces:
        print("No IPv6 interfaces found.")
    for i in interfaces:
        print(f"{i['ifname']}: {i['addr']}/{i['plen']} (scope={i['scope']}, flags={hex(i['flags'])})")

    print("\n=== IPv6 Routes ===")
    routes = parse_ipv6_routes()
    for r in routes:
        print(f"{r['ifname']}: {r['dst']}/{r['dst_len']} via {r['gateway']} (metric {r['metric']})")

    print("\n=== Multicast Discovery ===")
    for i in interfaces:
        if i["ifname"] != "lo":
            ping_multicast(i["ifname"])

if __name__ == "__main__":
    main()
