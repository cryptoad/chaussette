#!/usr/bin/env python3
"""
scan_local_net.py

Find the first non-lo interface (via /proc/net/route), get its IPv4 address,
construct the /24 containing that IPv4, and scan port 2024 and 15004 on all hosts
in that /24. Uses pure stdlib.

Usage:
    python3 scan_local_net.py
    python3 scan_local_net.py --iface eth0
    python3 scan_local_net.py --cidr 192.168.1.0/24
    python3 scan_local_net.py -t 1.5 -c 200
"""

from __future__ import annotations
import socket
import struct
import fcntl
import os
import argparse
import threading
import queue
import time
from typing import Optional, Tuple, List

DEFAULT_PORTS = [2024, 15004]

# ioctl constants
SIOCGIFADDR = 0x8915  # get PA address

def read_proc_net_route(path="/proc/net/route") -> List[Tuple[str,str]]:
    """Return list of (iface, dest_hex) entries from /proc/net/route"""
    if not os.path.exists(path):
        return []
    entries = []
    try:
        with open(path, "r") as f:
            lines = f.read().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0]
                dest = parts[1]  # in hex little-endian
                entries.append((iface, dest))
    except Exception:
        pass
    return entries

def choose_non_lo_iface() -> Optional[str]:
    """
    Choose the first interface from /proc/net/route that is not 'lo'.
    This is usually the interface used for default routes.
    """
    entries = read_proc_net_route()
    for iface, dest in entries:
        if iface == "lo":
            continue
        # prefer default route (dest == 00000000), otherwise first non-lo
        if dest == "00000000":
            return iface
    # fallback to any non-lo iface in file order
    for iface, dest in entries:
        if iface != "lo":
            return iface
    return None

def get_ipv4_for_iface(ifname: str) -> Optional[str]:
    """Use SIOCGIFADDR ioctl to fetch IPv4 address for interface (returns dotted quad)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifname_b = ifname.encode('utf-8')
        # pack interface name into 256-bytes as required
        packed = struct.pack('256s', ifname_b[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        # result contains sockaddr structure; IPv4 address is at bytes 20:24
        addr = struct.unpack_from('!4B', res, 20)
        return "{}.{}.{}.{}".format(*addr)
    except OSError:
        return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def cidr_from_ip(ip: str) -> Optional[str]:
    """Return the x.y.z.0/24 CIDR for an IPv4 dotted-quad string"""
    parts = ip.split('.')
    if len(parts) != 4:
        return None
    try:
        a,b,c,_ = parts
        return f"{a}.{b}.{c}.0/24"
    except Exception:
        return None

def iter_hosts_from_cidr(cidr: str):
    """Yield all host IPs in /24 except .0 and .255 (1..254)"""
    base, prefix = cidr.split('/')
    if int(prefix) != 24:
        raise ValueError("This helper only supports /24")
    a,b,c,_ = base.split('.')
    for i in range(1, 255):
        yield f"{a}.{b}.{c}.{i}"

def worker(q: queue.Queue, results: list, ports: list, timeout: float, lock: threading.Lock):
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            return
        for port in ports:
            start = time.time()
            status = "CLOSED"
            err = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                try:
                    s.connect((ip, port))
                    status = "OPEN"
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
            except socket.timeout:
                status = "TIMEOUT"
            except Exception as e:
                err = str(e)
                # For many connection failures we'll treat them as closed
                if isinstance(e, ConnectionRefusedError):
                    status = "CLOSED"
                else:
                    status = "ERR"
            took = time.time() - start
            with lock:
                results.append((ip, port, status, err, took))
                print(f"{ip:15} :{port:5} -> {status:8} {'' if not err else err} (took {took:.2f}s)")
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="Scan /24 of non-lo interface on ports 2024 and 15004.")
    parser.add_argument("--iface", help="explicit interface to use (skip auto-detection)")
    parser.add_argument("--cidr", help="explicit CIDR to scan, e.g. 192.168.1.0/24 (overrides iface)")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="per-connection timeout (seconds)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="number of concurrent worker threads")
    parser.add_argument("-p", "--ports", help="comma separated ports, default 2024,15004", default="2024,15004")
    args = parser.parse_args()

    ports = []
    try:
        for part in args.ports.split(","):
            part = part.strip()
            if part:
                ports.append(int(part))
    except Exception:
        print("Invalid ports specified.")
        return

    cidr = None
    if args.cidr:
        cidr = args.cidr.strip()
    else:
        iface = args.iface
        if not iface:
            iface = choose_non_lo_iface()
            if not iface:
                print("Could not auto-detect non-loopback interface (no /proc/net/route?). Provide --iface or --cidr.")
                return
        ip = get_ipv4_for_iface(iface)
        if not ip:
            print(f"Could not determine IPv4 address for interface {iface}. Provide --cidr or check permissions.")
            return
        cidr = cidr_from_ip(ip)
        if not cidr:
            print(f"Could not produce /24 CIDR from IP {ip}.")
            return
        print(f"Using interface {iface} with IP {ip}; scanning {cidr}")

    # Build host queue
    q = queue.Queue()
    scanned = 0
    try:
        for host in iter_hosts_from_cidr(cidr):
            q.put(host)
            scanned += 1
    except Exception as e:
        print(f"Error parsing CIDR {cidr}: {e}")
        return

    lock = threading.Lock()
    results = []
    threads = []
    concurrency = max(1, min(args.concurrency, scanned))
    for _ in range(concurrency):
        t = threading.Thread(target=worker, args=(q, results, ports, args.timeout, lock), daemon=True)
        t.start()
        threads.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("Interrupted. Gathering partial results...")

    # allow threads to finish shortly
    for t in threads:
        t.join(timeout=0.1)

    # Summarize
    print("\nSummary (open ports):")
    open_entries = [r for r in results if r[2] == "OPEN"]
    if not open_entries:
        print("  (none found)")
    else:
        for ip, port, status, err, took in sorted(open_entries, key=lambda x:(x[0], x[1])):
            print(f"  {ip}:{port}  (took {took:.2f}s)")

if __name__ == "__main__":
    main()
