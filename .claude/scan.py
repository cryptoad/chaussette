#!/usr/bin/env python3
"""
scan_local_net_with_srcport.py

Scan the /24 for the first non-loopback interface and probe ports (default 2024,15004),
attempting to use a specific source port (default 15004) for outbound TCP connects.

If binding the source port fails for a particular socket, the code will fall back to an
ephemeral source port and record that in the results.

Usage:
    python3 scan_local_net_with_srcport.py
    python3 scan_local_net_with_srcport.py --src-port 15004 -c 200 -t 1.5
    python3 scan_local_net_with_srcport.py --iface eth0 --cidr 10.10.0.0/24
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

# ioctl constant for SIOCGIFADDR
SIOCGIFADDR = 0x8915

def read_proc_net_route(path="/proc/net/route") -> List[Tuple[str,str]]:
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
                dest = parts[1]
                entries.append((iface, dest))
    except Exception:
        pass
    return entries

def choose_non_lo_iface() -> Optional[str]:
    entries = read_proc_net_route()
    for iface, dest in entries:
        if iface == "lo":
            continue
        if dest == "00000000":
            return iface
    for iface, dest in entries:
        if iface != "lo":
            return iface
    return None

def get_ipv4_for_iface(ifname: str) -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifname_b = ifname.encode('utf-8')
        packed = struct.pack('256s', ifname_b[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        # IPv4 bytes are at offset 20..24 in the returned struct
        addr = struct.unpack_from('!4B', res, 20)
        return "{}.{}.{}.{}".format(*addr)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def cidr_from_ip(ip: str) -> Optional[str]:
    parts = ip.split('.')
    if len(parts) != 4:
        return None
    a,b,c,_ = parts
    return f"{a}.{b}.{c}.0/24"

def iter_hosts_from_cidr(cidr: str):
    base, prefix = cidr.split('/')
    if int(prefix) != 24:
        raise ValueError("This helper only supports /24")
    a,b,c,_ = base.split('.')
    for i in range(1, 255):
        yield f"{a}.{b}.{c}.{i}"

def create_bound_socket(src_ip: Optional[str], src_port: int, timeout: float):
    """
    Create a TCP socket, attempt to set reuse options, bind it to (src_ip_or_0.0.0.0, src_port),
    then return socket object. If bind fails, returns socket already created but unbound and
    a flag indicating bind failed.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set to close-on-exec by default in python3; keep default blocking and set timeout when using
    # try to set reuse options to increase chance multiple sockets can bind same local port
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    # SO_REUSEPORT may not exist on all platforms; attempt if available
    try:
        if hasattr(socket, "SO_REUSEPORT"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass

    bind_target = (src_ip if src_ip else "0.0.0.0", src_port)
    try:
        s.bind(bind_target)
        bound_ok = True
    except Exception as e:
        # bind failed; fall back to ephemeral (unbound) socket and return reason
        s.close()
        # create a fresh socket without bind
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bound_ok = False
        bind_error = str(e)
        return s, bound_ok, bind_error
    return s, bound_ok, None

def worker(q: queue.Queue, results: list, ports: list, timeout: float, lock: threading.Lock, src_port: int, src_ip: Optional[str]):
    while True:
        try:
            ip = q.get_nowait()
        except queue.Empty:
            return
        for port in ports:
            start = time.time()
            status = "CLOSED"
            err = None
            bind_info = ""
            try:
                # create and attempt to bind the socket to the requested source port
                s, bound_ok, bind_err = create_bound_socket(src_ip, src_port, timeout)
                if not bound_ok:
                    bind_info = f"bind_failed: {bind_err}"
                # set per-operation timeout before connect
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
                # connection refused is most common closed signal
                if isinstance(e, ConnectionRefusedError):
                    status = "CLOSED"
                else:
                    status = "ERR"
            took = time.time() - start
            with lock:
                results.append((ip, port, status, err, bind_info, took))
                bind_note = f" [{bind_info}]" if bind_info else ""
                err_note = f" {err}" if err else ""
                print(f"{ip:15} :{port:5} -> {status:8}{bind_note}{err_note} (took {took:.2f}s)")
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="Scan /24 of non-lo interface on ports and attempt to use a chosen source port.")
    parser.add_argument("--iface", help="explicit interface to use (skip auto-detection)")
    parser.add_argument("--cidr", help="explicit CIDR to scan, e.g. 192.168.1.0/24 (overrides iface)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="per-connection timeout (seconds)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="number of concurrent worker threads")
    parser.add_argument("-p", "--ports", help="comma separated target ports, default 2024,15004", default="2024,15004")
    parser.add_argument("--src-port", type=int, default=15004, help="source port to bind locally (default 15004)")
    parser.add_argument("--src-ip", help="optional local source IP to bind to (defaults to interface IP if auto-detected)")
    args = parser.parse_args()

    # build ports list
    try:
        ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    except Exception:
        print("Invalid ports specified.")
        return

    src_port = int(args.src_port)
    src_ip = args.src_ip

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
        if not src_ip:
            ip = get_ipv4_for_iface(iface)
            if not ip:
                print(f"Could not determine IPv4 address for interface {iface}. Provide --cidr or --src-ip.")
                return
            src_ip = ip
            cidr = cidr_from_ip = cidr_from_ip if False else None  # placeholder to avoid shadowing function
            cidr = cidr_from_ip = None
            # produce /24
            parts = src_ip.split(".")
            if len(parts) != 4:
                print(f"Could not parse interface IP {src_ip}")
                return
            a,b,c,_ = parts
            cidr = f"{a}.{b}.{c}.0/24"
            print(f"Using interface {iface} with IP {src_ip}; scanning {cidr}")
        else:
            # src_ip provided, but still need CIDR if not given
            ip = src_ip
            parts = ip.split(".")
            if len(parts) != 4:
                print(f"Could not parse src-ip {src_ip}")
                return
            a,b,c,_ = parts
            cidr = f"{a}.{b}.{c}.0/24"
            print(f"Using provided src-ip {src_ip}; scanning {cidr}")

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
        t = threading.Thread(target=worker, args=(q, results, ports, args.timeout, lock, src_port, src_ip), daemon=True)
        t.start()
        threads.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("Interrupted. Gathering partial results...")

    for t in threads:
        t.join(timeout=0.1)

    # Summarize
    print("\nSummary (open ports):")
    open_entries = [r for r in results if r[2] == "OPEN"]
    if not open_entries:
        print("  (none found)")
    else:
        for ip, port, status, err, bind_info, took in sorted(open_entries, key=lambda x:(x[0], x[1])):
            bind_note = f" [{bind_info}]" if bind_info else ""
            print(f"  {ip}:{port}{bind_note}  (took {took:.2f}s)")

if __name__ == "__main__":
    main()
