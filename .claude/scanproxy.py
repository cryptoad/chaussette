#!/usr/bin/env python3
"""
proxy_port_scan.py

Reads HTTP_PROXY/http_proxy from env, extracts host/IP and port,
then attempts TCP connections to ~400 likely ports (fast timeout, concurrent).
Designed for quick discovery on Linux / Envoy-ish setups.

Usage:
    python3 proxy_port_scan.py            # default timeout and workers
    python3 proxy_port_scan.py -t 0.5 -w 200   # custom timeout and concurrency
"""

import os
import sys
import argparse
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Set
import csv
from datetime import datetime

DEFAULT_TIMEOUT = 0.6    # seconds (short because of likely filtering)
DEFAULT_WORKERS = 200

COMMON_PORTS = {
    # very common service ports
    20,21,22,23,25,53,67,68,69,80,110,123,135,137,138,139,143,161,179,389,443,
    445,465,514,515,587,636,873,993,995,1080,1194,1433,1521,1723,2049,3306,3389,
    4443,5432,5900,5985,5986,6379,6443,7001,8080,8443,8888,9000,9090,9100,9200,
    9300,10000,15000,15001,15002,15003,15004,15005,15006,15020,15090,15443,15672,
    16000,17000,18000,19000,20000,2022,2023,2024,2025,2375,2376,2379,2380,3000,
    3001,3500,4567,5000,5001,5601,5701,5702,5703,5672,5901,7000,7002,8001
}

def parse_http_proxy_env() -> (str, int, str):
    """Parse HTTP_PROXY or http_proxy env var. Returns (host, port, original_host_str)."""
    env = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    if not env:
        raise SystemExit("Environment variable HTTP_PROXY or http_proxy not set.")
    # ensure scheme for urlparse
    if '://' not in env:
        env = 'http://' + env
    p = urllib.parse.urlparse(env)
    host = p.hostname
    port = p.port
    if host is None:
        raise SystemExit(f"Could not parse host from HTTP_PROXY ({env})")
    if port is None:
        # default to 80 when no port provided (uncommon)
        port = 80
    return host, port, env

def resolve_host(hostname: str) -> str:
    """Resolve hostname to IPv4 address (returns string)."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        raise SystemExit(f"Failed to resolve hostname {hostname}: {e}")

def build_port_set() -> Set[int]:
    """
    Build a curated set of ~400 ports likely to be interesting for Envoy / Linux / proxy setups.
    Strategy: union of COMMON_PORTS + ranges covering common service ranges.
    """
    ports = set(COMMON_PORTS)

    # Add several ranges that are likely to include admin / app / sidecar ports:
    ranges = [
        (8000, 8100),    # HTTP app ports
        (8080, 8099),    # more HTTP app ports
        (15000, 15099),  # many Envoy sidecar / local proxy ports
        (9000, 9049),    # dev/admin ports
        (10000, 10049),  # additional management / app ports
        (20000, 20049),  # user / app ports
    ]

    for a, b in ranges:
        ports.update(range(a, b + 1))

    # add a handful of extra candidates often seen in infra:
    extras = {9901, 9902, 9903, 4200, 5671, 4242, 56000, 56001, 15010, 15432, 15433}
    ports.update(extras)

    # remove obviously invalid / out-of-range
    ports = {p for p in ports if 1 <= p <= 65535}

    # Sort and return
    return ports

def try_connect(ip: str, port: int, timeout: float) -> (int, bool, str):
    """
    Try a TCP connect to (ip, port) with given timeout.
    Returns (port, True/False, message)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # success
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()
        return port, True, "open"
    except socket.timeout:
        return port, False, "timeout"
    except ConnectionRefusedError:
        return port, False, "refused"
    except OSError as e:
        # e.g., network unreachable, no route, etc.
        return port, False, f"oserror:{e}"
    finally:
        try:
            s.close()
        except Exception:
            pass

def scan_ports(ip: str, ports: Iterable[int], timeout: float, workers: int):
    ports = sorted(set(ports))
    total = len(ports)
    print(f"Scanning {total} ports on {ip} with timeout {timeout}s using {workers} workers...")
    open_ports = []
    results = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(try_connect, ip, p, timeout): p for p in ports}
        completed = 0
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                port, ok, msg = fut.result()
            except Exception as e:
                port, ok, msg = p, False, f"err:{e}"
            results.append((port, ok, msg))
            completed += 1
            # small progress print every 25 completed items
            if completed % 25 == 0 or completed == total:
                print(f"  progress: {completed}/{total} ports checked...")
            if ok:
                open_ports.append((port, msg))
    return results, open_ports

def save_csv(results, filename: str):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["port", "open", "note"])
        for port, ok, note in sorted(results, key=lambda x: x[0]):
            writer.writerow([port, bool(ok), note])

def main():
    parser = argparse.ArgumentParser(description="Quick TCP port probe for HTTP_PROXY host")
    parser.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT,
                        help=f"connect timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS,
                        help=f"max concurrent workers (default {DEFAULT_WORKERS})")
    parser.add_argument('--save', type=str, default=None,
                        help="save detailed results CSV to file")
    args = parser.parse_args()

    host, proxy_port, raw_env = parse_http_proxy_env()
    print(f"HTTP_PROXY env: {raw_env}")
    print(f"Extracted host: {host} proxy port: {proxy_port}")

    ip = resolve_host(host)
    print(f"Resolved {host} -> {ip}")

    ports = build_port_set()
    # If user provided a proxy port in HTTP_PROXY, include it near top of scan list
    ports.add(proxy_port)

    start = datetime.utcnow()
    results, open_ports = scan_ports(ip, ports, timeout=args.timeout, workers=args.workers)
    elapsed = (datetime.utcnow() - start).total_seconds()

    print(f"\nScan finished in {elapsed:.2f}s. Open ports found: {len(open_ports)}")
    if open_ports:
        for p, note in sorted(open_ports):
            print(f"  - {p}  ({note})")
    else:
        print("  No open ports detected (within timeout and scan set).")

    if args.save:
        save_csv(results, args.save)
        print(f"Saved results to {args.save}")

if __name__ == "__main__":
    main()
