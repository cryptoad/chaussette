#!/usr/bin/env python3
import os, argparse, socket, urllib.parse, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def proxy_ip():
    s = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    if not s: raise SystemExit("HTTP_PROXY/http_proxy not set")
    if "://" not in s: s = "http://" + s
    p = urllib.parse.urlparse(s)
    if not p.hostname: raise SystemExit(f"Bad proxy: {s}")
    return socket.gethostbyname(p.hostname), (p.port or 80), s

def parse_ports(items):
    out = set()
    for x in items:
        for part in x.split(","):
            if "-" in part:
                a, b = map(int, part.split("-", 1))
                out.update(range(a, b + 1))
            else:
                out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535)

def probe(ip, port, timeout):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return str(ip), port
    except OSError:
        return None

def main():
    ap = argparse.ArgumentParser(description="Scan proxy /24 for selected TCP ports")
    ap.add_argument("ports", nargs="*", help="ports/ranges, e.g. 80 443 8080-8090")
    ap.add_argument("-t", "--timeout", type=float, default=0.3)
    ap.add_argument("-w", "--workers", type=int, default=512)
    args = ap.parse_args()

    ip, proxy_port, raw = proxy_ip()
    ports = parse_ports(args.ports or [str(proxy_port)])
    net = ipaddress.ip_network(f"{ip}/24", strict=False)

    print(f"HTTP_PROXY={raw}")
    print(f"proxy={ip}  subnet={net}  ports={','.join(map(str, ports))}")

    hits = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(probe, host, port, args.timeout) for host in net.hosts() for port in ports]
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                hits.append(r)
                print(f"{r[0]}:{r[1]}")

    print(f"\nOpen: {len(hits)}")
    for ip, port in sorted(hits, key=lambda x: tuple(map(int, x[0].split("."))) + (x[1],)):
        print(f"{ip}:{port}")

if __name__ == "__main__":
    main()
