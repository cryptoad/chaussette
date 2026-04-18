#!/usr/bin/env python3
import argparse, csv, socket, struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

DEFAULT_TIMEOUT = 0.6
DEFAULT_WORKERS = 200

COMMON_PORTS = {
    20,21,22,23,25,53,67,68,69,80,110,123,135,137,138,139,143,161,179,389,443,
    445,465,514,515,587,636,873,993,995,1080,1194,1433,1521,1723,2049,3306,3389,
    4443,5432,5900,5985,5986,6379,6443,7001,8080,8443,8888,9000,9090,9100,9200,
    9300,10000,15000,15001,15002,15003,15004,15005,15006,15020,15090,15443,15672,
    16000,17000,18000,19000,20000,2022,2023,2024,2025,2375,2376,2379,2380,3000,
    3001,3500,4567,5000,5001,5601,5701,5702,5703,5672,5901,7000,7002,8001
}

def get_default_gateway_linux() -> str:
    with open("/proc/net/route") as f:
        next(f)  # skip header
        for line in f:
            fields = line.strip().split()
            if len(fields) < 3:
                continue
            iface, dest, gateway = fields[0], fields[1], fields[2]
            if dest == "00000000":  # default route
                return socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
    raise SystemExit("No default gateway found in /proc/net/route")

def build_port_set():
    ports = set(COMMON_PORTS)
    for a, b in [
        (8000, 8100),
        (8080, 8099),
        (9000, 9049),
        (10000, 10049),
        (15000, 15099),
        (20000, 20049),
    ]:
        ports.update(range(a, b + 1))
    ports.update({9901, 9902, 9903, 4200, 5671, 4242, 56000, 56001, 15010, 15432, 15433})
    return {p for p in ports if 1 <= p <= 65535}

def try_connect(ip: str, port: int, timeout: float):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        return port, True, "open"
    except socket.timeout:
        return port, False, "timeout"
    except ConnectionRefusedError:
        return port, False, "refused"
    except OSError as e:
        return port, False, f"oserror:{e}"
    finally:
        s.close()

def scan_ports(ip: str, ports, timeout: float, workers: int):
    ports = sorted(set(ports))
    total = len(ports)
    print(f"Scanning {total} ports on gateway {ip} with timeout {timeout}s using {workers} workers...")
    results, open_ports = [], []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(try_connect, ip, p, timeout): p for p in ports}
        for i, fut in enumerate(as_completed(futures), 1):
            p = futures[fut]
            try:
                port, ok, msg = fut.result()
            except Exception as e:
                port, ok, msg = p, False, f"err:{e}"
            results.append((port, ok, msg))
            if i % 25 == 0 or i == total:
                print(f"  progress: {i}/{total} ports checked...")
            if ok:
                open_ports.append((port, msg))
    return results, open_ports

def save_csv(results, filename: str):
    with open(filename, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["port", "open", "note"])
        for port, ok, note in sorted(results):
            w.writerow([port, bool(ok), note])

def main():
    ap = argparse.ArgumentParser(description="Quick TCP port probe for default gateway")
    ap.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--save", type=str, default=None)
    args = ap.parse_args()

    ip = get_default_gateway_linux()
    print(f"Default gateway: {ip}")

    ports = build_port_set()
    start = datetime.utcnow()
    results, open_ports = scan_ports(ip, ports, args.timeout, args.workers)
    elapsed = (datetime.utcnow() - start).total_seconds()

    print(f"\nScan finished in {elapsed:.2f}s. Open ports found: {len(open_ports)}")
    for p, note in sorted(open_ports):
        print(f"  - {p} ({note})")
    if not open_ports:
        print("  No open ports detected.")

    if args.save:
        save_csv(results, args.save)
        print(f"Saved results to {args.save}")

if __name__ == "__main__":
    main()
