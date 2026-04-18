#!/usr/bin/env python3
import re
import socket
import sys

PORT = 15004
TIMEOUT = 3

def get_ips_from_fib_trie():
    ips = []
    with open("/proc/net/fib_trie", "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        m = re.match(r"\s*\|\--\s+(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        ip = m.group(1)

        # In fib_trie, local addresses are followed shortly by "/32 host LOCAL"
        window = "".join(lines[i:i+3])
        if "/32 host LOCAL" in window and not ip.startswith("127."):
            ips.append(ip)

    # dedupe, preserve order
    out = []
    seen = set()
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

def main():
    ips = get_ips_from_fib_trie()
    if not ips:
        print("[!] No non-localhost LOCAL IPv4 found in /proc/net/fib_trie", file=sys.stderr)
        sys.exit(1)

    ip = ips[0]
    print(f"[+] Target IP: {ip}:{PORT}")

    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {ip}:{PORT}\r\n"
        f"User-Agent: raw-socket-test\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    print("[+] Request:")
    print(req, end="")

    try:
        with socket.create_connection((ip, PORT), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(req.encode())

            print("[+] Response:")
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
            sys.stdout.flush()

    except Exception as e:
        print(f"\n[!] Error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
