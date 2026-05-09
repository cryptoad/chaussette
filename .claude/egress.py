#!/usr/bin/env python3
import socket
import hashlib

tests = [
    "169.16646142",   # typo / maps to 169.253.255.254 on glibc-like parsers
    "169.16689662",   # correct shortened form for 169.254.169.254
    "169.254.43518",  # also maps to 169.254.169.254
    "2852039166",     # decimal dword for 169.254.169.254
    "0xa9fea9fe",     # hex dword for 169.254.169.254
]

for host in tests:
    print("=" * 80)
    print("host:", host)

    try:
        resolved = socket.gethostbyname(host)
    except Exception as e:
        resolved = f"{type(e).__name__}: {e}"
    print("socket.gethostbyname:", resolved)

    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: focused-egress-parser-test/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    try:
        s = socket.create_connection((host, 80), timeout=2)
        s.settimeout(2)
        s.sendall(payload)
        data = s.recv(1024)
        s.close()

        print("connected: yes")
        print("status:", data.splitlines()[0].decode("latin-1", "replace") if data else None)
        print("sha256_16:", hashlib.sha256(data).hexdigest()[:16] if data else None)
        print("preview:", repr(data[:300]))
    except Exception as e:
        print("connected: no")
        print("error:", type(e).__name__, str(e))
