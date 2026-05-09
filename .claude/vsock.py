#!/usr/bin/env python3
import socket
import errno
import time

HOST_CID = 2  # VMADDR_CID_HOST on Linux
TIMEOUT = 0.15

ports = list(range(1, 2048)) + [2024, 8000, 8080, 9000, 10250, 5000, 2375]
seen = set()

for port in ports:
    if port in seen:
        continue
    seen.add(port)

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST_CID, port))
        print(f"[+] open vsock port {port}")
        # Optional ultra-safe banner read:
        s.settimeout(0.25)
        try:
            data = s.recv(128)
            if data:
                print(f"    banner: {data!r}")
        except Exception:
            pass
    except OSError as e:
        # Common: ECONNREFUSED, ETIMEDOUT, ENODEV, EHOSTUNREACH
        pass
    finally:
        s.close()
    time.sleep(0.01)
