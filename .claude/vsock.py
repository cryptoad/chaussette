#!/usr/bin/env python3
import socket
import errno
import time

CID_HOST = 2
PORTS = list(range(1, 65536))

def try_port(port, timeout=0.15):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((CID_HOST, port))
        return True
    except OSError as e:
        return False
    finally:
        s.close()

hits = []
start = time.time()
for p in PORTS:
    if try_port(p):
        print(f"[+] open vsock port {p}", flush=True)
        hits.append(p)

print(f"done: {len(hits)} open ports in {time.time()-start:.1f}s")
print(hits)
