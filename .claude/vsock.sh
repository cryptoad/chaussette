cat > /tmp/vsock_state_deeper.py <<'PY'
#!/usr/bin/env python3
import os
import socket
import fcntl
import struct
import threading
import time

IOCTL_VM_SOCKETS_GET_LOCAL_CID = 0x7b9

def section(name):
    print(f"\n== {name} ==")

section("local CID ioctl with mutable buffer")
try:
    fd = os.open("/dev/vsock", os.O_RDONLY | os.O_CLOEXEC)
    try:
        buf = bytearray(4)
        try:
            fcntl.ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, buf, True)
            cid = struct.unpack("I", buf)[0]
            print(f"local CID ioctl: {cid}")
        except OSError as e:
            print(f"local CID ioctl errno={e.errno} {e.strerror!r}")
    finally:
        os.close(fd)
except OSError as e:
    print(f"open /dev/vsock errno={e.errno} {e.strerror!r}")

section("bind/listen/getsockname")
srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
try:
    srv.bind((socket.VMADDR_CID_ANY, 23456))
    srv.listen(1)
    print("server bind/listen: ok")
    try:
        print("server getsockname:", srv.getsockname())
    except Exception as e:
        print(f"server getsockname error: {type(e).__name__}: {e}")
finally:
    srv.close()

section("candidate self-connect attempts")
candidates = []
if hasattr(socket, "VMADDR_CID_LOCAL") and socket.VMADDR_CID_LOCAL is not None:
    candidates.append(("LOCAL", socket.VMADDR_CID_LOCAL))
if hasattr(socket, "VMADDR_CID_ANY"):
    candidates.append(("ANY", socket.VMADDR_CID_ANY))
# Sometimes people test the returned local CID manually if ioctl worked.
# Add common reserved values for completeness, but most should fail.
candidates += [("HOST", 2), ("HYPERVISOR", 0), ("RESERVED1", 1)]

for label, cid in candidates:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((cid, 23456))
        print(f"connect {label} cid={cid}: ok")
    except OSError as e:
        print(f"connect {label} cid={cid}: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()
PY

chmod +x /tmp/vsock_state_deeper.py
/tmp/vsock_state_deeper.py
