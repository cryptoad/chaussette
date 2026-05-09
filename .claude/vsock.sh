cat > /tmp/vsock_alone_probe.py <<'PY'
#!/usr/bin/env python3
import os
import socket
import fcntl
import errno
import struct

IOCTL_VM_SOCKETS_GET_LOCAL_CID = 0x7b9

def section(name):
    print(f"\n== {name} ==")

section("device node")
try:
    st = os.stat("/dev/vsock")
    print(f"/dev/vsock mode={oct(st.st_mode & 0o777)} rdev={os.major(st.st_rdev)},{os.minor(st.st_rdev)} uid={st.st_uid} gid={st.st_gid}")
except OSError as e:
    print(f"stat /dev/vsock: errno={e.errno} {e.strerror!r}")

section("open and ioctl")
try:
    fd = os.open("/dev/vsock", os.O_RDONLY | os.O_CLOEXEC)
    print(f"open: ok fd={fd}")
    try:
        cid = fcntl.ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, 0)
        print(f"IOCTL_VM_SOCKETS_GET_LOCAL_CID returned {cid}")
    except OSError as e:
        print(f"IOCTL_VM_SOCKETS_GET_LOCAL_CID: errno={e.errno} {e.strerror!r}")
    os.close(fd)
except OSError as e:
    print(f"open: errno={e.errno} {e.strerror!r}")

section("AF_VSOCK constants")
print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))
print("VMADDR_CID_ANY:", getattr(socket, "VMADDR_CID_ANY", None))
print("VMADDR_CID_LOCAL:", getattr(socket, "VMADDR_CID_LOCAL", None))

if not hasattr(socket, "AF_VSOCK"):
    raise SystemExit(0)

section("socket creation")
for typ_name, typ in [("SOCK_STREAM", socket.SOCK_STREAM), ("SOCK_DGRAM", socket.SOCK_DGRAM)]:
    try:
        s = socket.socket(socket.AF_VSOCK, typ)
        print(f"{typ_name}: socket() ok")
        s.close()
    except OSError as e:
        print(f"{typ_name}: socket() errno={e.errno} {e.strerror!r}")

section("connect to host CID")
for port in [1, 22, 80, 443, 8000, 8080, 50051]:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((socket.VMADDR_CID_HOST, port))
        print(f"connect host:{port}: ok")
    except OSError as e:
        print(f"connect host:{port}: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()

section("bind/listen experiments")
# These may succeed locally even without a useful transport, but no host can reach them.
bind_tests = []
if hasattr(socket, "VMADDR_CID_ANY"):
    bind_tests.append(("ANY", socket.VMADDR_CID_ANY, 12345))
if hasattr(socket, "VMADDR_CID_LOCAL") and socket.VMADDR_CID_LOCAL is not None:
    bind_tests.append(("LOCAL", socket.VMADDR_CID_LOCAL, 12346))

if not bind_tests:
    print("No VMADDR_CID_ANY/LOCAL constants available for bind tests")

for label, cid, port in bind_tests:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        s.bind((cid, port))
        print(f"bind {label} cid={cid} port={port}: ok")
        try:
            s.listen(1)
            print(f"listen {label} port={port}: ok")
        except OSError as e:
            print(f"listen {label} port={port}: errno={e.errno} {e.strerror!r}")
    except OSError as e:
        print(f"bind {label} cid={cid} port={port}: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()
PY

chmod +x /tmp/vsock_alone_probe.py
/tmp/vsock_alone_probe.py
