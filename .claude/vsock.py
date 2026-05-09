import socket, errno

ports = [
    22, 80, 443, 2024, 2375, 2376, 5000, 5001,
    5432, 6379, 8000, 8080, 8443, 9000, 9090, 50051
]

for port in ports:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((socket.VMADDR_CID_HOST, port))
        print(f"[+] vsock host CID 2 port {port}: connected")
        try:
            s.sendall(b"\n")
            data = s.recv(128)
            print(f"    recv: {data!r}")
        except Exception as e:
            print(f"    connected, no banner/read error: {e}")
    except OSError as e:
        if e.errno not in (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ENETUNREACH):
            print(f"[?] port {port}: {type(e).__name__}: {e}")
    finally:
        s.close()
