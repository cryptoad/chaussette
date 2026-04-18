import socket, struct, fcntl, sys

def get_default_iface():
    for line in open("/proc/net/route"):
        f = line.strip().split()
        if len(f) >= 2 and f[1] == "00000000":
            return f[0]

def get_ipv4(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode())
    )[20:24])

iface = get_default_iface()
print(f"[+] iface={iface}", flush=True)

if not iface:
    print("[!] no default iface found", flush=True)
    sys.exit(1)

ip = get_ipv4(iface)
print(f"[+] ip={ip}", flush=True)

req = f"GET / HTTP/1.1\r\nHost: {ip}:15004\r\nUser-Agent: debug\r\nConnection: close\r\n\r\n"
print("[+] request:", flush=True)
print(req, end="", flush=True)

try:
    s = socket.create_connection((ip, 15004), timeout=3)
    s.settimeout(3)
    s.sendall(req.encode())
    print("[+] response:", flush=True)
    while True:
        b = s.recv(4096)
        if not b:
            break
        sys.stdout.write(b.decode(errors="replace"))
        sys.stdout.flush()
    print("\n[+] done", flush=True)
except Exception as e:
    print(f"[!] error: {type(e).__name__}: {e}", flush=True)
