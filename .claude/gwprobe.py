#!/usr/bin/env python3
import socket
import ssl
import struct

TIMEOUT = 2.0
PORTS = [80, 443]

HOST_HEADERS = [
    "localhost",
    "127.0.0.1",
    "example.com",
    "google.com",
    "internal",
    "",
]

CONNECT_TARGETS = [
    "example.com:80",
    "example.com:443",
    "google.com:443",
    "1.1.1.1:443",
    "127.0.0.1:80",
]

def get_default_gateway_linux():
    with open("/proc/net/route") as f:
        next(f)  # skip header
        for line in f:
            fields = line.strip().split()
            if len(fields) < 3:
                continue
            iface, dest, gateway = fields[0], fields[1], fields[2]
            if dest == "00000000":
                gw_ip = socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
                return iface, gw_ip
    raise SystemExit("No default gateway found in /proc/net/route")

def recv_all(sock):
    sock.settimeout(TIMEOUT)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                break
    except socket.timeout:
        pass
    return data

def print_response(label, data):
    print(f"\n--- {label} ---")
    if not data:
        print("(no response)")
        return
    text = data.decode(errors="replace")
    lines = text.splitlines()
    for line in lines[:40]:
        print(line)

def connect(ip, port, use_ssl=False, sni=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((ip, port))
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=(sni or ip))
    return s

def probe_get(ip, port, use_ssl):
    for host in HOST_HEADERS:
        try:
            s = connect(ip, port, use_ssl=use_ssl, sni=(host if host else None))
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: gw-probe/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            data = recv_all(s)
            print_response(
                f"GET / (Host: {host or '<empty>'}) on {port}{' TLS' if use_ssl else ''}",
                data,
            )
            s.close()
        except Exception as e:
            print(f"\n--- GET failed (Host: {host or '<empty>'}) on {port}: {e}")

def probe_connect(ip, port, use_ssl):
    for target in CONNECT_TARGETS:
        try:
            s = connect(ip, port, use_ssl=use_ssl)
            req = (
                f"CONNECT {target} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: gw-probe/1.0\r\n"
                f"Proxy-Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            data = recv_all(s)
            print_response(
                f"CONNECT {target} on {port}{' TLS' if use_ssl else ''}",
                data,
            )
            s.close()
        except Exception as e:
            print(f"\n--- CONNECT failed ({target}) on {port}: {e}")

def probe_absolute_get(ip, port, use_ssl):
    urls = [
        "http://example.com/",
        "http://1.1.1.1/",
        "http://127.0.0.1/",
    ]
    for url in urls:
        try:
            s = connect(ip, port, use_ssl=use_ssl)
            req = (
                f"GET {url} HTTP/1.1\r\n"
                f"Host: example.com\r\n"
                f"User-Agent: gw-probe/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            data = recv_all(s)
            print_response(
                f"Absolute-form GET {url} on {port}{' TLS' if use_ssl else ''}",
                data,
            )
            s.close()
        except Exception as e:
            print(f"\n--- Absolute GET failed ({url}) on {port}: {e}")

def main():
    iface, ip = get_default_gateway_linux()
    print(f"Default gateway on {iface}: {ip}")

    for port in PORTS:
        print(f"\n========== PORT {port} ==========")
        use_ssl = (port == 443)

        print("\n### GET tests ###")
        probe_get(ip, port, use_ssl)

        print("\n### CONNECT tests ###")
        probe_connect(ip, port, use_ssl)

        print("\n### Absolute-form GET tests ###")
        probe_absolute_get(ip, port, use_ssl)

if __name__ == "__main__":
    main()
