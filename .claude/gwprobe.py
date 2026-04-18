#!/usr/bin/env python3
import socket, ssl, struct, base64, itertools

TIMEOUT = 2.5
MAX_READ = 16384

def get_default_gateway_linux():
    with open("/proc/net/route") as f:
        next(f)
        for line in f:
            fields = line.strip().split()
            if len(fields) >= 3 and fields[1] == "00000000":
                return fields[0], socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    raise SystemExit("No default gateway found in /proc/net/route")

def recv_all(sock, max_bytes=MAX_READ):
    sock.settimeout(TIMEOUT)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def open_sock(ip, port, use_tls=False, sni=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((ip, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=(sni or ip))
    return s

def show_cert(ip):
    try:
        s = open_sock(ip, 443, use_tls=True, sni="example.com")
        cert = s.getpeercert()
        print("\n=== TLS certificate on 443 ===")
        print(cert if cert else "(no parsed cert details)")
        s.close()
    except Exception as e:
        print(f"\n=== TLS certificate fetch failed: {e}")

def do_req(ip, port, label, raw, use_tls=False, sni=None):
    print(f"\n--- {label} ---")
    try:
        s = open_sock(ip, port, use_tls=use_tls, sni=sni)
        s.sendall(raw.encode("utf-8", "replace"))
        data = recv_all(s)
        s.close()
        if not data:
            print("(no response)")
            return
        print(data.decode("utf-8", "replace"))
    except Exception as e:
        print(f"ERROR: {e}")

def basic_auth(user, pw):
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {tok}"

def main():
    iface, gw = get_default_gateway_linux()
    print(f"Gateway: {gw} via {iface}")

    targets = [
        ("example.com", "93.184.216.34"),
        ("google.com", "142.250.190.14"),
        ("1.1.1.1", "1.1.1.1"),
    ]

    host_headers = ["example.com", "google.com", "localhost", "127.0.0.1", gw, ""]
    snis = [None, "example.com", "google.com", "localhost"]

    show_cert(gw)

    for port in (80, 443):
        tls = (port == 443)
        print(f"\n================ PORT {port} {'TLS' if tls else 'PLAINTEXT'} ================")

        # origin-form requests
        for host in host_headers:
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: gw-probe/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            do_req(gw, port, f"GET / Host={host or '<empty>'}", req, use_tls=tls, sni=("example.com" if tls else None))

        # alternate methods
        for method in ("HEAD", "OPTIONS"):
            req = (
                f"{method} / HTTP/1.1\r\n"
                f"Host: example.com\r\n"
                f"User-Agent: gw-probe/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            do_req(gw, port, f"{method} /", req, use_tls=tls, sni=("example.com" if tls else None))

        # absolute-form GETs
        for host, ip in targets:
            for url in (f"http://{host}/", f"http://{ip}/"):
                req = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: gw-probe/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                do_req(gw, port, f"ABSOLUTE GET {url}", req, use_tls=tls, sni=(host if tls else None))

        # CONNECT tests
        for host, ip in targets:
            for dest in (f"{host}:443", f"{ip}:443", f"{host}:80", f"{ip}:80"):
                req = (
                    f"CONNECT {dest} HTTP/1.1\r\n"
                    f"Host: {dest}\r\n"
                    f"User-Agent: gw-probe/2.0\r\n"
                    f"Proxy-Connection: close\r\n\r\n"
                )
                do_req(gw, port, f"CONNECT {dest}", req, use_tls=tls, sni=("example.com" if tls else None))

        # header variation tests
        header_variants = [
            ("xff-public", "X-Forwarded-For: 8.8.8.8\r\n"),
            ("xff-private", "X-Forwarded-For: 127.0.0.1\r\n"),
            ("forwarded", "Forwarded: for=8.8.8.8;proto=http;host=example.com\r\n"),
            ("proxy-auth", f"Proxy-Authorization: {basic_auth('test','test')}\r\n"),
            ("all", "X-Forwarded-For: 8.8.8.8\r\nForwarded: for=8.8.8.8;proto=http;host=example.com\r\n"),
        ]
        for name, extra in header_variants:
            req = (
                f"GET http://example.com/ HTTP/1.1\r\n"
                f"Host: example.com\r\n"
                f"{extra}"
                f"User-Agent: gw-probe/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            do_req(gw, port, f"ABSOLUTE GET variant={name}", req, use_tls=tls, sni=("example.com" if tls else None))

        # SNI variation on 443
        if tls:
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "User-Agent: gw-probe/2.0\r\n"
                "Connection: close\r\n\r\n"
            )
            for sni in snis:
                do_req(gw, port, f"SNI={sni or '<none>'} Host=example.com", req, use_tls=True, sni=sni)

if __name__ == "__main__":
    main()
