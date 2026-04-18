#!/usr/bin/env python3
import socket, ssl, struct, base64

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

def show_cert(label, ip, sni="example.com"):
    try:
        s = open_sock(ip, 443, use_tls=True, sni=sni)
        cert = s.getpeercert()
        print(f"\n=== TLS certificate on 443 for {label} ({ip}) ===")
        print(cert if cert else "(no parsed cert details)")
        s.close()
    except Exception as e:
        print(f"\n=== TLS certificate fetch failed for {label} ({ip}): {e}")

def do_req(connect_ip, port, label, raw, use_tls=False, sni=None):
    print(f"\n--- {label} ---")
    try:
        s = open_sock(connect_ip, port, use_tls=use_tls, sni=sni)
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

    # We still print the gateway, but requests below connect directly to target IPs.
    targets = [
        ("example.com", "93.184.216.34"),
        ("google.com", "142.250.190.14"),
        ("1.1.1.1", "1.1.1.1"),
    ]

    # Host headers to try when sending origin-form requests to each target.
    host_headers = ["example.com", "google.com", "localhost", "127.0.0.1", gw, ""]
    snis = [None, "example.com", "google.com", "localhost"]

    for host, ip in targets:
        show_cert(host, ip, sni=host if host != "1.1.1.1" else None)

    for port in (80, 443):
        tls = (port == 443)
        print(f"\n================ PORT {port} {'TLS' if tls else 'PLAINTEXT'} ================")

        # origin-form requests: connect directly to each target IP
        for target_host, target_ip in targets:
            for host in host_headers:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: direct-probe/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                do_req(
                    target_ip,
                    port,
                    f"GET / connect={target_ip} target={target_host} Host={host or '<empty>'}",
                    req,
                    use_tls=tls,
                    sni=(target_host if tls and target_host != "1.1.1.1" else None),
                )

        # alternate methods: connect directly to each target IP
        for target_host, target_ip in targets:
            for method in ("HEAD", "OPTIONS"):
                req = (
                    f"{method} / HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: direct-probe/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                do_req(
                    target_ip,
                    port,
                    f"{method} / connect={target_ip} target={target_host}",
                    req,
                    use_tls=tls,
                    sni=(target_host if tls and target_host != "1.1.1.1" else None),
                )

        # absolute-form GETs: connect directly to each target IP
        for target_host, target_ip in targets:
            for url in (f"http://{target_host}/", f"http://{target_ip}/"):
                req = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: direct-probe/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                do_req(
                    target_ip,
                    port,
                    f"ABSOLUTE GET {url} connect={target_ip}",
                    req,
                    use_tls=tls,
                    sni=(target_host if tls and target_host != "1.1.1.1" else None),
                )

        # CONNECT tests: connect directly to each target IP and ask it to CONNECT elsewhere
        for connect_host, connect_ip in targets:
            for dest_host, dest_ip in targets:
                for dest in (
                    f"{dest_host}:443",
                    f"{dest_ip}:443",
                    f"{dest_host}:80",
                    f"{dest_ip}:80",
                ):
                    req = (
                        f"CONNECT {dest} HTTP/1.1\r\n"
                        f"Host: {dest}\r\n"
                        f"User-Agent: direct-probe/2.0\r\n"
                        f"Proxy-Connection: close\r\n\r\n"
                    )
                    do_req(
                        connect_ip,
                        port,
                        f"CONNECT {dest} connect={connect_ip} server={connect_host}",
                        req,
                        use_tls=tls,
                        sni=(connect_host if tls and connect_host != "1.1.1.1" else None),
                    )

        # header variation tests: connect directly to each target IP
        header_variants = [
            ("xff-public", "X-Forwarded-For: 8.8.8.8\r\n"),
            ("xff-private", "X-Forwarded-For: 127.0.0.1\r\n"),
            ("forwarded", "Forwarded: for=8.8.8.8;proto=http;host=example.com\r\n"),
            ("proxy-auth", f"Proxy-Authorization: {basic_auth('test','test')}\r\n"),
            ("all", "X-Forwarded-For: 8.8.8.8\r\nForwarded: for=8.8.8.8;proto=http;host=example.com\r\n"),
        ]
        for target_host, target_ip in targets:
            for name, extra in header_variants:
                req = (
                    f"GET http://example.com/ HTTP/1.1\r\n"
                    f"Host: example.com\r\n"
                    f"{extra}"
                    f"User-Agent: direct-probe/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                do_req(
                    target_ip,
                    port,
                    f"ABSOLUTE GET variant={name} connect={target_ip} target={target_host}",
                    req,
                    use_tls=tls,
                    sni=(target_host if tls and target_host != "1.1.1.1" else None),
                )

        # SNI variation on 443: connect directly to each target IP
        if tls:
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "User-Agent: direct-probe/2.0\r\n"
                "Connection: close\r\n\r\n"
            )
            for target_host, target_ip in targets:
                for sni in snis:
                    do_req(
                        target_ip,
                        port,
                        f"SNI={sni or '<none>'} Host=example.com connect={target_ip} target={target_host}",
                        req,
                        use_tls=True,
                        sni=sni,
                    )

if __name__ == "__main__":
    main()
