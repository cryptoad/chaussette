#!/usr/bin/env python3
import socket, ssl, struct, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 0.8
MAX_READ = 4096
WORKERS = 32

def get_default_gateway_linux():
    with open("/proc/net/route") as f:
        next(f)
        for line in f:
            fields = line.strip().split()
            if len(fields) >= 3 and fields[1] == "00000000":
                return fields[0], socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    raise SystemExit("No default gateway found in /proc/net/route")

def recv_some(sock, max_bytes=MAX_READ):
    sock.settimeout(TIMEOUT)
    try:
        data = sock.recv(max_bytes)
        return data or b""
    except socket.timeout:
        return b""

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

def basic_auth(user, pw):
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {tok}"

def run_one(connect_ip, port, label, raw, use_tls=False, sni=None):
    out = [f"\n--- {label} ---"]
    try:
        s = open_sock(connect_ip, port, use_tls=use_tls, sni=sni)
        s.sendall(raw.encode("utf-8", "replace"))
        data = recv_some(s)
        s.close()
        if not data:
            out.append("(no response)")
        else:
            out.append(data.decode("utf-8", "replace"))
    except Exception as e:
        out.append(f"ERROR: {e}")
    return "\n".join(out)

def main():
    iface, gw = get_default_gateway_linux()
    print(f"Gateway: {gw} via {iface}")

    # Connect-to targets: where the TCP socket is opened.
    targets = [
        ("example.com", "93.184.216.34"),
        ("zero", "0.0.0.0"),
    ]

    # Host header cases for normal GET tests.
    host_headers = [
        "example.com",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "",
    ]

    header_variants = [
        ("plain", ""),
        ("xff-private", "X-Forwarded-For: 127.0.0.1\r\n"),
        ("proxy-auth", f"Proxy-Authorization: {basic_auth('test','test')}\r\n"),
    ]

    # CONNECT destinations: keep small and high-signal so runtime stays low.
    connect_dests = [
        ("example.com", 443),
        ("93.184.216.34", 443),

        ("example.com", 80),
        ("93.184.216.34", 80),

        ("iana.org", 443),
        ("1.1.1.1", 443),
        ("8.8.8.8", 443),

        # Documentation/reserved cases useful for policy mapping
        ("127.0.0.1", 443),
        ("0.0.0.0", 443),
        ("localhost", 443),
        ("[::1]", 443),

        # RFC5737 documentation nets
        ("192.0.2.1", 443),
        ("198.51.100.1", 443),
        ("203.0.113.1", 443),
    ]

    jobs = []

    for target_host, target_ip in targets:
        # Plain HTTP on 80
        for host in host_headers:
            req = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: fast-probe/5.0\r\n"
                "Connection: close\r\n\r\n"
            )
            jobs.append((
                target_ip,
                80,
                f"GET / host={host or '<empty>'} connect={target_ip}",
                req,
                False,
                None,
            ))

        # Absolute-form GET on 80
        for name, extra in header_variants:
            req = (
                "GET http://example.com/ HTTP/1.1\r\n"
                "Host: example.com\r\n"
                f"{extra}"
                "User-Agent: fast-probe/5.0\r\n"
                "Connection: close\r\n\r\n"
            )
            jobs.append((
                target_ip,
                80,
                f"ABSOLUTE GET variant={name} connect={target_ip}",
                req,
                False,
                None,
            ))

        # CONNECT on 80
        for dest_host, dest_port in connect_dests:
            dest = f"{dest_host}:{dest_port}"
            req = (
                f"CONNECT {dest} HTTP/1.1\r\n"
                f"Host: {dest}\r\n"
                "User-Agent: fast-probe/5.0\r\n"
                "Proxy-Connection: close\r\n"
                "Connection: close\r\n\r\n"
            )
            jobs.append((
                target_ip,
                80,
                f"CONNECT {dest} connect={target_ip}",
                req,
                False,
                None,
            ))

        # HTTPS GET on 443
        for sni in (None, "example.com", "localhost"):
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "User-Agent: fast-probe/5.0\r\n"
                "Connection: close\r\n\r\n"
            )
            jobs.append((
                target_ip,
                443,
                f"TLS GET sni={sni or '<none>'} connect={target_ip}",
                req,
                True,
                sni,
            ))

        # CONNECT over TLS on 443
        for dest_host, dest_port in connect_dests:
            dest = f"{dest_host}:{dest_port}"
            req = (
                f"CONNECT {dest} HTTP/1.1\r\n"
                f"Host: {dest}\r\n"
                "User-Agent: fast-probe/5.0\r\n"
                "Proxy-Connection: close\r\n"
                "Connection: close\r\n\r\n"
            )
            jobs.append((
                target_ip,
                443,
                f"TLS CONNECT {dest} connect={target_ip}",
                req,
                True,
                "example.com",
            ))

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(run_one, *job) for job in jobs]
        for fut in as_completed(futs):
            print(fut.result())

if __name__ == "__main__":
    main()
