#!/usr/bin/env python3
"""
Enhanced CONNECT test with response origin analysis (proxy vs target).
"""

import os
import sys
import socket
import argparse
import base64
import urllib.parse
import subprocess
import shutil
import time

DEFAULT_TARGET_PORT = 2024
DEFAULT_TIMEOUT = 5.0

def get_env_proxy():
    return os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")

def parse_proxy_url(proxy_url):
    if "://" not in proxy_url:
        proxy_url = "http://" + proxy_url
    p = urllib.parse.urlparse(proxy_url)
    return {
        "scheme": p.scheme or "http",
        "username": urllib.parse.unquote(p.username) if p.username else None,
        "password": urllib.parse.unquote(p.password) if p.password else None,
        "host": p.hostname,
        "port": p.port,
    }

def get_local_ip():
    if shutil.which("hostname"):
        try:
            out = subprocess.check_output(["hostname", "-I"], text=True).strip()
            if out:
                for ip in out.split():
                    if not ip.startswith("127.") and not ip.startswith("::1"):
                        return ip
                return out.split()[0]
        except Exception:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def build_connect_request(host, port, user=None, pw=None):
    lines = [
        f"CONNECT {host}:{port} HTTP/1.1",
        f"Host: {host}:{port}",
        "Proxy-Connection: keep-alive",
    ]
    if user and pw:
        import base64
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()

def recv_with_timestamp(sock, timeout):
    sock.settimeout(timeout)
    t0 = time.time()
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except socket.timeout:
        pass
    t1 = time.time()
    return b"".join(chunks), t1 - t0

def parse_http_headers(raw):
    try:
        txt = raw.decode("iso-8859-1", errors="replace")
        lines = txt.splitlines()
        status = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, txt
    except Exception:
        return "", {}, raw.decode("utf-8", errors="replace")

def main():
    ap = argparse.ArgumentParser(description="CONNECT test with response source detection.")
    ap.add_argument("--proxy", help="Proxy URL (e.g. http://user:pass@proxy:3128)")
    ap.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = ap.parse_args()

    proxy_url = args.proxy or get_env_proxy()
    if not proxy_url:
        sys.exit("No proxy specified via --proxy or HTTP_PROXY")

    p = parse_proxy_url(proxy_url)
    local_ip = get_local_ip()
    print(f"Using proxy {p['host']}:{p['port']} (user={'yes' if p['username'] else 'no'})")
    print(f"Target: {local_ip}:{args.port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    s.connect((p["host"], p["port"]))

    # ---- CONNECT ----
    req = build_connect_request(local_ip, args.port, p["username"], p["password"])
    s.sendall(req)
    resp1, dt1 = recv_with_timestamp(s, args.timeout)
    status1, hdrs1, txt1 = parse_http_headers(resp1)
    print("\n[Proxy Response]")
    print(txt1)
    print(f"(elapsed {dt1:.2f}s, server={hdrs1.get('server', 'unknown')})")
    print("→ Origin: PROXY (CONNECT response)\n")

    # ---- Send TEST ----
    if "200" in status1:
        s.sendall(b"TEST\r\n\r\n")
        resp2, dt2 = recv_with_timestamp(s, args.timeout)
        if not resp2:
            print("(no reply from target within timeout)")
        else:
            status2, hdrs2, txt2 = parse_http_headers(resp2)
            probable_origin = "TARGET"
            if hdrs2.get("server", "").lower().startswith("envoy"):
                probable_origin = "PROXY"
            print("[Second Response]")
            print(txt2)
            print(f"(elapsed {dt2:.2f}s, server={hdrs2.get('server', 'unknown')})")
            print(f"→ Probable origin: {probable_origin}")
    else:
        print("CONNECT failed; no tunnel established.")
    s.close()

if __name__ == "__main__":
    main()
