#!/usr/bin/env python3
"""
proxy_connect_head.py

Performs an HTTP CONNECT via proxy (from HTTP_PROXY or --proxy), then sends
a HEAD / HTTP/1.1 request to the target (local IP by default) and shows the response.
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
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()

def recv_until_timeout(sock, timeout, max_bytes=65536):
    sock.settimeout(timeout)
    data = b""
    t0 = time.time()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= max_bytes or time.time() - t0 > timeout:
                break
    except socket.timeout:
        pass
    return data

def parse_http_response(raw):
    try:
        text = raw.decode("iso-8859-1", errors="replace")
    except Exception:
        text = str(raw)
    lines = text.splitlines()
    if not lines:
        return "(no headers)", text
    status = lines[0]
    server = ""
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    return status + f" (server={server or 'unknown'})", text

def main():
    ap = argparse.ArgumentParser(description="CONNECT then send HEAD / HTTP/1.1 request through proxy tunnel.")
    ap.add_argument("--proxy", help="Proxy URL (overrides HTTP_PROXY). Example: http://user:pass@proxy:3128")
    ap.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT, help="Target port (default 2024)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout (seconds)")
    ap.add_argument("--host", help="Override Host header (default = target IP)")
    args = ap.parse_args()

    proxy_url = args.proxy or get_env_proxy()
    if not proxy_url:
        sys.exit("No proxy specified via --proxy or HTTP_PROXY")

    p = parse_proxy_url(proxy_url)
    local_ip = get_local_ip()
    host_hdr = args.host or local_ip

    print(f"Using proxy {p['host']}:{p['port']} (user={'yes' if p['username'] else 'no'})")
    print(f"Target: {local_ip}:{args.port}")
    print(f"Host header: {host_hdr}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    s.connect((p["host"], p["port"]))

    # --- CONNECT ---
    req = build_connect_request(local_ip, args.port, p["username"], p["password"])
    s.sendall(req)
    proxy_reply = recv_until_timeout(s, args.timeout)
    print("\n[Proxy Response]")
    print(proxy_reply.decode("utf-8", errors="replace"))
    if b"200" not in proxy_reply:
        print("CONNECT failed; aborting.")
        s.close()
        return

    # --- HEAD request ---
    head_req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"User-Agent: proxy-connect-test/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    print("[Sending HEAD request...]")
    s.sendall(head_req)

    resp = recv_until_timeout(s, args.timeout)
    print("\n[Response through tunnel]")
    if resp:
        status, text = parse_http_response(resp)
        print(status)
        print(text)
    else:
        print("(no response, timed out or connection closed silently)")
    s.close()

if __name__ == "__main__":
    main()
