#!/usr/bin/env python3
"""
proxy_connect_test.py

Reads HTTP proxy from HTTP_PROXY/http_proxy, performs:
  CONNECT <local_ip>:2024 HTTP/1.1
If CONNECT succeeds (HTTP/1.1 200), sends "TEST\r\n\r\n" through the tunnel
and prints the response.

Usage:
  HTTP_PROXY='http://user:pass@proxy.example:3128' python proxy_connect_test.py
  python proxy_connect_test.py --proxy 'http://proxy:3128' --port 2024 --timeout 5
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
DEFAULT_TIMEOUT = 5.0  # seconds

def get_env_proxy():
    for k in ("HTTP_PROXY", "http_proxy"):
        v = os.environ.get(k)
        if v:
            return v
    return None

def parse_proxy_url(proxy_url):
    # Accept forms like http://user:pass@host:port or host:port
    if "://" not in proxy_url:
        proxy_url = "http://" + proxy_url
    p = urllib.parse.urlparse(proxy_url)
    scheme = p.scheme or "http"
    username = urllib.parse.unquote(p.username) if p.username else None
    password = urllib.parse.unquote(p.password) if p.password else None
    host = p.hostname
    port = p.port
    return {"scheme": scheme, "username": username, "password": password, "host": host, "port": port}

def get_local_ip_prefer_hostname_I():
    # Try `hostname -I` if available (simple per user's preference)
    if shutil.which("hostname"):
        try:
            out = subprocess.checkoutput(["hostname", "-I"], stderr=subprocess.DEVNULL, text=True, timeout=1)
        except AttributeError:
            # Python <3.7 compatibility: check_output capitalization
            out = subprocess.check_output(["hostname", "-I"], stderr=subprocess.DEVNULL, text=True, timeout=1)
        except Exception:
            out = ""
        if out:
            for token in out.strip().split():
                if token and not token.startswith("127.") and not token.startswith("::1"):
                    return token.strip()
            # fallback to first token if nothing else
            if out.strip():
                return out.strip().split()[0]
    # Fallback: UDP socket trick to learn the primary outbound address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))  # doesn't actually send
        addr = s.getsockname()[0]
        s.close()
        if addr:
            return addr
    except Exception:
        pass
    # Last resort: gethostbyname
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def build_connect_request(target_host, target_port, username=None, password=None):
    req_lines = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
        "Proxy-Connection: keep-alive",
    ]
    if username is not None and password is not None:
        creds = f"{username}:{password}"
        b64 = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        req_lines.append(f"Proxy-Authorization: Basic {b64}")
    req_lines.append("")  # blank line to end headers
    req_lines.append("")
    return "\r\n".join(req_lines).encode("utf-8")

def recv_all_until(sock, timeout, max_bytes=65536):
    sock.settimeout(timeout)
    chunks = []
    t0 = time.time()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) >= max_bytes:
                break
            if time.time() - t0 > timeout:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)

def read_http_status_line(header_bytes):
    try:
        text = header_bytes.decode("iso-8859-1", errors="replace")
        lines = text.splitlines()
        if len(lines) >= 1:
            return lines[0].strip()
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Issue CONNECT via HTTP proxy to local IP:port and send TEST.")
    parser.add_argument("--proxy", "-p", help="Proxy URL (overrides HTTP_PROXY env). Example: http://user:pass@host:3128")
    parser.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT, help=f"Target port on local machine (default {DEFAULT_TARGET_PORT})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Socket read timeout seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--raw", action="store_true", help="If set, print raw bytes only (no utf-8 attempt)")
    args = parser.parse_args()

    proxy_url = args.proxy or get_env_proxy()
    if not proxy_url:
        print("ERROR: No proxy provided. Set HTTP_PROXY or pass --proxy.", file=sys.stderr)
        sys.exit(2)

    parsed = parse_proxy_url(proxy_url)
    if not parsed["host"] or not parsed["port"]:
        print(f"ERROR: Could not parse proxy host/port from '{proxy_url}'", file=sys.stderr)
        sys.exit(2)

    if parsed["scheme"].lower() not in ("http", ""):
        print(f"WARNING: proxy scheme is '{parsed['scheme']}'. This script opens a plain TCP socket to the proxy. If the proxy requires TLS (https), this script will NOT wrap with TLS.", file=sys.stderr)

    local_ip = get_local_ip_prefer_hostname_I()
    target_port = args.port
    print(f"Using proxy: {parsed['host']}:{parsed['port']} (user={'yes' if parsed['username'] else 'no'})")
    print(f"Target (local) IP: {local_ip}:{target_port}")
    print("Opening TCP connection to proxy...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((parsed["host"], parsed["port"]))
    except Exception as e:
        print(f"ERROR: could not connect to proxy {parsed['host']}:{parsed['port']}: {e}", file=sys.stderr)
        s.close()
        sys.exit(3)

    # Build and send CONNECT request
    req = build_connect_request(local_ip, target_port, parsed["username"], parsed["password"])
    try:
        s.sendall(req)
    except Exception as e:
        print(f"ERROR: sending CONNECT to proxy failed: {e}", file=sys.stderr)
        s.close()
        sys.exit(4)

    # Read proxy response (headers)
    resp = recv_all_until(s, timeout=args.timeout)
    if not resp:
        print("No response received from proxy (timeout or closed).")
        s.close()
        sys.exit(5)

    status_line = read_http_status_line(resp)
    print("<<< Proxy response headers/raw >>>")
    if args.raw:
        sys.stdout.buffer.write(resp)
        print()
    else:
        try:
            print(resp.decode("utf-8", errors="replace"))
        except Exception:
            sys.stdout.buffer.write(resp)
            print()
    print("<<< end proxy response >>>")

    if status_line and ("200" in status_line.split()[:2]):
        print("Proxy returned 200 -> tunnel established. Sending TEST through tunnel...")
        try:
            s.sendall(b"TEST\r\n\r\n")
        except Exception as e:
            print(f"ERROR: sending TEST through tunnel failed: {e}", file=sys.stderr)
            s.close()
            sys.exit(6)

        reply = recv_all_until(s, timeout=args.timeout)
        print("<<< Reply from target service (raw) >>>")
        if not reply:
            print("(no reply received from target within timeout)")
        else:
            if args.raw:
                sys.stdout.buffer.write(reply)
                print()
            else:
                try:
                    print(reply.decode("utf-8", errors="replace"))
                except Exception:
                    sys.stdout.buffer.write(reply)
                    print()
        print("<<< end reply >>>")
    else:
        print("CONNECT likely failed (non-200). Not sending TEST.")
    s.close()

if __name__ == "__main__":
    main()
