#!/usr/bin/env python3
"""
proxy_get_localip.py

Send an absolute-form HTTP GET to the non-loopback interface IP via HTTP_PROXY (ignores NO_PROXY).
Supports basic auth embedded in HTTP_PROXY. Uses only Python stdlib.

Usage:
    python3 proxy_get_localip.py
    python3 proxy_get_localip.py --port 80 --path /health -t 5
    python3 proxy_get_localip.py --proxy http://user:pass@proxy.example:3128
"""

from __future__ import annotations
import os
import socket
import ssl
import struct
import fcntl
import argparse
import time
import urllib.parse
import base64
from typing import Optional, Tuple

SIOCGIFADDR = 0x8915

def parse_proxy_env(explicit_proxy: Optional[str] = None) -> Optional[Tuple[str,str,int,Optional[str]]]:
    """
    Parse HTTP_PROXY/http_proxy or explicit_proxy argument.
    Return tuple (scheme, host, port, proxy_auth_header_or_None)
    """
    proxy_val = explicit_proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not proxy_val:
        return None
    proxy = proxy_val.strip()
    if "://" not in proxy:
        proxy = "http://" + proxy
    p = urllib.parse.urlparse(proxy)
    scheme = p.scheme.lower()
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    auth_header = None
    if p.username:
        user = urllib.parse.unquote(p.username)
        passwd = urllib.parse.unquote(p.password or "")
        creds = f"{user}:{passwd}"
        auth_header = "Basic " + base64.b64encode(creds.encode()).decode()
    return scheme, host, port, auth_header

def choose_non_lo_iface() -> Optional[str]:
    """
    Inspect /proc/net/route: prefer default route interface (dest==00000000), otherwise first non-lo.
    """
    try:
        with open("/proc/net/route", "r") as f:
            lines = f.read().splitlines()
    except Exception:
        return None
    entries = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2:
            iface = parts[0]
            dest = parts[1]
            entries.append((iface, dest))
    for iface, dest in entries:
        if iface == "lo":
            continue
        if dest == "00000000":
            return iface
    for iface, dest in entries:
        if iface != "lo":
            return iface
    return None

def get_ipv4_for_iface(ifname: str) -> Optional[str]:
    """Return dotted-quad IPv4 address for interface or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack('256s', ifname.encode('utf-8')[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        # IPv4 address bytes are at offset 20..24
        ip_bytes = struct.unpack_from('!4B', res, 20)
        return "{}.{}.{}.{}".format(*ip_bytes)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def recv_until_double_crlf(sock: socket.socket, timeout: float) -> bytes:
    """Read until CRLFCRLF or timeout, return headers bytes (may be partial)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    except Exception:
        pass
    return buf

def read_body_after_headers(sock: socket.socket, initial_body: bytes, max_bytes: int, timeout: float) -> bytes:
    """
    Given a socket positioned after reading headers (and possibly some body), read up to max_bytes more or until socket closes/timeout.
    """
    data = bytearray()
    if initial_body:
        data += initial_body
    sock.settimeout(timeout)
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(min(4096, max_bytes - len(data)))
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except Exception:
        pass
    return bytes(data)

def do_absolute_get_via_proxy(proxy_scheme: str, proxy_host: str, proxy_port: int, proxy_auth: Optional[str],
                              target_ip: str, target_port: int, path: str, timeout: float):
    """
    Connect to the proxy and send:
       GET http://{target_ip}:{target_port}{path} HTTP/1.1
    Return (status_line, headers_text, body_snippet_bytes, raw_head_bytes, error_str_or_None)
    """
    addr = (proxy_host, proxy_port)
    start = time.time()
    sock = None
    try:
        sock = socket.create_connection(addr, timeout=timeout)
    except Exception as e:
        return None, None, None, None, f"Could not connect to proxy {proxy_host}:{proxy_port}: {e}"
    # TLS to proxy if scheme is https
    if proxy_scheme == "https":
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return None, None, None, None, f"TLS to proxy failed: {e}"

    try:
        url = f"http://{target_ip}:{target_port}{path}"
        req_lines = [
            f"GET {url} HTTP/1.1",
            f"Host: {target_ip}:{target_port}",
        ]
        if proxy_auth:
            req_lines.append(f"Proxy-Authorization: {proxy_auth}")
        # include a common user-agent so some proxies don't drop requests
        req_lines.append("User-Agent: proxy-get-localip/1.0")
        req_lines.append("Connection: close")
        req_lines.append("")  # blank line
        req_lines.append("")  # end
        req_data = "\r\n".join(req_lines).encode("utf-8")
        sock.settimeout(timeout)
        sock.sendall(req_data)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return None, None, None, None, f"Failed to send request to proxy: {e}"

    # read headers (and possibly part of body)
    head = recv_until_double_crlf(sock, timeout=timeout)
    if not head:
        # no response
        try:
            sock.close()
        except Exception:
            pass
        return None, None, None, None, "No response from proxy (timeout or closed)"
    # split headers/body
    try:
        head_parts = head.split(b"\r\n\r\n", 1)
        raw_headers = head_parts[0]
        initial_body = head_parts[1] if len(head_parts) > 1 else b""
        # decode headers text for printing; keep original raw for diagnostics
        try:
            headers_text = raw_headers.decode("utf-8", errors="replace")
        except Exception:
            headers_text = raw_headers.decode("latin-1", errors="replace")
        # parse status line
        first_line = headers_text.splitlines()[0] if headers_text else ""
        # read up to N bytes after headers to give a snippet
        body_snippet = read_body_after_headers(sock, initial_body, max_bytes=4096, timeout=1.0)
        try:
            sock.close()
        except Exception:
            pass
        return first_line, headers_text, body_snippet, raw_headers, None
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return None, None, None, None, f"Error parsing response: {e}"

def main():
    parser = argparse.ArgumentParser(description="Send absolute-form HTTP GET for local interface IP via HTTP_PROXY (ignores NO_PROXY).")
    parser.add_argument("--proxy", help="Explicit proxy URL to use (overrides HTTP_PROXY env).")
    parser.add_argument("--port", type=int, default=80, help="Target port at the local IP (default 80)")
    parser.add_argument("--path", default="/", help="Path to GET (default '/')")
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="Socket timeout (seconds)")
    args = parser.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("HTTP_PROXY or http_proxy not set (or use --proxy). Exiting.")
        return
    proxy_scheme, proxy_host, proxy_port, proxy_auth = proxy
    print(f"Using proxy: {proxy_scheme}://{proxy_host}:{proxy_port} {'(auth)' if proxy_auth else ''}")

    # find non-loopback interface IP
    iface = choose_non_lo_iface()
    if not iface:
        print("Could not find a non-loopback interface from /proc/net/route. Exiting.")
        return
    ip = get_ipv4_for_iface(iface)
    if not ip:
        print(f"Could not determine IPv4 for interface {iface}. Exiting.")
        return
    print(f"Using local interface {iface} with IP {ip}")

    print(f"Sending absolute GET to http://{ip}:{args.port}{args.path} via proxy...")
    status_line, headers_text, body_snippet, raw_headers, err = do_absolute_get_via_proxy(
        proxy_scheme, proxy_host, proxy_port, proxy_auth, ip, args.port, args.path, args.timeout
    )
    if err:
        print("ERROR:", err)
        return
    print("\n--- Proxy response status line ---")
    print(status_line or "(no status line)")
    print("\n--- Proxy response headers ---")
    print(headers_text or "(no headers)")
    print("\n--- Body snippet (first 4KB) ---")
    if body_snippet:
        # try to print as utf-8, fallback to latin1 with replacement
        try:
            print(body_snippet.decode("utf-8", errors="replace"))
        except Exception:
            print(body_snippet.decode("latin-1", errors="replace"))
    else:
        print("(no body)")

if __name__ == "__main__":
    main()
