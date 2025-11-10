#!/usr/bin/env python3
"""
scan_proxy_subnet_ws_upgrade.py

Scan odd IPs in the /24 of the proxy IP (from HTTP_PROXY).
For each odd IP O:
  - attempt TCP connect to O:proxy_port
  - if connect succeeds, attempt "CONNECT E:2024" where E = O - 1
  - if CONNECT returns 2xx, send a WebSocket-style Upgrade request
  - print result and stop scanning on the first successful CONNECT

Usage:
  python3 scan_proxy_subnet_ws_upgrade.py
  python3 scan_proxy_subnet_ws_upgrade.py --proxy http://user:pass@1.2.3.4:3128 -t 3
"""

import os
import socket
import ssl
import urllib.parse
import base64
import argparse
import hashlib
import time

DEFAULT_TIMEOUT = 3.0
READ_LIMIT = 4096
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def parse_proxy_env(explicit=None):
    val = explicit or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not val:
        return None
    if "://" not in val:
        val = "http://" + val
    p = urllib.parse.urlparse(val)
    scheme = p.scheme.lower()
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    auth = None
    if p.username:
        creds = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
        auth = "Basic " + base64.b64encode(creds.encode()).decode()
    return scheme, host, port, auth

def resolve_to_ipv4(host):
    try:
        parts = host.split(".")
        if len(parts) == 4 and all(0 <= int(p) < 256 for p in parts):
            return host
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None

def ip_to_octets(ip):
    return [int(x) for x in ip.split(".")]

def iter_odd_ips_in_24(base_ip):
    a,b,c,_ = ip_to_octets(base_ip)
    for host in range(1, 255, 2):  # odd IPs
        yield f"{a}.{b}.{c}.{host}"

def tcp_connect(ip, port, timeout):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        return s, None
    except Exception as e:
        return None, str(e)

def wrap_tls(sock, scheme, hostname):
    if scheme != "https":
        return sock
    ctx = ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=hostname)

def read_until(sock, marker=b"\r\n\r\n", timeout=2.0, max_bytes=16384):
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                break
    except Exception:
        pass
    return data

def parse_status_line(head):
    if not head:
        return None, ""
    first = head.split(b"\r\n",1)[0].decode(errors="replace")
    parts = first.split()
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    return code, first

def make_ws_key():
    key = os.urandom(16)
    return base64.b64encode(key).decode()

def ws_expected_accept(key):
    sha = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(sha).decode()

def attempt(ip_odd, proxy_port, scheme, proxy_auth, timeout):
    result = {"odd_ip": ip_odd, "even_ip": None, "connect_status": None, "reply": None}

    # compute even IP
    a,b,c,d = ip_to_octets(ip_odd)
    if d < 2:
        return result
    even_ip = f"{a}.{b}.{c}.{d-1}"
    result["even_ip"] = even_ip

    sock, err = tcp_connect(ip_odd, proxy_port, timeout)
    if not sock:
        print(f"  no-connect ({err})")
        return result
    sock = wrap_tls(sock, scheme, ip_odd if scheme == "https" else None)

    # send CONNECT
    req = f"CONNECT {even_ip}:2024 HTTP/1.1\r\nHost: {even_ip}:2024\r\n"
    if proxy_auth:
        req += f"Proxy-Authorization: {proxy_auth}\r\n"
    req += "Connection: keep-alive\r\n\r\n"
    sock.sendall(req.encode())
    head = read_until(sock)
    code, line = parse_status_line(head)
    result["connect_status"] = code

    if not code or code < 200 or code >= 300:
        print(f"  CONNECT failed ({line})")
        sock.close()
        return result

    print(f"  CONNECT OK ({line})")

    # send WebSocket Upgrade request
    ws_key = make_ws_key()
    expected_accept = ws_expected_accept(ws_key)
    upgrade_req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {even_ip}:2024\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: proxy-ws-upgrade/1.0\r\n"
        "\r\n"
    )
    sock.sendall(upgrade_req.encode())
    data = read_until(sock)
    sock.close()

    if not data:
        print("  No response to WebSocket Upgrade.")
        return result

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data[:512])
    print("\n--- WebSocket Upgrade Reply ---")
    print(text)
    print("--- End ---\n")
    result["reply"] = text

    # stop scanning
    print("Stopping after first successful CONNECT.")
    return result

def main():
    ap = argparse.ArgumentParser(description="Scan odd IPs in proxy /24; CONNECT to even_ip:2024 then send WebSocket Upgrade and stop on first success.")
    ap.add_argument("--proxy", help="override HTTP_PROXY")
    ap.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="timeout seconds")
    args = ap.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("No HTTP_PROXY set. Exiting.")
        return
    scheme, phost, pport, pauth = proxy
    proxy_ip = resolve_to_ipv4(phost)
    if not proxy_ip:
        print(f"Could not resolve {phost}.")
        return
    print(f"Using proxy {scheme}://{phost}:{pport} ({proxy_ip})")

    for odd in iter_odd_ips_in_24(proxy_ip):
        print(f"[+] Trying {odd}:{pport} ...", end="", flush=True)
        res = attempt(odd, pport, scheme, pauth, args.timeout)
        if res.get("connect_status") and 200 <= res["connect_status"] < 300:
            # successful CONNECT → stop scanning
            return
    print("No successful CONNECT found.")

if __name__ == "__main__":
    main()
