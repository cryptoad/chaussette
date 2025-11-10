#!/usr/bin/env python3
"""
scan_proxy_subnet_connect.py

Scan odd IPs in the /24 of the proxy IP (from HTTP_PROXY). For each odd IP O:
  - attempt TCP connect to O:proxy_port
  - if connect succeeds, attempt "CONNECT E:2024" where E = O - 1 (even previous IP)
  - if CONNECT returns 2xx, send "TEST\r\n\r\n" through the tunnel, read a small reply,
    print the result and exit.

Usage:
  python3 scan_proxy_subnet_connect.py
  python3 scan_proxy_subnet_connect.py --proxy http://user:pass@1.2.3.4:3128 -t 3

Notes:
 - Honours HTTP_PROXY / http_proxy (or --proxy override). Does NOT consult NO_PROXY.
 - Supports http and https proxies (will TLS to the proxy host if scheme is https).
 - Stops after first successful CONNECT+TEST attempt (even if the target gives no response),
   as requested.
"""

from __future__ import annotations
import os
import socket
import ssl
import urllib.parse
import base64
import argparse
import time
import struct
import fcntl

# For reading local interface if needed (not strictly necessary here)
SIOCGIFADDR = 0x8915

DEFAULT_TIMEOUT = 3.0
TEST_PAYLOAD = b"TEST\r\n\r\n"
READ_LIMIT = 4096

def parse_proxy_env(explicit: str | None = None):
    """Parse HTTP_PROXY / http_proxy or an explicit proxy string.
    Returns (scheme, host, port, proxy_auth_header_or_None).
    """
    val = explicit or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not val:
        return None
    s = val.strip()
    if "://" not in s:
        s = "http://" + s
    p = urllib.parse.urlparse(s)
    scheme = p.scheme.lower()
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    auth = None
    if p.username:
        user = urllib.parse.unquote(p.username)
        pwd = urllib.parse.unquote(p.password or "")
        creds = f"{user}:{pwd}"
        auth = "Basic " + base64.b64encode(creds.encode()).decode()
    return scheme, host, port, auth

def resolve_to_ipv4(host: str) -> str | None:
    """Resolve hostname to the first IPv4 string, or return host if already IPv4."""
    try:
        # quick check if already IPv4 dotted
        parts = host.split(".")
        if len(parts) == 4 and all(0 <= int(p) < 256 for p in parts):
            return host
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if not infos:
            return None
        return infos[0][4][0]
    except Exception:
        return None

def ip_to_octets(ip: str):
    return [int(x) for x in ip.split(".")]

def octets_to_ip(o):
    return ".".join(str(x) for x in o)

def iter_odd_ips_in_24(base_ip: str):
    """Yield odd host IPs in the /24 of base_ip (1..254, last octet odd)."""
    a,b,c,d = ip_to_octets(base_ip)
    for host in range(1, 255):
        if host % 2 == 1:
            yield f"{a}.{b}.{c}.{host}"

def tcp_connect(addr: str, port: int, timeout: float):
    """Try to open TCP socket to addr:port. Return (sock, errstr) where sock is a connected socket or None."""
    try:
        s = socket.create_connection((addr, port), timeout=timeout)
        return s, None
    except Exception as e:
        return None, str(e)

def wrap_tls_if_needed(sock: socket.socket, scheme: str, server_hostname: str):
    """If scheme == 'https', wrap socket in TLS. Return wrapped socket or raise."""
    if scheme != "https":
        return sock
    ctx = ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=server_hostname)

def read_headers(sock: socket.socket, timeout: float):
    """Read until CRLFCRLF or timeout and return the bytes read (may be partial)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16*1024:
                break
    except socket.timeout:
        pass
    except Exception as e:
        return None, f"read error: {e}"
    return buf, None

def parse_status_line_from_head(head: bytes) -> (int | None, str):
    if not head:
        return None, ""
    try:
        first = head.split(b"\r\n",1)[0].decode(errors="replace")
        parts = first.split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        return status, first
    except Exception:
        return None, head.split(b"\r\n",1)[0].decode(errors="replace")

def attempt_connect_then_proxy_connect(odd_ip: str, proxy_port: int, scheme: str, proxy_auth: str | None, timeout: float):
    """
    Connect to odd_ip:proxy_port, then send CONNECT to even_ip:2024.
    Returns dict with keys:
      - odd_ip, even_ip, tcp_connect_err (if any),
      - connect_response_status (int or None), connect_response_line,
      - probe_sent (bool), probe_response (bytes or None), probe_err (str or None)
    """
    res = {
        "odd_ip": odd_ip,
        "even_ip": None,
        "tcp_connect_err": None,
        "connect_status": None,
        "connect_line": None,
        "connect_head_raw": None,
        "probe_sent": False,
        "probe_response": None,
        "probe_err": None,
    }

    # compute even IP (previous)
    try:
        a,b,c,d = ip_to_octets(odd_ip)
        even_host = d - 1
        if even_host < 1 or even_host > 254:
            res["tcp_connect_err"] = f"computed even host {even_host} out of range"
            return res
        even_ip = f"{a}.{b}.{c}.{even_host}"
        res["even_ip"] = even_ip
    except Exception as e:
        res["tcp_connect_err"] = f"ip math error: {e}"
        return res

    # 1) TCP connect to odd_ip:proxy_port
    sock, err = tcp_connect(odd_ip, proxy_port, timeout)
    if not sock:
        res["tcp_connect_err"] = err
        return res

    # wrap TLS to proxy if scheme==https
    try:
        sock = wrap_tls_if_needed(sock, scheme, server_hostname=odd_ip if scheme=="https" else None)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        res["tcp_connect_err"] = f"TLS wrap failed: {e}"
        return res

    # 2) send CONNECT even_ip:2024
    connect_req = f"CONNECT {res['even_ip']}:2024 HTTP/1.1\r\nHost: {res['even_ip']}:2024\r\n"
    if proxy_auth:
        connect_req += f"Proxy-Authorization: {proxy_auth}\r\n"
    connect_req += "Connection: keep-alive\r\n\r\n"
    try:
        sock.settimeout(timeout)
        sock.sendall(connect_req.encode())
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        res["tcp_connect_err"] = f"failed to send CONNECT: {e}"
        return res

    # 3) read proxy response headers
    head, read_err = read_headers(sock, timeout=timeout)
    if read_err:
        try:
            sock.close()
        except Exception:
            pass
        res["tcp_connect_err"] = read_err
        return res

    res["connect_head_raw"] = head
    status, first_line = parse_status_line_from_head(head)
    res["connect_status"] = status
    res["connect_line"] = first_line

    if status is None:
        # no numeric status — could be empty (no headers) or unparsable
        # treat as failure and close
        try:
            sock.close()
        except Exception:
            pass
        return res

    if not (200 <= status < 300):
        # CONNECT not successful; close and continue scanning
        try:
            sock.close()
        except Exception:
            pass
        return res

    # 4) CONNECT succeeded (200): send TEST payload and read reply
    try:
        sock.settimeout(timeout)
        sock.sendall(TEST_PAYLOAD)
        res["probe_sent"] = True
    except Exception as e:
        res["probe_err"] = f"failed to send probe payload: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return res

    # read small reply
    try:
        sock.settimeout(timeout)
        data = sock.recv(READ_LIMIT)
        if data == b"":
            # peer closed
            res["probe_response"] = b""
        else:
            res["probe_response"] = data
    except socket.timeout:
        # no data in timeout
        res["probe_response"] = None
    except Exception as e:
        res["probe_err"] = f"read after probe failed: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return res

def main():
    parser = argparse.ArgumentParser(description="Scan odd IPs in /24 of proxy IP and try CONNECT to preceding even IP:2024 then send TEST.")
    parser.add_argument("--proxy", help="explicit proxy URL to use (overrides HTTP_PROXY env)")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-operation timeout seconds")
    args = parser.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("HTTP_PROXY or http_proxy not set (or use --proxy). Exiting.")
        return
    scheme, proxy_host, proxy_port, proxy_auth = proxy
    print(f"Using proxy setting: {scheme}://{proxy_host}:{proxy_port} {'(auth)' if proxy_auth else ''}")

    # resolve proxy_host to IPv4
    proxy_ip = resolve_to_ipv4(proxy_host)
    if not proxy_ip:
        print(f"Could not resolve proxy host {proxy_host} to IPv4. Exiting.")
        return
    print(f"Proxy resolved to IPv4: {proxy_ip}; scanning its /24 odd hosts on port {proxy_port}")

    # iterate odd IPs
    for odd_ip in iter_odd_ips_in_24(proxy_ip):
        print(f"[+] trying {odd_ip}:{proxy_port} ...", end="", flush=True)
        res = attempt_connect_then_proxy_connect(odd_ip, proxy_port, scheme, proxy_auth, args.timeout)
        if res.get("tcp_connect_err"):
            print(f" no-connect ({res['tcp_connect_err']})")
            continue
        # we connected to odd_ip; now see CONNECT status
        status = res.get("connect_status")
        line = res.get("connect_line") or ""
        if status is None:
            print(" connected -> no numeric response from proxy (skipping)")
            continue
        print(f" connected -> CONNECT responded {line!s}")

        if 200 <= status < 300:
            # CONNECT succeeded; we already sent TEST. Show result and stop scanning.
            probe_sent = res.get("probe_sent")
            probe_resp = res.get("probe_response")
            probe_err = res.get("probe_err")
            print(" -> CONNECT 200 OK; TEST sent.")
            if probe_err:
                print(f"Probe error: {probe_err}")
            if probe_sent:
                if probe_resp is None:
                    print("Probe: no response (timeout).")
                elif probe_resp == b"":
                    print("Probe: peer closed connection immediately (empty read).")
                else:
                    # print snippet safely
                    snippet = probe_resp[:1024]
                    try:
                        s = snippet.decode("utf-8", errors="replace")
                    except Exception:
                        s = repr(snippet)
                    print(f"Probe: got {len(probe_resp)} bytes back:\n{s}")
            else:
                print("Probe: not sent.")
            print("\nResult (first successful):")
            print(f"  odd_ip_used       : {res['odd_ip']}")
            print(f"  proxy_port        : {proxy_port}")
            print(f"  even_target       : {res['even_ip']}:2024")
            print(f"  connect_status    : {status} ({line})")
            print(f"  probe_sent        : {probe_sent}")
            print(f"  probe_response_len: {None if probe_resp is None else len(probe_resp)}")
            return

        # CONNECT wasn't 200 — close and continue
        print(" -> CONNECT not allowed (not 2xx), continuing scan.")

    print("Scan finished: no odd IP produced a successful CONNECT+TEST sequence.")

if __name__ == "__main__":
    main()
