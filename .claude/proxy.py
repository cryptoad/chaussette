#!/usr/bin/env python3
"""
proxy_scan_local.py

Use HTTP_PROXY (explicitly) to probe 127.0.0.1:port via the proxy (ignores NO_PROXY).
Tries HTTP CONNECT first, falls back to absolute-form GET.

Usage:
    python3 proxy_scan_local.py               # scans default common ports
    python3 proxy_scan_local.py -p 22,80,443  # scan specific ports
    python3 proxy_scan_local.py -t 3 -c 20    # timeout 3s, concurrency 20
"""

import os
import argparse
import socket
import ssl
import threading
import queue
import time
import urllib.parse
import base64

DEFAULT_PORTS = [
    21,22,23,25,53,80,110,143,443,445,
    587,631,993,995,3306,3389,5900,6379,8080,8443,8888
]

def parse_proxy_env():
    """Parse HTTP_PROXY / http_proxy and return (scheme, host, port, auth_header_or_None)"""
    for key in ("HTTP_PROXY", "http_proxy"):
        val = os.environ.get(key)
        if val:
            proxy = val.strip()
            # ensure scheme
            if "://" not in proxy:
                proxy = "http://" + proxy
            p = urllib.parse.urlparse(proxy)
            scheme = p.scheme.lower()
            host = p.hostname
            port = p.port or (443 if scheme == "https" else 80)
            auth = None
            if p.username:
                # Basic auth header
                userpass = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
                auth = "Basic " + base64.b64encode(userpass.encode()).decode()
            return scheme, host, port, auth
    return None  # no proxy


def recv_until_double_crlf(sock, timeout):
    """Read until CRLFCRLF or timeout; return bytes (may be partial if timeout)."""
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


def try_connect_via_proxy(proxy_scheme, proxy_host, proxy_port, proxy_auth, target_host, target_port, timeout, use_tls_for_proxy=False):
    """
    Attempt HTTP CONNECT target_host:target_port via proxy.
    Returns (status, details)
      status in {"connected", "proxy_auth", "refused", "timeout", "error", "closed"}
    details - text
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except socket.timeout:
        return "timeout", f"connection to proxy {proxy_host}:{proxy_port} timed out"
    except Exception as e:
        return "error", f"could not connect to proxy {proxy_host}:{proxy_port}: {e}"

    # TLS to proxy if https scheme
    if use_tls_for_proxy:
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        except Exception as e:
            sock.close()
            return "error", f"TLS to proxy failed: {e}"

    try:
        connect_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
        if proxy_auth:
            connect_line += f"Proxy-Authorization: {proxy_auth}\r\n"
        connect_line += "Connection: close\r\n\r\n"
        sock.sendall(connect_line.encode())
        head = recv_until_double_crlf(sock, timeout=timeout)
        if not head:
            sock.close()
            return "closed", "no response from proxy after CONNECT"
        # parse status line
        try:
            first_line = head.split(b"\r\n",1)[0].decode(errors="ignore")
            parts = first_line.split()
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        except Exception:
            sock.close()
            return "error", f"couldn't parse proxy response: {first_line!r}"
        sock.close()
        if status_code is None:
            return "error", f"couldn't parse status code: {first_line!r}"
        if 200 <= status_code < 300:
            return "connected", f"proxy CONNECT succeeded (HTTP {status_code})"
        elif status_code == 407:
            return "proxy_auth", f"proxy requires authentication (HTTP {status_code})"
        else:
            return "error", f"proxy returned HTTP {status_code} on CONNECT"
    except socket.timeout:
        sock.close()
        return "timeout", "timeout while waiting for CONNECT response"
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return "error", f"exception during CONNECT: {e}"


def try_get_via_proxy(proxy_scheme, proxy_host, proxy_port, proxy_auth, target_host, target_port, timeout, use_tls_for_proxy=False):
    """
    Fallback: send an absolute-form GET to proxy requesting http://target_host:target_port/
    If proxy connects and returns any HTTP response, we assume it could reach the host:port.
    Returns (status, details)
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except socket.timeout:
        return "timeout", f"connection to proxy {proxy_host}:{proxy_port} timed out"
    except Exception as e:
        return "error", f"could not connect to proxy {proxy_host}:{proxy_port}: {e}"

    if use_tls_for_proxy:
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        except Exception as e:
            sock.close()
            return "error", f"TLS to proxy failed: {e}"

    try:
        # Request absolute URI
        url = f"http://{target_host}:{target_port}/"
        req = [
            f"GET {url} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
        ]
        if proxy_auth:
            req.append(f"Proxy-Authorization: {proxy_auth}")
        req.append("Connection: close")
        req.append("")  # blank line
        req.append("")
        req_data = "\r\n".join(req).encode()
        sock.sendall(req_data)
        head = recv_until_double_crlf(sock, timeout=timeout)
        if not head:
            sock.close()
            return "closed", "no response from proxy after GET"
        try:
            first_line = head.split(b"\r\n",1)[0].decode(errors="ignore")
            parts = first_line.split()
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        except Exception:
            sock.close()
            return "error", f"couldn't parse proxy response: {first_line!r}"
        sock.close()
        if status_code is None:
            return "error", f"couldn't parse status code: {first_line!r}"
        if status_code == 407:
            return "proxy_auth", f"proxy requires authentication (HTTP {status_code})"
        # If we got any 2xx/3xx/4xx/5xx, the proxy did connect to the target (even if target returned 404).
        return "got_http", f"proxy returned HTTP {status_code} for GET"
    except socket.timeout:
        sock.close()
        return "timeout", "timeout while waiting for GET response"
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return "error", f"exception during GET: {e}"


def worker(q, out_lock, proxy_info, timeout, results):
    scheme, host, port, auth = proxy_info
    use_tls = (scheme == "https")
    while True:
        try:
            tgt_port = q.get_nowait()
        except queue.Empty:
            return
        target_host = "127.0.0.1"
        start = time.time()
        status, details = try_connect_via_proxy(scheme, host, port, auth, target_host, tgt_port, timeout, use_tls_for_proxy=use_tls)
        took = time.time() - start
        if status == "connected":
            res = (tgt_port, "OPEN (CONNECT)", details, took)
        elif status == "proxy_auth":
            res = (tgt_port, "PROXY_AUTH", details, took)
        else:
            # fallback to GET attempt
            start2 = time.time()
            status2, details2 = try_get_via_proxy(scheme, host, port, auth, target_host, tgt_port, timeout, use_tls_for_proxy=use_tls)
            took2 = time.time() - start2
            if status2 in ("got_http", "connected"):
                res = (tgt_port, "OPEN (GET)", details2, took + took2)
            else:
                # Combine for debugging
                res = (tgt_port, f"CLOSED/UNREACHABLE ({status},{status2})", details + " | " + details2, took + took2)
        with out_lock:
            results.append(res)
            print(f"[{res[0]:5}] {res[1]:20} {res[2]} (took {res[3]:.2f}s)")
        q.task_done()


def main():
    p = parse_proxy_env()
    if not p:
        print("HTTP_PROXY not set (HTTP_PROXY or http_proxy). Exiting.")
        return
    scheme, host, port, auth = p
    print(f"Using proxy: {scheme}://{host}:{port} {'(auth supplied)' if auth else ''}")
    parser = argparse.ArgumentParser(description="Probe 127.0.0.1:ports via HTTP proxy (ignores NO_PROXY).")
    parser.add_argument("-p", "--ports", help="Comma-separated ports (e.g. 80,443) or ranges like 8000-8010", default=None)
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="Socket timeout seconds")
    parser.add_argument("-c", "--concurrency", type=int, default=8, help="Thread concurrency")
    args = parser.parse_args()

    ports = []
    if args.ports:
        parts = args.ports.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                a,b = part.split("-",1)
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(part))
    else:
        ports = DEFAULT_PORTS

    q = queue.Queue()
    for portnum in sorted(set(ports)):
        q.put(portnum)

    out_lock = threading.Lock()
    results = []
    proxy_info = (scheme, host, port, auth)
    threads = []
    for _ in range(min(args.concurrency, q.qsize())):
        t = threading.Thread(target=worker, args=(q, out_lock, proxy_info, args.timeout, results), daemon=True)
        t.start()
        threads.append(t)

    # Wait for queue to finish
    q.join()
    # small join of threads
    for t in threads:
        t.join(timeout=0.1)

    # Summarize
    print("\nSummary:")
    results.sort(key=lambda r: r[0])
    for portnum, status, detail, took in results:
        print(f"{portnum:5}  {status:20}  {detail}")

if __name__ == "__main__":
    main()
