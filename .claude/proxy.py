#!/usr/bin/env python3
"""
proxy_scan_local_probe.py

Probe 127.0.0.1:ports via HTTP proxy (ignores NO_PROXY), using CONNECT and then
attempting to send small probe payloads through the established tunnel to detect
whether the proxy actually connected to the target port.

Usage:
    python3 proxy_scan_local_probe.py
    python3 proxy_scan_local_probe.py -p 1-1024,8080 -t 3 -c 12
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
import select

DEFAULT_PORTS = [
    21,22,23,25,53,80,110,135,139,143,443,445,
    587,631,993,995,3306,3389,5900,6379,8080,8443,8888
]

# ports we treat as HTTP-like (send GET)
HTTP_LIKE = {80, 8080, 8000, 8888, 8008, 3128, 6081}
# ports we treat as TLS-like (try TLS handshake)
TLS_LIKE = {443, 8443, 993, 995, 465, 636}

def parse_proxy_env():
    """Parse HTTP_PROXY / http_proxy and return (scheme, host, port, auth_header_or_None)"""
    for key in ("HTTP_PROXY", "http_proxy"):
        val = os.environ.get(key)
        if val:
            proxy = val.strip()
            if "://" not in proxy:
                proxy = "http://" + proxy
            p = urllib.parse.urlparse(proxy)
            scheme = p.scheme.lower()
            host = p.hostname
            port = p.port or (443 if scheme == "https" else 80)
            auth = None
            if p.username:
                userpass = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
                auth = "Basic " + base64.b64encode(userpass.encode()).decode()
            return scheme, host, port, auth
    return None

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

def establish_connect(proxy_scheme, proxy_host, proxy_port, proxy_auth, target_host, target_port, timeout, use_tls_for_proxy=False):
    """
    Establish CONNECT to proxy. Returns (status, details, sock_or_None).
    status: "connected" (200) or "proxy_auth" (407) or "error"/"timeout"/"closed"
    If connected, returns the socket object still open and positioned after the proxy response.
    Caller MUST close returned socket.
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except socket.timeout:
        return "timeout", f"connection to proxy {proxy_host}:{proxy_port} timed out", None
    except Exception as e:
        return "error", f"could not connect to proxy {proxy_host}:{proxy_port}: {e}", None

    if use_tls_for_proxy:
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=proxy_host)
        except Exception as e:
            sock.close()
            return "error", f"TLS to proxy failed: {e}", None

    try:
        connect_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
        if proxy_auth:
            connect_line += f"Proxy-Authorization: {proxy_auth}\r\n"
        connect_line += "Connection: keep-alive\r\n\r\n"
        sock.sendall(connect_line.encode())
        head = recv_until_double_crlf(sock, timeout=timeout)
        if not head:
            # no response yet — return socket anyway to let caller attempt read/write
            return "closed", "no response from proxy after CONNECT", sock
        try:
            first_line = head.split(b"\r\n",1)[0].decode(errors="ignore")
            parts = first_line.split()
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        except Exception:
            return "error", f"couldn't parse proxy response: {head!r}", sock
        if status_code is None:
            return "error", f"couldn't parse status code: {first_line!r}", sock
        if 200 <= status_code < 300:
            return "connected", f"proxy CONNECT succeeded (HTTP {status_code})", sock
        elif status_code == 407:
            sock.close()
            return "proxy_auth", f"proxy requires authentication (HTTP {status_code})", None
        else:
            sock.close()
            return "error", f"proxy returned HTTP {status_code} on CONNECT", None
    except socket.timeout:
        sock.close()
        return "timeout", "timeout while waiting for CONNECT response", None
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return "error", f"exception during CONNECT: {e}", None

def probe_tunnel(sock, target_port, timeout, proxy_scheme):
    """
    Given a socket whose CONNECT succeeded (tunnel established), try a set of probes and
    decide whether the upstream port accepted the connection.

    Returns (result_str, detail_str)
     - result_str in {"OPEN", "CLOSED", "UNKNOWN"}
    """
    # Use non-blocking/select based reads/writes with timeouts so we don't hang.
    sock.settimeout(timeout)

    def safe_recv_some(wait):
        """Wait up to wait seconds for readability; then recv small."""
        try:
            r, _, _ = select.select([sock], [], [], wait)
            if r:
                try:
                    data = sock.recv(4096)
                    return data  # may be b'' (closed) or bytes
                except Exception as e:
                    return e
            return None
        except Exception as e:
            return e

    def safe_send_probe(payload):
        try:
            sock.sendall(payload)
            return True, None
        except Exception as e:
            return False, e

    # 1) Immediate read: sometimes services send banner immediately (e.g., SMTP, FTP)
    data = safe_recv_some(0.3)
    if isinstance(data, Exception):
        return "CLOSED", f"socket error while reading initial banner: {data}"
    if data == b"":
        return "CLOSED", "peer closed connection immediately (empty read)"
    if data:
        return "OPEN", f"received banner/data ({len(data)} bytes): {repr(data[:200])}"

    # 2) If port is HTTP-like -> send GET
    if target_port in HTTP_LIKE:
        ok, err = safe_send_probe(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        if not ok:
            # write error -> closed/filtered
            return "CLOSED", f"send failed: {err}"
        data = safe_recv_some(1.0)
        if isinstance(data, Exception):
            return "CLOSED", f"read error after GET: {data}"
        if data == b"":
            return "CLOSED", "connection closed after GET"
        if data:
            # We got an HTTP response or some bytes
            # attempt to parse status line
            try:
                first = data.split(b"\r\n",1)[0].decode(errors="ignore")
                return "OPEN", f"HTTP-like response: {first}"
            except Exception:
                return "OPEN", f"Received {len(data)} bytes after GET"
        # no response -> unknown
        return "UNKNOWN", "no response to GET"

    # 3) If TLS-like -> try to perform a TLS handshake on the established socket.
    if target_port in TLS_LIKE:
        # wrap the existing socket in SSL and attempt handshake
        try:
            ctx = ssl.create_default_context()
            # don't verify certs (we only care if handshake succeeds)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(timeout)
            ssock = ctx.wrap_socket(sock, server_hostname="127.0.0.1", do_handshake_on_connect=False)
            # attempt handshake with timeout by using settimeout
            ssock.settimeout(timeout)
            try:
                ssock.do_handshake()
                # handshake succeeded
                try:
                    # attempt to read any immediate data
                    data = ssock.recv(1024)
                    if data == b"":
                        ssock.close()
                        return "CLOSED", "TLS handshake succeeded but peer closed immediately"
                    if data:
                        ssock.close()
                        return "OPEN", f"TLS handshake succeeded and received {len(data)} bytes"
                    ssock.close()
                    return "OPEN", "TLS handshake succeeded (no immediate data)"
                except Exception:
                    ssock.close()
                    return "OPEN", "TLS handshake succeeded (no immediate data)"
            except ssl.SSLError as e:
                # handshake failed -> closed / not TLS
                try:
                    ssock.close()
                except Exception:
                    pass
                return "UNKNOWN", f"TLS handshake failed: {e}"
        except Exception as e:
            # wrapping failed, fall back to generic probe
            pass

    # 4) Generic probe: send a single NULL byte and wait briefly
    ok, err = safe_send_probe(b"\x00")
    if not ok:
        return "CLOSED", f"write failed sending null byte: {err}"
    data = safe_recv_some(0.8)
    if isinstance(data, Exception):
        return "CLOSED", f"read error after null-byte: {data}"
    if data == b"":
        return "CLOSED", "peer closed connection after null-byte"
    if data:
        return "OPEN", f"received {len(data)} bytes after null-byte: {repr(data[:200])}"

    # 5) Nothing observed — upstream might have accepted the connection but is silent.
    return "UNKNOWN", "no response to probes (connection may be open but silent)"

def try_probe_port_via_proxy(proxy_scheme, proxy_host, proxy_port, proxy_auth, target_host, target_port, timeout, use_tls_for_proxy=False):
    """
    Do the CONNECT and probe. Returns a tuple: (port, result_label, detail_str, total_time)
    result_label in {"OPEN", "CLOSED", "UNKNOWN", "PROXY_AUTH", "ERROR", "TIMEOUT"}
    """
    start = time.time()
    status, details, sock = establish_connect(proxy_scheme, proxy_host, proxy_port, proxy_auth, target_host, target_port, timeout, use_tls_for_proxy)
    if status == "connected":
        # sock represents a tunnel socket; perform probes on it
        try:
            probe_result, probe_detail = probe_tunnel(sock, target_port, timeout, proxy_scheme)
        except Exception as e:
            probe_result, probe_detail = "ERROR", f"exception during probe: {e}"
        finally:
            try:
                sock.close()
            except Exception:
                pass
        total = time.time() - start
        return (target_port, probe_result, f"{details} -> {probe_detail}", total)
    else:
        total = time.time() - start
        # ensure sock closed if returned
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        if status == "proxy_auth":
            return (target_port, "PROXY_AUTH", details, total)
        if status == "timeout":
            return (target_port, "TIMEOUT", details, total)
        return (target_port, "ERROR", details, total)

def worker(q, out_lock, proxy_info, timeout, results):
    scheme, host, port, auth = proxy_info
    use_tls = (scheme == "https")
    while True:
        try:
            tgt_port = q.get_nowait()
        except queue.Empty:
            return
        res = try_probe_port_via_proxy(scheme, host, port, auth, "127.0.0.1", tgt_port, timeout, use_tls_for_proxy=use_tls)
        with out_lock:
            results.append(res)
            print(f"[{res[0]:5}] {res[1]:8}  {res[2]} (took {res[3]:.2f}s)")
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
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="per-operation timeout seconds")
    parser.add_argument("-c", "--concurrency", type=int, default=8, help="thread concurrency")
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

    q.join()
    for t in threads:
        t.join(timeout=0.1)

    print("\nSummary:")
    results.sort(key=lambda r: r[0])
    for portnum, status, detail, took in results:
        print(f"{portnum:5}  {status:8}  {detail} (took {took:.2f}s)")

if __name__ == "__main__":
    main()
