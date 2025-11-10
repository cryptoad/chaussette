#!/usr/bin/env python3
"""
proxy_port_scan.py

Usage:
    python proxy_port_scan.py 9000-10000
    python proxy_port_scan.py --range 9000-9010 --concurrency 50 --timeout 5

The script parses HTTP_PROXY (or http_proxy) env var for proxy host:port and optional auth,
then connects to that proxy and issues GET requests for http://127.0.0.1:<port>/ across the given port range.
Only successful responses (HTTP status code < 400) are printed.
"""

import os
import sys
import argparse
import socket
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 1.0  # seconds


def parse_proxy_env():
    env = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not env:
        raise SystemExit("No HTTP_PROXY/http_proxy environment variable set.")

    # Ensure a scheme exists so urlparse handles it predictably
    if "://" not in env:
        env = "http://" + env

    p = urlparse(env)

    # Host may be in p.hostname, port in p.port
    if not p.hostname or not p.port:
        raise SystemExit(f"Could not parse proxy host/port from '{env}'")

    auth = None
    if p.username is not None:
        # Note: urlparse may percent-decode the username/password already
        username = p.username
        password = p.password or ""
        token = f"{username}:{password}".encode("utf-8")
        auth = "Basic " + base64.b64encode(token).decode("ascii")

    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "port": p.port,
        "auth_header": auth,
        "raw": env,
    }


def parse_port_range(s: str):
    # Accept formats like "9000-10000" or comma separated numbers/ranges "9000,9002,9004-9006"
    parts = s.split(",")
    ports = set()
    for part in parts:
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            a = int(a)
            b = int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            if part:
                ports.add(int(part))
    # Validate port numbers
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    return valid


def build_get_request(target_host: str, target_port: int, auth_header: str | None):
    # Use absolute URI in request line, per proxy-caching behavior.
    request_lines = [
        f"GET http://{target_host}:{target_port}/ HTTP/1.1",
        f"Host: {target_host}:{target_port}",
        "Connection: close",
    ]
    if auth_header:
        request_lines.append(f"Proxy-Authorization: {auth_header}")
    request_lines.append("")  # empty line to end headers
    request_lines.append("")  # another empty line for final CRLF
    return "\r\n".join(request_lines).encode("utf-8")


def attempt_proxy_fetch(proxy_host, proxy_port, auth_header, target_port, timeout):
    """
    Connect to the proxy and request GET http://127.0.0.1:target_port/
    Returns (success_bool, info_string)
    """
    target_host = "127.0.0.1"
    req = build_get_request(target_host, target_port, auth_header)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((proxy_host, proxy_port))
    except Exception as e:
        return False, f"port {target_port}: connect to proxy {proxy_host}:{proxy_port} failed: {e}"
    try:
        sock.sendall(req)
    except Exception as e:
        sock.close()
        return False, f"port {target_port}: send failed: {e}"

    # read a chunk of response (we don't need the whole body)
    try:
        resp = b""
        # Read until we have at least the status line + some headers, or timeout/close
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            # stop early if we've read headers end
            if b"\r\n\r\n" in resp or len(resp) > 16 * 1024:
                break
    except socket.timeout:
        sock.close()
        return False, f"port {target_port}: timed out waiting for proxy response"
    except Exception as e:
        sock.close()
        return False, f"port {target_port}: recv failed: {e}"
    finally:
        sock.close()

    # Parse HTTP status line
    try:
        text = resp.decode("iso-8859-1", errors="replace")
        first_line = text.splitlines()[0] if text.splitlines() else ""
        # Expected "HTTP/1.1 200 OK" or similar
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            code = int(parts[1])
            if code < 400:
                # success; return some useful info (code + short snippet)
                snippet = text.split("\r\n\r\n", 1)[0]
                return True, f"port {target_port}: HTTP {code} via proxy {proxy_host}:{proxy_port}\n{snippet}"
            else:
                return False, f"port {target_port}: HTTP {code} (not counted as success)"
        else:
            # Non-HTTP or unexpected response from proxy
            return False, f"port {target_port}: unexpected response: {first_line}"
    except Exception as e:
        return False, f"port {target_port}: error parsing response: {e}"


def main():
    ap = argparse.ArgumentParser(description="Scan target ports by asking HTTP proxy to GET 127.0.0.1:<port>")
    ap.add_argument("range", nargs=1, help="Port range (e.g. 9000-10000 or 9000,9002,9004-9006)")
    ap.add_argument("--concurrency", "-c", type=int, default=20, help="Number of worker threads (default 20)")
    ap.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help=f"Socket timeout in seconds (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--brief", action="store_true", help="Only print a one-line summary for each success")
    args = ap.parse_args()

    try:
        proxy = parse_proxy_env()
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    ports = parse_port_range(args.range[0])
    if not ports:
        print("No valid ports parsed from range.", file=sys.stderr)
        sys.exit(1)

    print(f"Using proxy {proxy['host']}:{proxy['port']} (auth={'yes' if proxy['auth_header'] else 'no'})")
    print(f"Scanning {len(ports)} ports with concurrency={args.concurrency} timeout={args.timeout} ...")

    successes = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {
            ex.submit(
                attempt_proxy_fetch,
                proxy["host"],
                proxy["port"],
                proxy["auth_header"],
                p,
                args.timeout,
            ): p
            for p in ports
        }
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                ok, info = fut.result()
            except Exception as e:
                # Unexpected exception in worker
                print(f"port {p}: exception in worker: {e}", file=sys.stderr)
                continue
            if ok:
                successes.append((p, info))
                if args.brief:
                    print(f"[OK] port {p}")
                else:
                    print("-----")
                    print(info)
                    print("-----")

    if not successes:
        print("No successful responses found.")
        sys.exit(2)
    else:
        print(f"\nFound {len(successes)} successful port(s).")
        # optionally: list them succinctly
        print("Successful ports:", ", ".join(str(p) for p, _ in successes))


if __name__ == "__main__":
    main()
