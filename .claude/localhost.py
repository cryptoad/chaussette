#!/usr/bin/env python3
"""
proxy_port_scan.py

Scan a range of ports by asking the HTTP proxy (from HTTP_PROXY/http_proxy env var)
to GET http://127.0.0.1:<port>/ for each port in the range.

Usage:
    python proxy_port_scan.py 9000-9010
    python proxy_port_scan.py 9000-9010 --any-reply --concurrency 50 --timeout 3 --brief

Options:
    --any-reply    Treat any non-empty response (including binary/garbage) as a successful "open".
    --concurrency  Number of worker threads (default 20).
    --timeout      Socket timeout in seconds (default 4.0).
    --brief        Print only one-line summary per success.
"""

import os
import sys
import argparse
import socket
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 4.0  # seconds
MAX_READ_BYTES = 16 * 1024  # safety cap when reading response
SNIPPET_BYTES = 128  # bytes to show for non-HTTP replies


def parse_proxy_env():
    env = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not env:
        raise SystemExit("No HTTP_PROXY/http_proxy environment variable set.")

    # Ensure scheme so urlparse behaves predictably
    if "://" not in env:
        env = "http://" + env

    p = urlparse(env)

    if not p.hostname or not p.port:
        raise SystemExit(f"Could not parse proxy host/port from '{env}'")

    auth_header = None
    if p.username is not None:
        user = p.username
        pwd = p.password or ""
        token = f"{user}:{pwd}".encode("utf-8")
        auth_header = "Basic " + base64.b64encode(token).decode("ascii")

    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "port": p.port,
        "auth_header": auth_header,
        "raw": env,
    }


def parse_port_range(s):
    """
    Accepts "9000-10000", "9000,9002,9004-9006", or single port "9000".
    Returns a sorted list of unique ints (1..65535).
    """
    parts = s.split(",")
    ports = set()
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a = int(a)
                b = int(b)
            except ValueError:
                raise SystemExit(f"Invalid range element: {part}")
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise SystemExit(f"Invalid port: {part}")
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    return valid


def build_get_request(target_host, target_port, proxy_auth):
    # Absolute-URI request line (proxy style)
    lines = [
        f"GET http://{target_host}:{target_port}/ HTTP/1.1",
        f"Host: {target_host}:{target_port}",
        "User-Agent: proxy-port-scan/1.0",
        "Connection: close",
    ]
    if proxy_auth:
        lines.append(f"Proxy-Authorization: {proxy_auth}")
    lines.append("")  # end headers
    lines.append("")  # final CRLF
    return "\r\n".join(lines).encode("utf-8")


def safe_snippet_bytes(b):
    """Return a text-friendly snippet if printable, else hex of first few bytes."""
    try:
        # Try to decode as utf-8-ish; show replacement chars for non-decodable bytes
        text = b.decode("utf-8", errors="replace")
        # If mostly printable, return first SNIPPET_BYTES chars
        snippet = text[:SNIPPET_BYTES]
        # Represent newlines visually
        return snippet.replace("\r", "\\r").replace("\n", "\\n")
    except Exception:
        # Fallback to hex
        return b[:SNIPPET_BYTES].hex(" ")


def attempt_proxy_fetch(proxy_host, proxy_port, auth_header, target_port, timeout, any_reply=False):
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
        return False, f"port {target_port}: connect to proxy {proxy_host}:{proxy_port} failed: {e!s}"

    try:
        sock.sendall(req)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return False, f"port {target_port}: send failed: {e!s}"

    resp = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                break
            if len(resp) >= MAX_READ_BYTES:
                break
    except socket.timeout:
        # timeout while waiting for response
        pass
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return False, f"port {target_port}: recv failed: {e!s}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if not resp:
        return False, f"port {target_port}: no response"

    # Try parse as HTTP status line
    try:
        text = resp.decode("iso-8859-1", errors="replace")
        first_line = text.splitlines()[0] if text.splitlines() else ""
    except Exception:
        first_line = ""

    if first_line.startswith("HTTP/"):
        parts = first_line.split()
        if len(parts) >= 2:
            try:
                code = int(parts[1])
                if code < 400:
                    # HTTP success
                    headers = text.split("\r\n\r\n", 1)[0]
                    short = headers.splitlines()[0] if headers else first_line
                    return True, f"port {target_port}: HTTP {code} via proxy {proxy_host}:{proxy_port}\n{short}"
                else:
                    return False, f"port {target_port}: HTTP {parts[1]} (not counted)"
            except ValueError:
                return False, f"port {target_port}: malformed HTTP status line '{first_line}'"
        else:
            return False, f"port {target_port}: malformed HTTP-like line '{first_line}'"
    else:
        # Non-HTTP reply
        if any_reply:
            # show a small snippet (attempt printable, fallback hex)
            snippet = safe_snippet_bytes(resp[:SNIPPET_BYTES])
            return True, f"port {target_port}: non-HTTP reply ({len(resp)} bytes) via proxy {proxy_host}:{proxy_port}\n{snippet}..."
        else:
            # not counted by default
            # show first line (decoded) in message
            display_line = first_line if first_line else safe_snippet_bytes(resp[:64])
            return False, f"port {target_port}: unexpected response '{display_line}'"


def main():
    ap = argparse.ArgumentParser(description="Scan target ports by asking HTTP proxy to GET 127.0.0.1:<port>")
    ap.add_argument("range", nargs=1, help="Port range (e.g. 9000-10000 or 9000,9002,9004-9006)")
    ap.add_argument("--concurrency", "-c", type=int, default=20, help="Number of worker threads (default 20)")
    ap.add_argument("--timeout", "-t", type=float, default=DEFAULT_TIMEOUT, help=f"Socket timeout in seconds (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--brief", action="store_true", help="Only print a one-line summary for each success")
    ap.add_argument("--any-reply", action="store_true", help="Treat any response (even garbage) as success")
    args = ap.parse_args()

    try:
        proxy = parse_proxy_env()
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    try:
        ports = parse_port_range(args.range[0])
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    if not ports:
        print("No valid ports parsed from range.", file=sys.stderr)
        sys.exit(1)

    print(f"Using proxy {proxy['host']}:{proxy['port']} (auth={'yes' if proxy['auth_header'] else 'no'})")
    print(f"Scanning {len(ports)} ports with concurrency={args.concurrency} timeout={args.timeout} any_reply={args.any_reply} ...")

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
                args.any_reply,
            ): p
            for p in ports
        }

        for fut in as_completed(futures):
            p = futures[fut]
            try:
                ok, info = fut.result()
            except Exception as e:
                print(f"port {p}: exception in worker: {e!s}", file=sys.stderr)
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
        print("Successful ports:", ", ".join(str(p) for p, _ in successes))


if __name__ == "__main__":
    main()
