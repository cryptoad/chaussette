#!/usr/bin/env python3
"""
0.0.0.0 egress/parser differential tester (non-destructive).

Purpose:
  Exercise common representations and parser-confusion variants of 0.0.0.0
  and related "this network" / unspecified IPv4 forms. These can be mishandled
  by URL validators, proxies, HTTP clients, libc inet_aton-style parsers, or
  egress policy layers.

What it tests:
  - Direct socket connections to 0.0.0.0 variants
  - HTTP Host header authority variants while connecting to public controls
  - Absolute-form request-target variants while connecting to public controls
  - CONNECT method authority variants while connecting to public controls
  - Optional local-loopback listener check to distinguish "refused" from
    "0.0.0.0 mapped to local service"

Safety:
  - One request per case, short timeouts, no credentials, no fuzzing volume.
  - Defaults to HTTP only. It does not scan ports; it tests the configured port.
  - Writes JSONL and a human-readable summary.

Examples:
  python3 /tmp/zero_variants_egress_tester.py
  python3 /tmp/zero_variants_egress_tester.py --port 80 --timeout 1.5
  python3 /tmp/zero_variants_egress_tester.py --public-control example.com --public-control 1.1.1.1
  python3 /tmp/zero_variants_egress_tester.py --start-local-listener --port 18080

Notes:
  On many systems, connecting to 0.0.0.0:<port> can behave like connecting to a
  local address if a local listener is bound on that port. That is why the
  optional --start-local-listener mode is useful: it can reveal whether a stack
  treats an ostensibly "unspecified" remote address as loopback/local.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import asdict, dataclass
from typing import Iterable, Optional

PUBLIC_CONTROLS_DEFAULT = ["example.com", "1.1.1.1"]

# Variants that different parsers may treat as 0.0.0.0, equivalent-ish, or as
# domain names. Some are intentionally ambiguous parser-differential controls.
ZERO_HOST_VARIANTS = [
    # Canonical / shortened IPv4 forms accepted by inet_aton-like parsers.
    "0.0.0.0",
    "0.0.0",
    "0.0",
    "0",
    "00.00.00.00",
    "000.000.000.000",
    "0000.0000.0000.0000",

    # Decimal / hex / octal integer forms for 0.0.0.0.
    "0x0",
    "0x00000000",
    "000000000000",
    "0000000000",

    # Per-octet hex/octal-looking forms. Some libraries accept these, others
    # treat them as DNS reg-names.
    "0x0.0x0.0x0.0x0",
    "00.00.00.00",
    "000.000.000.000",

    # Userinfo / authority confusion. These should not be used as connect_host
    # literals, but are useful in Host and absolute-form request targets.
    "0.0.0.0@127.0.0.1",
    "127.0.0.1@0.0.0.0",
    "0.0.0.0@example.com",
    "example.com@0.0.0.0",

    # Bracket-ish / IPv6-ish unspecified forms. Some are invalid as socket
    # hosts but useful as HTTP authorities.
    "[0.0.0.0]",
    "::",
    "[::]",
    "::ffff:0.0.0.0",
    "[::ffff:0.0.0.0]",

    # Percent-encoding and textual controls for URL/HTTP parser differentials.
    "%30.%30.%30.%30",
    "0%2e0%2e0%2e0",
    "0.0.0.0%00.example.com",
    "0.0.0.0%09.example.com",
    "0.0.0.0%0a.example.com",
    "0.0.0.0%0d.example.com",
    "0.0.0.0.",
    "0.0.0.0..",

    # Dotted labels that can be interpreted as names by strict parsers.
    "0.0.0.0.example.com",
    "0.0.0.0.localhost",
]

# A few related low/unspecified-ish destinations that are sometimes normalized
# incorrectly by application allow/deny logic. These are not all equivalent to
# 0.0.0.0; they are included as controls for overly-broad or overly-narrow
# handling of 0/8 and loopback-adjacent special-use space.
RELATED_ZERO_NET_VARIANTS = [
    "0.0.0.1",
    "0.0.0.7",
    "0.0.1.0",
    "0.1.0.0",
    "0.255.255.255",
    "000.000.000.001",
    "0x00000001",
    "1",
    "0.1",
]


@dataclass
class Result:
    ts: float
    category: str
    variant: str
    connect_host: str
    connect_port: int
    resolved_ip: Optional[str]
    request_authority: Optional[str]
    request_kind: str
    connected: bool
    tls: bool
    error_type: Optional[str]
    error: Optional[str]
    response_len: int
    response_sha256_16: Optional[str]
    response_preview: str
    status_line: Optional[str]
    deny_reason: Optional[str]
    classification: str


def resolve_host(host: str) -> Optional[str]:
    h = host.strip("[]")
    # Do not feed full userinfo authorities to gethostbyname.
    if "/" in h or "@" in h or "%" in h or h == "":
        return None
    try:
        return socket.gethostbyname(h)
    except Exception:
        return None


def first_line(data: bytes) -> Optional[str]:
    if not data:
        return None
    return data.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("latin-1", "replace")


def sha16(data: bytes) -> Optional[str]:
    return hashlib.sha256(data).hexdigest()[:16] if data else None


def preview(data: bytes, limit: int = 500) -> str:
    return repr(data[:limit])[2:-1] if data else ""


def deny_reason(data: bytes) -> Optional[str]:
    low = data.lower()
    for line in data.splitlines():
        if line.lower().startswith(b"x-deny-reason:"):
            return line.split(b":", 1)[1].strip().decode("utf-8", "replace")
    if b"private" in low or b"reserved" in low:
        return "body_mentions_private_or_reserved"
    if b"forbidden" in low:
        return "body_or_status_forbidden"
    if b"not allowed" in low or b"denied" in low:
        return "body_mentions_denied"
    return None


def classify(connected: bool, err: Optional[str], data: bytes, resolved_ip: Optional[str]) -> str:
    if not connected:
        msg = (err or "").lower()
        if "timed out" in msg or "timeout" in msg:
            return "timeout"
        if "refused" in msg:
            return "connection_refused"
        if "name or service not known" in msg or "nodename nor servname" in msg or "gaierror" in msg:
            return "resolve_or_parse_failed"
        return "connect_failed"

    dr = deny_reason(data)
    if dr:
        return f"blocked:{dr}"
    status = first_line(data) or ""
    if " 403 " in status:
        return "blocked:403"
    if status.startswith("HTTP/") and (" 2" in status or " 3" in status):
        if resolved_ip and (resolved_ip == "0.0.0.0" or resolved_ip.startswith("0.")):
            return "allowed_http_response_zero_net"
        return "allowed_http_response"
    if data:
        if b"zero-variant-local-listener" in data:
            return "reached_local_listener"
        return "connected_with_response"
    return "connected_no_response"


def http_request(authority: str, absolute: Optional[str] = None) -> bytes:
    target = absolute if absolute else "/"
    return (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "User-Agent: zero-variant-egress-tester/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def connect_request(authority: str, port: int) -> bytes:
    return (
        f"CONNECT {authority}:{port} HTTP/1.1\r\n"
        f"Host: {authority}:{port}\r\n"
        "User-Agent: zero-variant-egress-tester/1.0\r\n"
        "Proxy-Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def try_one(
    *,
    category: str,
    variant: str,
    connect_host: str,
    connect_port: int,
    payload: bytes,
    request_authority: Optional[str],
    request_kind: str,
    timeout: float,
    use_tls: bool = False,
    tls_server_hostname: Optional[str] = None,
) -> Result:
    resolved = resolve_host(connect_host)
    data = b""
    connected = False
    err_type = None
    err = None
    try:
        raw = socket.create_connection((connect_host, connect_port), timeout=timeout)
        raw.settimeout(timeout)
        connected = True
        s = raw
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(raw, server_hostname=tls_server_hostname or request_authority or connect_host)
            s.settimeout(timeout)
        try:
            s.sendall(payload)
            try:
                data = s.recv(2048)
            except socket.timeout:
                data = b""
        finally:
            with contextlib.suppress(Exception):
                s.close()
    except Exception as e:
        err_type = type(e).__name__
        err = str(e)

    return Result(
        ts=time.time(),
        category=category,
        variant=variant,
        connect_host=connect_host,
        connect_port=connect_port,
        resolved_ip=resolved,
        request_authority=request_authority,
        request_kind=request_kind,
        connected=connected,
        tls=use_tls,
        error_type=err_type,
        error=err,
        response_len=len(data),
        response_sha256_16=sha16(data),
        response_preview=preview(data),
        status_line=first_line(data),
        deny_reason=deny_reason(data),
        classification=classify(connected, err, data, resolved),
    )


def iter_tests(port: int, public_controls: list[str], include_related: bool) -> Iterable[dict]:
    variants = list(ZERO_HOST_VARIANTS)
    if include_related:
        variants += RELATED_ZERO_NET_VARIANTS

    # 1. Direct destination tests. Skip obvious authority-only values that are
    # not valid socket host candidates.
    for host in variants:
        if any(x in host for x in ["@", "%00", "%09", "%0a", "%0d"]):
            continue
        authority = host.strip("[]") if host.startswith("[") and host.endswith("]") else host
        yield dict(
            category="direct_zero_variant",
            variant="origin_form",
            connect_host=host,
            connect_port=port,
            payload=http_request(authority),
            request_authority=authority,
            request_kind="http_origin_form",
        )
        yield dict(
            category="direct_zero_variant",
            variant="absolute_form_self",
            connect_host=host,
            connect_port=port,
            payload=http_request(authority, absolute=f"http://{authority}:{port}/"),
            request_authority=authority,
            request_kind="http_absolute_form",
        )

    # 2. Connect to public controls but put 0.0.0.0 variants in Host header.
    for public in public_controls:
        for authority in variants:
            yield dict(
                category="public_dest_zero_authority",
                variant="host_header_zero_variant",
                connect_host=public,
                connect_port=80,
                payload=http_request(authority),
                request_authority=authority,
                request_kind="http_host_header",
            )
            abs_authority = authority
            if "%" not in abs_authority:
                abs_url = f"http://{abs_authority}:{port}/"
            else:
                # Preserve percent encodings in the request-target.
                abs_url = f"http://{abs_authority}:{port}/"
            yield dict(
                category="public_dest_zero_authority",
                variant="absolute_form_zero_variant",
                connect_host=public,
                connect_port=80,
                payload=http_request(authority, absolute=abs_url),
                request_authority=authority,
                request_kind="http_absolute_form",
            )

    # 3. CONNECT method to 0.0.0.0 variants via public controls.
    for public in public_controls:
        for authority in variants:
            if any(x in authority for x in ["/", "%00", "%09", "%0a", "%0d"]):
                continue
            yield dict(
                category="connect_method_zero_authority",
                variant="connect_zero_variant",
                connect_host=public,
                connect_port=80,
                payload=connect_request(authority, port),
                request_authority=f"{authority}:{port}",
                request_kind="connect",
            )


class LocalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = (
            "zero-variant-local-listener\n"
            f"client={self.client_address!r}\n"
            f"path={self.path}\n"
            f"host={self.headers.get('Host')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def start_local_listener(port: int) -> socketserver.TCPServer:
    class ReuseTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    srv = ReuseTCPServer(("0.0.0.0", port), LocalHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main() -> int:
    ap = argparse.ArgumentParser(description="0.0.0.0 egress/parser differential tester")
    ap.add_argument("--out-dir", default=f"/tmp/zero_variant_egress_{int(time.time())}")
    ap.add_argument("--port", type=int, default=80, help="Destination port for zero-variant tests")
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--public-control", action="append", default=[], help="Public host/IP for Host/CONNECT mismatch tests")
    ap.add_argument("--include-related", action="store_true", help="Also test related 0/8 variants, not just 0.0.0.0 forms")
    ap.add_argument("--start-local-listener", action="store_true", help="Bind a local HTTP listener on 0.0.0.0:--port before testing")
    ap.add_argument("--max-tests", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    jsonl_path = os.path.join(args.out_dir, "results.jsonl")
    summary_path = os.path.join(args.out_dir, "summary.txt")

    listener = None
    if args.start_local_listener:
        listener = start_local_listener(args.port)
        print(f"Started local listener on 0.0.0.0:{args.port}")
        time.sleep(0.1)

    public_controls = args.public_control or PUBLIC_CONTROLS_DEFAULT
    tests = list(iter_tests(args.port, public_controls, args.include_related))
    if args.max_tests > 0:
        tests = tests[: args.max_tests]

    print(f"Output directory: {args.out_dir}")
    print(f"Results JSONL: {jsonl_path}")
    print(f"Planned tests: {len(tests)}")
    print(f"Timeout: {args.timeout}s")

    results: list[Result] = []
    with open(jsonl_path, "w", encoding="utf-8") as jf:
        for i, t in enumerate(tests, 1):
            r = try_one(timeout=args.timeout, **t)
            results.append(r)
            jf.write(json.dumps(asdict(r), sort_keys=True) + "\n")
            jf.flush()
            print(
                f"[{i:03d}/{len(tests):03d}] "
                f"{r.category}/{r.variant} "
                f"connect={r.connect_host}:{r.connect_port} resolved={r.resolved_ip} "
                f"authority={r.request_authority!r} connected={r.connected} "
                f"class={r.classification} status={r.status_line!r} err={r.error_type or ''}"
            )

    counts: dict[str, int] = {}
    for r in results:
        counts[r.classification] = counts.get(r.classification, 0) + 1

    interesting = []
    for r in results:
        if r.category != "public_control" and r.classification not in {
            "timeout",
            "connection_refused",
            "connect_failed",
            "resolve_or_parse_failed",
        } and not r.classification.startswith("blocked"):
            interesting.append(r)
        if r.classification in {"reached_local_listener", "allowed_http_response_zero_net"}:
            if r not in interesting:
                interesting.append(r)

    with open(summary_path, "w", encoding="utf-8") as sf:
        sf.write(f"Output directory: {args.out_dir}\n")
        sf.write(f"Results JSONL: {jsonl_path}\n")
        sf.write("\n== classification counts ==\n")
        for k in sorted(counts):
            sf.write(f"{k}: {counts[k]}\n")
        sf.write("\n== potentially interesting non-blocked zero-variant cases ==\n")
        if not interesting:
            sf.write("None detected by heuristic.\n")
        else:
            for r in interesting:
                sf.write(
                    f"{r.category}/{r.variant} connect={r.connect_host}:{r.connect_port} "
                    f"resolved={r.resolved_ip} authority={r.request_authority!r} "
                    f"class={r.classification} status={r.status_line} "
                    f"preview={r.response_preview[:180]}\n"
                )

    print("\n== summary ==")
    print(open(summary_path, encoding="utf-8").read())

    if listener:
        listener.shutdown()
        listener.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
