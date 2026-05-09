#!/usr/bin/env python3
"""
Egress bypass diagnostic tester (non-destructive).

Purpose:
  Exercise common private/reserved-destination egress filter bypass classes from
  inside a guest VM/container. The script records whether TCP connections are
  possible and captures the first response bytes for several request variants.

What it tests:
  - Direct private/reserved IPs and common metadata IPs
  - Numeric IPv4 encodings (decimal integer, hex integer, octal dotted, shortened)
  - Host-header mismatches (public destination with private Host, and reverse)
  - Absolute-form proxy-style HTTP requests
  - WebSocket upgrade style requests
  - Public destination controls

Safety:
  - Does not send credentials.
  - Does not fuzz or send high-volume traffic.
  - Uses short timeouts and one request per test case.
  - Writes JSONL findings and a human-readable summary.

Usage:
  python3 /tmp/egress_bypass_tester.py
  python3 /tmp/egress_bypass_tester.py --out-dir /tmp/egress_test --timeout 2
  python3 /tmp/egress_bypass_tester.py --extra-host example.net --extra-host 203.0.113.10

Notes:
  A TCP "connected=True" to a blocked private IP can still mean a transparent
  proxy/gateway accepted the connection and returned a deny page. Review the
  captured response and classification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import socket
import ssl
import time
from dataclasses import dataclass, asdict
from typing import Optional, Iterable

PRIVATE_TARGETS = [
    # Metadata / link-local / cloud-ish
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    # Common local gateway/container/VM ranges
    "10.0.2.2",
    "172.16.0.1",
    "172.17.0.1",
    "192.168.122.1",
    # This environment's observed gateway and guest network
    "192.0.2.1",
    "192.0.2.2",
    # Loopback should be blocked if the policy is destination based.
    "127.0.0.1",
    "0.0.0.0",
]

PUBLIC_CONTROLS = [
    "example.com",
    "example.org",
    "1.1.1.1",
]

# Encodings for 169.254.169.254, 10.0.2.2, 127.0.0.1, etc.
ENCODED_HOSTS = [
    # 169.254.169.254 variants
    "2852039166",            # decimal integer
    "0xa9fea9fe",            # hex integer
    "0251.0376.0251.0376",   # octal dotted
    "169.254.43518",         # shortened mixed
    "169.16646142",          # shortened mixed
    "[::ffff:169.254.169.254]",
    "::ffff:169.254.169.254",
    # 10.0.2.2 variants
    "167772674",             # decimal integer
    "0x0a000202",
    "012.000.002.002",
    "10.514",
    "10.0.514",
    "[::ffff:10.0.2.2]",
    # loopback variants
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "127.1",
    "[::ffff:127.0.0.1]",
]

PRIVATE_HOST_HEADERS = [
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "10.0.2.2",
    "172.17.0.1",
    "192.168.122.1",
    "127.0.0.1",
    "localhost",
]

USER_AGENTS = [
    "egress-bypass-tester/1.0",
    "curl/8.0.0",
]


@dataclass
class Result:
    ts: float
    category: str
    variant: str
    connect_host: str
    connect_port: int
    resolved_ip: Optional[str]
    request_host_header: Optional[str]
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


def now() -> float:
    return time.time()


def safe_preview(data: bytes, limit: int = 500) -> str:
    if not data:
        return ""
    chunk = data[:limit]
    return repr(chunk)[2:-1]


def sha16(data: bytes) -> Optional[str]:
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()[:16]


def parse_status_line(data: bytes) -> Optional[str]:
    if not data:
        return None
    first = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    try:
        return first.decode("iso-8859-1", "replace")
    except Exception:
        return repr(first)


def parse_deny_reason(data: bytes) -> Optional[str]:
    low = data.lower()
    marker = b"x-deny-reason:"
    if marker in low:
        for line in data.splitlines():
            if line.lower().startswith(marker):
                return line.split(b":", 1)[1].strip().decode("utf-8", "replace")
    if b"private/reserved" in low:
        return "body_mentions_private_reserved"
    if b"forbidden" in low:
        return "body_or_status_forbidden"
    return None


def classify(connected: bool, err: Optional[str], data: bytes) -> str:
    if not connected:
        if err and "timed out" in err.lower():
            return "timeout"
        if err and "refused" in err.lower():
            return "connection_refused"
        return "connect_failed"
    deny = parse_deny_reason(data)
    if deny:
        return f"blocked:{deny}"
    status = parse_status_line(data) or ""
    if " 403 " in status:
        return "blocked:403"
    if " 426 " in status:
        return "upgrade_required_or_proxy_hint"
    if " 2" in status or " 3" in status:
        return "allowed_http_response"
    if data:
        return "connected_with_response"
    return "connected_no_response"


def resolve_host(host: str) -> Optional[str]:
    # Do not resolve bracketed IPv6 literal via gethostbyname.
    h = host.strip("[]")
    try:
        return socket.gethostbyname(h)
    except Exception:
        return None


def make_http_request(host_header: str, path: str = "/", absolute_url: Optional[str] = None) -> bytes:
    ua = random.choice(USER_AGENTS)
    target = absolute_url if absolute_url else path
    return (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {ua}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def make_ws_request(host_header: str, path: str = "/") -> bytes:
    key = base64.b64encode(os.urandom(16)).decode()
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: egress-bypass-tester/1.0\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def make_connect_request(target_host: str, target_port: int) -> bytes:
    return (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "User-Agent: egress-bypass-tester/1.0\r\n"
        "Proxy-Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def connect_and_send(
    *,
    category: str,
    variant: str,
    connect_host: str,
    connect_port: int,
    payload: bytes,
    request_host_header: Optional[str],
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
        # Use create_connection so Python handles DNS and IPv4 parsing variants.
        raw = socket.create_connection((connect_host, connect_port), timeout=timeout)
        raw.settimeout(timeout)
        connected = True
        s = raw
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(raw, server_hostname=tls_server_hostname or request_host_header or connect_host)
            s.settimeout(timeout)
        try:
            s.sendall(payload)
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as e:
        err_type = type(e).__name__
        err = str(e)

    return Result(
        ts=now(),
        category=category,
        variant=variant,
        connect_host=connect_host,
        connect_port=connect_port,
        resolved_ip=resolved,
        request_host_header=request_host_header,
        request_kind=request_kind,
        connected=connected,
        tls=use_tls,
        error_type=err_type,
        error=err,
        response_len=len(data),
        response_sha256_16=sha16(data),
        response_preview=safe_preview(data),
        status_line=parse_status_line(data),
        deny_reason=parse_deny_reason(data),
        classification=classify(connected, err, data),
    )


def iter_tests(extra_hosts: list[str], include_tls: bool) -> Iterable[dict]:
    # Direct private/reserved HTTP and WS.
    for host in PRIVATE_TARGETS + extra_hosts:
        for port in [80, 443]:
            hh = host.strip("[]")
            yield dict(
                category="direct_private_or_extra",
                variant="http_origin_form",
                connect_host=host,
                connect_port=port,
                payload=make_http_request(hh),
                request_host_header=hh,
                request_kind="http",
                use_tls=False,
            )
            yield dict(
                category="direct_private_or_extra",
                variant="websocket_upgrade",
                connect_host=host,
                connect_port=port,
                payload=make_ws_request(hh),
                request_host_header=hh,
                request_kind="websocket",
                use_tls=False,
            )
            yield dict(
                category="direct_private_or_extra",
                variant="absolute_form_self_url",
                connect_host=host,
                connect_port=port,
                payload=make_http_request(hh, absolute_url=f"http://{hh}/"),
                request_host_header=hh,
                request_kind="http_absolute_form",
                use_tls=False,
            )

    # Encoded host variants. Only port 80 by default to limit noise.
    for host in ENCODED_HOSTS:
        hh = host.strip("[]")
        yield dict(
            category="encoded_private_host",
            variant="http_encoded_destination",
            connect_host=host,
            connect_port=80,
            payload=make_http_request(hh),
            request_host_header=hh,
            request_kind="http",
            use_tls=False,
        )
        yield dict(
            category="encoded_private_host",
            variant="absolute_form_encoded_destination",
            connect_host=host,
            connect_port=80,
            payload=make_http_request(hh, absolute_url=f"http://{hh}/"),
            request_host_header=hh,
            request_kind="http_absolute_form",
            use_tls=False,
        )

    # Public controls.
    for host in PUBLIC_CONTROLS:
        for port in [80, 443]:
            yield dict(
                category="public_control",
                variant="http_public",
                connect_host=host,
                connect_port=port,
                payload=make_http_request(host),
                request_host_header=host,
                request_kind="http",
                use_tls=False,
            )
            if include_tls and port == 443 and not host.replace(".", "").isdigit():
                yield dict(
                    category="public_control",
                    variant="https_public",
                    connect_host=host,
                    connect_port=port,
                    payload=make_http_request(host),
                    request_host_header=host,
                    request_kind="https",
                    use_tls=True,
                    tls_server_hostname=host,
                )

    # Host header mismatch: connect public with private Host header.
    public_connects = ["example.com", "1.1.1.1"]
    for connect_host in public_connects:
        for private_hh in PRIVATE_HOST_HEADERS:
            yield dict(
                category="host_header_mismatch",
                variant="public_dest_private_host_header",
                connect_host=connect_host,
                connect_port=80,
                payload=make_http_request(private_hh),
                request_host_header=private_hh,
                request_kind="http",
                use_tls=False,
            )
            yield dict(
                category="host_header_mismatch",
                variant="public_dest_private_absolute_url",
                connect_host=connect_host,
                connect_port=80,
                payload=make_http_request(private_hh, absolute_url=f"http://{private_hh}/"),
                request_host_header=private_hh,
                request_kind="http_absolute_form",
                use_tls=False,
            )

    # Reverse mismatch: connect private with public Host header.
    for private_dest in ["169.254.169.254", "10.0.2.2", "172.17.0.1", "192.168.122.1"]:
        yield dict(
            category="host_header_mismatch",
            variant="private_dest_public_host_header",
            connect_host=private_dest,
            connect_port=80,
            payload=make_http_request("example.com"),
            request_host_header="example.com",
            request_kind="http",
            use_tls=False,
        )

    # CONNECT method direct to possible proxy-ish endpoints. This does not include credentials.
    for connect_host in ["example.com", "1.1.1.1", "169.254.169.254", "10.0.2.2"]:
        for target in ["169.254.169.254", "10.0.2.2", "127.0.0.1"]:
            yield dict(
                category="connect_method",
                variant="connect_private_target",
                connect_host=connect_host,
                connect_port=80,
                payload=make_connect_request(target, 80),
                request_host_header=f"{target}:80",
                request_kind="connect",
                use_tls=False,
            )


def main() -> int:
    ap = argparse.ArgumentParser(description="Egress bypass diagnostic tester")
    ap.add_argument("--out-dir", default=f"/tmp/egress_bypass_{int(time.time())}")
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--extra-host", action="append", default=[], help="Additional host/IP to test as direct target")
    ap.add_argument("--include-tls", action="store_true", help="Also perform real TLS GET for public HTTPS controls")
    ap.add_argument("--max-tests", type=int, default=0, help="Stop after N tests (0 = all)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    jsonl_path = os.path.join(args.out_dir, "results.jsonl")
    summary_path = os.path.join(args.out_dir, "summary.txt")

    results: list[Result] = []
    tests = list(iter_tests(args.extra_host, args.include_tls))
    if args.max_tests and args.max_tests > 0:
        tests = tests[: args.max_tests]

    print(f"Output directory: {args.out_dir}")
    print(f"Planned tests: {len(tests)}")
    print(f"Timeout: {args.timeout}s")

    with open(jsonl_path, "w", encoding="utf-8") as jf:
        for i, t in enumerate(tests, 1):
            res = connect_and_send(timeout=args.timeout, **t)
            results.append(res)
            jf.write(json.dumps(asdict(res), sort_keys=True) + "\n")
            jf.flush()
            print(
                f"[{i:03d}/{len(tests):03d}] "
                f"{res.category}/{res.variant} "
                f"connect={res.connect_host}:{res.connect_port} "
                f"host={res.request_host_header} "
                f"connected={res.connected} class={res.classification} "
                f"status={res.status_line!r} err={res.error_type or ''}"
            )

    # Summarize by classification and highlight potentially interesting cases.
    counts: dict[str, int] = {}
    for r in results:
        counts[r.classification] = counts.get(r.classification, 0) + 1

    interesting = []
    for r in results:
        # Private/encoded/host-mismatch cases that did not appear blocked are worth review.
        if r.category in {"direct_private_or_extra", "encoded_private_host", "host_header_mismatch", "connect_method"}:
            if not r.classification.startswith("blocked") and r.classification not in {"timeout", "connection_refused", "connect_failed"}:
                interesting.append(r)

    with open(summary_path, "w", encoding="utf-8") as sf:
        sf.write(f"Output directory: {args.out_dir}\n")
        sf.write(f"Results JSONL: {jsonl_path}\n")
        sf.write("\n== classification counts ==\n")
        for k in sorted(counts):
            sf.write(f"{k}: {counts[k]}\n")
        sf.write("\n== potentially interesting non-blocked private/bypass cases ==\n")
        if not interesting:
            sf.write("None detected by heuristic.\n")
        else:
            for r in interesting:
                sf.write(
                    f"{r.category}/{r.variant} connect={r.connect_host}:{r.connect_port} "
                    f"resolved={r.resolved_ip} host={r.request_host_header} "
                    f"class={r.classification} status={r.status_line} preview={r.response_preview[:160]}\n"
                )

    print("\n== summary ==")
    print(open(summary_path, encoding="utf-8").read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
