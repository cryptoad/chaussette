#!/usr/bin/env python3
"""
scan_proxy_subnet_ws_all.py

Scan odd IPs in the /24 of the proxy IP (from HTTP_PROXY). For each odd IP O:
  - attempt TCP connect to O:proxy_port
  - if connect succeeds, attempt "CONNECT E:2024" where E = O - 1 (even previous IP)
  - if CONNECT returns 2xx, attempt a WebSocket handshake over the tunnel:
      * send WebSocket opening GET with Sec-WebSocket-Key
      * validate Sec-WebSocket-Accept
      * if accepted, send a masked "TEST" text frame and read one reply frame
  - print result for each odd IP (do NOT stop on first success)
  - prints summary at the end

Usage:
  python3 scan_proxy_subnet_ws_all.py
  python3 scan_proxy_subnet_ws_all.py --proxy http://user:pass@1.2.3.4:3128 -t 3
"""

from __future__ import annotations
import os
import socket
import ssl
import urllib.parse
import base64
import argparse
import time
import hashlib
import struct
import random

DEFAULT_TIMEOUT = 3.0
TEST_PAYLOAD = b"TEST"
READ_LIMIT = 8192
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def parse_proxy_env(explicit: str | None = None):
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
    try:
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

def iter_odd_ips_in_24(base_ip: str):
    a,b,c,d = ip_to_octets(base_ip)
    for host in range(1, 255):
        if host % 2 == 1:
            yield f"{a}.{b}.{c}.{host}"

def tcp_connect(addr: str, port: int, timeout: float):
    try:
        s = socket.create_connection((addr, port), timeout=timeout)
        return s, None
    except Exception as e:
        return None, str(e)

def wrap_tls_if_needed(sock: socket.socket, scheme: str, server_hostname: str | None):
    if scheme != "https":
        return sock
    ctx = ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=server_hostname)

def read_until_double_crlf(sock: socket.socket, timeout: float):
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16384:
                break
    except Exception:
        pass
    return buf

def parse_status_line(head: bytes):
    if not head:
        return None, ""
    first = head.split(b"\r\n",1)[0].decode(errors="replace")
    parts = first.split()
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    return code, first

def ws_make_key() -> str:
    key = os.urandom(16)
    return base64.b64encode(key).decode()

def ws_expected_accept(key: str) -> str:
    tohash = (key + WS_GUID).encode("utf-8")
    h = hashlib.sha1(tohash).digest()
    return base64.b64encode(h).decode()

def ws_build_masked_text_frame(payload: bytes) -> bytes:
    fin_and_opcode = 0x81  # FIN=1, opcode=1 (text)
    length = len(payload)
    if length < 126:
        pl_header = struct.pack("!B", 0x80 | length)
    elif length < (1<<16):
        pl_header = struct.pack("!BH", 0x80 | 126, length)
    else:
        pl_header = struct.pack("!BQ", 0x80 | 127, length)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes([fin_and_opcode]) + pl_header + mask + masked

def ws_read_frame(sock: socket.socket, timeout: float):
    sock.settimeout(timeout)
    try:
        h = sock.recv(2)
        if not h or len(h) < 2:
            return None, "no data / closed"
        b1, b2 = h[0], h[1]
        opcode = b1 & 0x0f
        masked = (b2 >> 7) & 1
        plen = b2 & 0x7f
        if plen == 126:
            ext = sock.recv(2)
            if len(ext) < 2:
                return None, "incomplete extended len"
            plen = struct.unpack("!H", ext)[0]
        elif plen == 127:
            ext = sock.recv(8)
            if len(ext) < 8:
                return None, "incomplete extended len"
            plen = struct.unpack("!Q", ext)[0]
        mask_key = b""
        if masked:
            mask_key = sock.recv(4)
            if len(mask_key) < 4:
                return None, "incomplete mask key"
        payload = b""
        toread = plen
        while toread:
            chunk = sock.recv(min(4096, toread))
            if not chunk:
                break
            payload += chunk
            toread -= len(chunk)
        if masked and mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return opcode, payload
    except Exception as e:
        return None, f"read error: {e}"

def attempt_connect_then_ws(odd_ip: str, proxy_port: int, scheme: str, proxy_auth: str | None, timeout: float):
    """
    Connect to odd_ip:proxy_port, send CONNECT to even_ip:2024, if 2xx then attempt WebSocket handshake
    and a single masked TEXT frame exchange. Return a dict of results.
    """
    res = {
        "odd_ip": odd_ip,
        "even_ip": None,
        "tcp_connect_err": None,
        "connect_status": None,
        "connect_line": None,
        "ws_handshake_ok": False,
        "ws_reason": None,
        "ws_reply": None,
    }

    # compute even IP
    try:
        a,b,c,d = ip_to_octets(odd_ip)
        even = d - 1
        if even < 1 or even > 254:
            res["tcp_connect_err"] = f"even host {even} out of range"
            return res
        even_ip = f"{a}.{b}.{c}.{even}"
        res["even_ip"] = even_ip
    except Exception as e:
        res["tcp_connect_err"] = f"ip math error: {e}"
        return res

    # TCP connect to odd_ip:proxy_port
    sock, err = tcp_connect(odd_ip, proxy_port, timeout)
    if not sock:
        res["tcp_connect_err"] = err
        return res

    # TLS to proxy if needed
    try:
        sock = wrap_tls_if_needed(sock, scheme, server_hostname=odd_ip if scheme=="https" else None)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        res["tcp_connect_err"] = f"TLS wrap failed: {e}"
        return res

    # send CONNECT even_ip:2024
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

    # read proxy response
    head = read_until_double_crlf(sock, timeout)
    code, first_line = parse_status_line(head)
    res["connect_status"] = code
    res["connect_line"] = first_line
    if code is None or not (200 <= code < 300):
        try:
            sock.close()
        except Exception:
            pass
        return res

    # CONNECT succeeded: attempt WebSocket handshake
    ws_key = ws_make_key()
    expected_accept = ws_expected_accept(ws_key)
    req_lines = [
        f"GET / HTTP/1.1",
        f"Host: {res['even_ip']}:2024",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: proxy-ws-scan/1.0",
        "",
        ""
    ]
    hs_req = "\r\n".join(req_lines).encode()
    try:
        sock.settimeout(timeout)
        sock.sendall(hs_req)
    except Exception as e:
        res["ws_reason"] = f"failed to send WS handshake: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return res

    head2 = read_until_double_crlf(sock, timeout)
    if not head2:
        res["ws_reason"] = "no handshake response"
        try:
            sock.close()
        except Exception:
            pass
        return res

    code2, first2 = parse_status_line(head2)
    if code2 != 101:
        res["ws_reason"] = f"handshake failed, status: {first2!s}"
        try:
            sock.close()
        except Exception:
            pass
        return res

    # validate Sec-WebSocket-Accept
    try:
        hdr_text = head2.decode(errors="replace")
        accept_val = None
        for line in hdr_text.split("\r\n")[1:]:
            if ":" not in line:
                continue
            k,v = line.split(":",1)
            if k.strip().lower() == "sec-websocket-accept":
                accept_val = v.strip()
                break
        if accept_val != expected_accept:
            res["ws_reason"] = f"accept mismatch: got {accept_val!r} expected {expected_accept!r}"
            try:
                sock.close()
            except Exception:
                pass
            return res
    except Exception as e:
        res["ws_reason"] = f"error parsing handshake headers: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return res

    # handshake OK
    res["ws_handshake_ok"] = True

    # send masked text frame "TEST"
    try:
        frame = ws_build_masked_text_frame(TEST_PAYLOAD)
        sock.settimeout(timeout)
        sock.sendall(frame)
    except Exception as e:
        res["ws_reason"] = f"failed to send WS frame: {e}"
        try:
            sock.close()
        except Exception:
            pass
        return res

    # read one frame back
    op_payload = ws_read_frame(sock, timeout)
    if op_payload is None:
        res["ws_reason"] = "no ws frame / read error"
    else:
        op, payload_or_err = op_payload
        if op is None:
            res["ws_reason"] = f"ws read error: {payload_or_err}"
        else:
            res["ws_reply"] = payload_or_err

    try:
        sock.close()
    except Exception:
        pass

    return res

def main():
    ap = argparse.ArgumentParser(description="Scan odd IPs in proxy IP /24; attempt WebSocket handshake after successful CONNECT and report for all hosts.")
    ap.add_argument("--proxy", help="explicit proxy URL")
    ap.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="timeout seconds")
    args = ap.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("HTTP_PROXY/http_proxy not set and --proxy not supplied. Exiting.")
        return
    scheme, proxy_host, proxy_port, proxy_auth = proxy
    print(f"Using proxy: {scheme}://{proxy_host}:{proxy_port} {'(auth)' if proxy_auth else ''}")

    proxy_ip = resolve_to_ipv4(proxy_host)
    if not proxy_ip:
        print(f"Could not resolve proxy host {proxy_host} to IPv4. Exiting.")
        return
    print(f"Proxy IPv4: {proxy_ip}; scanning odd hosts in its /24 on port {proxy_port}")

    results = []
    for odd in iter_odd_ips_in_24(proxy_ip):
        print(f"[+] Trying {odd}:{proxy_port} ...", end="", flush=True)
        r = attempt_connect_then_ws(odd, proxy_port, scheme, proxy_auth, args.timeout)
        if r.get("tcp_connect_err"):
            print(f" no-connect ({r['tcp_connect_err']})")
            results.append((odd, r))
            continue
        print(f" connected -> CONNECT {r['connect_line']!s}")
        if not (r["connect_status"] and 200 <= r["connect_status"] < 300):
            print(" -> CONNECT not 2xx")
            results.append((odd, r))
            continue

        # CONNECT succeeded; report WS/probe details (but continue scanning)
        if r["ws_handshake_ok"]:
            reply_summary = "(no reply)"
            if r.get("ws_reply") is None:
                reply_summary = "(no ws frame received)"
            elif r["ws_reply"] == b"":
                reply_summary = "(peer closed immediately)"
            else:
                try:
                    reply_summary = r["ws_reply"].decode("utf-8", errors="replace")
                except Exception:
                    reply_summary = repr(r["ws_reply"][:200])
            print(f" -> WebSocket handshake: SUCCESS; reply: {reply_summary!s}")
        else:
            print(f" -> WebSocket handshake FAILED: {r.get('ws_reason')}")
        results.append((odd, r))
        # continue scanning (do NOT stop on first success)

    # Summary
    print("\n--- Summary ---")
    total = len(results)
    success_ws = [t for t in results if t[1].get("ws_handshake_ok")]
    connected = [t for t in results if not t[1].get("tcp_connect_err") and t[1].get("connect_status")]
    print(f"Hosts tried: {total}")
    print(f"Hosts where TCP connect succeeded (to odd_ip): {len(connected)}")
    print(f"Hosts where WS handshake succeeded: {len(success_ws)}")
    if success_ws:
        print("\nSuccessful WebSocket targets:")
        for odd, r in success_ws:
            print(f"  odd {odd} -> even {r['even_ip']}:2024, reply_len: {None if r.get('ws_reply') is None else len(r.get('ws_reply'))}")
    print("--- Done ---")

if __name__ == "__main__":
    main()
