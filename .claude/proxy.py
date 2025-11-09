#!/usr/bin/env python3
"""
proxy_connect_probe.py

Do an HTTP CONNECT to the proxy for the local non-loopback interface IP and a target port,
then send a few lightweight probes through the established tunnel to infer whether the
proxy actually connected to the target.

Usage:
  python3 proxy_connect_probe.py            # scans default port 15004
  python3 proxy_connect_probe.py -p 15004,2024 -t 4.0
  python3 proxy_connect_probe.py --proxy http://user:pass@proxy:3128 --tls

Notes:
 - Respects HTTP_PROXY / http_proxy (or --proxy). Does NOT consult NO_PROXY.
 - If proxy uses https://, TLS to the proxy is performed before sending CONNECT.
 - The probes are heuristic; some services will accept but remain silent => UNKNOWN.
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
import select

SIOCGIFADDR = 0x8915

# small defaults
DEFAULT_PORTS = [15004]
DEFAULT_TIMEOUT = 4.0

def parse_proxy_env(explicit_proxy: str | None = None):
    val = explicit_proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
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
        auth = "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()
    return scheme, host, port, auth

def choose_non_lo_iface():
    try:
        with open("/proc/net/route", "r") as f:
            lines = f.read().splitlines()
    except Exception:
        return None
    entries = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1]))
    # prefer default route
    for iface, dest in entries:
        if iface == "lo":
            continue
        if dest == "00000000":
            return iface
    for iface, dest in entries:
        if iface != "lo":
            return iface
    return None

def get_ipv4_for_iface(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack('256s', ifname.encode('utf-8')[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        ip_bytes = struct.unpack_from('!4B', res, 20)
        return "{}.{}.{}.{}".format(*ip_bytes)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

def recv_until_double_crlf(sock, timeout):
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

def read_some(sock, timeout):
    """Wait for readability up to timeout seconds, then recv up to 4096 bytes"""
    try:
        r, _, _ = select.select([sock], [], [], timeout)
        if r:
            data = sock.recv(4096)
            return data
        return None
    except Exception as e:
        return e

def do_connect_and_probe(proxy, target_ip, target_port, timeout=DEFAULT_TIMEOUT, try_tls=False):
    """
    proxy: (scheme, host, port, auth) where auth is 'Basic ...' or None
    returns dict with keys: connect_status, connect_detail, probe_result, probe_detail, durations...
    """
    scheme, phost, pport, auth = proxy
    result = {
        "connect_status": None,
        "connect_detail": None,
        "probe_result": None,
        "probe_detail": None,
        "connect_time": None,
        "probe_time": None,
    }
    start_conn = time.time()
    try:
        sock = socket.create_connection((phost, pport), timeout=timeout)
    except Exception as e:
        result["connect_status"] = "error"
        result["connect_detail"] = f"could not connect to proxy {phost}:{pport}: {e}"
        result["connect_time"] = time.time() - start_conn
        return result

    # TLS to proxy if https
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=phost)
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            result["connect_status"] = "error"
            result["connect_detail"] = f"tls to proxy failed: {e}"
            result["connect_time"] = time.time() - start_conn
            return result

    # send CONNECT
    try:
        sock.settimeout(timeout)
        connect_req = f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n"
        if auth:
            connect_req += f"Proxy-Authorization: {auth}\r\n"
        connect_req += "Connection: keep-alive\r\n\r\n"
        sock.sendall(connect_req.encode())
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        result["connect_status"] = "error"
        result["connect_detail"] = f"failed to send CONNECT: {e}"
        result["connect_time"] = time.time() - start_conn
        return result

    # read status line + headers
    head = recv_until_double_crlf(sock, timeout=timeout)
    ct = time.time() - start_conn
    result["connect_time"] = ct
    if not head:
        # no headers returned — keep socket open and attempt probes anyway (some proxies delay)
        result["connect_status"] = "no-response"
        result["connect_detail"] = "no HTTP response headers from proxy (timeout or closed). Proceeding to probes..."
    else:
        # parse first header line
        try:
            first_line = head.split(b"\r\n",1)[0].decode(errors="replace")
            # example: HTTP/1.1 200 Connection established
            parts = first_line.split()
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
            if status_code and 200 <= status_code < 300:
                result["connect_status"] = "200"
                result["connect_detail"] = f"proxy responded: {first_line}"
            elif status_code == 407:
                result["connect_status"] = "proxy_auth"
                result["connect_detail"] = f"proxy requires auth: {first_line}"
                try:
                    sock.close()
                except Exception:
                    pass
                return result
            else:
                result["connect_status"] = f"http_{status_code}" if status_code else "http_unknown"
                result["connect_detail"] = f"proxy response: {first_line}"
                # If non-2xx, close and return
                try:
                    sock.close()
                except Exception:
                    pass
                return result
        except Exception as e:
            result["connect_status"] = "parse_error"
            result["connect_detail"] = f"couldn't parse proxy response: {e}"
            # continue to probes? safer to return
            try:
                sock.close()
            except Exception:
                pass
            return result

    # At this point the proxy indicated tunnel established (or gave no headers). We'll probe.
    start_probe = time.time()
    probe_detail_parts = []

    # helper to record and return
    def finish_and_close(label, detail):
        result["probe_time"] = time.time() - start_probe
        result["probe_result"] = label
        result["probe_detail"] = "; ".join(probe_detail_parts + [detail])
        try:
            sock.close()
        except Exception:
            pass
        return result

    # 1) immediate banner read (short)
    r = read_some(sock, timeout=0.3)
    if isinstance(r, Exception):
        return finish_and_close("CLOSED", f"socket error during initial read: {r}")
    if r == b"":
        return finish_and_close("CLOSED", "peer closed connection immediately (empty read)")
    if r:
        # got some banner/data
        snippet = (r[:200]).decode("latin-1", errors="replace")
        return finish_and_close("OPEN", f"received initial banner/data ({len(r)} bytes): {snippet!r}")

    probe_detail_parts.append("no initial banner")

    # 2) send short ASCII probe
    try:
        sock.settimeout(timeout)
        sock.sendall(b"HELLO\r\n")
    except Exception as e:
        return finish_and_close("CLOSED", f"error sending ascii probe: {e}")

    r2 = read_some(sock, timeout=0.6)
    if isinstance(r2, Exception):
        return finish_and_close("CLOSED", f"socket error after ascii probe: {r2}")
    if r2 == b"":
        return finish_and_close("CLOSED", "peer closed connection after ascii probe")
    if r2:
        snippet = (r2[:200]).decode("latin-1", errors="replace")
        return finish_and_close("OPEN", f"got reply to ascii probe ({len(r2)} bytes): {snippet!r}")

    probe_detail_parts.append("no reply to ascii probe")

    # 3) send an HTTP-style probe (may trigger HTTP servers)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    except Exception as e:
        return finish_and_close("CLOSED", f"error sending HTTP probe: {e}")

    r3 = read_some(sock, timeout=1.0)
    if isinstance(r3, Exception):
        return finish_and_close("CLOSED", f"socket error after HTTP probe: {r3}")
    if r3 == b"":
        return finish_and_close("CLOSED", "peer closed connection after HTTP probe")
    if r3:
        # parse status line if available
        try:
            first = r3.split(b"\r\n",1)[0].decode(errors="replace")
            return finish_and_close("OPEN", f"HTTP-like response: {first!r} (bytes={len(r3)})")
        except Exception:
            return finish_and_close("OPEN", f"Received {len(r3)} bytes after HTTP probe")

    probe_detail_parts.append("no HTTP-like reply")

    # 4) optional TLS handshake probe (if requested by caller)
    if try_tls:
        try:
            # wrap the raw socket and do handshake
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Important: we must not call sock.close() on failure to let TLS layer cleanup,
            # but wrap_socket will take ownership
            ssock = ctx.wrap_socket(sock, server_hostname=target_ip, do_handshake_on_connect=False)
            ssock.settimeout(timeout)
            try:
                ssock.do_handshake()
                # handshake succeeded
                # try reading some bytes
                try:
                    data = ssock.recv(1024)
                    if data == b"":
                        ssock.close()
                        return finish_and_close("CLOSED", "TLS handshake succeeded but peer closed immediately")
                    if data:
                        snippet = data[:200].decode("latin-1", errors="replace")
                        ssock.close()
                        return finish_and_close("OPEN", f"TLS handshake succeeded; got {len(data)} bytes: {snippet!r}")
                    ssock.close()
                    return finish_and_close("OPEN", "TLS handshake succeeded; no immediate data")
                except Exception:
                    ssock.close()
                    return finish_and_close("OPEN", "TLS handshake succeeded; no immediate data/read error")
            except ssl.SSLError as e:
                try:
                    ssock.close()
                except Exception:
                    pass
                probe_detail_parts.append(f"tls_handshake_failed: {e}")
            except Exception as e:
                try:
                    ssock.close()
                except Exception:
                    pass
                probe_detail_parts.append(f"tls_handshake_exc: {e}")
            # If TLS failed, we must create/close the original socket because wrap_socket consumed it.
            # But wrap_socket consumes the underlying socket even on failure; we've already closed ssock.
            # Return UNKNOWN below.
        except Exception as e:
            probe_detail_parts.append(f"tls-wrap-failed: {e}")

    # 5) final: nothing observed — upstream may be accepting but silent
    return finish_and_close("UNKNOWN", "no data seen in any probe (connection may be open but silent)")

def main():
    parser = argparse.ArgumentParser(description="Do CONNECT via HTTP_PROXY to local non-loopback IP and probe the tunnel.")
    parser.add_argument("--proxy", help="explicit proxy URL (overrides env)")
    parser.add_argument("-p", "--ports", help="comma separated ports (default 15004)", default="15004")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="socket timeout seconds")
    parser.add_argument("--tls", action="store_true", help="try TLS handshake probe after other probes")
    args = parser.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("No HTTP_PROXY/http_proxy set and --proxy not supplied. Exiting.")
        return
    scheme, phost, pport, auth = proxy
    print(f"Using proxy {scheme}://{phost}:{pport} {'(auth)' if auth else ''}")

    iface = choose_non_lo_iface()
    if not iface:
        print("Could not determine non-loopback interface from /proc/net/route. Exiting.")
        return
    ip = get_ipv4_for_iface(iface)
    if not ip:
        print(f"Could not get IPv4 for interface {iface}. Exiting.")
        return
    print(f"Local non-loopback interface: {iface} -> {ip}")

    # parse ports
    ports = []
    for part in args.ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a,b = part.split("-",1)
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))

    for port in ports:
        print("\n---")
        print(f"Probing {ip}:{port} via proxy...")
        res = do_connect_and_probe(proxy, ip, port, timeout=args.timeout, try_tls=args.tls)
        print(f"CONNECT status: {res['connect_status']} ({res['connect_detail']})")
        if res.get("probe_result"):
            print(f"Probe result : {res['probe_result']} ({res['probe_detail']})")
        print(f"Timings: connect {res.get('connect_time'):.3f}s, probe {res.get('probe_time'):.3f}s")

if __name__ == "__main__":
    main()
