#!/usr/bin/env python3
"""
proxy_raw_probe.py

Do HTTP CONNECT via HTTP_PROXY to the non-loopback interface IP and perform a raw probe
through the established tunnel to classify the target port as OPEN / CLOSED / UNKNOWN.

Usage:
    python3 proxy_raw_probe.py            # default port 15004
    python3 proxy_raw_probe.py -p 15004,2024 -t 3
    python3 proxy_raw_probe.py --proxy http://user:pass@proxy:3128 -p 80

Notes:
 - Respects HTTP_PROXY / http_proxy (or --proxy). Does NOT consult NO_PROXY.
 - If proxy URL uses https://, TLS to the proxy is done before CONNECT.
 - The probe is conservative: immediate read (0.3s), then send one probe byte and wait (0.8s).
"""

from __future__ import annotations
import os
import socket
import ssl
import struct
import fcntl
import urllib.parse
import base64
import argparse
import time
import select

SIOCGIFADDR = 0x8915

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

def get_ipv4_for_iface(ifname: str):
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

def recv_some(sock: socket.socket, timeout: float):
    """Wait up to timeout for readability and return recv() result or None if no data."""
    try:
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            return None
        data = sock.recv(4096)
        return data  # may be b'' if closed
    except Exception as e:
        return e

def connect_via_proxy(proxy, target_ip, target_port, timeout):
    scheme, phost, pport, auth = proxy
    try:
        sock = socket.create_connection((phost, pport), timeout=timeout)
    except Exception as e:
        return "proxy_connect_error", f"could not connect to proxy {phost}:{pport}: {e}", None
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=phost)
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return "proxy_connect_error", f"tls to proxy failed: {e}", None
    # send CONNECT
    try:
        sock.settimeout(timeout)
        req = f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n"
        if auth:
            req += f"Proxy-Authorization: {auth}\r\n"
        req += "Connection: keep-alive\r\n\r\n"
        sock.sendall(req.encode())
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return "proxy_connect_error", f"failed to send CONNECT: {e}", None

    # read headers (short)
    buf = b""
    try:
        sock.settimeout(1.0)
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # safety cap
            if len(buf) > 16384:
                break
    except socket.timeout:
        # may still have partial response or none
        pass
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return "proxy_connect_error", f"error reading proxy response: {e}", None

    if not buf:
        # no headers returned (proxy may delay); treat as success but probe.
        return "no_headers", "no HTTP response from proxy (proceed to probe)", sock

    # parse status line
    try:
        first = buf.split(b"\r\n",1)[0].decode(errors="replace")
        parts = first.split()
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return "proxy_parse_error", f"couldn't parse proxy response: {buf[:200]!r}", None

    if status_code == 407:
        try:
            sock.close()
        except Exception:
            pass
        return "proxy_auth", f"proxy requires authentication: {first}", None
    if 200 <= status_code < 300:
        return "ok", first, sock
    else:
        try:
            sock.close()
        except Exception:
            pass
        return "proxy_refused", f"proxy returned {first}", None

def raw_probe_over_tunnel(sock: socket.socket, timeout: float, probe_byte: bytes = b"\x00"):
    """
    With an established tunnel socket (connected to proxy with upstream connected),
    do:
      - short immediate read (0.3s)
      - send probe_byte and wait (0.8s)
    Return tuple (result_label, detail)
      result_label in {"OPEN","CLOSED","UNKNOWN","ERROR"}
    """
    # immediate read
    r = recv_some(sock, 0.3)
    if isinstance(r, Exception):
        return "ERROR", f"read error during initial banner: {r}"
    if r == b"":
        return "CLOSED", "peer closed immediately (empty read)"
    if r:
        # got some data
        try:
            s = r[:200].decode("latin-1", errors="replace")
        except Exception:
            s = repr(r[:200])
        return "OPEN", f"initial data ({len(r)} bytes): {s!r}"

    # send probe byte
    try:
        sock.settimeout(timeout)
        sock.sendall(probe_byte)
    except Exception as e:
        return "ERROR", f"failed to send probe byte: {e}"

    r2 = recv_some(sock, 0.8)
    if isinstance(r2, Exception):
        return "ERROR", f"read error after probe: {r2}"
    if r2 == b"":
        return "CLOSED", "peer closed after probe"
    if r2:
        try:
            s2 = r2[:200].decode("latin-1", errors="replace")
        except Exception:
            s2 = repr(r2[:200])
        return "OPEN", f"reply to probe ({len(r2)} bytes): {s2!r}"

    # nothing observed
    return "UNKNOWN", "no data in probes (connection may be open but silent)"

def probe_port(proxy, target_ip, port, timeout, probe_byte):
    start = time.time()
    status, detail, sock = connect_via_proxy(proxy, target_ip, port, timeout)
    connect_time = time.time() - start
    if status == "ok" or status == "no_headers":
        # sock is open: probe
        probe_start = time.time()
        res_label, res_detail = raw_probe_over_tunnel(sock, timeout, probe_byte)
        probe_time = time.time() - probe_start
        try:
            sock.close()
        except Exception:
            pass
        return {
            "port": port,
            "connect_status": status,
            "connect_detail": detail,
            "connect_time": connect_time,
            "probe_status": res_label,
            "probe_detail": res_detail,
            "probe_time": probe_time,
        }
    else:
        return {
            "port": port,
            "connect_status": status,
            "connect_detail": detail,
            "connect_time": connect_time,
            "probe_status": None,
            "probe_detail": None,
            "probe_time": None,
        }

def main():
    p = argparse.ArgumentParser(description="Raw probe target ports via HTTP proxy CONNECT to local non-loopback IP.")
    p.add_argument("--proxy", help="explicit proxy URL (overrides env)")
    p.add_argument("-p", "--ports", default="15004", help="comma-separated target ports (e.g. 15004,2024)")
    p.add_argument("-t", "--timeout", type=float, default=3.0, help="per-operation timeout seconds")
    p.add_argument("--probe-byte", default="00", help="hex for single probe byte to send after tunnel (default 00)")
    args = p.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("HTTP_PROXY/http_proxy not set and --proxy not supplied. Exiting.")
        return
    scheme, phost, pport, auth = proxy
    print(f"Using proxy: {scheme}://{phost}:{pport} {'(auth)' if auth else ''}")

    iface = choose_non_lo_iface()
    if not iface:
        print("Could not detect non-loopback interface from /proc/net/route. Exiting.")
        return
    ip = get_ipv4_for_iface(iface)
    if not ip:
        print(f"Could not read IPv4 for interface {iface}. Exiting.")
        return
    print(f"Target local IP (non-lo iface {iface}): {ip}")

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

    # parse probe byte
    try:
        pb = bytes.fromhex(args.probe_byte)
        if len(pb) == 0:
            pb = b"\x00"
        pb = pb[:1]
    except Exception:
        print("Invalid --probe-byte value; expecting hex like '00' or 'ff'. Using 00.")
        pb = b"\x00"

    for port in ports:
        print("\n---")
        print(f"Probing {ip}:{port} via proxy...")
        r = probe_port(proxy, ip, port, args.timeout, pb)
        print(f"CONNECT phase : {r['connect_status']} ({r['connect_detail']})  (took {r['connect_time']:.3f}s)")
        if r["probe_status"] is not None:
            print(f"PROBE result  : {r['probe_status']} ({r['probe_detail']})  (took {r['probe_time']:.3f}s)")
        else:
            print("PROBE result  : (no probe; CONNECT failed or proxy refused)")
    print("\nDone.")

if __name__ == '__main__':
    import argparse
    main()
