#!/usr/bin/env python3
"""
proxy_connect_custom_probe.py

Do an HTTP CONNECT via proxy (from HTTP_PROXY or --proxy) to the non-loopback interface IP
and send a custom payload (default "X\\r\\n\\r\\n") through the tunnel, then print any response.

Usage examples:
  python3 proxy_connect_custom_probe.py -p 15004
  python3 proxy_connect_custom_probe.py -p 2024 --payload "X\\r\\n\\r\\n"
  python3 proxy_connect_custom_probe.py --proxy http://user:pass@proxy:3128 --payload "HELLO\\r\\n"

"""

import os, socket, ssl, struct, fcntl, urllib.parse, base64, argparse, time

SIOCGIFADDR = 0x8915

def parse_proxy_env(explicit=None):
    val = explicit or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not val:
        return None
    if "://" not in val:
        val = "http://" + val
    p = urllib.parse.urlparse(val)
    scheme = p.scheme.lower()
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    auth = None
    if p.username:
        creds = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
        auth = "Basic " + base64.b64encode(creds.encode()).decode()
    return scheme, host, port, auth

def choose_non_lo_iface():
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                iface, dest = line.split()[:2]
                if iface != "lo" and dest == "00000000":
                    return iface
            f.seek(0)
            next(f)
            for line in f:
                iface, dest = line.split()[:2]
                if iface != "lo":
                    return iface
    except Exception:
        pass
    return None

def get_ipv4_for_iface(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack('256s', ifname[:15].encode())
        res = fcntl.ioctl(s, SIOCGIFADDR, req)
        return ".".join(map(str, res[20:24]))
    except Exception:
        return None
    finally:
        s.close()

def recv_some(sock, timeout=1.0, max_bytes=4096):
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    return data

def do_connect_and_probe(proxy, target_ip, target_port, payload, timeout=3.0):
    scheme, phost, pport, auth = proxy
    s = socket.create_connection((phost, pport), timeout=timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=phost)

    # CONNECT phase
    req = f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n"
    if auth:
        req += f"Proxy-Authorization: {auth}\r\n"
    req += "Connection: keep-alive\r\n\r\n"
    s.sendall(req.encode())

    head = b""
    s.settimeout(timeout)
    try:
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
            if len(head) > 16384:
                break
    except socket.timeout:
        pass

    first = head.split(b"\r\n",1)[0].decode(errors="replace") if head else ""
    if not first.startswith("HTTP/1.1 200"):
        print(f"Proxy CONNECT failed: {first or head[:100]}")
        s.close()
        return

    print(f"Proxy CONNECT OK ({first})")

    # Send custom payload
    payload_bytes = payload.encode("utf-8", errors="replace")
    print(f"Sending payload ({len(payload_bytes)} bytes): {repr(payload)}")
    try:
        s.sendall(payload_bytes)
    except Exception as e:
        print(f"Send error: {e}")
        s.close()
        return

    # Read some response
    data = recv_some(s, timeout=timeout)
    s.close()

    if not data:
        print("No response (silent or closed).")
        return

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    print(f"\n--- Response ({len(data)} bytes) ---")
    print(text if len(text) < 2000 else text[:2000] + "\n[...truncated...]")
    print("--- End ---\n")

def main():
    ap = argparse.ArgumentParser(description="HTTP CONNECT raw probe via proxy to local IP.")
    ap.add_argument("-p","--port", type=int, default=15004, help="target port")
    ap.add_argument("--proxy", help="override HTTP_PROXY env")
    ap.add_argument("--payload", default="X\\r\\n\\r\\n",
                    help="payload string to send after CONNECT (default 'X\\r\\n\\r\\n')")
    ap.add_argument("-t","--timeout", type=float, default=3.0, help="timeout seconds")
    args = ap.parse_args()

    proxy = parse_proxy_env(args.proxy)
    if not proxy:
        print("No HTTP_PROXY set or invalid proxy URL.")
        return
    scheme, phost, pport, _ = proxy
    print(f"Using proxy {scheme}://{phost}:{pport}")

    iface = choose_non_lo_iface()
    if not iface:
        print("Could not find non-lo interface.")
        return
    ip = get_ipv4_for_iface(iface)
    if not ip:
        print(f"Could not get IP for {iface}")
        return

    print(f"Target {ip}:{args.port}")
    do_connect_and_probe(proxy, ip, args.port, args.payload, args.timeout)

if __name__ == "__main__":
    main()
