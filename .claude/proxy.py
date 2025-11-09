#!/usr/bin/env python3
"""
proxy_connect_http_probe.py

Perform HTTP CONNECT via proxy (from HTTP_PROXY or --proxy) to the non-loopback interface IP,
then send a simple HTTP GET / through the tunnel and display the response.

Usage:
    python3 proxy_connect_http_probe.py -p 2024
"""

import os, socket, ssl, struct, fcntl, urllib.parse, base64, time, argparse

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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        req = struct.pack('256s', ifname[:15].encode())
        res = fcntl.ioctl(s, SIOCGIFADDR, req)
        return ".".join(map(str, res[20:24]))
    except Exception:
        return None
    finally:
        s.close()

def recv_until(sock, marker=b"\r\n\r\n", timeout=3):
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data

def do_connect_and_http(proxy, target_ip, target_port, timeout=4.0):
    scheme, phost, pport, auth = proxy
    start = time.time()
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
    head = recv_until(s, timeout=timeout)
    first = head.split(b"\r\n",1)[0].decode(errors="replace") if head else ""
    if not first.startswith("HTTP/1.1 200"):
        print(f"Proxy refused CONNECT: {first}")
        s.close()
        return
    print(f"Proxy CONNECT OK ({first})")

    # Now the tunnel is open: send HTTP request through it
    http_req = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: proxy-probe/1.0\r\nConnection: close\r\n\r\n"
    s.sendall(http_req.encode())
    resp = b""
    s.settimeout(timeout)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 16384:
                break
    except Exception:
        pass
    s.close()

    # Show result
    if not resp:
        print("No response from target.")
        return
    try:
        text = resp.decode("utf-8", errors="replace")
    except Exception:
        text = resp.decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    print("\n--- Response ---")
    print(head.splitlines()[0] if head else "(no status line)")
    print(head)
    if body:
        print("\nBody (first 512 bytes):")
        print(body[:512])
    print("\n--- End ---")

def main():
    ap = argparse.ArgumentParser(description="CONNECT through HTTP_PROXY and perform HTTP GET / through the tunnel.")
    ap.add_argument("-p", "--port", type=int, default=2024, help="target port")
    ap.add_argument("--proxy", help="override HTTP_PROXY env")
    ap.add_argument("-t", "--timeout", type=float, default=4.0, help="timeout seconds")
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
    print(f"Targeting {ip}:{args.port}\n")

    do_connect_and_http(proxy, ip, args.port, timeout=args.timeout)

if __name__ == "__main__":
    main()
