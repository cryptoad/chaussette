import os, socket, base64, requests
from urllib.parse import urlparse

TIMEOUT = 5


def proxy_cfg():
    p = urlparse(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    if not p.hostname:
        raise RuntimeError("HTTP_PROXY not set")

    return {
        "host": p.hostname,
        "port": p.port or 8080,
        "auth": (
            "Basic " + base64.b64encode(f"{p.username}:{p.password}".encode()).decode()
            if p.username else None
        ),
        "url": f"{p.scheme or 'http'}://"
               f"{(p.username+':'+p.password+'@') if p.username else ''}"
               f"{p.hostname}:{p.port or 8080}",
    }


def req(url, proxies):
    try:
        r = requests.get(url, proxies=proxies, timeout=TIMEOUT)
        print(f"[REQ ] {url:<35} -> {r.status_code}")
    except Exception as e:
        print(f"[REQ ] {url:<35} -> FAIL ({type(e).__name__})")


def raw(proxy, payload, label):
    try:
        s = socket.create_connection((proxy["host"], proxy["port"]), TIMEOUT)
        if proxy["auth"]:
            payload = payload.replace(
                b"\r\n\r\n",
                f"\r\nProxy-Authorization: {proxy['auth']}\r\n\r\n".encode(),
            )
        s.sendall(payload)
        r = s.recv(256).decode(errors="ignore").splitlines()[0]
        s.close()
        print(f"[RAW ] {label:<30} -> {r}")
    except Exception as e:
        print(f"[RAW ] {label:<30} -> FAIL ({type(e).__name__})")


def connect(proxy, host, port):
    raw(
        proxy,
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode(),
        f"CONNECT {host}:{port}",
    )


def main():
    proxy = proxy_cfg()
    proxies = {"http": proxy["url"], "https": proxy["url"]}

    print("== Local / Internal ==")
    for u in [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://10.0.0.1",
        "http://192.168.0.1",
        "http://169.254.169.254",
    ]:
        req(u, proxies)

    print("\n== Absolute vs Origin form ==")
    raw(
        proxy,
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "absolute-form",
    )
    raw(
        proxy,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "origin-form",
    )

    print("\n== Host / URL mismatch ==")
    raw(
        proxy,
        b"GET http://example.com/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "URL ext / Host local",
    )

    print("\n== Credential & encoding tricks ==")
    raw(
        proxy,
        b"GET http://user:pass@127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "creds in URL",
    )
    raw(
        proxy,
        b"GET http://%31%32%37.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "encoded loopback",
    )

    print("\n== Protocol confusion ==")
    raw(
        proxy,
        b"GET ftp://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "ftp scheme",
    )
    raw(
        proxy,
        b"GET http://example.com/ HTTP/1.0\r\n\r\n",
        "HTTP/1.0",
    )

    print("\n== CONNECT policy ==")
    connect(proxy, "example.com", 443)
    connect(proxy, "example.com", 80)
    connect(proxy, "127.0.0.1", 80)
    connect(proxy, "169.254.169.254", 80)
    connect(proxy, "[::1]", 443)


if __name__ == "__main__":
    main()
