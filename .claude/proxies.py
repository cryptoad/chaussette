import os
import requests

# Read proxy config from environment
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

# === BASE TARGETS (port 80) ===
TARGETS = [
    # Explicit from your NO_PROXY
    "http://169.254.169.254:80",
    "http://metadata.google.internal:80",

    # Well-known *.svc.cluster.local names
    "http://kubernetes.default.svc.cluster.local:80",
    "http://kube-dns.kube-system.svc.cluster.local:80",
    "http://api-server.default.svc.cluster.local:80",
    "http://metrics-server.kube-system.svc.cluster.local:80",
    "http://cluster.local.svc.cluster.local:80",

    # Well-known *.local names
    "http://localhost.local:80",
    "http://router.local:80",
    "http://gateway.local:80",
    "http://printer.local:80",
    "http://nas.local:80",
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
    print("### Tests for NO_PROXY & Local-like Hosts (port 80) ###")
    for t in TARGETS:
        try_request(t, use_proxy=False)  # Expected to bypass proxy
        try_request(t, use_proxy=True)   # Forced proxy usage


if __name__ == "__main__":
    main()
