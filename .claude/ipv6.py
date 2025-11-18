#!/usr/bin/env python3
import subprocess
import socket
import struct
import fcntl
import os
import time
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed

ETH_P_IP = 0x0800
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

COMMON_TCP_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,111,119,123,135,137,138,139,
    143,161,162,389,443,445,465,514,587,631,636,873,993,995,
    1080,1433,1521,2024,2049,2181,2379,2380,3306,3389,3690,
    4443,4500,5000,5001,5432,5672,5900,6080,6081,6379,6443,
    6667,7001,8000,8008,8080,8443,8883,9000,9001,9092,11211,
    15004
]

SCAN_PORTS = COMMON_TCP_PORTS
SCAN_TIMEOUT = 0.2
SNIFF_TIMEOUT = 5.0
RETRYABLE_ERRNOS = {errno.EAGAIN, errno.EALREADY}

# ------------------------- Netlink constants -------------------------

NLMSG_ERROR = 2
NLM_F_REQUEST = 1
NLM_F_CREATE  = 0x400
NLM_F_REPLACE = 0x100
RTM_NEWNEIGH  = 28
AF_INET6 = socket.AF_INET6

# struct ndmsg { u8 fam; u8 pad1; u16 pad2; int ifindex; u16 state; u8 flags; u8 type }
NDMSG_STRUCT = "BBHiHBB"
RTN_UNICAST = 1

NUD_PERMANENT = 0x80

NLA_HDR = "HH"
NDA_DST = 1
NDA_LLADDR = 2

def nla(attr_type, payload):
    l = 4 + len(payload)
    pad = (4 - (l % 4)) % 4
    return struct.pack(NLA_HDR, l, attr_type) + payload + (b"\x00" * pad)

def add_permanent_ipv6_neighbor(iface, ipv6_addr, mac_bytes):
    ifindex = socket.if_nametoindex(iface)
    dst_bin = socket.inet_pton(AF_INET6, ipv6_addr)

    ndmsg = struct.pack(
        NDMSG_STRUCT,
        AF_INET6,       # family
        0,              # pad1
        0,              # pad2
        ifindex,        # ifindex
        NUD_PERMANENT,  # state
        0,              # flags (must be 0 here)
        RTN_UNICAST     # type
    )

    attrs = nla(NDA_DST, dst_bin) + nla(NDA_LLADDR, mac_bytes)

    NLMSG_HDR = "IHHII"
    nlmsg_len = struct.calcsize(NLMSG_HDR) + len(ndmsg) + len(attrs)

    nlmsg = struct.pack(
        NLMSG_HDR,
        nlmsg_len,
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
        1,
        os.getpid()
    )

    msg = nlmsg + ndmsg + attrs

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.send(msg)
    resp = s.recv(65535)

    _, msg_type, _, _, _ = struct.unpack_from(NLMSG_HDR, resp, 0)
    if msg_type == NLMSG_ERROR:
        errno_val = struct.unpack_from("i", resp, struct.calcsize(NLMSG_HDR))[0]
        if errno_val != 0:
            raise OSError(errno_val, os.strerror(errno_val))

    s.close()

# ------------------------- Utilities -------------------------

def errno_to_name(rc):
    if isinstance(rc, str) and rc.startswith("EXC:"):
        return rc
    return errno.errorcode.get(rc, f"ERR_{rc}")

def get_local_ipv4_from_hostname():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    for tok in out.split():
        if "." in tok and not tok.startswith("127."):
            return tok
    raise RuntimeError("No IPv4")

def get_iface_ipv4(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    s.close()
    return socket.inet_ntoa(res[20:24])

def get_default_gateway_for_ip(local_ip):
    with open("/proc/net/route","r") as f:
        lines = f.readlines()[1:]

    for line in lines:
        fields = line.strip().split()
        iface, dst, gw, flags = fields[0], fields[1], fields[2], int(fields[3],16)
        if dst=="00000000" and (flags & 0x2):
            try:
                if get_iface_ipv4(iface) == local_ip:
                    return iface, socket.inet_ntoa(struct.pack("<L", int(gw,16)))
            except OSError:
                pass

    for line in lines:
        fields = line.strip().split()
        iface, dst, gw, flags = fields[0], fields[1], fields[2], int(fields[3],16)
        if dst=="00000000" and (flags & 0x2):
            return iface, socket.inet_ntoa(struct.pack("<L", int(gw,16)))

    raise RuntimeError("No gateway")

def get_local_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface.encode("utf-8"))
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    s.close()
    return res[18:24]

def bytes_to_mac_str(b):
    return ":".join(f"{x:02x}" for x in b)

def sniff_gateway_mac(iface, gw_ip, timeout=SNIFF_TIMEOUT):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.bind((iface, 0))
    s.settimeout(timeout)
    gw_bytes = socket.inet_aton(gw_ip)
    start = time.time()

    while True:
        if time.time() - start > timeout:
            break
        try:
            pkt, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        if len(pkt) < 34:
            continue
        eth_src = pkt[6:12]
        ip_hdr = pkt[14:]
        if ip_hdr[0] >> 4 != 4:
            continue
        src_ip = ip_hdr[12:16]
        dst_ip = ip_hdr[16:20]
        if src_ip == gw_bytes:
            s.close()
            return eth_src, True
        if dst_ip == gw_bytes:
            s.close()
            return pkt[0:6], False

    s.close()
    return None, None

def mac_to_ipv6_link_local(mac_bytes):
    mac = bytearray(mac_bytes)
    mac[0] ^= 0x02
    eui = bytearray(8)
    eui[0:3] = mac[0:3]
    eui[3:5] = b"\xff\xfe"
    eui[5:8] = mac[3:6]
    parts = [
        (eui[0] << 8) | eui[1],
        (eui[2] << 8) | eui[3],
        (eui[4] << 8) | eui[5],
        (eui[6] << 8) | eui[7],
    ]
    return "fe80::" + ":".join(f"{p:x}" for p in parts)

# ------------------------- Port scanning -------------------------

def scan_one_port(addr, port, timeout, scope_id, max_retries=1):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setblocking(True)
    s.settimeout(timeout)

    tries = 0
    while True:
        rc = s.connect_ex((addr, port, 0, scope_id))
        if rc == 0:
            s.close()
            return port, None
        if rc in RETRYABLE_ERRNOS and tries < max_retries:
            tries += 1
            continue
        s.close()
        return None, errno_to_name(rc)

def scan_ipv6_ports(addr, iface, ports, timeout=SCAN_TIMEOUT, workers=1):
    print(f"\n[+] Scanning IPv6 {addr}%{iface}...")
    scope_id = socket.if_nametoindex(iface)
    errors = {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(scan_one_port, addr, p, timeout, scope_id): p
            for p in ports
        }
        for fut in as_completed(futs):
            port = futs[fut]
            open_p, err = fut.result()
            if open_p:
                print(f"  [OPEN] {open_p}")
            if err:
                errors[err] = errors.get(err, 0) + 1

    print("\n[+] Scan complete.")
    if errors:
        print("\n[!] connect_ex() error summary:")
        for n, c in sorted(errors.items()):
            print(f"   - {n}: {c}")
    else:
        print("[+] No errors.")

# ------------------------- Main -------------------------

def main():
    if os.geteuid() != 0:
        print("Must be root")
        return

    local_ip = get_local_ipv4_from_hostname()
    iface, gw_ip = get_default_gateway_for_ip(local_ip)

    print(f"[+] Local IP:  {local_ip}")
    print(f"[+] IFACE:     {iface}")
    print(f"[+] GW IPv4:   {gw_ip}")

    local_mac = get_local_mac(iface)
    print(f"[+] Local MAC: {bytes_to_mac_str(local_mac)}")

    print("[+] Sniffing packets to learn gateway MAC...")
    gw_mac, _ = sniff_gateway_mac(iface, gw_ip)
    if not gw_mac:
        print("[-] Could not discover gateway MAC")
        return

    print(f"[+] GW MAC:    {bytes_to_mac_str(gw_mac)}")

    local_ll = mac_to_ipv6_link_local(local_mac)
    gw_ll = mac_to_ipv6_link_local(gw_mac)

    print(f"[+] Local LL IPv6: {local_ll}%{iface}")
    print(f"[+] GW LL IPv6:    {gw_ll}%{iface}")

    print("[+] Installing permanent IPv6 neighbor entry...")
    add_permanent_ipv6_neighbor(iface, gw_ll, gw_mac)
    print("[+] Neighbor added.")

    scan_ipv6_ports(gw_ll, iface, SCAN_PORTS)

if __name__ == "__main__":
    main()
