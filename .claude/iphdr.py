#!/usr/bin/env python3
"""
Raw TCP SYN port scanner towards the default gateway for the current IP.

- Gets current IP via `hostname -I`
- Finds the interface that owns that IP
- Finds the default gateway for that interface (via /proc/net/route)
- Uses a raw socket with IP_HDRINCL to send TCP SYNs to a list of ports
- Listens for SYN/ACK or RST replies on a raw TCP socket
- Uses a thread pool to send SYNs in parallel and a global timeout

Linux-only, IPv4-only. Must be run as root.
"""

import os
import socket
import struct
import fcntl
import subprocess
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

SIOCGIFADDR = 0x8915  # get PA address
IPPROTO_TCP = socket.IPPROTO_TCP

# ---- Config -------------------------------------------------------------

SRC_PORT = 2024          # Source TCP port we use for all probes
SCAN_TIMEOUT = 5.0        # Seconds to wait for responses overall
SEND_WORKERS = 50         # Thread pool size for sending SYNs

PORTS_TO_SCAN = [
    # Fill this with your ~100 "interesting" ports.
    # Some examples (Kubernetes, Envoy, GCP-ish, plus the ones you asked for):
    22,      # SSH
    80, 443,
    15004,   # Envoy-ish / sidecar
    2024,    # Your specific port
    6443,    # Kubernetes API
    2379, 2380,  # etcd
    10250, 10255,  # kubelet
    15000, 15001, 15006, 15010, 15012, 15014,  # Istio/Envoy ports
    8080, 9090, 9091, 9100,
    # ...add more here...
]

# ---- Helpers: IP / interface / gateway ----------------------------------


def get_current_ip_from_hostname():
    out = subprocess.check_output(["hostname", "-I"], text=True).strip()
    # hostname -I can return multiple addresses; pick the first IPv4-looking one
    for token in out.split():
        if "." in token:
            return token
    raise RuntimeError("Could not find an IPv4 address from `hostname -I` output: %r" % out)


def get_iface_ip_map():
    """Return {iface_name: ipv4_addr_str} using SIOCGIFADDR."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iface_ip = {}
    for if_index, if_name in socket.if_nameindex():
        ifname_bytes = if_name.encode("utf-8")
        ifreq = struct.pack("256s", ifname_bytes[:15])
        try:
            res = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
        except OSError:
            continue
        ip_bytes = res[20:24]
        ip_str = socket.inet_ntoa(ip_bytes)
        iface_ip[if_name] = ip_str
    sock.close()
    return iface_ip


def get_iface_for_ip(ip_str):
    iface_ip = get_iface_ip_map()
    for iface, addr in iface_ip.items():
        if addr == ip_str:
            return iface
    raise RuntimeError(f"Could not find interface for IP {ip_str!r}")


def get_default_gateway_for_iface(iface):
    """
    Parse /proc/net/route to find the default gateway for a given interface.
    """
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:  # skip header
            fields = line.strip().split()
            if fields[0] != iface:
                continue
            dest_hex = fields[1]
            gate_hex = fields[2]
            flags = int(fields[3], 16)

            RTF_UP = 0x0001
            RTF_GATEWAY = 0x0002
            if dest_hex == "00000000" and (flags & RTF_UP) and (flags & RTF_GATEWAY):
                gw_bytes = struct.pack("<L", int(gate_hex, 16))
                return socket.inet_ntoa(gw_bytes)
    raise RuntimeError(f"Could not find default gateway for interface {iface!r}")


# ---- Helpers: checksums and headers -------------------------------------


def checksum(data: bytes) -> int:
    """Compute Internet Checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] << 8 | data[i + 1]
        s = (s + w) & 0xFFFFFFFF
    while (s >> 16) != 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, payload_len: int, ident: int) -> bytes:
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + payload_len
    flags_frag = 0
    ttl = 64
    proto = IPPROTO_TCP
    check = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        ident,
        flags_frag,
        ttl,
        proto,
        check,
        src_addr,
        dst_addr,
    )

    check = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        ident,
        flags_frag,
        ttl,
        proto,
        check,
        src_addr,
        dst_addr,
    )
    return ip_header


def build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, ack_seq: int, flags: int, window: int = 65535) -> bytes:
    data_offset = 5  # 5 * 4 = 20 bytes, no options
    offset_res = (data_offset << 4) + 0
    urg_ptr = 0
    checksum_placeholder = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        offset_res,
        flags,
        window,
        checksum_placeholder,
        urg_ptr,
    )

    # Pseudo-header for TCP checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = IPPROTO_TCP
    tcp_length = len(tcp_header)

    pseudo_header = struct.pack("!4s4sBBH", src_addr, dst_addr, placeholder, protocol, tcp_length)
    pseudo_packet = pseudo_header + tcp_header
    tcp_checksum = checksum(pseudo_packet)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        offset_res,
        flags,
        window,
        tcp_checksum,
        urg_ptr,
    )
    return tcp_header


# ---- Scanner -------------------------------------------------------------

class RawSynScanner:
    def __init__(self, src_ip: str, dst_ip: str, ports):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ports = list(ports)
        self.results = {p: "no_response" for p in self.ports}
        self.pending = {}  # ack_number -> port
        self.lock = Lock()

        # Raw socket for sending
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Raw socket for receiving TCP replies
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_TCP)
        self.recv_sock.settimeout(0.5)

    def send_syn(self, dst_port: int):
        seq = random.getrandbits(32)
        ident = random.getrandbits(16)

        ip_header = build_ip_header(self.src_ip, self.dst_ip, payload_len=20, ident=ident)
        # SYN flag = 0x02
        tcp_header = build_tcp_header(
            self.src_ip, self.dst_ip, SRC_PORT, dst_port, seq, 0, flags=0x02
        )

        packet = ip_header + tcp_header

        with self.lock:
            # We expect ACK = seq + 1 in replies
            self.pending[(seq + 1) & 0xFFFFFFFF] = dst_port

        try:
            self.send_sock.sendto(packet, (self.dst_ip, 0))
        except OSError as e:
            with self.lock:
                self.results[dst_port] = f"send_error:{e}"

    def recv_loop(self, deadline: float):
        src_ip_bytes = socket.inet_aton(self.dst_ip)  # replies come from dst_ip
        dst_ip_bytes = socket.inet_aton(self.src_ip)  # to our source IP

        while time.time() < deadline:
            try:
                data, addr = self.recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 40:
                continue

            # Parse IP header
            ver_ihl = data[0]
            ihl = ver_ihl & 0x0F
            ip_header_len = ihl * 4
            if ip_header_len < 20 or len(data) < ip_header_len + 20:
                continue

            proto = data[9]
            if proto != IPPROTO_TCP:
                continue

            src_addr = data[12:16]
            dst_addr = data[16:20]
            if src_addr != src_ip_bytes or dst_addr != dst_ip_bytes:
                continue

            # Parse TCP header
            tcp_header = data[ip_header_len:ip_header_len + 20]
            src_port, dst_port, seq_num, ack_num, offset_res, flags, window, chk, urg = struct.unpack(
                "!HHLLBBHHH", tcp_header
            )

            if dst_port != SRC_PORT:
                continue

            with self.lock:
                port = self.pending.pop(ack_num, None)
                if port is None:
                    continue

                # SYN/ACK -> open, RST -> closed
                # SYN flag 0x02, ACK 0x10, RST 0x04
                if flags & 0x12 == 0x12:  # SYN + ACK
                    self.results[port] = "open"
                elif flags & 0x04:  # RST
                    self.results[port] = "closed"
                else:
                    self.results[port] = f"other_flags:0x{flags:02x}"

    def scan(self, timeout: float = SCAN_TIMEOUT):
        deadline = time.time() + timeout

        # Fire off all SYNs via a thread pool
        with ThreadPoolExecutor(max_workers=SEND_WORKERS) as executor:
            futures = [executor.submit(self.send_syn, p) for p in self.ports]
            # Optionally wait for all send attempts to complete
            for f in as_completed(futures):
                _ = f.result()

        # Receive replies until deadline or all pending answered
        self.recv_loop(deadline)

        return self.results


def main():
    if os.geteuid() != 0:
        raise SystemExit("You must run this script as root to use raw sockets.")

    src_ip = get_current_ip_from_hostname()
    iface = get_iface_for_ip(src_ip)
    gw_ip = get_default_gateway_for_iface(iface)

    print(f"[+] Current IP from hostname -I: {src_ip}")
    print(f"[+] Interface for that IP:     {iface}")
    print(f"[+] Default gateway on iface:  {gw_ip}")
    print(f"[+] Scanning {len(PORTS_TO_SCAN)} ports on gateway {gw_ip} ...")

    scanner = RawSynScanner(src_ip, gw_ip, PORTS_TO_SCAN)
    results = scanner.scan(timeout=SCAN_TIMEOUT)

    print("\n[Scan results]")
    for p in sorted(results):
        print(f"  Port {p:5d}: {results[p]}")


if __name__ == "__main__":
    main()
