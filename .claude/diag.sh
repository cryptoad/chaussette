#!/usr/bin/env bash
set -u

OUT_DIR="${OUT_DIR:-/tmp/fc_guest_diag.$(date +%s)}"
mkdir -p "$OUT_DIR"

log() {
  printf '\n========== %s ==========\n' "$*"
}

run() {
  local name="$1"
  shift
  log "$name"
  {
    echo "+ $*"
    "$@"
  } 2>&1 | tee "$OUT_DIR/${name//[^A-Za-z0-9_.-]/_}.txt"
}

run_sh() {
  local name="$1"
  shift
  log "$name"
  {
    echo "+ $*"
    sh -c "$*"
  } 2>&1 | tee "$OUT_DIR/${name//[^A-Za-z0-9_.-]/_}.txt"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

log "output directory"
echo "$OUT_DIR"

###############################################################################
# Basic system
###############################################################################

run "uname" uname -a

run_sh "cmdline" '
cat /proc/cmdline 2>/dev/null || true
'

run_sh "whoami_caps" '
id
echo
grep -E "^(Cap|NoNewPrivs|Seccomp)" /proc/self/status 2>/dev/null || true
'

###############################################################################
# Device inventory
###############################################################################

run_sh "sensitive_device_nodes" '
for p in \
  /dev/mem \
  /dev/port \
  /dev/kmsg \
  /dev/snapshot \
  /dev/hwrng \
  /dev/net/tun \
  /dev/vda \
  /dev/vdb \
  /dev/vdc \
  /dev/vsock
do
  [ -e "$p" ] && ls -l "$p"
done
'

run_sh "virtio_devices" '
for d in /sys/bus/virtio/devices/*; do
  [ -e "$d/device" ] || continue
  echo "## $d"
  printf "device="; cat "$d/device"
  [ -e "$d/vendor" ] && { printf "vendor="; cat "$d/vendor"; }
  [ -e "$d/modalias" ] && { printf "modalias="; cat "$d/modalias"; }
  [ -e "$d/status" ] && { printf "status="; cat "$d/status"; }
  if [ -L "$d/driver" ]; then
    printf "driver="
    basename "$(readlink "$d/driver")"
  fi
  echo
done
'

run_sh "virtio_id_summary" '
for d in /sys/bus/virtio/devices/*; do
  [ -e "$d/device" ] || continue
  id="$(cat "$d/device")"
  case "$id" in
    0x0001) kind="net" ;;
    0x0002) kind="block" ;;
    0x0003) kind="console" ;;
    0x0004) kind="rng" ;;
    0x0005) kind="balloon" ;;
    0x0013) kind="vsock" ;;
    0x0018) kind="mem" ;;
    0x001b) kind="pmem" ;;
    *) kind="unknown" ;;
  esac
  echo "$(basename "$d") $id $kind"
done
'

###############################################################################
# Vsock diagnostics
###############################################################################

run_sh "dev_vsock" '
ls -l /dev/vsock 2>&1 || true
'

run_sh "vsock_modules" '
lsmod 2>/dev/null | grep -i vsock || true
find /sys/module -maxdepth 1 -iname "*vsock*" -print 2>/dev/null || true
'

run_sh "kernel_config_vsock" '
{
  zcat /proc/config.gz 2>/dev/null || true
  cat "/boot/config-$(uname -r)" 2>/dev/null || true
} | grep -E "CONFIG_(VSOCKETS|VIRTIO_VSOCKETS|VIRTIO_VSOCKETS_COMMON|VSOCKETS_LOOPBACK|VSOCKETS_DIAG|VHOST_VSOCK|VMWARE_VMCI_VSOCKETS)" || true
'

run_sh "proc_net_vsock" '
cat /proc/net/vsock 2>&1 || true
'

run_sh "dmesg_vsock" '
dmesg 2>/dev/null | grep -iE "vsock|virtio.*socket|virtio.*vsock" | tail -100 || true
'

log "python_af_vsock_probe"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/python_af_vsock_probe.txt" || true
import socket

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))
print("VMADDR_CID_LOCAL:", getattr(socket, "VMADDR_CID_LOCAL", None))

if not hasattr(socket, "AF_VSOCK"):
    print("Python/socket lacks AF_VSOCK")
    raise SystemExit(0)

ports = [1, 22, 80, 443, 2375, 5000, 8000, 8080, 8443, 9000, 50051]

for port in ports:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((socket.VMADDR_CID_HOST, port))
        print(f"[+] connect host cid={socket.VMADDR_CID_HOST} port={port}: ok")
        try:
            s.sendall(b"\n")
            data = s.recv(128)
            print(f"    recv={data!r}")
        except Exception as e:
            print(f"    read/write after connect: {type(e).__name__}: {e}")
    except OSError as e:
        print(f"[-] connect host cid={socket.VMADDR_CID_HOST} port={port}: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()
PY

###############################################################################
# Block devices and mounts
###############################################################################

run_sh "block_sysfs" '
for d in /sys/class/block/vd*; do
  [ -e "$d" ] || continue
  name="$(basename "$d")"
  echo "## $name"
  for f in ro size queue/logical_block_size queue/physical_block_size queue/rotational; do
    [ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f"
  done
  [ -e "$d/serial" ] && { printf "serial="; cat "$d/serial"; }
  echo
done
'

run_sh "block_signatures" '
for dev in /dev/vda /dev/vdb /dev/vdc /dev/vdd /dev/vde; do
  [ -e "$dev" ] || continue
  echo "## $dev"
  blkid "$dev" 2>/dev/null || true
  file -s "$dev" 2>/dev/null || true
  echo
done
'

run_sh "mounts_findmnt" '
if command -v findmnt >/dev/null 2>&1; then
  findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
else
  cat /proc/mounts
fi
'

run_sh "df" '
df -hT 2>/dev/null || true
'

###############################################################################
# Network diagnostics
###############################################################################

run_sh "network_interfaces_tools" '
ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null || true
echo
ip route 2>/dev/null || route -n 2>/dev/null || true
echo
ip neigh 2>/dev/null || arp -an 2>/dev/null || true
echo
cat /etc/resolv.conf 2>/dev/null || true
'

run_sh "network_proc" '
echo "== /proc/net/dev =="
cat /proc/net/dev 2>/dev/null || true
echo
echo "== /proc/net/route =="
cat /proc/net/route 2>/dev/null || true
echo
echo "== /proc/net/tcp =="
cat /proc/net/tcp 2>/dev/null || true
echo
echo "== /proc/net/udp =="
cat /proc/net/udp 2>/dev/null || true
echo
echo "== /proc/net/arp =="
cat /proc/net/arp 2>/dev/null || true
'

log "network_proc_decoded"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/network_proc_decoded.txt" || true
import os
import socket
import struct

def decode_ipv4_le(hex_ip):
    try:
        return socket.inet_ntoa(struct.pack("<L", int(hex_ip, 16)))
    except Exception:
        return hex_ip

print("== interfaces from /proc/net/dev ==")
try:
    for line in open("/proc/net/dev").read().splitlines()[2:]:
        name = line.split(":", 1)[0].strip()
        fields = line.split(":", 1)[1].split()
        rx_bytes, tx_bytes = fields[0], fields[8]
        print(f"{name}: rx_bytes={rx_bytes} tx_bytes={tx_bytes}")
except Exception as e:
    print(f"error reading /proc/net/dev: {e}")

print("\n== routes from /proc/net/route ==")
try:
    for line in open("/proc/net/route").read().splitlines()[1:]:
        cols = line.split()
        iface, dest, gateway, flags, mask = cols[0], cols[1], cols[2], cols[3], cols[7]
        print(f"iface={iface} dest={decode_ipv4_le(dest)} gateway={decode_ipv4_le(gateway)} mask={decode_ipv4_le(mask)} flags=0x{flags}")
except Exception as e:
    print(f"error reading /proc/net/route: {e}")

print("\n== tcp listeners from /proc/net/tcp ==")
try:
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        cols = line.split()
        local = cols[1]
        state = cols[3]
        if state != "0A":
            continue
        ip_hex, port_hex = local.split(":")
        ip = decode_ipv4_le(ip_hex)
        port = int(port_hex, 16)
        inode = cols[9] if len(cols) > 9 else "?"
        print(f"LISTEN {ip}:{port} inode={inode}")
except Exception as e:
    print(f"error reading /proc/net/tcp: {e}")
PY

run_sh "listening_sockets_tools" '
ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true
'

log "network_quick_http_probes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/network_quick_http_probes.txt" || true
import socket

targets = [
    ("169.254.169.254", 80),
    ("169.254.169.254", 443),
    ("169.254.170.2", 80),
    ("100.100.100.200", 80),
    ("10.0.2.2", 80),
    ("10.0.2.2", 443),
    ("172.16.0.1", 80),
    ("172.17.0.1", 80),
    ("192.168.122.1", 80),
]

for host, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.75)
    try:
        s.connect((host, port))
        print(f"[+] TCP {host}:{port} connected")
        try:
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            s.sendall(req)
            data = s.recv(256)
            print(f"    recv={data!r}")
        except Exception as e:
            print(f"    read/write: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"[-] TCP {host}:{port}: {type(e).__name__}: {e}")
    finally:
        s.close()
PY

log "network_websocket_upgrade_probes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/network_websocket_upgrade_probes.txt" || true
import socket
import base64
import os

targets = [
    ("169.254.169.254", 80),
    ("169.254.169.254", 443),
    ("169.254.170.2", 80),
    ("100.100.100.200", 80),
    ("10.0.2.2", 80),
    ("10.0.2.2", 443),
    ("172.16.0.1", 80),
    ("172.17.0.1", 80),
    ("192.168.122.1", 80),
]

for host, port in targets:
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()

    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        s.sendall(req)
        data = s.recv(512)
        print(f"== {host}:{port} ==")
        print(repr(data))
    except Exception as e:
        print(f"== {host}:{port} == {type(e).__name__}: {e}")
    finally:
        s.close()
PY

###############################################################################
# Environment/secrets exposure checks without dumping secret values
###############################################################################

log "proc_environ_secret_key_names"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/proc_environ_secret_key_names.txt" || true
import os
import re

pat = re.compile(r'(TOKEN|SECRET|PASSWORD|PASS|KEY|CRED|AUTH|COOKIE|SESSION)', re.I)

print("Scanning readable /proc/*/environ for secret-looking KEY NAMES only; values are redacted.")

for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()], key=lambda x: int(x)):
    try:
        comm = open(f"/proc/{pid}/comm", "r").read().strip()
    except Exception:
        comm = "?"
    try:
        data = open(f"/proc/{pid}/environ", "rb").read()
    except Exception:
        continue

    for item in data.split(b"\0"):
        if b"=" not in item:
            continue
        k, _v = item.split(b"=", 1)
        key = k.decode("utf-8", "replace")
        if pat.search(key):
            print(f"pid={pid} comm={comm} {key}=<redacted>")
PY

log "proc_environ_secret_key_hashes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/proc_environ_secret_key_hashes.txt" || true
import os
import re
import hashlib

pat = re.compile(r'(TOKEN|SECRET|PASSWORD|PASS|KEY|CRED|AUTH|COOKIE|SESSION)', re.I)

print("Scanning readable /proc/*/environ for secret-looking keys; values are not printed, only length and short hash.")

for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()], key=lambda x: int(x)):
    try:
        comm = open(f"/proc/{pid}/comm", "r").read().strip()
    except Exception:
        comm = "?"
    try:
        data = open(f"/proc/{pid}/environ", "rb").read()
    except Exception:
        continue

    for item in data.split(b"\0"):
        if b"=" not in item:
            continue
        k, v = item.split(b"=", 1)
        key = k.decode("utf-8", "replace")
        if pat.search(key):
            h = hashlib.sha256(v).hexdigest()[:16]
            print(f"pid={pid} comm={comm} key={key} value_len={len(v)} sha256_16={h}")
PY

###############################################################################
# Tool bundle read-only scan
###############################################################################

run_sh "tool_bundle_interesting_files" '
for root in /opt/claude-code /opt/env-runner; do
  [ -d "$root" ] || continue
  echo "## $root"
  find "$root" -xdev -maxdepth 8 -type f \( \
    -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o \
    -name "*.env" -o -name "*.conf" -o -name "*.pem" -o -name "*.key" -o \
    -name "*.crt" -o -iname "*token*" -o -iname "*secret*" -o -iname "*credential*" \
  \) -print 2>/dev/null | head -500
done
'

log "tool_bundle_secret_string_matches"
{
  echo "Secret-like string scan. Matching lines may include sensitive values; review output permissions."
  if have rg; then
    for root in /opt/claude-code /opt/env-runner; do
      [ -d "$root" ] || continue
      echo "## $root"
      rg -n --hidden --no-messages \
        'AKIA|ASIA|xox[baprs]-|gh[pousr]_|github_pat_|sk-[A-Za-z0-9]|Bearer [A-Za-z0-9._-]+|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|CODESIGN|TOKEN|SECRET|PASSWORD|API_KEY' \
        "$root" 2>/dev/null | head -300 || true
    done
  else
    echo "rg not installed; skipping content scan"
  fi
} 2>&1 | tee "$OUT_DIR/tool_bundle_secret_string_matches.txt" || true

###############################################################################
# Summary
###############################################################################

log "summary"
{
  echo "Output saved to: $OUT_DIR"
  echo
  echo "Virtio devices:"

  found_vsock=0
  found_net=0
  found_block=0
  found_rng=0

  for d in /sys/bus/virtio/devices/*; do
    [ -e "$d/device" ] || continue
    id="$(cat "$d/device")"
    case "$id" in
      0x0001) kind="net"; found_net=1 ;;
      0x0002) kind="block"; found_block=1 ;;
      0x0003) kind="console" ;;
      0x0004) kind="rng"; found_rng=1 ;;
      0x0005) kind="balloon" ;;
      0x0013) kind="vsock"; found_vsock=1 ;;
      0x0018) kind="mem" ;;
      0x001b) kind="pmem" ;;
      *) kind="unknown" ;;
    esac
    echo "  $(basename "$d"): $id $kind"
  done

  echo
  if [ "$found_vsock" -eq 1 ]; then
    echo "VSOCK: virtio-vsock device appears present."
  else
    echo "VSOCK: no virtio-vsock device observed. /dev/vsock alone is not enough."
  fi

  if [ "$found_net" -eq 1 ]; then
    echo "NET: virtio-net device observed."
  else
    echo "NET: no virtio-net device observed."
  fi

  if [ "$found_block" -eq 1 ]; then
    echo "BLOCK: virtio-block device(s) observed."
  else
    echo "BLOCK: no virtio-block devices observed."
  fi

  if [ "$found_rng" -eq 1 ]; then
    echo "RNG: virtio-rng device observed."
  else
    echo "RNG: no virtio-rng device observed."
  fi
} | tee "$OUT_DIR/SUMMARY.txt"
