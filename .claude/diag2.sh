#!/usr/bin/env bash
set -u

OUT_DIR="${OUT_DIR:-/tmp/fc_guest_followup.$(date +%s)}"
mkdir -p "$OUT_DIR"

log() {
  printf '\n========== %s ==========\n' "$*"
}

save_py() {
  local name="$1"
  shift
  log "$name"
  python3 - "$@" 2>&1 | tee "$OUT_DIR/${name//[^A-Za-z0-9_.-]/_}.txt"
}

save_sh() {
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
# 0. High-level context
###############################################################################

save_sh "basic_context" '
echo "== uname =="
uname -a
echo
echo "== cmdline =="
cat /proc/cmdline 2>/dev/null || true
echo
echo "== identity/caps =="
id
grep -E "^(Cap|NoNewPrivs|Seccomp)" /proc/self/status 2>/dev/null || true
echo
echo "== key device nodes =="
for p in /dev/mem /dev/port /dev/kmsg /dev/snapshot /dev/hwrng /dev/net/tun /dev/vda /dev/vdb /dev/vdc /dev/vsock; do
  [ -e "$p" ] && ls -l "$p"
done
'

###############################################################################
# 1. Virtio inventory and vsock confirmation
###############################################################################

save_sh "virtio_inventory" '
found_vsock=0
for d in /sys/bus/virtio/devices/*; do
  [ -e "$d/device" ] || continue
  id="$(cat "$d/device")"
  case "$id" in
    0x0001) kind="net" ;;
    0x0002) kind="block" ;;
    0x0003) kind="console" ;;
    0x0004) kind="rng" ;;
    0x0005) kind="balloon" ;;
    0x0013) kind="vsock"; found_vsock=1 ;;
    0x0018) kind="mem" ;;
    0x001b) kind="pmem" ;;
    *) kind="unknown" ;;
  esac
  echo "## $d"
  echo "kind=$kind"
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

echo "== verdict =="
if [ "$found_vsock" -eq 1 ]; then
  echo "virtio-vsock device PRESENT"
else
  echo "virtio-vsock device ABSENT; /dev/vsock alone is not enough"
fi
'

save_sh "vsock_state" '
echo "== /dev/vsock =="
ls -l /dev/vsock 2>&1 || true
echo
echo "== vsock modules =="
lsmod 2>/dev/null | grep -i vsock || true
find /sys/module -maxdepth 1 -iname "*vsock*" -print 2>/dev/null || true
echo
echo "== kernel config vsock =="
{
  zcat /proc/config.gz 2>/dev/null || true
  cat "/boot/config-$(uname -r)" 2>/dev/null || true
} | grep -E "CONFIG_(VSOCKETS|VIRTIO_VSOCKETS|VIRTIO_VSOCKETS_COMMON|VSOCKETS_LOOPBACK|VSOCKETS_DIAG|VHOST_VSOCK|VMWARE_VMCI_VSOCKETS)" || true
echo
echo "== /proc/net/vsock =="
cat /proc/net/vsock 2>&1 || true
echo
echo "== dmesg vsock =="
dmesg 2>/dev/null | grep -iE "vsock|virtio.*socket|virtio.*vsock" | tail -100 || true
'

log "vsock_connect_probe"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/vsock_connect_probe.txt" || true
import socket

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))
print("VMADDR_CID_LOCAL:", getattr(socket, "VMADDR_CID_LOCAL", None))

if not hasattr(socket, "AF_VSOCK"):
    print("No AF_VSOCK support in Python/socket")
    raise SystemExit(0)

for port in [1, 22, 80, 443, 2375, 5000, 8000, 8080, 8443, 9000, 50051]:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((socket.VMADDR_CID_HOST, port))
        print(f"[+] host cid={socket.VMADDR_CID_HOST} port={port}: connected")
    except OSError as e:
        print(f"[-] host cid={socket.VMADDR_CID_HOST} port={port}: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()
PY

###############################################################################
# 2. Network topology and listener/process mapping
###############################################################################

save_sh "network_raw_proc" '
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
echo
echo "== resolv.conf =="
cat /etc/resolv.conf 2>/dev/null || true
echo
echo "== tool-based network view, if available =="
ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null || true
ip route 2>/dev/null || route -n 2>/dev/null || true
ip neigh 2>/dev/null || arp -an 2>/dev/null || true
'

log "network_decoded_and_listener_owners"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/network_decoded_and_listener_owners.txt" || true
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
        rx_bytes, rx_packets, rx_drop = fields[0], fields[1], fields[3]
        tx_bytes, tx_packets, tx_drop = fields[8], fields[9], fields[11]
        print(f"{name}: rx_bytes={rx_bytes} rx_packets={rx_packets} rx_drop={rx_drop} tx_bytes={tx_bytes} tx_packets={tx_packets} tx_drop={tx_drop}")
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

listeners = {}
print("\n== tcp listeners ==")
try:
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        cols = line.split()
        local = cols[1]
        state = cols[3]
        inode = cols[9]
        if state != "0A":
            continue
        ip_hex, port_hex = local.split(":")
        ip = decode_ipv4_le(ip_hex)
        port = int(port_hex, 16)
        listeners[inode] = (ip, port, line)
        print(f"LISTEN {ip}:{port} inode={inode}")
except Exception as e:
    print(f"error reading /proc/net/tcp: {e}")

print("\n== tcp listener owners ==")
for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()], key=lambda x: int(x)):
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except Exception:
        continue
    try:
        comm = open(f"/proc/{pid}/comm").read().strip()
    except Exception:
        comm = "?"
    try:
        cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception:
        cmdline = ""
    for fd in fds:
        try:
            target = os.readlink(f"{fd_dir}/{fd}")
        except Exception:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inode = target[len("socket:["):-1]
            if inode in listeners:
                ip, port, _line = listeners[inode]
                print(f"{ip}:{port} inode={inode} pid={pid} fd={fd} comm={comm} cmdline={cmdline}")
PY

###############################################################################
# 3. Egress/proxy behavior
###############################################################################

log "private_reserved_http_and_ws_probes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/private_reserved_http_and_ws_probes.txt" || true
import socket, base64, os

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
    ("192.0.2.1", 80),
    ("192.0.2.1", 443),
]

def connect_send_recv(host, port, payload, timeout=1.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(payload)
        return True, s.recv(512)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}".encode()
    finally:
        s.close()

for host, port in targets:
    http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    ok, resp = connect_send_recv(host, port, http_req, 1.0)
    print(f"== HTTP {host}:{port} connected={ok} ==")
    print(repr(resp))

    key = base64.b64encode(os.urandom(16)).decode()
    ws_req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    ok, resp = connect_send_recv(host, port, ws_req, 1.0)
    print(f"== WS {host}:{port} connected={ok} ==")
    print(repr(resp))
PY

log "public_destination_policy_probes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/public_destination_policy_probes.txt" || true
import socket, base64, os

targets = [
    ("example.com", 80),
    ("example.com", 443),
    ("example.org", 80),
    ("1.1.1.1", 80),
    ("1.1.1.1", 443),
    ("8.8.8.8", 53),
    ("8.8.8.8", 443),
]

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        print(f"[resolve] {host}: {type(e).__name__}: {e}")
        return host

def probe_raw(host, port):
    ip = resolve(host)
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((ip, port))
        print(f"[+] RAW {host} ({ip}):{port} connected")
    except Exception as e:
        print(f"[-] RAW {host} ({ip}):{port} {type(e).__name__}: {e}")
    finally:
        s.close()

def probe_http(host, port):
    ip = resolve(host)
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        s.sendall(req)
        print(f"== HTTP {host} ({ip}):{port} ==")
        print(repr(s.recv(512)))
    except Exception as e:
        print(f"== HTTP {host}:{port} == {type(e).__name__}: {e}")
    finally:
        s.close()

def probe_ws(host, port):
    ip = resolve(host)
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
    s.settimeout(2)
    try:
        s.connect((ip, port))
        s.sendall(req)
        print(f"== WS {host} ({ip}):{port} ==")
        print(repr(s.recv(512)))
    except Exception as e:
        print(f"== WS {host}:{port} == {type(e).__name__}: {e}")
    finally:
        s.close()

for host, port in targets:
    probe_raw(host, port)
    probe_http(host, port)
    probe_ws(host, port)
PY

###############################################################################
# 4. Credential/env/FD exposure — redacted by default
###############################################################################

log "proc_env_secret_names_and_hashes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/proc_env_secret_names_and_hashes.txt" || true
import os, re, hashlib

pat = re.compile(r'(TOKEN|SECRET|PASSWORD|PASS|KEY|CRED|AUTH|COOKIE|SESSION)', re.I)

print("Readable /proc/*/environ entries with secret-like KEY NAMES.")
print("Values are NOT printed; value length and short SHA256 are shown.")

for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()], key=lambda x: int(x)):
    try:
        comm = open(f"/proc/{pid}/comm").read().strip()
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

log "claude_related_fd_targets_no_contents"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/claude_related_fd_targets_no_contents.txt" || true
import os

interesting_fd_keys = [
    "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
]
interesting_path_keys = [
    "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
]

for pid in sorted([p for p in os.listdir("/proc") if p.isdigit()], key=lambda x: int(x)):
    try:
        env_items = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
        comm = open(f"/proc/{pid}/comm").read().strip()
    except Exception:
        continue

    envd = {}
    for item in env_items:
        if b"=" in item:
            k, v = item.split(b"=", 1)
            envd[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")

    if not any(k in envd for k in interesting_fd_keys + interesting_path_keys):
        continue

    try:
        cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception:
        cmdline = ""

    print(f"== pid={pid} comm={comm} cmdline={cmdline} ==")

    for k in interesting_fd_keys:
        if k in envd:
            fd = envd[k]
            path = f"/proc/{pid}/fd/{fd}"
            try:
                target = os.readlink(path)
            except Exception as e:
                target = f"<unreadable: {e}>"
            print(f"{k}=fd {fd} target={target}")

    for k in interesting_path_keys:
        if k in envd:
            p = envd[k]
            try:
                st = os.stat(p)
                print(f"{k} path={p} mode={oct(st.st_mode & 0o777)} size={st.st_size} uid={st.st_uid} gid={st.st_gid}")
            except Exception as e:
                print(f"{k} path={p} stat_error={e}")

    print()
PY

###############################################################################
# 5. Block device / filesystem follow-up
###############################################################################

save_sh "block_and_mount_followup" '
echo "== block sysfs =="
for d in /sys/class/block/vd*; do
  [ -e "$d" ] || continue
  echo "## $(basename "$d")"
  for f in ro size queue/logical_block_size queue/physical_block_size queue/rotational; do
    [ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f"
  done
  [ -e "$d/serial" ] && { printf "serial="; cat "$d/serial"; }
  echo
done

echo "== block signatures =="
for dev in /dev/vda /dev/vdb /dev/vdc /dev/vdd /dev/vde; do
  [ -e "$dev" ] || continue
  echo "## $dev"
  blkid "$dev" 2>/dev/null || true
  file -s "$dev" 2>/dev/null || true
  echo
done

echo "== mounts =="
if command -v findmnt >/dev/null 2>&1; then
  findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
else
  cat /proc/mounts
fi

echo "== disk usage =="
df -hT 2>/dev/null || true
'

save_sh "tool_bundle_secret_file_and_string_scan" '
echo "== interesting filenames =="
for root in /opt/claude-code /opt/env-runner; do
  [ -d "$root" ] || continue
  echo "## $root"
  find "$root" -xdev -maxdepth 8 -type f \( \
    -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o \
    -name "*.env" -o -name "*.conf" -o -name "*.pem" -o -name "*.key" -o \
    -name "*.crt" -o -iname "*token*" -o -iname "*secret*" -o -iname "*credential*" \
  \) -print 2>/dev/null | head -500
done

echo
echo "== secret-like string matches =="
if command -v rg >/dev/null 2>&1; then
  for root in /opt/claude-code /opt/env-runner; do
    [ -d "$root" ] || continue
    echo "## $root"
    rg -n --hidden --no-messages \
      "AKIA|ASIA|xox[baprs]-|gh[pousr]_|github_pat_|sk-[A-Za-z0-9]|Bearer [A-Za-z0-9._-]+|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|CODESIGN|TOKEN|SECRET|PASSWORD|API_KEY" \
      "$root" 2>/dev/null | head -300 || true
  done
else
  echo "rg not installed; skipping content scan"
fi
'

###############################################################################
# 6. Guest device sanity checks — no writes
###############################################################################

log "guest_special_device_read_checks_no_writes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/guest_special_device_read_checks_no_writes.txt" || true
for path in ["/dev/mem", "/dev/port", "/dev/snapshot", "/dev/hwrng"]:
    print(f"== {path} ==")
    try:
        fd = open(path, "rb", buffering=0)
        print("open: ok")
        try:
            data = fd.read(1)
            print(f"read(1): ok len={len(data)}")
        except Exception as e:
            print(f"read(1): {type(e).__name__}: {e}")
        fd.close()
    except Exception as e:
        print(f"open: {type(e).__name__}: {e}")
PY

###############################################################################
# 7. Summary
###############################################################################

log "summary"
{
  echo "Output saved to: $OUT_DIR"
  echo

  echo "== virtio summary =="
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
    echo "VSOCK: PRESENT"
  else
    echo "VSOCK: ABSENT (/dev/vsock alone is not enough)"
  fi
  [ "$found_net" -eq 1 ] && echo "NET: PRESENT" || echo "NET: ABSENT"
  [ "$found_block" -eq 1 ] && echo "BLOCK: PRESENT" || echo "BLOCK: ABSENT"
  [ "$found_rng" -eq 1 ] && echo "RNG: PRESENT" || echo "RNG: ABSENT"

  echo
  echo "== route summary =="
  if [ -r /proc/net/route ]; then
    awk 'NR>1 {print}' /proc/net/route
  fi

  echo
  echo "== recommended review files =="
  echo "$OUT_DIR/network_decoded_and_listener_owners.txt"
  echo "$OUT_DIR/private_reserved_http_and_ws_probes.txt"
  echo "$OUT_DIR/public_destination_policy_probes.txt"
  echo "$OUT_DIR/proc_env_secret_names_and_hashes.txt"
  echo "$OUT_DIR/claude_related_fd_targets_no_contents.txt"
  echo "$OUT_DIR/guest_special_device_read_checks_no_writes.txt"
} | tee "$OUT_DIR/SUMMARY.txt"
