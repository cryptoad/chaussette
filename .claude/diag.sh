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
run_sh "cmdline" 'cat /proc/cmdline 2>/dev/null || true'
run_sh "whoami_caps" 'id; echo; grep -E "^(Cap|NoNewPrivs|Seccomp)" /proc/self/status 2>/dev/null || true'

###############################################################################
# Device inventory
###############################################################################

run_sh "dev_vsock" 'ls -l /dev/vsock 2>&1 || true'

run_sh "dev_sensitive_nodes" '
for p in /dev/mem /dev/port /dev/kmsg /dev/snapshot /dev/hwrng /dev/net/tun /dev/vda /dev/vdb /dev/vdc /dev/vsock; do
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
# Kernel config and vsock
###############################################################################

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

run_sh "proc_net_vsock" 'cat /proc/net/vsock 2>&1 || true'

run_sh "dmesg_vsock" 'dmesg 2>/dev/null | grep -iE "vsock|virtio.*socket|virtio.*vsock" | tail -100 || true'

log "python_af_vsock_probe"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/python_af_vsock_probe.txt" || true
import socket, errno

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))
print("VMADDR_CID_LOCAL:", getattr(socket, "VMADDR_CID_LOCAL", None))

if not hasattr(socket, "AF_VSOCK"):
    print("Python/socket lacks AF_VSOCK")
    raise SystemExit(0)

tests = []
tests.append(("host", getattr(socket, "VMADDR_CID_HOST", 2), 1))
for port in [1, 22, 80, 443, 2024, 2375, 5000, 8000, 8080, 8443, 9000, 50051]:
    tests.append(("host", getattr(socket, "VMADDR_CID_HOST", 2), port))

# Local loopback vsock only works if CONFIG_VSOCKETS_LOOPBACK is enabled.
if hasattr(socket, "VMADDR_CID_LOCAL"):
    tests.append(("local", socket.VMADDR_CID_LOCAL, 12345))

seen = set()
for label, cid, port in tests:
    if (cid, port) in seen:
        continue
    seen.add((cid, port))
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((cid, port))
        print(f"[+] connect {label} cid={cid} port={port}: ok")
        try:
            s.sendall(b"\n")
            data = s.recv(128)
            print(f"    recv={data!r}")
        except Exception as e:
            print(f"    read/write after connect: {type(e).__name__}: {e}")
    except OSError as e:
        print(f"[-] connect {label} cid={cid} port={port}: errno={e.errno} {e.strerror!r}")
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

run_sh "df" 'df -hT 2>/dev/null || true'

###############################################################################
# Network
###############################################################################

run_sh "network_interfaces" '
ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null || true
echo
ip route 2>/dev/null || route -n 2>/dev/null || true
echo
ip neigh 2>/dev/null || arp -an 2>/dev/null || true
echo
cat /etc/resolv.conf 2>/dev/null || true
'

run_sh "listening_sockets" '
ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true
'

log "network_quick_probes"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/network_quick_probes.txt" || true
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
            data = s.recv(160)
            print(f"    recv={data!r}")
        except Exception as e:
            print(f"    read/write: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"[-] TCP {host}:{port}: {type(e).__name__}: {e}")
    finally:
        s.close()
PY

###############################################################################
# process_api / local control-plane-ish surface
###############################################################################

run_sh "process_api_processes" '
ps auxww 2>/dev/null | grep -E "[/]process_api|environment-manager|claude" || true
'

log "process_api_probe"
python3 - <<'PY' 2>&1 | tee "$OUT_DIR/process_api_probe.txt" || true
import socket

targets = [
    ("127.0.0.1", 2024),
    ("0.0.0.0", 2024),
]

# Add primary non-loopback IPv4s.
try:
    import subprocess
    out = subprocess.check_output(["sh", "-c", "ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1"], text=True)
    for ip in out.split():
        targets.append((ip, 2024))
except Exception:
    pass

seen = set()
for host, port in targets:
    if (host, port) in seen:
        continue
    seen.add((host, port))
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        print(f"[+] connected to {host}:{port}")
        for req in [
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n",
        ]:
            try:
                s.sendall(req)
                print(f"    recv={s.recv(512)!r}")
                break
            except Exception as e:
                print(f"    send/recv: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"[-] {host}:{port}: {type(e).__name__}: {e}")
    finally:
        s.close()
PY

###############################################################################
# Environment/secrets exposure checks without dumping secret values
###############################################################################

run_sh "proc_environ_access" '
echo "Checking which process environments are readable by current user; not printing values."
for e in /proc/[0-9]*/environ; do
  pid="${e#/proc/}"
  pid="${pid%/environ}"
  if [ -r "$e" ]; then
    comm="$(cat /proc/$pid/comm 2>/dev/null || true)"
    bytes="$(wc -c < "$e" 2>/dev/null || echo 0)"
    echo "readable pid=$pid comm=$comm bytes=$bytes"
  fi
done | head -200
'

log "proc_environ_secret_key_names"
{
  echo "Scanning readable /proc/*/environ for secret-looking KEY NAMES only; values are redacted."
  for e in /proc/[0-9]*/environ; do
    [ -r "$e" ] || continue
    pid="${e#/proc/}"
    pid="${pid%/environ}"
    comm="$(cat /proc/$pid/comm 2>/dev/null || true)"
    tr '\0' '\n' < "$e" 2>/dev/null \
      | sed 's/=.*$/=<redacted>/' \
      | grep -Ei '(TOKEN|SECRET|PASSWORD|PASS|KEY|CRED|AUTH|COOKIE|SESSION)' \
      | sed "s#^#pid=$pid comm=$comm #"
  done
} 2>&1 | tee "$OUT_DIR/proc_environ_secret_key_names.txt" || true

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
    -name "*.crt" -o -name "*token*" -o -name "*secret*" -o -name "*credential*" \
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
      *) kind="unknown" ;;
    esac
    echo "  $(basename "$d"): $id $kind"
  done
  echo
  if grep -Rqs "0x0013" "$OUT_DIR/virtio_devices.txt" "$OUT_DIR/virtio_id_summary.txt" 2>/dev/null; then
    echo "VSOCK: virtio-vsock device appears present."
  else
    echo "VSOCK: no virtio-vsock device observed. /dev/vsock alone is not enough."
  fi
} | tee "$OUT_DIR/SUMMARY.txt"
