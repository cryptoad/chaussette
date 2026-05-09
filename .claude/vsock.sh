#!/bin/sh
set -eu

echo "== uname =="
uname -a

echo
echo "== /dev/vsock =="
ls -l /dev/vsock 2>&1 || true

echo
echo "== virtio devices =="
for d in /sys/bus/virtio/devices/*; do
  [ -e "$d/device" ] || continue
  printf '%s: device=' "$d"
  cat "$d/device"
  [ -e "$d/vendor" ] && { printf '  vendor='; cat "$d/vendor"; }
  [ -e "$d/modalias" ] && { printf '  modalias='; cat "$d/modalias"; }
done

echo
echo "== vsock modules =="
lsmod 2>/dev/null | grep -i vsock || true
find /sys/module -maxdepth 1 -iname '*vsock*' -print 2>/dev/null || true

echo
echo "== kernel config =="
zcat /proc/config.gz 2>/dev/null | egrep 'CONFIG_(VSOCKETS|VIRTIO_VSOCKETS|VHOST_VSOCK|VMWARE_VMCI_VSOCKETS)' || true
grep -E 'CONFIG_(VSOCKETS|VIRTIO_VSOCKETS|VHOST_VSOCK|VMWARE_VMCI_VSOCKETS)' /boot/config-$(uname -r) 2>/dev/null || true

echo
echo "== proc net vsock =="
cat /proc/net/vsock 2>&1 || true

echo
echo "== python AF_VSOCK probe =="
python3 - <<'PY'
import socket, errno, os

print("AF_VSOCK:", getattr(socket, "AF_VSOCK", None))
print("VMADDR_CID_HOST:", getattr(socket, "VMADDR_CID_HOST", None))
try:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    print("socket(): ok")
    try:
        s.settimeout(1)
        s.connect((socket.VMADDR_CID_HOST, 1))
        print("connect host:1: ok")
    except OSError as e:
        print(f"connect host:1: errno={e.errno} {e.strerror!r}")
    finally:
        s.close()
except OSError as e:
    print(f"socket(): errno={e.errno} {e.strerror!r}")
PY

echo
echo "== dmesg vsock lines =="
dmesg 2>/dev/null | grep -iE 'vsock|virtio.*socket|virtio.*vsock' | tail -100 || true
