import re, socket, sys
L=open("/proc/net/fib_trie").read().splitlines()
ips=[]
for i,x in enumerate(L):
    m=re.match(r"\s*\|\--\s+(\d+\.\d+\.\d+\.\d+)", x)
    if m and "/32 host LOCAL" in "\n".join(L[i:i+3]) and not m.group(1).startswith("127."):
        ips.append(m.group(1))
ips=list(dict.fromkeys(ips))
if not ips: raise SystemExit("no non-localhost IP found")
ip=ips[0]
print(f"[+] {ip}:15004")
req=f"GET / HTTP/1.1\r\nHost: {ip}:15004\r\nConnection: close\r\n\r\n"
print(req, end="")
try:
    s=socket.create_connection((ip,15004),timeout=3); s.sendall(req.encode())
    while 1:
        b=s.recv(4096)
        if not b: break
        sys.stdout.buffer.write(b)
except Exception as e:
    print(f"\n[!] {type(e).__name__}: {e}", file=sys.stdout)
