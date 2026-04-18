import re, socket, sys

L = open("/proc/net/fib_trie").read().splitlines()

ips = []
for i, x in enumerate(L):
    m = re.match(r"\s*\|\--\s+(\d+\.\d+\.\d+\.\d+)", x)
    if m and "/32 host LOCAL" in "\n".join(L[i:i+3]) and not m.group(1).startswith("127."):
        ips.append(m.group(1))

ips = list(dict.fromkeys(ips))
print(f"[+] discovered_ips={ips}", flush=True)

if not ips:
    print("[!] no non-localhost IP found", flush=True)
    sys.exit(1)

ip = ips[0]
print(f"[+] using_ip={ip}:15004", flush=True)

req = f"GET / HTTP/1.1\r\nHost: {ip}:15004\r\nUser-Agent: debug\r\nConnection: close\r\n\r\n"
print("[+] request:", flush=True)
print(req, end="", flush=True)

try:
    s = socket.create_connection((ip, 15004), timeout=3)
    s.settimeout(3)
    s.sendall(req.encode())

    print("[+] response:", flush=True)

    while True:
        b = s.recv(4096)
        if not b:
            break
        sys.stdout.write(b.decode(errors="replace"))
        sys.stdout.flush()

    print("\n[+] done", flush=True)

except Exception as e:
    print(f"[!] error: {type(e).__name__}: {e}", flush=True)
