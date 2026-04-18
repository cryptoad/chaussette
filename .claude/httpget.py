import re, socket, sys

L = open("/proc/net/fib_trie").read().splitlines()

ips = []
for i, x in enumerate(L):
    m = re.match(r"\s*\|\--\s+(\d+\.\d+\.\d+\.\d+)", x)
    if m and "/32 host LOCAL" in "\n".join(L[i:i+3]) and not m.group(1).startswith("127."):
        ips.append(m.group(1))

# dedupe
ips = list(dict.fromkeys(ips))

print(f"[+] discovered_ips={ips}")

if not ips:
    print("[!] no non-localhost IP found")
    sys.exit(1)

ip = ips[0]
print(f"[+] using_ip={ip}:15004")

req = f"GET / HTTP/1.1\r\nHost: {ip}:15004\r\nUser-Agent: debug\r\nConnection: close\r\n\r\n"
print("[+] request:")
print(req, end="")

try:
    s = socket.create_connection((ip, 15004), timeout=3)
    s.settimeout(3)
    s.sendall(req.encode())

    print("[+] response:")
    sys.stdout.flush()

    while True:
        b = s.recv(4096)
        if not b:
            break
        print(b.decode(errors="replace"), end="")

    print("\n[+] done")

except Exception as e:
    print(f"[!] error: {type(e).__name__}: {e}")
