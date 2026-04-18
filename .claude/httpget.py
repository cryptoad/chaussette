import socket

TEST_HOSTS = [
    # IPv4 loopback / local forms
    "127.0.0.1",
    "127.1",
    "127.000.000.001",
    "0.0.0.0",
    "0",
    "2130706433",      # 127.0.0.1 as dword
    "0177.0.0.1",      # octal-ish dotted form
    "017700000001",    # octal-ish dword
    "0x7f000001",      # hex dword
    "127.0.0.1:80",
    "0.0.0.0:80",

    # IPv6 local forms
    "::1",
    "[::1]",
    "::",
    "[::]",
    "::ffff:127.0.0.1",
    "[::ffff:127.0.0.1]",
    "fe80::1",
    "[fe80::1]",
    "fc00::1",
    "[fc00::1]",
    "fd00::1",
    "[fd00::1]",

    # Comparison cases
    "example.com",
    "localhost",
    "1.1.1.1",
    "[2606:4700:4700::1111]",
]

ip = "93.184.216.34"  # example.com
for host in TEST_HOSTS:
  s = socket.socket()
  s.connect((ip, 80))
  req = (
    "GET / HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Connection: close\r\n\r\n"
  )
  s.sendall(req.encode())
  print(host)
  print(s.recv(4096).decode(errors="replace"))
  s.close()
