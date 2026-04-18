import socket

ip = "93.184.216.34"  # example.com
s = socket.socket()
s.connect((ip, 80))

req = (
    "GET / HTTP/1.1\r\n"
    "Host: [::1]\r\n"
    "Connection: close\r\n\r\n"
)

s.sendall(req.encode())
print(s.recv(4096).decode(errors="replace"))
s.close()
