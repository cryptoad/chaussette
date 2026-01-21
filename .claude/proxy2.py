import os, socket, base64, requests
from urllib.parse import urlparse

T=5

def pxy():
    p=urlparse(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    if not p.hostname: raise SystemExit("HTTP_PROXY not set")
    a=("Basic "+base64.b64encode(f"{p.username}:{p.password}".encode()).decode()) if p.username else None
    u=f"{p.scheme or 'http'}://{(p.username+':'+p.password+'@') if p.username else ''}{p.hostname}:{p.port or 8080}"
    return {"h":p.hostname,"p":p.port or 8080,"a":a,"u":u}

def req(u,px):
    try: r=requests.get(u,proxies=px,timeout=T); print(f"[REQ] {u} -> {r.status_code}")
    except Exception as e: print(f"[REQ] {u} -> FAIL {type(e).__name__}")

def raw(px,b,l):
    try:
        s=socket.create_connection((px["h"],px["p"]),T)
        if px["a"]: b=b.replace(b"\r\n\r\n",f"\r\nProxy-Authorization: {px['a']}\r\n\r\n".encode())
        s.sendall(b); r=s.recv(256).decode(errors="ignore").splitlines()[0]; s.close()
        print(f"[RAW] {l} -> {r}")
    except Exception as e: print(f"[RAW] {l} -> FAIL {type(e).__name__}")

def conn(px,h,p):
    raw(px,f"CONNECT {h}:{p} HTTP/1.1\r\nHost: {h}:{p}\r\n\r\n".encode(),f"CONNECT {h}:{p}")

px=pxy()
proxies={"http":px["u"],"https":px["u"]}

for u in [
    "http://localhost","http://127.0.0.1","http://[::1]",
    "http://10.0.0.1","http://192.168.0.1","http://169.254.169.254"
]: req(u,proxies)

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n","abs-form")
raw(px,b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n","origin-form")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n","host/url mismatch")
raw(px,b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: example.com\r\n\r\n","abs local / host ext")
raw(px,b"GET http://user:pass@127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n","creds in URL")
raw(px,b"GET http://%31%32%37.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n","encoded loopback")
raw(px,b"GET ftp://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n","ftp scheme")
raw(px,b"GET http://example.com/ HTTP/1.0\r\n\r\n","HTTP/1.0")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nHost: 127.0.0.1\r\n\r\n","dup Host")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost:\texample.com\r\n\r\n","tab Host")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n","XFF loopback")

conn(px,"example.com",443)
conn(px,"example.com",80)
conn(px,"127.0.0.1",80)
conn(px,"169.254.169.254",80)
conn(px,"[::1]",443)
conn(px,"%31%32%37.0.0.1",80)
conn(px,"[::ffff:127.0.0.1]",80)

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Original-Host: 127.0.0.1\r\n\r\n","X-Original-Host")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Host: 127.0.0.1\r\n\r\n","X-Host")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nForwarded: for=127.0.0.1;host=127.0.0.1\r\n\r\n","Forwarded hdr")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n","Proxy-Connection")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Host\r\n\r\n","Connection: Host")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n","Expect 100")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n","Upgrade h2c")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n","TE chunked")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-encoding: chunked\r\n\r\n","TE case")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n","TE+CL")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nReferer: http://127.0.0.1/\r\n\r\n","Referer local")
raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nOrigin: http://127.0.0.1\r\n\r\n","Origin local")

raw(px,b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n:authority: 127.0.0.1\r\n\r\n",":authority hdr")
