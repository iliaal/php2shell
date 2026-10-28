#!/usr/bin/env python3
"""URL-encoded POST with many variables to trigger the max_input_vars warning
during php_hash_environment (before RINIT).

usage: fcgi_post.py <port> <count> [value]
"""
import socket
import struct
import sys

port = int(sys.argv[1])
count = int(sys.argv[2])
val = sys.argv[3] if len(sys.argv) > 3 else "v"
body = "&".join("a%d=%s" % (i, val) for i in range(count)).encode()

params = {
    b"SCRIPT_FILENAME": b"/var/www/html/index.php",
    b"REQUEST_METHOD": b"POST",
    b"CONTENT_TYPE": b"application/x-www-form-urlencoded",
    b"CONTENT_LENGTH": str(len(body)).encode(),
    b"REQUEST_URI": b"/index.php",
    b"DOCUMENT_ROOT": b"/var/www/html",
    b"SERVER_PROTOCOL": b"HTTP/1.1",
    b"GATEWAY_INTERFACE": b"CGI/1.1",
    b"SERVER_SOFTWARE": b"p2s",
    b"REMOTE_ADDR": b"127.0.0.1",
    b"SERVER_PORT": b"9000",
    b"SERVER_NAME": b"localhost",
}


def nv(name, value):
    def l(x):
        return bytes([x]) if x < 128 else (x | 0x80000000).to_bytes(4, "big")
    return l(len(name)) + l(len(value)) + name + value


def rec(t, rid, data):
    pad = (8 - len(data) % 8) % 8
    return struct.pack("!BBHHBB", 1, t, rid, len(data), pad, 0) + data + b"\0" * pad


def readn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


rid = 1
out = rec(1, rid, struct.pack("!HBxxxxx", 1, 0))
blob = b"".join(nv(k, v) for k, v in params.items())
for o in range(0, len(blob), 60000):
    out += rec(4, rid, blob[o:o+60000])
out += rec(4, rid, b"")
for o in range(0, len(body), 60000):
    out += rec(5, rid, body[o:o+60000])
out += rec(5, rid, b"")

s = socket.create_connection(("127.0.0.1", port), timeout=30)
s.sendall(out)
resp = b""
try:
    while True:
        h = readn(s, 8)
        if len(h) < 8:
            break
        _, t, _, clen, plen, _ = struct.unpack("!BBHHBB", h)
        data = b""
        while len(data) < clen:
            chunk = s.recv(clen - len(data))
            if not chunk:
                break
            data += chunk
        readn(s, plen)
        if t == 6:
            resp += data
        if t == 3:
            break
except socket.timeout:
    pass
s.close()
head, _, payload = resp.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode("latin-1") if head else "(no response)")
print("resp_body=%d" % len(payload))
