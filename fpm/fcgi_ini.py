#!/usr/bin/env python3
"""Minimal FastCGI GET with PHP_VALUE/PHP_ADMIN_VALUE params.

usage: fcgi_ini.py <port> <php_value>
"""
import socket
import struct
import sys

port = int(sys.argv[1])
ini = sys.argv[2]

params = {
    b"SCRIPT_FILENAME": b"/var/www/html/index.php",
    b"REQUEST_METHOD": b"GET",
    b"REQUEST_URI": b"/index.php",
    b"DOCUMENT_ROOT": b"/var/www/html",
    b"SERVER_PROTOCOL": b"HTTP/1.1",
    b"GATEWAY_INTERFACE": b"CGI/1.1",
    b"SERVER_SOFTWARE": b"p2s",
    b"REMOTE_ADDR": b"127.0.0.1",
    b"SERVER_PORT": b"9000",
    b"SERVER_NAME": b"localhost",
    b"PHP_VALUE": ini.encode(),
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
out += rec(5, rid, b"")
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
