#!/usr/bin/env python3
"""Pin FPM workers with incomplete FastCGI POST bodies.

Usage: pin_fcgi.py <port> <count> [script]

Each connection starts a request with a large CONTENT_LENGTH but sends only a
fragment of the body, so the worker blocks in the body read. The sockets stay
open until the process is killed. After sending the pins, the script queries
pm.status_path and waits until only the expected number of workers are idle.
"""
import os
import socket
import struct
import sys
import time

port = int(sys.argv[1])
count = int(sys.argv[2]) if len(sys.argv) > 2 else 3
script = sys.argv[3] if len(sys.argv) > 3 else "/var/www/html/index.php"
max_children = int(os.environ.get("MAX_CHILDREN", "4"))
status_path = os.environ.get("STATUS_PATH", "/status")
status_check = os.environ.get("STATUS_CHECK", "0") == "1"


def nv(name, value):
    def l(x):
        return bytes([x]) if x < 128 else (x | 0x80000000).to_bytes(4, "big")
    return l(len(name)) + l(len(value)) + name + value


def rec(t, rid, data):
    pad = (8 - len(data) % 8) % 8
    return struct.pack("!BBHHBB", 1, t, rid, len(data), pad, 0) + data + b"\0" * pad


def readn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def fcgi_get(params, timeout=5):
    out = rec(1, 1, struct.pack("!HBxxxxx", 1, 0))
    pblob = b"".join(nv(k, v) for k, v in params.items())
    out += rec(4, 1, pblob) + rec(4, 1, b"") + rec(5, 1, b"")
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(out)
    body = b""
    try:
        while True:
            h = readn(s, 8)
            if len(h) < 8:
                break
            _, t, _, clen, plen, _ = struct.unpack("!BBHHBB", h)
            data = readn(s, clen)
            readn(s, plen)
            if t == 6:
                body += data
            if t == 3:
                break
    except socket.timeout:
        pass
    s.close()
    return body


def status():
    params = {
        b"SCRIPT_NAME": status_path.encode(),
        b"SCRIPT_FILENAME": status_path.encode(),
        b"REQUEST_METHOD": b"GET",
        b"QUERY_STRING": b"plain",
        b"REQUEST_URI": status_path.encode(),
        b"DOCUMENT_ROOT": b"/var/www/html",
        b"SERVER_PROTOCOL": b"HTTP/1.1",
        b"GATEWAY_INTERFACE": b"CGI/1.1",
        b"REMOTE_ADDR": b"127.0.0.1",
        b"SERVER_PORT": b"9000",
        b"SERVER_NAME": b"localhost",
    }
    body = fcgi_get(params)
    text = body.decode("latin-1", "replace")
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


pblob_params = {
    b"SCRIPT_FILENAME": script.encode(),
    b"REQUEST_METHOD": b"POST",
    b"CONTENT_TYPE": b"multipart/form-data; boundary=----pin",
    b"CONTENT_LENGTH": b"1000000",
    b"REQUEST_URI": b"/index.php",
    b"DOCUMENT_ROOT": b"/var/www/html",
    b"SERVER_PROTOCOL": b"HTTP/1.1",
    b"GATEWAY_INTERFACE": b"CGI/1.1",
    b"REMOTE_ADDR": b"127.0.0.1",
    b"SERVER_PORT": b"9000",
    b"SERVER_NAME": b"localhost",
}
pblob = b"".join(nv(k, v) for k, v in pblob_params.items())
socks = []
for i in range(count):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    out = rec(1, 1, struct.pack("!HBxxxxx", 1, 0))
    out += rec(4, 1, pblob) + rec(4, 1, b"")
    # declare a 65528-byte STDIN record but send only the prefix; the worker
    # blocks reading the rest of the record payload
    out += struct.pack("!BBHHBB", 1, 5, 1, 0xFFF8, 0, 0)
    out += b"------pin\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n" + b"A" * 64
    s.sendall(out)
    socks.append(s)
print("pinned %d FPM workers on port %d" % (count, port), flush=True)

want_idle = max(0, max_children - count - 1)
deadline = time.time() + 15
ready = False
last = {}
while status_check and time.time() < deadline:
    try:
        last = status()
        idle = int(last.get("idle processes", "99"))
        active = int(last.get("active processes", "-1"))
        if idle <= want_idle:
            print("ready active=%d idle=%d" % (active, idle), flush=True)
            ready = True
            break
    except Exception as e:
        last = {"error": str(e)}
    time.sleep(0.3)
if not status_check:
    print("ready (status check disabled)", flush=True)
elif not ready:
    print("ready-timeout active=%s idle=%s err=%s" % (
        last.get("active processes", "?"), last.get("idle processes", "?"),
        last.get("error", "")), flush=True)

try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    pass
