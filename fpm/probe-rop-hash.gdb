set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_rop.log
set logging overwrite on
set logging enabled on

python
import gdb
def u64(a):
    try: return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    except Exception: return 0
def u32(a):
    try: return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 4)), "little")
    except Exception: return 0
FAKE_AR = 0x7ffff63f0e80

class _Update(gdb.Breakpoint):
    def stop(self):
        ht = int(gdb.parse_and_eval("$rdi"))
        if u64(ht + 0x10) == FAKE_AR:
            key = int(gdb.parse_and_eval("$rsi"))
            ks = ""
            try:
                klen = u64(key + 0x10)
                if 0 < klen < 64:
                    ks = bytes(gdb.selected_inferior().read_memory(key + 0x18, klen)).decode("latin-1")
            except Exception:
                pass
            mask = u32(ht + 0x0C)
            print("UPD HT=%#x key=%r cachedH=%#x nNumUsed=%d nTableSize=%d nTableMask=%#x(%d)"
                  % (ht, ks, u64(key + 0x08), u32(ht + 0x18), u32(ht + 0x20), mask, (mask - (1<<32)) if mask >= 0x80000000 else mask))
            if ks and ks.startswith("upload_progress"):
                h = u64(key + 0x08)
                idx = (h | (mask | (0xffffffff00000000 if mask & 0x80000000 else 0)))
                print("  progress: h=%#x mask=%#x slot_idx(h|mask low32)=%d" % (h, mask, (h | mask) & 0xffffffff if False else ((h & 0xffffffff) | mask) - (1<<32)))
        return False

_Update("*0x555555bdb780")    # zend_hash_update
end

run
printf "=== stopped pc=%p ===\n", $pc
