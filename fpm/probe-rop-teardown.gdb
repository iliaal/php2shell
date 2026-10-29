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
PIVOT = 0x555555abdd0e           # base 0x555555400000 + 0x6bdd0e (ASLR off under gdb)
DESTROY = 0x555555bddaf0         # zend_hash_destroy, offset 0x7ddaf0

def u64(a):
    try:
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    except Exception:
        return 0
def u32(a):
    try:
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 4)), "little")
    except Exception:
        return 0

# Every zend_hash_destroy whose pDestructor is the pivot gadget: dump the fake
# session table's header and buckets so we can see whether bucket 0 (the pivot
# buffer, val+0 == 0x0000037F00001F80) survived or was clobbered by the
# upload-progress append, and what nNumUsed is.
class _Destroy(gdb.Breakpoint):
    def stop(self):
        ht = int(gdb.parse_and_eval("$rdi"))
        if u64(ht + 0x30) == PIVOT:
            ar = u64(ht + 0x10); nu = u32(ht + 0x18); ts = u32(ht + 0x20)
            print("DESTROY HT=%#x arData=%#x nNumUsed=%d nTableSize=%d pDtor=PIVOT" % (ht, ar, nu, ts))
            for i in range(0, max(nu, 4)):
                b = ar + i * 0x20
                print("   b%d @%#x val=%#018x type=%#x h=%#x key=%#x"
                      % (i, b, u64(b), u32(b + 0x08), u64(b + 0x10), u64(b + 0x18)))
        return False

class _Pivot(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi"))
        print("PIVOT rdi=%#x val0=%#018x" % (rdi, u64(rdi)))
        gdb.execute("set follow-fork-mode parent")
        return False

_Destroy("*0x555555bddaf0")
_Pivot("*0x555555abdd0e")
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 8
