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
PIVOT = 0x555555abdd0e

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

FAKE_AR = 0x7ffff63f0e80

class _Destroy(gdb.Breakpoint):
    def stop(self):
        ht = int(gdb.parse_and_eval("$rdi"))
        if u64(ht + 0x30) == PIVOT:
            ar = u64(ht + 0x10)
            nu = u32(ht + 0x18)
            print("DESTROY HT=%#x arData=%#x nNumUsed=%d nTableSize=%d pDtor=PIVOT"
                  % (ht, ar, nu, u32(ht + 0x20)))
            for i in range(0, max(nu, 8)):
                b = ar + i * 0x20
                t = u32(b + 0x08) & 0xff
                print("   b%d @%#x val=%#x type=%#x(T%d) h=%#x key=%#x"
                      % (i, b, u64(b), u32(b + 0x08), t, u64(b + 0x10), u64(b + 0x18)))
        return False

class _Pivot(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi"))
        print("PIVOT rdi=%#x (bucket idx from FAKE_AR = %d)" % (rdi, (rdi - FAKE_AR)//0x20))
        return False

_Destroy("*0x555555bddaf0")   # zend_hash_destroy
_Pivot("*0x555555abdd0e")
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 6
