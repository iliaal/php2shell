set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_noframe.log
set logging overwrite on
set logging enabled on

python
import gdb

def u64(a):
    try:
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    except Exception:
        return 0

class _Zif(gdb.Breakpoint):
    def stop(self):
        try:
            v = int(gdb.parse_and_eval("$rdi"))
            print("ZIFENTER rdi=%#x rsi=%#x" % (v, int(gdb.parse_and_eval("$rsi"))))
            for o in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x2C, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60):
                print("F%02x=%#x" % (o, u64(v + o)))
            gdb.execute("set follow-fork-mode parent")
        except Exception as e:
            print("ZERR %s" % e)
        return False

_Zif("*0x555555a0e3a0")
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 6
