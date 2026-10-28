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
    try:
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    except Exception:
        return 0

# jump_fcontext stack pivot: base 0x555555400000 + 0x6bdd0e (ASLR off under gdb)
class _Pivot(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            print("PIVOT rdi=%#x rsp=%#x" % (rdi, int(gdb.parse_and_eval("$rsp"))))
            for o in (0x00, 0x08, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68):
                print("  P%02x=%#x" % (o, u64(rdi + o)))
            gdb.execute("set follow-fork-mode parent")
        except Exception as e:
            print("PIVOTERR %s" % e)
        return False

# popen@plt: base + 0x202e50
class _Popen(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            rsi = int(gdb.parse_and_eval("$rsi"))
            cmd = ""
            try:
                cmd = bytes(gdb.selected_inferior().read_memory(rdi, 48)).split(b"\0")[0].decode("latin-1")
            except Exception:
                pass
            mode = ""
            try:
                mode = bytes(gdb.selected_inferior().read_memory(rsi, 4)).split(b"\0")[0].decode("latin-1")
            except Exception:
                pass
            print("POPEN rdi=%#x rsi=%#x cmd=%r mode=%r" % (rdi, rsi, cmd, mode))
        except Exception as e:
            print("POPENERR %s" % e)
        return False

_Pivot("*0x555555abdd0e")
_Popen("*0x555555602e50")
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 8
