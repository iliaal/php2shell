set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_data.log
set logging overwrite on
set logging enabled on

python
import gdb
def u64(a):
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")

class _UV(gdb.Breakpoint):
    def stop(self):
        try:
            rval = int(gdb.parse_and_eval("$rdi"))
            rsi = int(gdb.parse_and_eval("$rsi"))
            rdx = int(gdb.parse_and_eval("$rdx"))
            rcx = int(gdb.parse_and_eval("$rcx"))
            p = u64(rsi)
            vh = u64(rcx) if rcx else 0
            try:
                data = bytes(gdb.selected_inferior().read_memory(p, 16)).hex()
            except Exception:
                data = "unreadable"
            print("UV rval=%#x p=%#x max=%#x varhashx=%#x d=%#x data=%s" % (
                rval, p, rdx, rcx, vh, data))
        except Exception as e:
            print("UVERR %s" % e)
        return False

_uv = _UV("php_var_unserialize")
end

run
printf "=== inferior stopped pc=%p ===\n", $pc
bt 12
x/6i $pc
info registers rax rbx rcx rdx rsi rdi rbp rsp
