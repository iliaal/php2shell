set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-bt.log
set logging overwrite on
set logging enabled on

python
import gdb

_C = [0]
_BT = [0]

def _inf():
    return gdb.selected_inferior()

def _q(a, size=8):
    return int.from_bytes(bytes(_inf().read_memory(a, size)), "little")

def _zstr(p):
    try:
        ln = _q(p + 0x10)
        if ln > 256:
            ln = 256
        return bytes(_inf().read_memory(p + 0x18, ln)).decode("latin-1", "replace")
    except Exception:
        return "?"

class _Ini(gdb.Breakpoint):
    def stop(self):
        try:
            print("INI buf=%#x text=%r" % (
                int(gdb.parse_and_eval("$rdi")),
                bytes(_inf().read_memory(int(gdb.parse_and_eval("$rdi")), 48)).decode("latin-1", "replace")))
        except Exception as e:
            print("INIERR %s" % e)
        return False

class _Fetch(gdb.Breakpoint):
    def stop(self):
        print("FETCH out=%#x" % int(gdb.parse_and_eval("$rdi")))
        return False

class _Trace(gdb.Breakpoint):
    def stop(self):
        _C[0] += 1
        _BT[0] = int(gdb.parse_and_eval("$rdi"))
        print("TRACE n=%d ht=%#x" % (_C[0], _BT[0]))
        return False

class _Err(gdb.Breakpoint):
    def stop(self):
        try:
            t = int(gdb.parse_and_eval("$rdi")) & 0xffffffff
            msg = _zstr(int(gdb.parse_and_eval("$rcx")))
            print("ERRAT type=%d msg=%s" % (t, msg))
        except Exception as e:
            print("ERRERR %s" % e)
        return False

class _AD(gdb.Breakpoint):
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            if ht == _BT[0]:
                print("ADESTROY_STALE ht=%#x" % ht)
                gdb.execute("bt 12")
            else:
                print("ADESTROY ht=%#x" % ht)
        except Exception as e:
            print("ADERR %s" % e)
        return False

_Ini("zend_parse_ini_string", internal=True)
_Fetch("zend_fetch_debug_backtrace", internal=True)
_Trace("zend_trace_to_string", internal=True)
_Err("zend_error_zstr_at", internal=True)
_AD("zend_array_destroy", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
