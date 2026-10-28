set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-ps.log
set logging overwrite on
set logging enabled on

python
import gdb

_PS = None

def _inf():
    return gdb.selected_inferior()

def _q(a, size=8, signed=False):
    return int.from_bytes(bytes(_inf().read_memory(a, size)), "little", signed=signed)

def _ps():
    global _PS
    if _PS is None:
        _PS = int(gdb.parse_and_eval("&ps_globals"))
    return _PS

def _dump(tag, bt=False):
    ps = _ps()
    idp = _q(ps + 0x10)
    hv = _q(ps + 0x168)
    ht = _q(ps + 0x170, 4)
    st = _q(ps + 0x68, 4)
    print("%s PS=%#x id=%#x http_vars=%#x http_type=%d status=%d" % (
        tag, ps, idp, hv, ht, st))
    if hv and ht == 10:
        print("  ref val=%#x type=%d" % (_q(hv + 8), _q(hv + 0x10, 4)))

class _Bail(gdb.Breakpoint):
    def stop(self):
        try:
            _dump("BAIL", True)
            gdb.execute("bt 6")
        except Exception as e:
            print("BAILERR %s" % e)
        return False

class _Track(gdb.Breakpoint):
    def stop(self):
        try:
            _dump("RESET")
        except Exception as e:
            print("TRACKERR %s" % e)
        return False

_Bail("_zend_bailout", internal=True)
_Track("php_session_reset_id", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
