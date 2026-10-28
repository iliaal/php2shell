set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-split3.log
set logging overwrite on
set logging enabled on

python
import gdb

_BG = None
_PRE = b"\xfe\xff\xff\xff\xff\xff\xff\xff"

def _inf():
    return gdb.selected_inferior()

def _q(a, size=8, signed=False):
    return int.from_bytes(bytes(_inf().read_memory(a, size)), "little", signed=signed)

def _bg():
    global _BG
    if _BG is None:
        _BG = int(gdb.parse_and_eval("&basic_globals"))
    return _BG

def _level():
    return _q(_bg() + 0x370, 4)

def _data():
    return _q(_bg() + 0x368, 8)

def _scan_chunk(base, what):
    try:
        blob = bytes(_inf().read_memory(base, 0x200000))
    except Exception as e:
        return
    off = blob.find(_PRE)
    if off != -1:
        print("  %s chunk=%#x PRE at +%#x" % (what, base, off))

def _dump(tag):
    lvl = _level()
    d = _data()
    if not d:
        print("%s level=%d d=0" % (tag, lvl))
        return
    ldt = _q(d + 0x10)
    print("%s level=%d d=%#x doff=%#x last=%#x fdt=%#x ldt=%#x ldt_off=%#x" % (
        tag, lvl, d, d & 0x1FFFFF, _q(d), _q(d + 8), ldt, ldt & 0x1FFFFF))
    if ldt:
        print("  ENT u=%d next=%#x q0=%#x q8=%#x" % (
            _q(ldt, signed=True), _q(ldt + 8), _q(ldt), _q(ldt + 8)))
        _scan_chunk(ldt & ~0x1FFFFF, "ldt")
    _scan_chunk(d & ~0x1FFFFF, "d")

class _Bail(gdb.Breakpoint):
    def stop(self):
        try:
            _dump("BAIL")
        except Exception as e:
            print("BAILERR %s" % e)
        return False

class _Init(gdb.Breakpoint):
    def stop(self):
        try:
            if _level() >= 1:
                _dump("INIT")
        except Exception as e:
            print("INITERR %s" % e)
        return False

_Bail("_zend_bailout", internal=True)
_Init("php_var_unserialize_init", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
