set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-split2.log
set logging overwrite on
set logging enabled on

python
import gdb

_BG = None

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

class _Init(gdb.Breakpoint):
    def stop(self):
        try:
            lvl = _level()
            d = _data()
            if not d:
                return False
            ldt = _q(d + 0x10)
            out = "INIT level=%d d=%#x doff=%#x last=%#x fdt=%#x ldt=%#x ldt_off=%#x" % (
                lvl, d, d & 0x1FFFFF, _q(d), _q(d + 8), ldt, ldt & 0x1FFFFF)
            if ldt:
                out += " ent_u=%d ent_next=%#x" % (_q(ldt, signed=True), _q(ldt + 8))
            print(out)
        except Exception as e:
            print("INITERR %s" % e)
        return False

class _Tmp(gdb.Breakpoint):
    def stop(self):
        try:
            if _level() != 2:
                return False
            vh = int(gdb.parse_and_eval("$rdi"))
            data = _q(vh)
            d = _q(data)
            blk = _q(d + 0x10)
            if not blk:
                print("TMP blk=0")
                return False
            u = _q(blk, signed=True)
            tgt = (blk + 0x10 + 16 * u) & 0xFFFFFFFFFFFFFFFF
            print("TMP d=%#x blk=%#x u=%d target=%#x" % (d, blk, u, tgt))
        except Exception as e:
            print("TMPERR %s" % e)
        return False

_Init("php_var_unserialize_init", internal=True)
_Tmp("var_tmp_var", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
