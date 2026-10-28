set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-alloc.log
set logging overwrite on
set logging enabled on

python
import gdb

_RETS = []
_PEND = {}
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

class _Ret(gdb.Breakpoint):
    def __init__(self, addr, tag):
        super().__init__("*%#x" % addr, internal=True, temporary=True)
        self.tag = tag
        self.addr = addr
        _RETS.append(self)

    def stop(self):
        try:
            print("ALLOC %s ptr=%#x" % (self.tag, int(gdb.parse_and_eval("$rax"))))
            _PEND.pop(self.addr, None)
        except Exception as e:
            print("RETERR %s" % e)
        return False

class _Alloc(gdb.Breakpoint):
    def __init__(self, sym, mode):
        super().__init__(sym, internal=True)
        self.mode = mode

    def stop(self):
        try:
            if self.mode == "re":
                size = int(gdb.parse_and_eval("$rsi"))
            elif self.mode == "ca":
                size = int(gdb.parse_and_eval("$rdi")) * int(gdb.parse_and_eval("$rsi"))
            else:
                size = int(gdb.parse_and_eval("$rdi"))
            if size >= 0x800:
                ra = int(gdb.parse_and_eval("*(void**)$rsp"))
                if ra in _PEND:
                    return False
                _PEND[ra] = 1
                print("CALL %s size=%d ret=%#x" % (self.mode, size, ra))
                _Ret(ra, "%s:%d" % (self.mode, size))
        except Exception as e:
            print("ALCERR %s" % e)
        return False

class _Init(gdb.Breakpoint):
    def stop(self):
        try:
            lvl = _q(_bg() + 0x370, 4)
            d = _q(_bg() + 0x368)
            print("INIT level=%d d=%#x" % (lvl, d))
        except Exception as e:
            print("INITERR %s" % e)
        return False

class _Tmp(gdb.Breakpoint):
    def stop(self):
        try:
            vh = int(gdb.parse_and_eval("$rdi"))
            d = _q(vh)
            print("TMP d=%#x" % d)
        except Exception as e:
            print("TMPERR %s" % e)
        return False

_Alloc("_emalloc", "em")
_Alloc("_ecalloc", "ca")
_Alloc("_erealloc", "re")
_Init("php_var_unserialize_init", internal=True)
_Tmp("var_tmp_var", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 6
