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
_SL = [0]
_SLBP = [None]

class _Strlen(gdb.Breakpoint):
    def stop(self):
        try:
            e = int(gdb.parse_and_eval("$rdi"))
            st = _q(e + 0x50)
            t = _q(e + 0x58, 4)
            ln = _q(st + 0x10) if (t & 0xff) == 6 else -1
            print("BIN2HEX st=%#x len=%d type=%d" % (st, ln, t))
        except Exception as ex:
            print("BIN2HEXERR %s" % ex)
        return False

def _resolve_strlen():
    if _SL[0]:
        return
    try:
        eg = int(gdb.parse_and_eval("&executor_globals"))
        ft = _q(eg + 456)
        zv = int(gdb.parse_and_eval("((void*(*)(void*, const char*, unsigned long))zend_hash_str_find)((void*)%#x, \"bin2hex\", 7)" % ft))
        fn = _q(zv)
        h = _q(fn + 0x58)
        _SL[0] = 1
        _SLBP[0] = _Strlen("*%#x" % h, internal=True)
        print("BIN2HEXRIG %#x" % h)
    except Exception as ex:
        print("BIN2HEXRIGERR %s" % ex)
_MARK = bytes.fromhex("0011223344556677")

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

def _find_get_ht():
    try:
        eg = int(gdb.parse_and_eval("&executor_globals"))
        blob = bytes(_inf().read_memory(eg, 0x1400))
    except Exception as e:
        print("GETERR eg %s" % e)
        return
    for off in range(0, 0x1400 - 0x40, 8):
        gc = int.from_bytes(blob[off:off+8], "little")
        ar = int.from_bytes(blob[off+0x10:off+0x18], "little")
        nu = int.from_bytes(blob[off+0x18:off+0x1c], "little")
        if (gc & 7) != 7:
            continue
        if not (0x7ff000000000 <= ar <= 0x800000000000):
            continue
        if not (0 < nu < 2000):
            continue
        try:
            buckets = bytes(_inf().read_memory(ar, nu * 0x20))
        except Exception:
            continue
        for i in range(nu):
            b = buckets[i*0x20:(i+1)*0x20]
            key = int.from_bytes(b[0x18:0x20], "little")
            if not key:
                continue
            try:
                ln = int.from_bytes(bytes(_inf().read_memory(key + 0x10, 8)), "little")
                if ln != 4:
                    continue
                if bytes(_inf().read_memory(key + 0x18, 4)) != b"_GET":
                    continue
            except Exception:
                continue
            val = int.from_bytes(b[0:8], "little")
            print("GETHT eg_off=%#x ht=%#x ar=%#x ht_off=%#x ar_off=%#x" % (
                off, val, int.from_bytes(b'\0\0\0\0\0\0\0\0', 'little'), val & 0x1FFFFF, 0))
            try:
                ght = val
                gar = _q(ght + 0x10)
                gnu = _q(ght + 0x18, 4)
                print("GETARR ht=%#x ar=%#x n=%d ht_off=%#x ar_off=%#x" % (
                    ght, gar, gnu, ght & 0x1FFFFF, gar & 0x1FFFFF))
            except Exception as e:
                print("GETARRERR %s" % e)
            return
    print("GETHT not found")

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
    try:
        pg = int(gdb.parse_and_eval("&core_globals"))
        blob = bytes(_inf().read_memory(pg, 0x270))
        for off in range(0, 0x270 - 16, 8):
            gv = int.from_bytes(blob[off:off+8], "little")
            gt = int.from_bytes(blob[off+8:off+12], "little")
            if (gt & 7) != 7 or not (0x7ff000000000 <= gv <= 0x800000000000):
                continue
            try:
                gar = _q(gv + 0x10)
                gnu = _q(gv + 0x18, 4)
            except Exception:
                continue
            if not (0x7ff000000000 <= gar <= 0x800000000000) or not (0 < gnu < 200):
                continue
            try:
                buckets = bytes(_inf().read_memory(gar, gnu * 0x20))
            except Exception:
                continue
            for i in range(gnu):
                b = buckets[i*0x20:(i+1)*0x20]
                key = int.from_bytes(b[0x18:0x20], "little")
                if not key:
                    continue
                try:
                    ln = int.from_bytes(bytes(_inf().read_memory(key + 0x10, 8)), "little")
                    if ln == 2 and bytes(_inf().read_memory(key + 0x18, 2)) == b"v0":
                        print("GETARR off=%#x ht=%#x ht_off=%#x ar=%#x ar_off=%#x n=%d" % (
                            off, gv, gv & 0x1FFFFF, gar, gar & 0x1FFFFF, gnu))
                        raise SystemExit
                except SystemExit:
                    raise
                except Exception:
                    continue
    except SystemExit:
        pass
    except Exception as e:
        print("GETARRERR2 %s" % e)
    try:
        ps = int(gdb.parse_and_eval("&ps_globals"))
        z = _q(ps + 0x168)
        ht = _q(z + 8) if z else 0
        ar = _q(ht + 0x10) if ht else 0
        nu = _q(ht + 0x18, 4) if ht else 0
        print("SESS ref=%#x ht=%#x ar=%#x n=%d off_ht=%#x off_ar=%#x" % (
            z, ht, ar, nu, ht & 0x1FFFFF if ht else 0, ar & 0x1FFFFF if ar else 0))
    except Exception as e:
        print("SESSERR %s" % e)
    ldt = _q(d + 0x10)
    print("%s level=%d d=%#x doff=%#x last=%#x fdt=%#x ldt=%#x ldt_off=%#x" % (
        tag, lvl, d, d & 0x1FFFFF, _q(d), _q(d + 8), ldt, ldt & 0x1FFFFF))
    try:
        print("  VERIFY d10=%#x d100=%#x d110=%#x" % (_q(d+0x10), _q(d+0x100), _q(d+0x110)))
    except Exception as e:
        print("  VERIFYERR %s" % e)
    if ldt:
        print("  ENT u=%d next=%#x q0=%#x q8=%#x" % (
            _q(ldt, signed=True), _q(ldt + 8), _q(ldt), _q(ldt + 8)))
        try:
            blob = bytes(_inf().read_memory(ldt - 0x60, 0xA0))
            print("  DUMP %#x: %s" % (ldt - 0x60, blob.hex()))
        except Exception as e:
            print("  DUMPERR %s" % e)
        try:
            base = ldt & ~0x1FFFFF
            blob = bytes(_inf().read_memory(base, 0x200000))
            off = blob.find(_MARK)
            print("  MARK at %#x k=%#x" % (off, ldt - (base + off) if off >= 0 else -1))
        except Exception as e:
            print("  MARKERR %s" % e)
        for delta in (0x1000, 0x2000):
            try:
                a = ldt - delta
                blob = bytes(_inf().read_memory(a, 0x30))
                print("  HDR %#x: %s" % (a, blob.hex()))
            except Exception as e:
                print("  HDRERR %s" % e)
        _scan_chunk(ldt & ~0x1FFFFF, "ldt")
    _scan_chunk(d & ~0x1FFFFF, "d")

class _TmpSess(gdb.Breakpoint):
    def stop(self):
        try:
            ps = int(gdb.parse_and_eval("&ps_globals"))
            z = _q(ps + 0x168)
            ht = _q(z + 8) if z else 0
            ar = _q(ht + 0x10) if ht else 0
            nu = _q(ht + 0x18, 4) if ht else 0
            print("TMPSESS ht=%#x ar=%#x n=%d ht_off=%#x ar_off=%#x" % (
                ht, ar, nu, ht & 0x1FFFFF, ar & 0x1FFFFF if ar else 0))
        except Exception as e:
            print("TMPSESSERR %s" % e)
        return False

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
                _resolve_strlen()
                _find_get_ht()
                _dump("INIT")
        except Exception as e:
            print("INITERR %s" % e)
        return False

_RETS = []

class _Ret(gdb.Breakpoint):
    def __init__(self, addr, tag):
        super().__init__("*%#x" % addr, internal=True, temporary=True)
        self.tag = tag
        _RETS.append(self)

    def stop(self):
        try:
            print("  ALLOCRET size=%s ptr=%#x" % (self.tag, int(gdb.parse_and_eval("$rax"))))
        except Exception as e:
            print("RETERR %s" % e)
        return False

class _Ec(gdb.Breakpoint):
    def stop(self):
        try:
            n = int(gdb.parse_and_eval("$rdi"))
            s = int(gdb.parse_and_eval("$rsi"))
            total = n * s
            if total >= 0x1000:
                ra = int(gdb.parse_and_eval("*(void**)$rsp"))
                print("ECALLOC n=%d s=%d total=%d ret=%#x" % (n, s, total, ra))
                _Ret(ra, "%d" % total)
        except Exception as e:
            print("ECERR %s" % e)
        return False

_Ec("_ecalloc", internal=True)

_TmpSess("var_tmp_var", internal=True)
_Bail("_zend_bailout", internal=True)
_Init("php_var_unserialize_init", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
