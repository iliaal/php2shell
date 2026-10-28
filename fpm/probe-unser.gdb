set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-probe.log
set logging overwrite on
set logging enabled on
python
import gdb

def php_mm_dump(tag):
    try:
        heap = int(gdb.parse_and_eval("(unsigned long)zend_mm_get_heap()"))
        inf = gdb.selected_inferior()
        def rd(addr, n):
            return bytes(inf.read_memory(addr, n))
        def q(addr):
            return int.from_bytes(rd(addr, 8), "little")
        main = q(heap + 0x140)
        cached = q(heap + 0x148)
        print("%s HEAP=%#x MAIN=%#x CACHED=%#x" % (tag, heap, main, cached))
        if main:
            c = q(main + 8)
            n = 0
            while c and c != main and n < 40:
                try:
                    fp = int.from_bytes(rd(c + 0x18, 4), "little")
                except Exception:
                    fp = -1
                print("  %s LIST[%d]=%#x free=%d" % (tag, n, c, fp))
                c = q(c + 8)
                n += 1
        c = cached
        n = 0
        while c and n < 40:
            try:
                fp = int.from_bytes(rd(c + 0x18, 4), "little")
            except Exception:
                fp = -1
            print("  %s CACHE[%d]=%#x free=%d" % (tag, n, c, fp))
            c = q(c + 8)
            n += 1
    except Exception as e:
        print("%s MMDBG error %s" % (tag, e))

def php_scan_field():
    try:
        heap = int(gdb.parse_and_eval("(unsigned long)zend_mm_get_heap()"))
        inf = gdb.selected_inferior()
        def q(a):
            return int.from_bytes(bytes(inf.read_memory(a, 8)), "little")
        main = q(heap + 0x140)
        cached = q(heap + 0x148)
        chunks = [main]
        c = cached
        n = 0
        while c and n < 20:
            chunks.append(c)
            c = q(c + 8)
            n += 1
        pat = b"L" * 64
        for c in chunks:
            try:
                data = bytes(inf.read_memory(c, 0x200000))
            except Exception:
                continue
            i = data.find(pat)
            while i != -1:
                print("FIELD chunk=%#x off=%#x addr=%#x" % (c, i, c + i))
                i = data.find(pat, i + 1)
    except Exception as e:
        print("SCAN err %s" % e)
end
break php_request_startup
commands
silent
python php_mm_dump("REQ")
continue
end
break php_request_shutdown
commands
silent
python php_mm_dump("SHUT")
continue
end
break php_var_unserialize_init
commands
silent
printf "INIT lock=%u level=%u data=%p\n", *(unsigned int*)((char*)&basic_globals+0x350), *(unsigned int*)((char*)&basic_globals+0x370), *(void**)((char*)&basic_globals+0x368)
if *(unsigned int*)((char*)&basic_globals+0x370) != 0
set $d = *(void**)((char*)&basic_globals+0x368)
x/4gx (char*)$d
set $mm = (unsigned long)zend_mm_get_heap()
set $main = *(unsigned long*)($mm+0x140)
printf "FMAP %#lx %#lx %#lx %#lx %#lx %#lx %#lx %#lx\n", *(unsigned long*)($main+0x28), *(unsigned long*)($main+0x30), *(unsigned long*)($main+0x38), *(unsigned long*)($main+0x40), *(unsigned long*)($main+0x48), *(unsigned long*)($main+0x50), *(unsigned long*)($main+0x58), *(unsigned long*)($main+0x60)
set $last = *(void**)$d
python
try:
    inf = gdb.selected_inferior()
    last = int(gdb.parse_and_eval("$last"))
    b = inf.read_memory(last, 16)
    print("LAST_MAP used=%d next=%d" % (int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:16], 'little')))
except Exception:
    print("LAST_UNMAP")
end
set $dt = *(void**)((char*)$d+0x10)
if (unsigned long)$dt > 0x1000000 && (unsigned long)$dt < 0x800000000000
printf "DTOR block %p\n", $dt
python
try:
    inf = gdb.selected_inferior()
    dt = int(gdb.parse_and_eval("$dt"))
    b = inf.read_memory(dt, 8)
    print("DT_MAP used=%d" % int.from_bytes(b[:8], 'little'))
except Exception:
    print("DT_UNMAP")
end
end
python php_scan_field()
end
bt 3
continue
end
break php_var_unserialize_destroy
commands
silent
set $d = (char*)$rdi
set $dt = *(void**)((char*)$d+0x10)
printf "DESTROY arg=%p level=%u data=%p dtor=%p\n", $d, *(unsigned int*)((char*)&basic_globals+0x370), *(void**)((char*)&basic_globals+0x368), $dt
continue
end
break _zend_bailout
commands
silent
set $d = *(void**)((char*)&basic_globals+0x368)
printf "BAILOUT level=%u data=%p", *(unsigned int*)((char*)&basic_globals+0x370), $d
if $d != 0
set $dt = *(void**)((char*)$d+0x10)
set $last = *(void**)$d
printf " dchunk=%#lx doff=%#lx last=%p", ((unsigned long)$d & ~0x1fffff), ((unsigned long)$d & 0x1fffff), $last
if (unsigned long)$last > 0x1000000 && (unsigned long)$last < 0x800000000000
printf " lused=%ld lnext=%p", *(long*)$last, *(void**)((char*)$last+8)
end
if (unsigned long)$dt > 0x1000000 && (unsigned long)$dt < 0x800000000000
printf " dtor=%p used=%ld dtchunk=%#lx dtoff=%#lx", $dt, *(long*)$dt, ((unsigned long)$dt & ~0x1fffff), ((unsigned long)$dt & 0x1fffff)
end
end
printf "\n"
python php_mm_dump("BAIL")
bt 4
continue
end
break munmap
commands
silent
if $rsi == 0x200000
printf "MUNMAP %p\n", $rdi
end
continue
end
break zend_mm_safe_error
commands
silent
printf "OOM level=%u data=%p\n", *(unsigned int*)((char*)&basic_globals+0x370), *(void**)((char*)&basic_globals+0x368)
bt 5
continue
end
run
printf "=== inferior stopped ===\n"
bt 8
info registers rip rdi rsi
