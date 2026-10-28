set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_norm.log
set logging overwrite on
set logging enabled on

python
import gdb

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

class _Norm(gdb.Breakpoint):
    def stop(self):
        try:
            key = int(gdb.parse_and_eval("$rdi"))
            arr = int(gdb.parse_and_eval("$rbp"))
            idx = int(gdb.parse_and_eval("$r12d"))
            bucket = int(gdb.parse_and_eval("$rax"))
            ar = u64(arr + 0x10) if arr else 0
            nu = u32(arr + 0x18) if arr else 0
            fl = u32(arr + 0x8) if arr else 0
            print("NORM idx=%d key=%#x arr=%#x bucket=%#x ar=%#x nu=%d fl=%#x" % (
                idx, key, arr, bucket, ar, nu, fl))
            if bucket:
                raw = bytes(gdb.selected_inferior().read_memory(bucket, 0x20))
                print("NB val=%s h=%#x key=%#x" % (
                    raw[0:16].hex(), int.from_bytes(raw[16:24], "little"),
                    int.from_bytes(raw[24:32], "little")))
            if key:
                try:
                    ln = u64(key + 0x10)
                    print("NKEY len=%#x data=%s" % (ln, bytes(
                        gdb.selected_inferior().read_memory(key + 0x18, min(ln, 16))).hex()))
                except Exception as e:
                    print("NKEYBAD %s" % e)
        except Exception as e:
            print("NERR %s" % e)
        return False

_Norm("*0x5555559b966d")

class _Find(gdb.Breakpoint):
    def stop(self):
        try:
            ht = int(gdb.parse_and_eval("$rdi"))
            key = int(gdb.parse_and_eval("$rsi"))
            print("FIND ht=%#x key=%#x" % (ht, key))
            if key:
                try:
                    ln = u64(key + 0x10)
                    print("FKEY len=%#x data=%s" % (ln, bytes(
                        gdb.selected_inferior().read_memory(key + 0x18, min(ln, 16))).hex()))
                except Exception as e:
                    print("FKEYBAD %s" % e)
        except Exception as e:
            print("FERR %s" % e)
        return False

_Find("zend_hash_find")

def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent) and ev.stop_signal == "SIGSEGV":
        print("CRASH pc=%#x rdi=%#x rsi=%#x rbp=%#x r12=%#x" % (
            int(gdb.parse_and_eval("$pc")), int(gdb.parse_and_eval("$rdi")),
            int(gdb.parse_and_eval("$rsi")), int(gdb.parse_and_eval("$rbp")),
            int(gdb.parse_and_eval("$r12"))))
        arr = int(gdb.parse_and_eval("$rbp"))
        try:
            print("CARR ar=%#x nu=%d fl=%#x" % (
                u64(arr + 0x10), u32(arr + 0x18), u32(arr + 0x8)))
            ar = u64(arr + 0x10)
            if ar:
                for i in range(6):
                    b = ar + i * 0x20
                    raw = bytes(gdb.selected_inferior().read_memory(b, 0x20))
                    print("CB%d %s" % (i, raw.hex()))
        except Exception as e:
            print("CDUMPERR %s" % e)
        try:
            gdb.execute("bt 6")
        except Exception:
            pass

gdb.events.stop.connect(on_stop)
end

run
printf "=== stopped pc=%p ===\n", $pc
bt 6
