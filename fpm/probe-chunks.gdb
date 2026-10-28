set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-chunks.log
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

def _chunk_list():
    d = _data()
    if not d:
        return
    ldt = _q(d + 0x10)
    cb = d & ~0x1FFFFF
    lb = ldt & ~0x1FFFFF if ldt else 0
    try:
        heap = _q(cb)  # chunk->heap
    except Exception as e:
        print("CHUNK heap read failed: %s" % e)
        return
    # find main chunk: chunk->heap points inside itself
    cur = cb
    main = 0
    for _ in range(64):
        h = _q(cur)
        if cur <= h < cur + 0x200000:
            main = cur
            break
        cur = _q(cur + 8)  # chunk->next
        if cur == cb:
            break
    if not main:
        main = cb
    print("CHUNKS main=%#x heap=%#x d_chunk=%#x ldt_chunk=%#x" % (main, heap, cb, lb))
    cur = main
    i = 0
    while i < 64:
        try:
            heap_p = _q(cur)
            nxt = _q(cur + 8)
            fp = _q(cur + 24, 4)
            ft = _q(cur + 28, 4)
        except Exception as e:
            print("  chunk[%d] read failed %s" % (i, e))
            break
        mark = ""
        if cur == cb:
            mark += " D"
        if lb and cur == lb:
            mark += " LDT"
        print("  chunk[%d]=%#x heap=%#x next=%#x free=%d tail=%d%s" % (
            i, cur, heap_p, nxt, fp, ft, mark))
        cur = nxt
        i += 1
        if cur == main:
            break

def _runs(base, page_hint=0):
    blob = bytes(_inf().read_memory(base + 0x40, 0x3c0))
    for off in range(0, 0x200, 8):
        q = int.from_bytes(blob[off:off+8], "little")
        print("  H%#x=%#018x pc=%d" % (0x40 + off, q, bin(q).count("1")))
    fm = base + 0x7C0
    bits = int.from_bytes(bytes(_inf().read_memory(fm, 64)), "little")
    runs = []
    p = 0
    while p < 512:
        if (bits >> p) & 1:
            p += 1
            continue
        s = p
        while p < 512 and not ((bits >> p) & 1):
            p += 1
        runs.append((s, p - s))
    shown = [r for r in runs if r[1] >= 2]
    print("  runs>=2: %s" % ", ".join("%#x+%d" % r for r in shown[:20]))
    for s, l in runs:
        if s <= page_hint < s + l:
            print("  hint page %#x in run %#x+%d" % (page_hint, s, l))
            break

class _Ec(gdb.Breakpoint):
    def stop(self):
        try:
            n = int(gdb.parse_and_eval("$rdi"))
            s = int(gdb.parse_and_eval("$rsi"))
            if n * s == 5121 and _level() >= 1 and _data() != 0:
                print("ECALLOC 5121 level=%d d=%#x" % (_level(), _data()))
                _chunk_list()
                d = _data()
                ldt = _q(d + 0x10)
                _runs(d & ~0x1FFFFF, (ldt & 0x1FFFFF) // 0x1000)
        except Exception as e:
            print("ECERR %s" % e)
        return False

_Ec("_ecalloc", internal=True)
end

run
printf "=== inferior stopped ===\n"
bt 8
