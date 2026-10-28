# Porting the php2shell chain across builds and architectures

The chain depends on three kinds of build-specific values: libphp/php-fpm
**symbol offsets** (`zval_ptr_dtor`, `zif_system`), **struct-field offsets**
inside globals (`BG(unserialize)`, `EG(function_table)`), and **heap-layout
values** (the reclaimed `d` address under `setarch -R`, the fill's `D`-relative
pointers, and the `main`-relative spray offsets). Symbol and heap offsets change
with every build; struct offsets change with the architecture. This guide
records how the x86-64 chain was ported to aarch64 and how to re-derive the
values when they drift.

Worked example: x86-64 Debian trixie NTS -> aarch64 (52-bit VA, Oracle kernel),
official `php:8.5.11-apache` / `php:8.5.11-fpm`, 2026-10-28.

## What ports cleanly and what does not

| Path | Address source | Portability |
|---|---|---|
| A, B, B2 (mod_php) | B1 runtime pointer leak | high: the leak supplies the ASLR bases; only the offset constants in `parse_leak*.php` and `stage3*.php` change |
| C (FPM native) | app-visible leak, dynamic fill | high: `run_native.sh` rebuilds the fill for the leaked `d` |
| D (FPM type-confusion) | fixed addresses baked in `sess_T` + `fillU.bin` under `setarch -R` | low: both the `d` reclaim and the fill groom are build-specific; re-derive per build (see below) |
| E (path1) | gdb pivot writes runtime addresses | gdb-only; the pivot reads addresses live |

Prefer the leak-based paths (A/B/C) when porting: they absorb ASLR and only need
the offset constants re-derived. The fixed-address paths (D) need the heap groom
re-tuned, which is the hardest step.

## The re-derivation toolkit

All of it runs from a gdb probe inside the target container. The binary is
stripped of static symbols but exports data globals (`basic_globals`,
`executor_globals`, `ps_globals`) and ~4000 `T` functions, so breakpoints bind
by name and globals resolve with `&basic_globals`.

Boot the probe with `setarch -R ... gdb -q -batch -x probe.gdb --args <sapi> -F`.
For FPM, set `follow-fork-mode child` and `detach-on-fork off` so the master
cannot reap the worker while it is stopped (otherwise the OOM request dies with
`signal 9`). End the script with `run`.

### 1. libphp / PIE base

`base = runtime(&basic_globals) - <file offset of basic_globals>`. Get the file
offset with `nm -D <binary> | grep ' B basic_globals'`. Under `setarch -R` the
base is fixed; with ASLR it is read per run.

### 2. zval_ptr_dtor and zif_system offsets

`zval_ptr_dtor` is exported: `nm -D libphp.so | grep zval_ptr_dtor` gives the
offset directly. `zif_system` is not exported; resolve it through the function
table with a linear scan (gdb inferior calls are unreliable under `-batch` +
follow-fork, so walk memory instead):

1. Scan `EG+0x00 .. EG+0x900` in 8-byte steps for a pointer to a HashTable
   (`*(p+0x18)` nNumUsed in 100..30000, `*(p+0x10)` arData a valid pointer).
   The function table is the one whose buckets contain `system`.
2. Walk its buckets (stride `0x20`, key at `+0x18`, zend_string len at key+0x10,
   chars at key+0x18). For the matching bucket, the `zend_function*` is the
   bucket value (`*(bucket+0x00)`) and the handler is at `fn+0x58`.
3. `zif_system_offset = handler - base`.

### 3. BG(unserialize) and EG(function_table) struct offsets

These shift with the architecture, not the build. Find them empirically: break
at `php_var_unserialize` during a small (non-OOMing) session decode and dump
`basic_globals+0x340 .. +0x3C0`; the heap pointer followed by a small integer is
`data` then `level`. Scan `EG` for the function-table pointer as in step 2.

### 4. The reclaimed d (fixed-address paths)

Break at `php_var_unserialize` during the A groom and read `BG(unserialize).data`
at the offset from step 3. Under `setarch -R` this is the stale `d` the exploit
reuses. Note: gdb can perturb the heap, so a gdb-derived `d` may differ from the
no-gdb run; confirm against a no-gdb attempt.

### 5. Rebasing the fill

`fillU.bin` holds `D`-relative pointers. Rebase every 8-byte qword in
`[D_old, D_old+0x10000)` to `D_new + (q - D_old)`. `sess_T` values are
`a=D+0x38, b=D+0x908, c=D+0xE00, d=256, e=zif_system`.

## x86-64 -> aarch64 deltas (this port)

| Value | x86-64 | aarch64 |
|---|---|---|
| user pointer range | `0x7000_0000_0000 .. 0x8000_0000_0000` | `0xf00_0000_0000 .. 0x1000_0000_0000` (52-bit VA) |
| PIE base (`setarch -R`) | `0x5555_5555_4000` | `0xaaaa_aaaa_0000` |
| apache `zval_ptr_dtor` off | `libphp+0x7b47a0` (low12 `0x7a0`) | `libphp+0x761b80` (low12 `0xb80`) |
| apache `zif_system` off | `libphp+0x5996e0` | `libphp+0x5314f0` |
| fpm `zif_system` off | `PIE+0x60e3a0` | `PIE+0x5163f0` |
| fpm leak: `BASE = pie_ptr -` | `0x7c9777` | `0x6e7810` |
| fpm leak: pie_ptr raw off / low12 | `0x3008` / `0x777` | `0x3008` / `0x810` |
| fpm leak: heap_ptr low12 | `0x428` | `0x428` (unchanged) |
| fpm leak: `D = heap_ptr +` | `0x15cbd8` | `0x15cbd8` (unchanged) |
| fpm leak->exploit `d` drift | `0x37000` | `0x37000` (unchanged) |
| fpm nogdb frame `p4/p5/p6` | `D+0x38 / D+0xA00 / D+0xE80` | same (layout) |
| `BG(unserialize).data` | `bg+0x368` | `bg+0x348` |
| `BG(unserialize).level` | `bg+0x370` | `bg+0x350` |
| `EG(function_table)` ptr | `EG+0x7f8` | `EG+0x7f8` (unchanged) |
| Bucket / HashTable / zval layout | 8-byte LP64 | identical |
| `S = main + 0xF7398` | holds | holds |

Only the symbol offsets, the pointer range, and the `BG` struct offset changed.
The zend_mm bin sizes, HashTable/Bucket/zval layouts, and the spray offsets are
architecture-independent on LP64, which is why the small-bin spray paths
(A/B/B2) ported with just constant edits (`parse_leak_arm.php`, `stage3_arm.php`,
`run_off_chain_arm.sh`). Verified: Path B gives `uid=33` 4/5 on clean aarch64
`php:8.5.11-apache`, ASLR on, pure HTTP.

Path C (FPM native, dynamic leak) likewise ported with constant edits only
(`run_native_arm.sh`: the five fpm-leak rows in the table above). The leak's
read-length write, the `D`-from-heap offset, the frame layout, and the drift are
all unchanged; only `zif_system`, the `BASE`-from-`pie_ptr` offset, the pie low12
tag, and the pointer range changed. Verified: `uid=33` 3/3 on clean aarch64
`php:8.5.11-fpm`. This is the FPM equivalent of the Path B win and the reason the
fixed-address Path D re-groom is not worth pursuing: the dynamic leak absorbs the
per-build heap layout that breaks D.

## When the memory layout changes within one architecture

The fixed-address FPM path (D) is sensitive to the exact build: the reclaimed `d`
drifts between image releases, and the fill groom can start reclaiming `d` itself
as a `zend_string` (symptom: `last_dtor` at `d+0x10` reads the fill-part length,
e.g. `0x1fea`=8170, and `var_tmp_var` faults). When that happens, re-derive `d`
(step 4), rebase `sess_T` and `fillU.bin` (step 5), and if the fault persists,
re-tune the fill part size and count so the reclaim lands on the freed
`var_dtor_entries` block rather than on `d`. The leak-based paths do not need
this: they read the current bases at run time.
