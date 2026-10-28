# Path 1: multipart/hash-table partial bucket (no sessions)

Status as of 2026-10-25: the trigger and the vulnerable state are reproduced on
stock PHP 8.5.11 mod_php. The teardown-impact groom is in progress. This folder is
separate from the upload-progress chain in `../off_chain`; nothing here sends a
session id or an upload-progress field.

## The bug

`_zend_hash_str_add_or_update_i()` (`Zend/zend_hash.c:904`) increments the table
counts before allocating the new key:

```c
idx = ht->nNumUsed++;
ht->nNumOfElements++;
p = ht->arData + idx;
p->key = key = zend_string_init(str, len, ...);   /* may zend_bailout() */
p->h = ZSTR_H(key) = h;
...
ZVAL_COPY_VALUE(&p->val, pData);
```

An OOM at `zend_string_init()` leaves the bucket at `idx` inside `nNumUsed` but
with an uninitialized key and value. The normal completion path never runs. On
mod_php, a request-startup failure still reaches `php_request_shutdown()`
(`sapi/apache2handler/sapi_apache2.c:672-674` then the request destructor), which
destroys `$_POST` / `$_FILES`; the hash teardown walks the count and interprets
the stale bucket. PHP-FPM exits the worker on the same startup failure
(`sapi/fpm/fpm/fpm_main.c:1838-1843`), so there is no second request to consume it.

## Reproducer

Target: stock PHP 8.5.11 mod_php, single persistent worker (lab: `apache2 -X` with
the stock `php.ini-production`; the lab container is `p2s-8511-off`).

```bash
# in the container, one worker with the gdb probe (lab only):
docker exec -d p2s-8511-off gdb -q -batch -x /tmp/path1.gdb
# on the host:
./run_path1.sh 8091 /tmp/p1.bin
```

`path1_body.py` defaults:

- 860 file parts with `filename=""`, nested 64 levels, 90-byte key pad. Each
  expands into six `$_FILES` entries and the deep hash hierarchy.
- 14 fillers with 103-byte names, one 15-byte post40 field.
- 60 big fields with 16000-byte values, 18 burners with 4000-byte values.
- One trailing file part with a 4000-byte content type.
- 20 groom fields with 280-byte values (bin 320).
- One final plain field `files[<4000-byte segment>][a]` with a 1000-byte value.

No session id and no `PHP_SESSION_UPLOAD_PROGRESS` are sent. The GET path adds five
`q...=v` and eight 15-byte `g<N>` values, matching the heap shape used in the
initial chain's A1.

## Observed

With the A1-shaped body (big 78 x 8000, burners 18, cttail 4000, longseg 4000,
longval 1000, no groom), the fatal allocation is the 4000-byte key of the final
nested field:

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

At the fatal allocation the target is the freshly created `$_POST['files']`
array. GDB shows `nNumUsed` and `nNumOfElements` go from 0 to 1 before the key
allocation fails; bucket 0 is visible to teardown and uninitialized. The request
returns 500. mod_php's request shutdown destroys the malformed table. In that run
the stale bytes were benign and the worker survived.

Neighbouring OOM sites found while tuning:

- `zend_hash_real_init_mixed` (a new array's bucket area): the table stays
  uninitialized; no partial bucket; worker survives.
- `zend_hash_do_resize` (a table grows): the resize allocation fails before the
  insert; the table stays valid; worker survives.

Only the key-allocation site leaves the malformed table.

## Groom design

The new `files` array's arData is a mixed-table allocation of 8 hash slots
(32 bytes) plus 8 buckets (256 bytes) = 288 bytes, bin 320. A 280-byte multipart
value has a 281-byte raw buffer, also bin 320; the parser frees it after each
field. The plan is for the arData to reuse the most recently freed groom raw
buffer, so bucket 0 receives `'C'` bytes: `key = 0x4343...`, `val.type = 0x43...`.
At teardown, `zend_string_release(p->key)` dereferences an unmapped address, and
the zval destructor sees an invalid type.

Constraints:

- Keep the top-level `$_POST` key count below the next resize threshold (128)
  until the final `files[...]` field. Otherwise the table resize fires first and
  the OOM lands in `zend_hash_do_resize`, which leaves a valid table. The current
  body has 114 plain keys with the groom included.
- The heap must be at the limit when the 4000-byte key allocation runs, not
  earlier in the big/burner value copies.

## Log

- 2026-10-25: key-allocation OOM reproduced with the A1-shaped session-free body;
  `nNumUsed` 0 -> 1, bucket 0 uninitialized, new `$_POST['files']` table, worker
  survived.
- 2026-10-25: first groom attempt used 231-byte values (bin 256) and 20 extra
  plain keys. The OOM moved to `zend_hash_do_resize` (the `$_POST` table crossed
  128 keys); the table stayed valid and the worker survived. Wrong bin and wrong
  key count.
- 2026-10-25: `path1_body.py` created with the bin-320 groom (280-byte values),
  `big=60` / `big_len=16000`, 114 plain keys, a local probe and runner. First
  groom run pending.
- 2026-10-25: isolated target `p2s-path1-dbg` on 8092; the stock-image probe
  (`set args -X`) and the gdb image `p2s-path1-gdb`. The tuned body `big=70`,
  `big_len=8000`, `burners=18`, `groom=20x280`, `parts=860`, `longseg=4000`,
  `longval=1000` (keys 124) OOMs in `php_register_variable_safe` at the
  4025-byte key (`tried to allocate 4096`), request 500. The teardown did not
  crash and the worker survived.
- 2026-10-25: `--cttail=0` moved the OOM to `_estrdup <- php_ap_getword` (the
  long-segment header) before the key; the worker survived. The long-segment
  header and key each need a page, and the cttail changes which one fails; the
  arData/groom bucket was not reached in either run.
- 2026-10-25: the generator gained `--final` (skip the long-key field) for the
  path-2 probe; path-1 defaults are unchanged.
- 2026-10-25: destroy probe (`probe-destroy.gdb`, condition on `nNumUsed==1`
  and a `0x43434343` bucket value) found no partial bucket with the tuned
  nested `files[L...][a]` body. The OOM is in `php_register_variable_safe`:
  the key is allocated before the hash insert, the array never reaches the
  `_zend_hash_str_add_or_update_i` count increment, and teardown is benign.
  The earlier A1-shaped body OOMs in `zend_hash_str_update_ind` after the
  increment; that is the shape the groom must use.
- 2026-10-25: destroy probe corrected: `ht->arData` already points at bucket 0
  (the hash slots precede it), so the earlier `arData+32` / `arData+40` checks
  were wrong. The single one-entry/8-slot destroy seen holds a valid stale
  string (type `0x0d`), not `0x43` bytes; that body's `arData` did not reuse a
  groom raw.
- 2026-10-25: nested groom (`groom[gNN]`) keeps the `$_POST` key count at
  112-113, below the 128-key resize, while still freeing bin-320 raw buffers.
  With `big=78` the A1 no-groom body OOMs at the hash key, but every groomed
  variant tested (big 76-78, cttail 0/4000, burners 17/18, groom 5-20,
  longval 0/1000, cold and warmed worker) fails one allocation earlier in
  `php_sapi_filter` at the final 4025-byte name (tried to allocate 4096). The
  groom's presence costs at least one free page at the final name; the hash
  needs the filter to succeed with one free page and then fail with zero.
- 2026-10-25: generator adds `--groom-nested`; `probe-destroy.gdb` now logs
  the OOM stack plus any one-entry/8-slot destroy whose bucket-0 value type is
  `0x43434343`.

## Next

1. Tune `big_len` / `parts` so the limit hits the final 4000-byte key with the
   groom in place, not the big value copies.
2. Verify the teardown consumes the groomed bucket and crashes (gdb signal
   backtrace), then characterize the faulting pointer.
3. Move from a crash to the advisory's controlled primitive: a valid fake
   zend_string / zval at a leaked or groomed address, or an arbitrary free. The
   Calif write-up reports RCE on mod_php from this path; that end state is not
   reproduced here yet.
4. Recover the filter/hash boundary with the groom in place: the A1 no-groom
   body reaches the hash key, but all groomed variants tested (big 76-78,
   cttail 0/4000, burners 17/18, groom 5-20, longval 0/1000, cold and warmed)
   fail in `php_sapi_filter` at the final 4025-byte name. Adjust the parts
   count, a single groom field, or `big_len` at a page boundary.

References: `Zend/zend_hash.c` (`_zend_hash_str_add_or_update_i`),
`main/php_variables.c` (`php_register_variable_ex`), mod_php
`sapi/apache2handler/sapi_apache2.c:672-674`, the Calif write-up
(calif.io/php2shell), and the initial chain log in `../progress.md`.
