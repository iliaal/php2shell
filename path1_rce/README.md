# Path 1: multipart/hash partial-bucket RCE (stock PHP 8.5.11 mod_php)

Status 2026-10-25: RCE verified in the lab with a gdb-assisted pivot. The proof
file in the target contains `uid=33(www-data) gid=33(www-data)`. This path is
independent of the session/upload-progress chain in `../off_chain`.

## INI dependencies

The trigger does **not** use `session.upload_progress`, `session.auto_start`,
`PHPSESSID`, or any session setting. It is the multipart parser's hash-table OOM
path, not the session path.

It does depend on:

- `file_uploads=On` (stock default). The final field is a file part with a
  non-empty filename; the file branch bypasses `sapi_module.input_filter` and
  the filter extension's internal `post_array`. With `file_uploads=Off` the
  part is skipped.
- `max_file_uploads >= 1` (default 20; the body uploads exactly one file).
- `post_max_size > ~1 MB` (the body is ~1 MB; default 8M).
- `max_input_vars >= 981` (857 nested parts + 124 plain keys; default 1000).
- `memory_limit=128M` (the heap must reach the limit at the final hash insert).
- `display_errors` is irrelevant; the crash does not need error output.

## Trigger

The body is 857 nested plain parts (deep arrays), big/burner fillers, 20
bin-320/384 groom fields, and one final **file part** named
`X[<longsegment>][a]` with filename `f`. The parse reaches the final
`$_FILES['X']` registration with the heap at the limit.

The long segment's key allocation fails inside `zend_hash_str_update_ind()`
**after** `nNumUsed++`, leaving a partial bucket at `$_FILES['X'][0]`:

```
OOM: zend_hash_str_update_ind <- php_register_variable_ex
     <- php_register_variable_safe <- rfc1867_post_handler
SIGSEGV: zend_array_destroy (recursive) <- php_request_shutdown <- php_handler
```

The 16K long segment is the window. 32K/64K fail earlier in
`substring_conf`/`_estrndup`; 128K+ fail in the header `smart_string`; a 4K key
is inserted successfully and the failure moves to the script compiler.

## Pivot

The fresh `$_FILES['X']` table's arData is a bin-320 block with mask `-16`;
`block = arData - 0x40`. At the partial array's destroy, the arData block is
overwritten with:

- caller bucket at `arData`: `val.ptr = blk`, `type = IS_ARRAY`, `key = NULL`;
- fake HashTable at `blk`: `arData = blk+0x60`, `nNumUsed = 1`,
  `pDestructor = zif_system`;
- fake execute_data at `blk+0x60`; fake command `zend_string` at `blk+0xC0`
  (`id>/tmp/p1hash`).

Then `zend_array_destroy -> pDestructor -> zif_system -> php_exec -> system`.
The proof file `/tmp/p1hash` contains `uid=33(www-data)`.

The arData offset from the 2 MB heap chunk is stable across ASLR runs:
`arData - chunk = 0x5d7c0` (verified in two runs).

## Remaining for HTTP-only

The pivot currently uses gdb to inject the runtime addresses (fake block and
`zif_system`) at the crash. HTTP-only requires:

1. the B1 session leak (`../off_chain`) for the chunk and libphp bases;
2. the PHP 8.5.11 `zif_system` offset;
3. the fake layout embedded in the groom value that becomes the arData.

The crash itself is already HTTP-only reproducible.

## Files

- `probe-pivot.gdb`: the gdb pivot used for the verified RCE.
- `../path1_hash/path1_body.py`: the body generator (`--final-file`,
  `--final-prefix`, `--groom-len`, `--cttail`, `--longseg`, ...).
- `../path1_hash/README.md`: the tuning log and the OOM-site history.

## Upload-progress-disabled targets (2026-10-28)

The crash trigger here does not use `PHPSESSID` or `PHP_SESSION_UPLOAD_PROGRESS`;
that is the point of this path. The RCE pivot, however, is still gdb-assisted:
the fake block needs the 2 MB chunk base (`arData - chunk = 0x5d7c0`) and the
libphp base (`zif_system = libphp + 0x5996e0`).

The B1 leak named under "Remaining for HTTP-only" is itself upload-progress
based (`session.upload_progress.enabled=On`), so it does not cover a target with
that setting disabled. On a bare endpoint the path-1 crash returns no response
and `display_errors` is irrelevant, so no independent pointer leak exists.
Path-1 HTTP-only on an upload-progress-disabled bare target is therefore still
blocked on a leak. With any independent leak (an app-reflected pointer, a debug
page, or `display_errors=On`), the fake block and the stable `arData - chunk`
offset complete the chain.

The current groom writes the full fake HashTable, including the 8-byte
`pDestructor`; a partial-overwrite or brute-force `pDestructor` would need a
narrower write primitive, which this path does not have.
