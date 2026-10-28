# Path 2: session.auto_start RINIT state (upload_progress off)

Status 2026-10-25: the auto_start RINIT OOM after the session id is created is
reproduced, and the next request's RINIT reset is observed. With upload_progress
off there is no consumer, so this path does not reach RCE on its own.

## Hypothesis

The CVE-2026-109619 chain needs an OOM after `php_session_reset_id()` sets
`PS(id)` / `PS(send_cookie)` and before the request runs, so the skipped
RSHUTDOWN leaves the session globals stale. `session.auto_start` moves the
session start into the RINIT, so the OOM can be placed there without an
upload-progress field. The open question is the consumer: something must read
the stale globals before the next `php_rinit_session_globals()` reset.

## Target

- `php:8.5.11-apache`, stock `php.ini-production` plus `session.auto_start=1`
  and `session.upload_progress.enabled=0`, a single `apache2 -X` under gdb.
- Probe image `p2s-path1-gdb` (gdb preinstalled, production ini; see
  `../path1_hash`). The probe breaks `php_session_start`,
  `php_session_reset_id`, and `zend_mm_safe_error`. The id is read at offset 16
  of `ps_globals` (`save_path`, `session_name`, `id`); the stock build has no
  debug type for the struct. `php_rinit_session_globals` is inlined and has no
  symbol, so `php_session_start` entry is the observation point: if the RINIT
  reset ran, it shows `id=(nil)`.

Container command:

```sh
docker run -d --name p2s-path2 -p 127.0.0.1:8093:80 \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/path2_autostart/probe.gdb:/tmp/path2.gdb:ro" p2s-path1-gdb \
  /bin/sh -c 'printf "session.auto_start=1\nsession.upload_progress.enabled=0\n" \
    >> /usr/local/etc/php/php.ini; . /etc/apache2/envvars; \
    exec gdb -q -batch -x /tmp/path2.gdb'
```

## Body

Generated with `../path1_hash/path1_body.py`; no session id and no upload
progress field. The final long-key field is skipped with `--final=0` so the
POST parse completes and the RINIT session start is the allocation that fails:

```sh
python3 ../path1_hash/path1_body.py --out /tmp/p2g.bin --big=70 --big-len=8000 \
  --burners=18 --groom=20 --groom-len=280 --longseg=0 --parts=860 \
  --cttail=4000 --final=0
```

## Observed

- `big=78/80/84`, no nested parts: POST `200`; `START id=(nil)`,
  `RESET id=<new>`. The auto_start session start at the RINIT succeeds.
- `parts=860`, `big=78`: the POST parse OOMs in `php_sapi_filter` before the
  RINIT; no `START` for the POST.
- `parts=860`, `big=70`, groom, cttail, no long key/final: the parse completes.
  POST: `START id=(nil)`, `RESET id=<new>`, then:

  ```
  zend_mm_alloc_large <- php_var_unserialize_init <- ps_srlzr_decode_php
    <- php_session_decode <- php_session_initialize <- php_session_start
      <- zm_activate_session <- zend_activate_modules
  ```

  The id and send_cookie were set by `RESET` before the failure. The request
  returns `500` and the worker survives.
- Next GET after that OOM: `START id=(nil)`. The RINIT's
  `php_rinit_session_globals()` cleared the stale session globals before the
  auto_start session start; `RESET` then creates a new id (the allocator reuses
  the address).

## Conclusion

The RINIT OOM leaves `PS(id)` / `PS(send_cookie)` stale, but every next request
runs `php_rinit_session_globals()` before any session code, and the only
pre-RINIT consumer in stock PHP is the upload-progress callback, which requires
`session.upload_progress.enabled=On`. With it off, auto_start is at most a
startup failure/DoS, not a use-after-free consumer. The upload-progress chain
in `../off_chain` remains the RCE path.

## Next

- If a different pre-RINIT consumer is found that reads `PS(id)` /
  `PS(send_cookie)` (another module RINIT, or a new handler), re-run this body
  and inspect that consumer.
- Otherwise keep auto_start as a hardening note: the RINIT OOM leaves globals
  set, but the reset ordering prevents reuse.
