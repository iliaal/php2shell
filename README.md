# php2shell lab

Reproduction harness for the PHP "php2shell" remote code execution
vulnerability, CVE-2026-109618 and CVE-2026-109619, fixed in PHP 8.5.12 /
8.4.27 / 8.3.36 / 8.2.35.

> **Lab only.** Every chain here targets the *vulnerable* `php:8.5.11` Docker
> images. The patched releases are the control in every test. Run this only
> against containers you own or are explicitly authorized to test. It is kept
> for defensive understanding and research, not for use against systems you do
> not control.

## What this is

End-to-end chains that turn a single unauthenticated HTTP request into
`uid=33(www-data)` on an unpatched PHP, across both execution models (Apache
mod_php and PHP-FPM) and both architectures (x86-64 and aarch64). The companion
write-up explains the root cause and why reliable exploitation is hard; this
repository is the runnable proof.

## Prerequisites

- Docker
- PHP CLI, 64-bit, on the host
- Python 3, curl
- The FPM paths create their own Docker network and nginx front end

## Start here

- **`RCE_PATHS.md`** is the map: every path, the exact container setup, the
  commands, the proof file, and every approach that was tried and stopped.
- **`PORTING.md`** documents how to re-derive the build-specific offsets when the
  PHP build or the CPU architecture changes (the x86-64 to aarch64 port).
- `progress.md` is the full research log, dead ends included.

## Paths at a glance

| Path | Model | Notes |
|---|---|---|
| A | mod_php | four-request chain, `display_errors=On` |
| B | mod_php | same chain, stock `php.ini-production`, pure HTTP |
| B2 | mod_php | Path B with a `popen` ROP stack |
| C | php-fpm | session-decode reuse, app-visible leak, ASLR on |
| E | mod_php | multipart partial-bucket teardown (debugger-assisted) |

aarch64 ports: `off_chain/run_off_chain_arm.sh` (mod_php, Path B) and
`fpm/run_native_arm.sh` (FPM, Path C).

## Layout

- `chain.php`, `off_chain/` — mod_php chains (Paths A, B, B2)
- `fpm/` — PHP-FPM chains (Path C and the native leak harness)
- `path1_hash/`, `path1_rce/` — Path E (multipart partial bucket)
- `lab/` — Apache and `php.ini` configs for the lab targets
- `www/` — the two-page lab application; run `composer install` in `www/` for
  the Path F auxiliary scenarios

## Fix

Upgrade. 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 remove both CVEs. Older branches have
source backports (7.4, 8.0, 8.1) and distro or maintainer builds. See the
companion write-up for the full mitigation list.
