# php2shell lab

Reproduction harness for the PHP "php2shell" remote code execution
vulnerability, CVE-2026-109618 and CVE-2026-109619, fixed in PHP 8.5.12 /
8.4.27 / 8.3.36 / 8.2.35.

> **Lab only, educational use.** Every chain here targets the *vulnerable*
> `php:8.5.11` Docker images. The patched releases are the control in every
> test. This exists for defensive understanding and research. Run it only
> against containers you own or are explicitly authorized to test, never
> against systems you do not control.
>
> **Never run code blindly.** Read every script and payload in this repository,
> and understand what it does, before you execute it. That holds for any code
> you find online, and doubly so for code whose whole purpose is to corrupt
> memory.

## What this is

End-to-end chains that turn a single unauthenticated HTTP request into
`uid=33(www-data)` on an unpatched PHP, across both execution models (Apache
mod_php and PHP-FPM) and both architectures (x86-64 and aarch64). The
[companion write-up](https://ilia.ws/blog/php2shell-two-ways-php-corrupts-its-own-memory)
explains the root cause and why reliable exploitation is hard; this repository
is the runnable proof.

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
| C2 | php-fpm | Path C fired through a `popen` ROP pivot, no forged `execute_data` |
| E | mod_php | multipart partial-bucket teardown (debugger-assisted) |

aarch64 ports: `off_chain/run_off_chain_arm.sh` (mod_php, Path B) and
`fpm/run_native_arm.sh` (FPM, Path C).

## Layout

- `chain.php`, `off_chain/`: mod_php chains (Paths A, B, B2)
- `fpm/`: PHP-FPM chains (Path C and the native leak harness)
- `path1_hash/`, `path1_rce/`: Path E (multipart partial bucket)
- `lab/`: Apache and `php.ini` configs for the lab targets
- `www/`: the two-page lab application; run `composer install` in `www/` for
  the Path F auxiliary scenarios

## Fix

Upgrade. 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 remove both CVEs. On an end-of-life
branch, do not hand-apply an isolated source patch on top of the last EOL
release: it closes these two CVEs but leaves you exposed to everything else
fixed since the branch went out of support. Get a maintained build from your
distro or a package maintainer, or upgrade. See the
[companion write-up](https://ilia.ws/blog/php2shell-two-ways-php-corrupts-its-own-memory)
for the full mitigation list.
