<?php
// Framework-style cache read: a base64 cookie decoded with unserialize(),
// the equivalent of Laravel/Symfony cache or metadata reads.
$raw = base64_decode($_COOKIE['app_cache'] ?? '', true);
$data = $raw === false ? null : @unserialize($raw);
header('Content-Type: application/json');
echo json_encode($data);
