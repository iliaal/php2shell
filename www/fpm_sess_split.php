<?php
ini_set('memory_limit', '4M');
$pad = (int)($_GET['pad'] ?? 0);
if ($pad > 0) {
    $p = str_repeat('A', $pad);
}
session_start();
echo "STARTED\n";
