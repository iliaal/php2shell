<?php
ini_set('memory_limit', $_GET['lim'] ?? '4M');
$pad = str_repeat('P', (int)($_GET['pad'] ?? 0));
session_start();
echo "OK ", session_id(), " pad=", strlen($pad), " peak=", memory_get_peak_usage(true), "\n";
