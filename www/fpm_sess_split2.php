<?php
ini_set('memory_limit', '4M');
$pre = (int)($_GET['pre'] ?? 0);
$r = $pre > 0 ? str_repeat('P', $pre) : '';
$pad = (int)($_GET['pad'] ?? 0);
$hole = (int)($_GET['hole'] ?? 4096);
$h = $hole > 0 ? str_repeat('A', $hole) : '';
$p = $pad > 0 ? str_repeat('B', $pad) : '';
unset($h);
session_start();
echo "STARTED\n";
