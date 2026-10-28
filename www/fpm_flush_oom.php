<?php
ini_set('memory_limit', '4M');
session_start();
$n = (int)($_GET['n'] ?? 2500000);
$_SESSION['x'] = str_repeat('A', $n);
echo "STORED\n";
