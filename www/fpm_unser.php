<?php
ini_set('memory_limit', '4M');
$d = $_POST['d'] ?? '';
if ($d === '' && isset($_FILES['d'])) {
    $d = file_get_contents($_FILES['d']['tmp_name']);
}
$r = @unserialize($d);
echo "OK type=", gettype($r), " peak=", memory_get_peak_usage(true), " len=", strlen($d), "\n";
