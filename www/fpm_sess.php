<?php
session_start();
$d = $_POST['d'] ?? '';
if ($d === '' && isset($_FILES['d'])) {
    $d = file_get_contents($_FILES['d']['tmp_name']);
}
if ($d !== '') {
    $_SESSION['p'] = @unserialize($d);
}
echo "sid=", session_id(), "\n";
