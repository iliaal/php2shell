<?php
// Framework-style session write: a controller storing request data.
// "ref" creates a PHP reference between two session keys, the pattern that
// makes the session serializer emit R:<n> records.
session_start();
$k = $_POST['k'] ?? 'p';
$v = $_POST['v'] ?? '';
if ($k !== '') {
    $_SESSION[$k] = $v;
}
if (!empty($_POST['ref'])) {
    $_SESSION[$_POST['ref']] = &$_SESSION[$k];
}
echo "sid=", session_id(), "\n";
