<?php
session_start();
if (array_key_exists('k0', $_POST)) {
    $_SESSION['k0'] = (int)$_POST['k0'];
}
if (array_key_exists('k1', $_POST)) {
    $_SESSION['k1'] = null;
}
if (array_key_exists('cmd', $_POST)) {
    $_SESSION['k2'] = (string)$_POST['cmd'];
}
echo "sid=", session_id(), "\n";
