<?php
// Upload-progress polling endpoint, as found in typical upload UIs.
// json_encode reflects a PHP integer losslessly as a decimal, so a $_SESSION
// integer field carrying a leaked pointer round-trips verbatim to the client.
session_start();
header('Content-Type: application/json');
$prefix = ini_get('session.upload_progress.prefix') ?: 'upload_progress_';
$n = $_GET['n'] ?? '';
echo json_encode($_SESSION[$prefix . $n] ?? $_SESSION);
