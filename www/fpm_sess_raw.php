<?php
/* Lab research only: writes an arbitrary session record. */
$sid = $_GET['sid'] ?? '';
$data = $_GET['d'] ?? '';
if ($data === '') {
    $data = file_get_contents('php://input');
}
if ($sid === '' || $data === '') {
    http_response_code(400);
    echo "need sid and d\n";
    exit;
}
file_put_contents(sys_get_temp_dir() . '/sess_' . $sid, $data);
echo "WROTE ", strlen($data), "\n";
