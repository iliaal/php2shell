<?php
session_start();
if (isset($_POST['nest'])) {
    $n = (int)$_POST['nest'];
    $b = (int)($_POST['bomb'] ?? 0);
    $a = range(0, $n - 1);
    $a[] = str_repeat('A', $b);
    $_SESSION['p'] = $a;
} elseif (isset($_POST['multi'])) {
    $long = (int)($_POST['long'] ?? 1500000);
    $vals = (int)($_POST['vals'] ?? 0);
    $vsize = (int)($_POST['vsize'] ?? 0);
    $bomb = (int)($_POST['bomb'] ?? 0);
    $_SESSION[str_repeat('k', $long)] = 'x';
    for ($i = 0; $i < $vals; $i++) {
        $_SESSION["v$i"] = str_repeat('A', $vsize);
    }
    $_SESSION['bomb'] = str_repeat('B', $bomb);
} elseif (isset($_POST['s2'])) {
    $_SESSION['a'] = 2;
    $_SESSION['b'] = 123;
    $cnt = (int)$_POST['s2'];
    for ($i = 0; $i < $cnt; $i++) {
        $_SESSION["k$i"] = $i;
    }
} else {
    $klen = (int)($_POST['klen'] ?? 0);
    $vlen = (int)($_POST['vlen'] ?? 0);
    if ($klen > 0) {
        $_SESSION[str_repeat('k', $klen)] = str_repeat('A', $vlen);
    }
}
echo "sid=", session_id(), " peak=", memory_get_peak_usage(true), "\n";
