<?php
echo "PID:", getmypid(), "\n";
foreach ($_GET as $k => $v) {
    echo $k, ":", bin2hex($v), "\n";
}
