<?php
foreach ($_GET as $k => $v) {
    echo $k, ":", bin2hex($v), "\n";
}
