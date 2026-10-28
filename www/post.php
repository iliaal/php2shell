<?php
foreach ($_POST as $k => $v) {
    echo $k, ":", bin2hex($v), "\n";
}
