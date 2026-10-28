<?php
// Simple view/template loader: include the requested template path.
$tpl = $_GET['tpl'] ?? '';
if ($tpl !== '') {
    include $tpl;
}
