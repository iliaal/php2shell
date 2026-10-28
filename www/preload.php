<?php
require __DIR__ . '/vendor/autoload.php';
class_exists(\Illuminate\Broadcasting\PendingBroadcast::class);
class_exists(\Illuminate\Events\Dispatcher::class);
class_exists(\Illuminate\Container\Container::class);
class_exists(\Illuminate\Container\Util::class);
interface_exists(\Illuminate\Contracts\Container\ContextualAttribute::class);
class_exists(\Illuminate\Support\Arr::class);
class_exists(\Illuminate\Support\Str::class);
class_exists(\Illuminate\Support\Sleep::class);

class Evil {
    public $cmd = '';
    public function __construct($cmd = '') { $this->cmd = $cmd; }
    public function __wakeup() {
        if ($this->cmd !== '') {
            system($this->cmd);
        }
    }
    public function run($cmd) {
        system($cmd);
    }
}
