<?php
class Evil2 {
    public $cmd = '';
    public function __construct($cmd = '') { $this->cmd = $cmd; }
    public function __destruct() {
        if ($this->cmd !== '' && !str_contains($_SERVER['REQUEST_URI'] ?? '', 'preload_store2')) {
            system($this->cmd);
        }
    }
}
