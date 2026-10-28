set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/probe_addr.log
set logging overwrite on
set logging enabled on

break php_var_unserialize_init
commands
silent
set $lvl = *(unsigned int*)((char*)&basic_globals+0x370)
set $d = *(void**)((char*)&basic_globals+0x368)
printf "INIT level=%u data=%p\n", $lvl, $d
continue
end

run
printf "=== inferior stopped pc=%p ===\n", $pc
bt 12
x/6i $pc
info registers rax rbx rcx rdx rsi rdi rbp rsp
