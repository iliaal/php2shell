set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-split.log
set logging overwrite on
set logging enabled on

break php_var_unserialize_init
commands
silent
set $lvl = *(unsigned int*)((char*)&basic_globals+0x370)
set $d = *(void**)((char*)&basic_globals+0x368)
if $lvl != 0 || $d != 0
  printf "INIT level=%u d=%p off=%#lx last=%#lx fdt=%#lx ldt=%#lx entslot=%#lx\n", $lvl, $d, ((unsigned long)$d)&0x1FFFFF, *(unsigned long*)$d, *(unsigned long*)((char*)$d+8), *(unsigned long*)((char*)$d+0x10), *(unsigned long*)((char*)$d+0x38)
end
continue
end

break _zend_bailout
commands
silent
set $d = *(void**)((char*)&basic_globals+0x368)
printf "BAIL level=%u d=%p off=%#lx last=%#lx fdt=%#lx ldt=%#lx entslot=%#lx\n", *(unsigned int*)((char*)&basic_globals+0x370), $d, ((unsigned long)$d)&0x1FFFFF, *(unsigned long*)$d, *(unsigned long*)((char*)$d+8), *(unsigned long*)((char*)$d+0x10), *(unsigned long*)((char*)$d+0x38)
bt 4
continue
end

run
printf "=== inferior stopped ===\n"
bt 8
