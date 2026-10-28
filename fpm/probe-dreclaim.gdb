set pagination off
set confirm off
set breakpoint pending on
set follow-fork-mode child
set detach-on-fork on
set logging file /tmp/fpm-dreclaim.log
set logging overwrite on
set logging enabled on

break php_var_unserialize_init
commands
silent
set $lvl = *(unsigned int*)((char*)&basic_globals+0x370)
set $d = *(void**)((char*)&basic_globals+0x368)
printf "INIT level=%u data=%p\n", $lvl, $d
if $lvl != 0 && $d != 0
  printf "D bytes: "
  x/16gx (char*)$d
  set *(void**)$d = (char*)$d + 0x38
  set *(void**)((char*)$d+0x08) = 0
  set *(void**)((char*)$d+0x10) = (char*)$d + 0x100
  set *(long*)((char*)$d+0x28) = 0
  set *(long*)((char*)$d+0x30) = 0x7fffffff
  set *(long*)((char*)$d+0x38) = 0
  set *(void**)((char*)$d+0x40) = 0
  set *(long*)((char*)$d+0x100) = -2
  set *(void**)((char*)$d+0x108) = 0
  printf "PATCH last=%p first=%p last_dtor=%p used=%ld target=%p\n", *(void**)$d, *(void**)((char*)$d+8), *(void**)((char*)$d+0x10), *(long*)((char*)$d+0x100), (char*)$d+0xF0
end
continue
end

break var_tmp_var
commands
silent
set $vh = (void**)$rdi
set $d = *$vh
if $d != 0
  set $dt = *(void**)((char*)$d+0x10)
  if $dt != 0
    set $used = *(long*)$dt
    printf "TMP d=%p last_dtor=%p used=%ld target=%p\n", $d, $dt, $used, (char*)$dt+16+16*$used
    x/4gx (char*)$dt+16+16*$used
  else
    printf "TMP d=%p last_dtor=NULL\n", $d
  end
else
  printf "TMP var_hashx=%p d=NULL\n", $vh
end
continue
end

break php_var_unserialize_destroy
commands
silent
set $d = (void**)$rdi
printf "DESTROY d=%p level=%u\n", $d, *(unsigned int*)((char*)&basic_globals+0x370)
continue
end

break _zend_bailout
commands
silent
set $d = *(void**)((char*)&basic_globals+0x368)
printf "BAILOUT level=%u d=%p\n", *(unsigned int*)((char*)&basic_globals+0x370), $d
bt 4
continue
end

break munmap
commands
silent
if $rsi == 0x200000
printf "MUNMAP %p\n", $rdi
end
continue
end

run
printf "=== inferior stopped ===\n"
bt 8
info registers rip rdi rsi
