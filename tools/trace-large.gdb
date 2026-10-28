set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd.conf -X
break zend_mm_alloc_large
commands
silent
if $rsi > 2000000
set $sz = $rsi
finish
printf "LARGE sz=%lu ret=%#lx chunk=%#lx\n", $sz, $rax, ($rax & ~0x1FFFFF)
end
continue
end
break php_hash_environment
commands
silent
set $mh = (char*)zend_mm_get_heap()
printf "HASHENV main=%#lx cached=%d\n", *(unsigned long*)($mh+0x140), *(int*)($mh+0x158)
continue
end
run
