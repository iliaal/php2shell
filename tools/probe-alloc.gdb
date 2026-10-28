set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd.conf -X
break php_hash_environment
commands
silent
set $mh = (char*)zend_mm_get_heap()
printf "HASHENV cached=%d chunks=%d head=%#lx\n", *(int*)($mh+0x158), *(int*)($mh+0x150), *(unsigned long*)($mh+0x148)
set $c = *(unsigned long*)($mh+0x148)
set $i = 0
while $c != 0 && $i < 12
printf "  cache[%d]=%#lx\n", $i, $c
set $c = *(unsigned long*)($c + 0x8)
set $i = $i + 1
end
continue
end
break zend_mm_alloc_large
commands
silent
if $rsi > 2000000
set $mh = (char*)zend_mm_get_heap()
printf "ALLOC sz=%lu head=%#lx cached=%d chunks=%d\n", $rsi, *(unsigned long*)($mh+0x148), *(int*)($mh+0x158), *(int*)($mh+0x150)
end
continue
end
run
