set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd.conf -X
break php_session_initialize
commands
silent
set $mh = (char*)zend_mm_get_heap()
printf "INIT cached=%d chunks=%d peak=%d main=%#lx\n", *(int*)($mh+0x158), *(int*)($mh+0x150), *(int*)($mh+0x154), *(unsigned long*)($mh+0x140)
continue
end
run
