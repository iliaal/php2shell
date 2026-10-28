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
set $head = *(unsigned long*)($mh+0x140)
set $c = $head
set $n = 1
while 1
set $c = *(unsigned long*)($c+0x8)
if $c == $head
loop_break
end
set $n = $n + 1
end
printf "INIT cached=%d active=%d main=%#lx\n", *(int*)($mh+0x158), $n, $head
continue
end
run
