set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd.conf -X
break php_session_reset_id
commands
silent
set $psg = (char*)&ps_globals
set $mh = (char*)zend_mm_get_heap()
set $s = *(unsigned long*)($mh + 0x28 + 11*8)
set $c = 0
while $s != 0 && $c < 200
set $s = *(unsigned long*)$s
set $c = $c + 1
end
set $chunk = *(unsigned long*)($mh + 0x140)
set $fpages = 0
set $n = 0
while $n < 200
set $fpages = $fpages + *(unsigned int*)($chunk + 0x18)
set $chunk = *(unsigned long*)($chunk + 0x8)
set $n = $n + 1
if $chunk == *(unsigned long*)($mh + 0x140)
set $n = 999
end
end
printf "STATE send_cookie=%d bin128=%d free_pages=%d idpage=%#lx mdpage=%#lx\n", *(unsigned char*)($psg+0x15e), $c, $fpages, (*(unsigned long*)($psg+0x10) & 0x1FFFFF), (*(unsigned long*)($psg+0x60) & 0x1FFFFF)
continue
end
break zend_mm_safe_error
commands
silent
set $psg = (char*)&ps_globals
printf "OOM send_cookie=%d\n", *(unsigned char*)($psg+0x15e)
bt 5
continue
end
run
