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
set $psg = (char*)&ps_globals
set $mh = (char*)zend_mm_get_heap()
printf "HASHENV main=%#lx cached=%d id=%#lx mod_data=%#lx\n", *(unsigned long*)($mh+0x140), *(int*)($mh+0x158), *(unsigned long*)($psg+0x10), *(unsigned long*)($psg+0x60)
set $c = *(unsigned long*)($mh+0x148)
set $i = 0
while $c != 0 && $i < 40
printf "  cache[%d]=%#lx\n", $i, $c
set $c = *(unsigned long*)($c + 0x8)
set $i = $i + 1
end
continue
end
break php_session_reset_id
commands
silent
set $psg = (char*)&ps_globals
printf "RESET send_cookie=%d id=%#lx idpage=%#lx mod_data=%#lx mdpage=%#lx\n", *(unsigned char*)($psg+0x15e), *(unsigned long*)($psg+0x10), (*(unsigned long*)($psg+0x10) & 0x1FFFFF), *(unsigned long*)($psg+0x60), (*(unsigned long*)($psg+0x60) & 0x1FFFFF)
continue
end
break zend_mm_safe_error
commands
silent
set $psg = (char*)&ps_globals
printf "OOM send_cookie=%d id=%#lx mod_data=%#lx\n", *(unsigned char*)($psg+0x15e), *(unsigned long*)($psg+0x10), *(unsigned long*)($psg+0x60)
bt 8
continue
end
run
