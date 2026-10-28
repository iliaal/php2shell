set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd-lab-debug.conf -X
break php_hash_environment
commands
silent
set $psg = (char*)&ps_globals
set $mh = (char*)zend_mm_get_heap()
printf "HASHENV main=%#lx id=%#lx mod_data=%#lx hsv_type=%d hsv_val=%#lx\n", *(unsigned long*)($mh+0x140), *(unsigned long*)($psg+0x10), *(unsigned long*)($psg+0x60), *(unsigned char*)($psg+0x168+8), *(unsigned long*)($psg+0x168)
continue
end
break php_session_initialize
commands
silent
set $psg = (char*)&ps_globals
set $hsv = *(unsigned long*)($psg+0x168)
if *(unsigned char*)($psg+0x168+8) == 10
printf "INIT hsv=%#lx id=%#lx\n", $hsv, *(unsigned long*)($psg+0x10)
set $idp = *(unsigned long*)($psg+0x10)
if $idp != 0
x/4gx $idp
end
x/6gx $hsv
set $mh = (char*)zend_mm_get_heap()
set $main = *(unsigned long*)($mh+0x140)
set $target = $main + 0xF53B8
printf "FIND target=%#lx\n", $target
find /g $main, $main+0x200000, $target
end
continue
end
break zend_mm_safe_error
commands
silent
set $psg = (char*)&ps_globals
printf "OOM send_cookie=%d id=%#lx mod_data=%#lx hsv_type=%d hsv_val=%#lx\n", *(unsigned char*)($psg+0x15e), *(unsigned long*)($psg+0x10), *(unsigned long*)($psg+0x60), *(unsigned char*)($psg+0x168+8), *(unsigned long*)($psg+0x168)
bt 12
continue
end
run
