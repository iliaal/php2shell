set pagination off
set confirm off
set breakpoint pending on
set auto-load safe-path /
set logging file /tmp/ps.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -f /tmp/httpd.conf -X
catch signal SIGABRT
commands
silent
printf "=== SIGABRT ===\n"
bt 12
end
catch signal SIGSEGV
commands
silent
printf "=== SIGSEGV ===\n"
bt 12
end
break php_hash_environment
commands
silent
set $mh = (char*)zend_mm_get_heap()
printf "HASHENV cached=%d\n", *(int*)($mh+0x158)
set $c = *(unsigned long*)($mh+0x148)
set $i = 0
while $c != 0 && $i < 40
printf "  cache[%d]=%#lx\n", $i, $c
set $c = *(unsigned long*)($c + 0x8)
set $i = $i + 1
end
continue
end
break ps_close_files
commands
silent
set $psg = (char*)&ps_globals
set $idp = *(unsigned long*)($psg+0x10)
printf "IDCHK id=%#lx page=%#lx\n", $idp, ($idp & 0x1FFFFF)
if $idp != 0
x/4gx $idp
set $idc = $idp & ~0x1FFFFF
find /g $idc, $idc+0x200000, 0x424242424231302f
end
set $data = *(unsigned long*)$rdi
set $chunk = $data & ~0x1FFFFF
set $page = ($data - $chunk) >> 12
set $info = *(unsigned int*)($chunk + 0x250 + $page*4)
set $bd = *(unsigned long*)($data+8)
set $bdc = $bd & ~0x1FFFFF
set $bdpage = ($bd - $bdc) >> 12
set $bdinfo = *(unsigned int*)($bdc + 0x250 + $bdpage*4)
printf "CLOSE data=%#lx page=%#lx mapinfo=%#x fd=%d last_key=%#lx basedir=%#lx bdref=%#lx bdlen=%lu bdpage=%#lx bdinfo=%#x\n", $data, $page, $info, *(int*)($data+0x24), *(unsigned long*)$data, $bd, *(unsigned long*)$bd, *(unsigned long*)($bd+0x10), $bdpage, $bdinfo
continue
end
run
