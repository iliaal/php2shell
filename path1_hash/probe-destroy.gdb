set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/p1d.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -X
break zend_mm_safe_error
commands
silent
printf "OOM\n"
bt 8
continue
end
break zend_array_destroy
commands
silent
set $ht = (char *)$rdi
set $nu = *(unsigned int *)($ht + 24)
if $nu == 1
set $ad = *(char **)($ht + 16)
printf "AD ht=%p nu=%u sz=%u ad=%p flags=%x mask=%x\n", $ht, $nu, *(unsigned int *)($ht + 32), $ad, *(unsigned int *)($ht + 8), *(unsigned int *)($ht + 12)
x/4gx $ad
set $mm = *(char **)&alloc_globals
if $mm != 0
set $mc = *(char **)($mm + 0x160)
printf "HEAP mm=%p main_chunk=%p delta=%#lx\n", $mm, $mc, (unsigned long)$ad - (unsigned long)$mc
end
end
continue
end
run
bt 10
