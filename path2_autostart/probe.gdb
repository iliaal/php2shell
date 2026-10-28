set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/path2.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -X
break php_session_start
commands
silent
printf "START id=%p\n", *(void **)((char *)&ps_globals + 16)
continue
end
break php_session_reset_id
commands
silent
printf "RESET id=%p\n", *(void **)((char *)&ps_globals + 16)
continue
end
break zend_mm_safe_error
commands
silent
printf "OOM\n"
bt 10
continue
end
run
