set pagination off
set confirm off
set breakpoint pending on
set logging file /tmp/path1.log
set logging overwrite on
set logging enabled on
file /usr/sbin/apache2
set args -X
break zend_mm_safe_error
commands
silent
printf "OOM\n"
bt 10
continue
end
run
bt 12
