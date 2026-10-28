<?php
echo "peak=", memory_get_peak_usage(true), "\n";
echo "post=", count($_POST), " files=", count($_FILES), "\n";
