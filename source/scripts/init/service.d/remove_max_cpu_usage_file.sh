#!/bin/sh
if [ -f /etc/utopia/service.d/log_capture_path.sh ]; then
    . /etc/utopia/service.d/log_capture_path.sh
fi
/usr/ccsp/tad/remove_max_cpu_usage_file.sh
