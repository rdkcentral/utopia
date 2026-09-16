#!/bin/sh
if [ -f /etc/utopia/service.d/log_capture_path.sh ]; then
    . /etc/utopia/service.d/log_capture_path.sh
fi
nice -n 19 sh /usr/ccsp/tad/log_hourly.sh &
