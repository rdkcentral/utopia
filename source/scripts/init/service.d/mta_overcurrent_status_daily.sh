#!/bin/sh
if [ -f /etc/utopia/service.d/log_capture_path.sh ]; then
    . /etc/utopia/service.d/log_capture_path.sh
fi
sh /usr/ccsp/mta/mta_overcurrentfault_status.sh &
