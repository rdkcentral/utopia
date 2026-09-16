#!/bin/sh
if [ -f /etc/utopia/service.d/log_capture_path.sh ]; then
    . /etc/utopia/service.d/log_capture_path.sh
fi
sysevent set cron_every_minute
