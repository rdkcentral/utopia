#!/bin/sh
####################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2024 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
####################################################################################

. /etc/include.properties
. /etc/device.properties

if [ -f /lib/rdk/t2Shared_api.sh ]; then
      source /lib/rdk/t2Shared_api.sh
fi

SYSTIMESET_LOG_FILE="$LOG_PATH/ntpLog.log"
TIMESET_FILE="/tmp/systimeset"

systimeSetLog()
{
    echo "$(/bin/timestamp) : $0: $*" >> $SYSTIMESET_LOG_FILE
}

TIMESYNC_STATUS=`sysevent get TimeSync-status`
if [ "x$TIMESYNC_STATUS" = "xsynced" ]; then
    systimeSetLog "System Time Set To TOD"

    if [ ! -f $TIMESET_FILE ]; then
        touch $TIMESET_FILE
        uptime=$(cut -d. -f1 /proc/uptime)
        uptime_ms=$((uptime*1000))
	t2ValNotify "SYST_INFO_SETSYSTIME" "$uptime_ms"
    fi
fi


