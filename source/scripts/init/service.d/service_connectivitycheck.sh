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
CONNCHECK_LOG_FILE="$LOG_PATH/ntpLog.log"
CONNCHECK_FILE="/tmp/connectivity_check_done"
CONNCHECK_TIMEOUT=120   # 2 minutes
# Exponential backoff parameters
CONNCHECK_INITIAL_INTERVAL=1         # Start From 1 second
CONNCHECK_MAX_INTERVAL=10            # Optional: cap to 10 seconds
DBUS_SEND_BIN="/usr/bin/dbus-send"
LOCKFILE="/tmp/service_connectivitycheck.pid"
    
connectivityCheckLog()
{
    uptime_log=$(cut -d. -f1 /proc/uptime)
    UPTIME_MS=$((uptime_log*1000))
    echo "$(/bin/timestamp) (uptime: ${UPTIME_MS} ms) : $0: $*" >> $CONNCHECK_LOG_FILE
}
CURRENT_WAN_STATE=`sysevent get current_wan_state`
CURRENT_WAN_STATUS=`sysevent get wan-status`
if [ "x$CURRENT_WAN_STATE" = "xup" ] || [ "x$CURRENT_WAN_STATUS" = "xstarted" ]; then
    connectivityCheckLog "WAN is up. Continuing with connectivity check..."
    connectivityCheckLog "CURRENT_WAN_STATE=$CURRENT_WAN_STATE and CURRENT_WAN_STATUS=$CURRENT_WAN_STATUS"
    if [ -f $LOCKFILE ]; then
        connectivityCheckLog "Already One Instance Of connectivity check is in progress or completed"
        exit 1
    else
        echo $$ > ${LOCKFILE}
        connectivityCheckLog "Created Connectivity check LOCK file $LOCKFILE"
    fi
    # Your main script logic goes here
else
    connectivityCheckLog "WAN is not up (status: $CURRENT_WAN_STATUS and $CURRENT_WAN_STATE). Exiting."
    exit 1
fi
if [ -n "$CONNECTIVITY_CHECK_URL" ]; then
    URL="$CONNECTIVITY_CHECK_URL"
else
    connectivityCheckLog "CONNECTIVITY_CHECK_URL not set. Exiting."
    if [ ! -f $CONNCHECK_FILE ]; then
        touch $CONNCHECK_FILE
    fi
    t2CountNotify "SYST_WARN_connectivitycheck_nourl_set"
    # Send dbus-send
    if [ -x "$DBUS_SEND_BIN" ]; then
        $DBUS_SEND_BIN --system --type=method_call --dest=org.freedesktop.nm_connectivity /org/freedesktop/nm_connectivity org.freedesktop.nm_connectivity.NotifyFullyConnected
    else
        connectivityCheckLog "Warning: dbus-send not found at $DBUS_SEND_BIN. Skipping D-Bus signal."
        exit 1
    fi
    exit 0
fi
START=$(cut -d. -f1 /proc/uptime)
SLEEP_INTERVAL=$CONNCHECK_INITIAL_INTERVAL
while true; do
    NOW=$(cut -d. -f1 /proc/uptime)
    ELAPSED=$((NOW - START))
    if [ "$ELAPSED" -ge "$CONNCHECK_TIMEOUT" ]; then
        connectivityCheckLog "Failed to get HTTP 204 within $CONNCHECK_TIMEOUT seconds."
        if [ ! -f $CONNCHECK_FILE ]; then
            touch $CONNCHECK_FILE
        fi
        t2CountNotify "SYST_WARN_connectivitycheck_time_expire"
        # Send dbus-send
        if [ -x "$DBUS_SEND_BIN" ]; then
            $DBUS_SEND_BIN --system --type=method_call --dest=org.freedesktop.nm_connectivity /org/freedesktop/nm_connectivity org.freedesktop.nm_connectivity.NotifyFullyConnected
        else
            connectivityCheckLog "Warning: dbus-send not found at $DBUS_SEND_BIN. Skipping D-Bus signal."
            exit 1
        fi
        exit 0
    fi
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    CURL_STATUS=$?
    uptime=$(cut -d. -f1 /proc/uptime)
    uptime_ms=$((uptime*1000))
    if [ "$HTTP_CODE" -eq 204 ]; then
        connectivityCheckLog "Connected: Received HTTP 204 and curlstatus=$CURL_STATUS"
        if [ ! -f $CONNCHECK_FILE ]; then
            touch $CONNCHECK_FILE
        fi
        
        t2ValNotify "SYS_INFO_INTERNETRDY_split" "$uptime_ms"
        # Send dbus-send
        if [ -x "$DBUS_SEND_BIN" ]; then
            $DBUS_SEND_BIN --system --type=method_call --dest=org.freedesktop.nm_connectivity /org/freedesktop/nm_connectivity org.freedesktop.nm_connectivity.NotifyFullyConnected
        else
            connectivityCheckLog "Warning: dbus-send not found at $DBUS_SEND_BIN. Skipping D-Bus signal."
            exit 1
        fi
        exit 0
    else
        connectivityCheckLog "connectivitycheck.sh Not connected Http=$HTTP_CODE curlstatus$CURL_STATUS=. Retrying in $SLEEP_INTERVAL seconds..."
    fi
    # Calculate remaining time to avoid sleeping past the timeout
    REMAIN=$((CONNCHECK_TIMEOUT - ELAPSED))
    if [ "$SLEEP_INTERVAL" -gt "$REMAIN" ]; then
        SLEEP_INTERVAL=$REMAIN
    fi
    if [ "$SLEEP_INTERVAL" -le 0 ]; then
        connectivityCheckLog "Timeout reached. Exiting."
        # Send dbus-send
        if [ -x "$DBUS_SEND_BIN" ]; then
            $DBUS_SEND_BIN --system --type=method_call --dest=org.freedesktop.nm_connectivity /org/freedesktop/nm_connectivity org.freedesktop.nm_connectivity.NotifyFullyConnected
        else
            connectivityCheckLog "Warning: dbus-send not found at $DBUS_SEND_BIN. Skipping D-Bus signal."
            exit 1
        fi
        exit 0
    fi
    sleep $SLEEP_INTERVAL
    # Exponential backoff: double the interval, up to max
    SLEEP_INTERVAL=$((SLEEP_INTERVAL * 2))
    if [ "$SLEEP_INTERVAL" -gt "$CONNCHECK_MAX_INTERVAL" ]; then
        SLEEP_INTERVAL=$CONNCHECK_MAX_INTERVAL
    fi
done

