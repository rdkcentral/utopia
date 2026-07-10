#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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
##########################################################################

source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/log_capture_path.sh
source /etc/log_timestamp.sh    # define 'echo_t' ASAP!
source /etc/waninfo.sh
source /etc/device.properties

SERVICE_NAME="chronyd"
SELF_NAME="`basename "$0"`"
CHRONY_CONF_TMP=/tmp/chrony.conf
CHRONY_BIN=chronyd
LOCKFILE=/var/tmp/service_chronyd.pid
RFC_FLAG=/nvram/chrony_enabled
SYNC_FILE=/tmp/clock-event
NTP_SYNCED_FILE=/tmp/.ntp_time_synced

if [ -z "$NTPD_LOG_NAME" ]; then
    NTPD_LOG_NAME=/rdklogs/logs/chrony.log
fi

CONNCHECK_FILE="/tmp/connectivity_check_done"

LANIPV6Support=$(sysevent get LANIPv6GUASupport)
CURRENT_WAN_STATUS=$(sysevent get wan-status)
WAN_INTERFACE=$(getWanInterfaceName)

# ──────────────────────────────────────────────────────────────────────────────
# service_init: load syscfg NTP server values into environment
# ──────────────────────────────────────────────────────────────────────────────
service_init() {
    FOO=$(utctx_cmd get ntp_server1 ntp_server2 ntp_server3 ntp_server4 ntp_server5 \
                       ntp_enabled new_ntp_enabled)
    eval "$FOO"
}

# ──────────────────────────────────────────────────────────────────────────────
# wan_wait: poll WAN interface until IPv4 or IPv6 address is available
#   $1 — name of variable to receive the WAN IP
# ──────────────────────────────────────────────────────────────────────────────
wan_wait() {
    local WAN_UP=""
    local WAN_IPv4=""
    local WAN_IPv6=""
    local retry=0
    local MAX_RETRY=20

    while [ -z "$WAN_UP" ]; do
        retry=$((retry + 1))
        WAN_IPv4=$(ifconfig -a "$WAN_INTERFACE" | grep inet | grep -v inet6 \
                   | tr -s " " | cut -d ":" -f2 | cut -d " " -f1 | head -n1)

        if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || \
           [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || \
           [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$LANIPV6Support" = "true" ]; then
            CURRENT_WAN_IPV6_STATUS=$(sysevent get ipv6_connection_state)
            if [ "up" = "$CURRENT_WAN_IPV6_STATUS" ]; then
                ULAprefix=$(sysevent get ula_address | cut -d ':' -f1)
                if [ -z "$ULAprefix" ]; then
                    WAN_IPv6=$(ifconfig "$NTPD_IPV6_INTERFACE" | grep inet6 | grep Global \
                               | awk '/inet6/{print $3}' | grep -v 'fdd7' \
                               | cut -d '/' -f1 | head -n1)
                else
                    WAN_IPv6=$(ifconfig "$NTPD_IPV6_INTERFACE" | grep inet6 | grep Global \
                               | awk '/inet6/{print $3}' | grep -v 'fdd7' \
                               | grep -v "$ULAprefix" | cut -d '/' -f1 | head -n1)
                fi
            fi
        else
            WAN_IPv6=$(ifconfig "$WAN_INTERFACE" | grep inet6 | grep Global \
                       | awk '/inet6/{print $3}' | cut -d '/' -f1 | head -n1)
        fi

        if [ -n "$WAN_IPv4" ] || [ -n "$WAN_IPv6" ]; then
            WAN_UP="$WAN_INTERFACE"
            break
        fi

        sleep 6
        WAN_INTERFACE=$(getWanInterfaceName)

        if [ "$retry" -ge "$MAX_RETRY" ]; then
            echo_t "SERVICE_CHRONYD : WAN IP not acquired after max retries. Exiting" >> $NTPD_LOG_NAME
            break
        fi
    done

    eval "$1=\$WAN_UP"
}

# ──────────────────────────────────────────────────────────────────────────────
# build_chrony_conf: construct /tmp/chrony.conf from syscfg NTP servers
# ──────────────────────────────────────────────────────────────────────────────
build_chrony_conf() {
    local WAN_IP="$1"
    local WAN_IPv4=""
    local WAN_IPv6=""

    rm -f "$CHRONY_CONF_TMP"


    # NTP servers from syscfg
    if [ "$NTP_SERVER_URL_RESTORE" = "false" ]; then
        if [ "$SYSCFG_new_ntp_enabled" = "true" ]; then
            # Multi-server pool (new_ntp_enabled mode)
            for srv in "$SYSCFG_ntp_server1" "$SYSCFG_ntp_server2" "$SYSCFG_ntp_server3" \
                       "$SYSCFG_ntp_server4" "$SYSCFG_ntp_server5"; do
                if [ -n "$srv" ] && [ "$srv" != "no_ntp_address" ]; then
                    echo "pool $srv iburst maxsources 3 minpoll 10 maxpoll 12" >> $CHRONY_CONF_TMP
                fi
            done
        else
            # Legacy single-server mode
            local SRV="$SYSCFG_ntp_server1"
            if [ -z "$SRV" ] || [ "$SRV" = "no_ntp_address" ]; then
                if [ -f "/nvram/ETHWAN_ENABLE" ] || [ -z "$PARTNER_ID" ]; then
                    SRV="time1.google.com"
                    echo_t "SERVICE_CHRONYD : NTP server not configured, using default" >> $NTPD_LOG_NAME
                else
                    echo_t "SERVICE_CHRONYD : NTP server not configured and PartnerID set — aborting" >> $NTPD_LOG_NAME
                    return 1
                fi
            fi
            echo "pool $SRV iburst maxsources 2 minpoll 10 maxpoll 12" >> $CHRONY_CONF_TMP
        fi
    fi

    # Fast initial step-correction
    echo "makestep 1.0 3" >> $CHRONY_CONF_TMP

    # Drift file
    echo "driftfile /var/lib/chrony/drift" >> $CHRONY_CONF_TMP

    # Bind acquisition (outgoing NTP client) sockets to the WAN interface by name,
    # covering both IPv4 and IPv6 without needing to extract individual IPs.
    if [ -n "$WAN_IP" ]; then
        echo "bindacqdevice $WAN_INTERFACE" >> $CHRONY_CONF_TMP
        echo_t "SERVICE_CHRONYD : binding acquisition sockets to interface $WAN_INTERFACE" >> $NTPD_LOG_NAME
    fi

    if [ "$MULTI_CORE" = "yes" ] && [ "$NTPD_IMMED_PEER_SYNC" != "true" ]; then
        echo "bindaddress $HOST_INTERFACE_IP" >> $CHRONY_CONF_TMP
    fi


    echo_t "SERVICE_CHRONYD : chrony.conf built at $CHRONY_CONF_TMP" >> $NTPD_LOG_NAME
    return 0
}

# ──────────────────────────────────────────────────────────────────────────────
# set_chrony_sync_status: background monitor — polls chronyc until Leap=Normal
# ──────────────────────────────────────────────────────────────────────────────
set_chrony_sync_status() {
    local retry=1
    local MAX_RETRY=12   # 12 × 10s = 120s max wait

    while true; do
        if [ "$retry" -gt "$MAX_RETRY" ]; then
            echo_t "SERVICE_CHRONYD : sync not confirmed within 120s — daemon still running" >> $NTPD_LOG_NAME
            break
        fi

        leap=$(chronyc tracking 2>/dev/null | grep "Leap status" | awk '{print $NF}')
        if [ "$leap" = "Normal" ]; then
            echo_t "SERVICE_CHRONYD : time sync confirmed (Leap status Normal)" >> $NTPD_LOG_NAME
            syscfg set ntp_status 3
            sysevent set ntp_time_sync 1
            touch "$SYNC_FILE"
            touch "$NTP_SYNCED_FILE"
            DEVICEFIRSTUSEDATE=$(syscfg get device_first_use_date)
            if [ -z "$DEVICEFIRSTUSEDATE" ] || [ "0" = "$DEVICEFIRSTUSEDATE" ]; then
                syscfg set device_first_use_date "$(date +%Y-%m-%dT%H:%M:%S)"
            fi
            break
        fi

        retry=$((retry + 1))
        sleep 10
    done
    exit 0
}

waitForConnChkFile()
{ 
       echo_t "SERVICE_NTPD CONNCHK: Waiting for connection check for  completion..." >> $NTPD_LOG_NAME
    TIMEOUT=120
    INTERVAL=1

    # Get system uptime in seconds at start
    START_TIME=$(cut -d. -f1 /proc/uptime)

    echo_t "SERVICE_NTPD CONNCHK: Waiting for $CONNCHECK_FILE (max ${TIMEOUT}s)..." >> $NTPD_LOG_NAME

    while true; do
        if [ -f "$CONNCHECK_FILE" ]; then
            echo_t "SERVICE_NTPD CONNCHK: File $CONNCHECK_FILE present" >> $NTPD_LOG_NAME
            return 0
        fi

        CURRENT_TIME=$(cut -d. -f1 /proc/uptime)
        ELAPSED=$((CURRENT_TIME - START_TIME))

        if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
            echo_t "SERVICE_NTPD CONNCHK: Timeout ${TIMEOUT}s expired - file $CONNCHECK_FILE not found" >> $NTPD_LOG_NAME
            return 1
        fi

        sleep "$INTERVAL"
    done
}
# ──────────────────────────────────────────────────────────────────────────────
# service_start: main start path
# ──────────────────────────────────────────────────────────────────────────────
service_start() {
    # RFC guard — only run if flag is present
    if [ ! -f "$RFC_FLAG" ]; then
        echo_t "SERVICE_CHRONYD : RFC flag absent — chrony path inactive" >> $NTPD_LOG_NAME
      #  return 0   - TBD
    fi

   # Wait for connectivitycheck to complete
   if [ -f $CONNCHECK_FILE ]; then
       echo_t "SERVICE_NTPD CONNCHK: connectivity success $CONNCHECK_FILE present" >> $NTPD_LOG_NAME
   else
       # Exclude XLE device from connectivity check. TODO
       if [ "$BOX_TYPE" != "WNXL11BWL" ];then
           echo_t "SERVICE_NTPD CONNCHK: start connectivity check waiting for $CONNCHECK_FILE file" >> $NTPD_LOG_NAME
           #waitForConnChkFile
	   fi
   fi
   
    if [ -n "$SYSCFG_ntp_enabled" ] && [ "0" = "$SYSCFG_ntp_enabled" ]; then
        syscfg set ntp_status 2
        sysevent set ${SERVICE_NAME}-status "stopped"
        return 0
    fi

    # Do not start a second instance if chronyd is already running
    if pidof "$CHRONY_BIN" > /dev/null 2>&1; then
        echo_t "SERVICE_CHRONYD : already running (pid=$(pidof $CHRONY_BIN)), skipping start" >> $NTPD_LOG_NAME
        return 0
    fi

    syscfg set ntp_status 2
    sysevent set ${SERVICE_NAME}-status "starting"

    # WAN check
    if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || \
       [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || \
       [ "$BOX_TYPE" = "SR213" ] || [ "$LANIPV6Support" = "true" ]; then
        WAN_IPV6_STATUS=$(sysevent get ipv6_connection_state)
        if [ "started" != "$CURRENT_WAN_STATUS" ] && [ "up" != "$WAN_IPV6_STATUS" ]; then
            syscfg set ntp_status 2
            sysevent set ${SERVICE_NAME}-status "wan-down"
            return 0
        fi
    else
        if [ "started" != "$CURRENT_WAN_STATUS" ]; then
            syscfg set ntp_status 2
            sysevent set ${SERVICE_NAME}-status "wan-down"
            return 0
        fi
    fi

    # Stop ntpd if running — mutual exclusivity with chrony
    if pidof ntpd > /dev/null 2>&1; then
        echo_t "SERVICE_CHRONYD : stopping ntpd for mutual exclusivity" >> $NTPD_LOG_NAME
        systemctl stop ntpd
        killall ntpd 2>/dev/null
        sleep 2
    fi

    # Wait for WAN IP
    local WAN_IP=""
    wan_wait WAN_IP

    # Build chrony.conf
    #build_chrony_conf "$WAN_IP"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        sysevent set ${SERVICE_NAME}-status "error"
        return 1
    fi

    # Start chronyd — only reaches here when no instance is running
    echo_t "SERVICE_CHRONYD : starting chronyd daemon" >> $NTPD_LOG_NAME
    systemctl start chronyd
    rc=$?
    if [ "$rc" -eq 0 ]; then
           if [ -e "/usr/bin/print_uptime" ] && [ ! -f "/tmp/ntp_boot_uptime_logged" ]; then
               /usr/bin/print_uptime "boot_to_chrony_uptime"
               touch /tmp/ntp_boot_uptime_logged
           fi
    fi
    if [ "$rc" -ne 0 ]; then
        echo_t "SERVICE_CHRONYD : systemctl start chronyd failed (rc=$rc)" >> $NTPD_LOG_NAME
        sysevent set ${SERVICE_NAME}-status "error"
        return 1
    fi

   
    sysevent set ${SERVICE_NAME}-status "started"
    echo_t "SERVICE_CHRONYD : chronyd started — monitoring sync in background" >> $NTPD_LOG_NAME

    # Background sync monitor
    set_chrony_sync_status &
}

# ──────────────────────────────────────────────────────────────────────────────
# service_stop
# ──────────────────────────────────────────────────────────────────────────────
service_stop() {

    # RFC guard — if chrony is not the active client, nothing to stop
    if [ ! -f "$RFC_FLAG" ]; then
        echo_t "SERVICE_CHRONYD : RFC flag absent — skipping chronyd stop" >> $NTPD_LOG_NAME
        return 0
    fi
    echo_t "SERVICE_CHRONYD : stopping chronyd" >> $NTPD_LOG_NAME
    systemctl stop chronyd 2>/dev/null
    killall chronyd 2>/dev/null
    sysevent set ${SERVICE_NAME}-status "stopped"
}

# ──────────────────────────────────────────────────────────────────────────────
# Script entry point — serialise concurrent invocations via lockfile
# ──────────────────────────────────────────────────────────────────────────────
while [ -e "$LOCKFILE" ]; do
    kill -0 "$(cat "$LOCKFILE")" 2>/dev/null || break
    echo_t "SERVICE_CHRONYD : waiting for parallel instance to finish..." >> $NTPD_LOG_NAME
    sleep 1
done

trap 'rm -f ${LOCKFILE}; exit' INT TERM EXIT
echo $$ > "$LOCKFILE"

service_init
CURRENT_WAN_STATUS=$(sysevent get wan-status)

case "$1" in
    "${SERVICE_NAME}-start")
        echo_t "SERVICE_CHRONYD : ${SERVICE_NAME}-start received" >> $NTPD_LOG_NAME
        service_start
        ;;
    "${SERVICE_NAME}-stop")
        echo_t "SERVICE_CHRONYD : ${SERVICE_NAME}-stop received" >> $NTPD_LOG_NAME
        service_stop
        ;;
    "${SERVICE_NAME}-restart")
        echo_t "SERVICE_CHRONYD : ${SERVICE_NAME}-restart received" >> $NTPD_LOG_NAME
        service_stop
        service_start
        ;;
    wan-status)
        if [ "started" = "$CURRENT_WAN_STATUS" ]; then
            # service_start() already guards against duplicate instances via pidof
            echo_t "SERVICE_CHRONYD : wan-status=started, calling service_start" >> $NTPD_LOG_NAME
            service_start
        fi
        ;;
    ipv6_connection_state)
        # HUB4/SKY and ntpHealthCheck-enabled platforms only
        ntpHealthCheck=$(sysevent get NTPHealthCheckSupport)
        if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || \
           [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || \
           [ "$BOX_TYPE" = "SR213" ] || [ "$ntpHealthCheck" = "true" ]; then
            CHRONY_PID=$(pidof $CHRONY_BIN)
            NTP_STATUS=$(syscfg get ntp_status)
            if [ "$NTP_STATUS" = "3" ] && [ -n "$CHRONY_PID" ]; then
                # Already synced — signal chrony to re-acquire sources, no restart needed
                echo_t "SERVICE_CHRONYD : IPv6 state change, running chronyc online" >> $NTPD_LOG_NAME
                chronyc online > /dev/null 2>&1
            else
                WAN_IPV6_STATUS=$(sysevent get ipv6_connection_state)
                if [ "up" = "$WAN_IPV6_STATUS" ]; then
                    CURRENT_WAN_V6_PREFIX=$(syscfg get ipv6_prefix_address)
                    NTP_PREFIX=$(sysevent get ntp_prefix)
                    if [ -n "$CURRENT_WAN_V6_PREFIX" ] && [ "$NTP_PREFIX" != "$CURRENT_WAN_V6_PREFIX" ]; then
                        echo_t "SERVICE_CHRONYD : IPv6 prefix changed, restarting" >> $NTPD_LOG_NAME
                        sysevent set ntp_prefix "$CURRENT_WAN_V6_PREFIX"
                        service_start
                    fi
                fi
            fi
        fi
        ;;
    *)
        echo "Usage: $SELF_NAME [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart | wan-status | ipv6_connection_state ]" >&2
        rm -f "$LOCKFILE"
        exit 3
        ;;
esac

echo_t "SERVICE_CHRONYD : end of script" >> $NTPD_LOG_NAME
rm -f "$LOCKFILE"
