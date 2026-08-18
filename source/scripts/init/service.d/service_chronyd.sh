#!/bin/sh
#######################################################################o
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
CHRONY_CONF_TMP=/etc/rdk_chrony.conf
CHRONY_BIN=chronyd
LOCKFILE=/var/tmp/service_chronyd.pid
SYNC_FILE=/tmp/clock-event
NTP_SYNCED_FILE=/tmp/.ntp_time_synced

# Marker recording the WAN interface the running chronyd is bound to (bindacqdevice).
# Written solely by build_chrony_conf.sh at config-build time; read-only here.
WAN_IFACE_MARKER=/tmp/chrony_last_wan_ifname
if [ -f /lib/rdk/t2Shared_api.sh ]; then
      source /lib/rdk/t2Shared_api.sh
fi

# /rdklogs is a tmpfs that starts empty on every boot; the logs/ subdirectory
# may not exist yet when this script fires early in the boot sequence.
# Ensure it exists before any echo_t write so no log lines are silently dropped.
mkdir -p /rdklogs/logs

# chrony_rfc_enabled: returns 0 (true) when the chrony RFC path is active.
# Single source of the RFC check so all gates stay consistent.
chrony_rfc_enabled() {
    [ "$(syscfg get chrony_enabled)" = "true" ]
}

if [ -z "$NTPD_LOG_NAME" ]; then
    NTPD_LOG_NAME=/rdklogs/logs/ntpLog.log
fi

CONNCHECK_FILE="/tmp/connectivity_check_done"

LANIPV6Support=$(sysevent get LANIPv6GUASupport)
CURRENT_WAN_STATUS=$(sysevent get wan-status)
WAN_INTERFACE=$(getWanInterfaceName)

# ──────────────────────────────────────────────────────────────────────────────
# service_init: load syscfg ntp_enabled into environment
# ──────────────────────────────────────────────────────────────────────────────
service_init() {
    FOO=$(utctx_cmd get ntp_enabled)
    eval "$FOO"
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

        tracking=$(chronyc tracking 2>/dev/null)
        if [ -z "$tracking" ]; then
           echo_t "chronyc tracking failed or returned no output, skipping this sample"
           return 1
        fi
		
        leap=$(echo "$tracking" | awk '/^Leap status/ {print $NF}')
        if [ "$leap" = "Normal" ]; then
		    uptime=$(cut -d. -f1 /proc/uptime)
            uptime_ms=$((uptime*1000))
            echo_t "SERVICE_CHRONYD : NTP synchronization is successful at $uptime_ms ms" >> $NTPD_LOG_NAME
			t2ValNotify "SYS_INFO_NTP_SYNC_split" $uptime_ms
            syscfg set ntp_status 3
            sysevent set ntp_time_sync 1
            touch "$SYNC_FILE"
            touch "$NTP_SYNCED_FILE"
            DEVICEFIRSTUSEDATE=$(syscfg get device_first_use_date)
            if [ -z "$DEVICEFIRSTUSEDATE" ] || [ "0" = "$DEVICEFIRSTUSEDATE" ]; then
                syscfg set device_first_use_date "$(date +%Y-%m-%dT%H:%M:%S)"
            fi
			offset=$(echo "$tracking" | awk '/^Last offset/ {print $4}')
	        echo_t "SERVICE_CHRONYD :Initial Offset: $offset"  >> $NTPD_LOG_NAME
            break
        fi

        retry=$((retry + 1))
        sleep 10
    done
    exit 0
}

waitForConnChkFile()
{ 
    echo_t "SERVICE_CHRONYD CONNCHK: Waiting for connection check completion..." >> $NTPD_LOG_NAME
    TIMEOUT=120
    INTERVAL=1

    # Get system uptime in seconds at start
    START_TIME=$(cut -d. -f1 /proc/uptime)

    echo_t "SERVICE_CHRONYD : Waiting for $CONNCHECK_FILE (max ${TIMEOUT}s)..." >> $NTPD_LOG_NAME

    while true; do
        if [ -f "$CONNCHECK_FILE" ]; then
            echo_t "SERVICE_CHRONYD : File $CONNCHECK_FILE present" >> $NTPD_LOG_NAME
            return 0
        fi

        CURRENT_TIME=$(cut -d. -f1 /proc/uptime)
        ELAPSED=$((CURRENT_TIME - START_TIME))

        if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
            echo_t "SERVICE_CHRONYD : Timeout ${TIMEOUT}s expired - file $CONNCHECK_FILE not found" >> $NTPD_LOG_NAME
            return 1
        fi

        sleep "$INTERVAL"
    done
}

# ───────────────────────────────────────────────────────────────────────────────────────────
# chrony_sources_reachable: return 0 if at least one chrony source is reachable
#   Reachability register (reach) is a non-zero octal value once a source has
#   answered at least one recent poll.
# ──────────────────────────────────────────────────────────────────────────────────────────
chrony_selectable_source_available() {
    chronyc -n sources 2>/dev/null | awk '
        /^.[*+]/ { found=1 }
        END { exit (found?0:1) }
    '
}
# ────────────────────────────────────────────────────────────────────────────────────────────
# chrony_offset_exceeds_threshold: return 0 if |Last offset| > 1.0s
# ──────────────────────────────────────────────────────────────────────────────────────────
chrony_offset_exceeds_threshold() {
    local offset
    offset=$(chronyc tracking 2>/dev/null | awk -F: '/Last offset/ {print $2}' | awk '{print $1}')
    [ -n "$offset" ] || return 1
    awk -v o="$offset" 'BEGIN { if (o<0) o=-o; exit (o>1.0?0:1) }'
}
# ──────────────────────────────────────────────────────────────────────────────────────────
# chrony_fast_resync: on network reconnect (chronyd already running and a prior
#   sync happened this boot), bring the clock up to date quickly without
#   restarting chronyd. Uses chronyc control commands only.
#     - No selectable source : online -> burst -> waitsync (bounded) -> makestep
#     - Selectable source     : makestep only when |offset| > 1.0s
# ──────────────────────────────────────────────────────────────────────────────────────────
chrony_fast_resync() {
    # Reconnect only: require chronyd running and a prior sync this boot
    if ! pidof "$CHRONY_BIN" > /dev/null 2>&1; then
        return 0
    fi
    if [ ! -f "$NTP_SYNCED_FILE" ]; then
        # First sync has not happened this boot — let the normal start path handle it
        return 0
    fi
    if chrony_selectable_source_available; then
        # Sources already reachable — a recent measurement exists; step only if needed
        if chrony_offset_exceeds_threshold; then
            echo_t "SERVICE_CHRONYD : fast-resync — selectable sources, offset > 1.0s, stepping" >> $NTPD_LOG_NAME
            chronyc makestep > /dev/null 2>&1
        else
            echo_t "SERVICE_CHRONYD : fast-resync — selectable sources, offset <= 1.0s, no step" >> $NTPD_LOG_NAME
        fi
        return 0
    fi
    # Sources unreachable — re-acquire, force a fresh measurement, then step
    echo_t "SERVICE_CHRONYD : fast-resync — sources unreachable, burst+waitsync+makestep" >> $NTPD_LOG_NAME
        waitForConnChkFile
    chronyc burst 4/4 > /dev/null 2>&1
    # Bounded wait: max 10 tries, no max-correction limit (0). Backgrounded so the
    # sysevent dispatcher and lockfile are not held for the wait duration.
    (
        if chronyc waitsync 10 0 > /dev/null 2>&1; then
            echo_t "SERVICE_CHRONYD : fast-resync — waitsync succeeded, stepping" >> $NTPD_LOG_NAME
        else
            echo_t "SERVICE_CHRONYD : fast-resync — waitsync timed out" >> $NTPD_LOG_NAME
        fi
                chronyc makestep > /dev/null 2>&1
    ) &
}

# ──────────────────────────────────────────────────────────────────────────────
# service_start: main start path
# ──────────────────────────────────────────────────────────────────────────────
service_start() {

   # $1 == "force": skip the wan-status gate (failover path — during failover
   # wan-status is set to "stopped" and would otherwise defer the restart).
    local skip_wan_gate="$1"
    # RFC guard — only run if flag is present
     if ! chrony_rfc_enabled; then
        echo_t "SERVICE_CHRONYD : RFC flag absent — chrony path inactive" >> $NTPD_LOG_NAME
        return 0   
    fi

   # Wait for connectivitycheck to complete
   if [ -f $CONNCHECK_FILE ]; then
       echo_t "SERVICE_CHRONYD : connectivity success $CONNCHECK_FILE present" >> $NTPD_LOG_NAME
   else
       # Exclude XLE device from connectivity check. TODO
       if [ "$BOX_TYPE" != "WNXL11BWL" ];then
           echo_t "SERVICE_CHRONYD : start connectivity check waiting for $CONNCHECK_FILE file" >> $NTPD_LOG_NAME
           waitForConnChkFile
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

if [ "$skip_wan_gate" != "force" ]; then  
    if [ "started" != "$CURRENT_WAN_STATUS" ]; then
            syscfg set ntp_status 2
            sysevent set ${SERVICE_NAME}-status "wan-down"
            return 0
    fi
fi

    # Stop ntpd if running — mutual exclusivity with chrony
    if pidof ntpd > /dev/null 2>&1; then
    echo_t "SERVICE_CHRONYD : stopping ntpd for mutual exclusivity" >> "$NTPD_LOG_NAME"
    systemctl stop ntpd 2>/dev/null
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo_t "SERVICE_CHRONYD : failed to stop ntpd (rc=$rc), not starting chronyd" >> "$NTPD_LOG_NAME"
        sysevent set ${SERVICE_NAME}-status "error"
        return 1
    fi
    sleep 2
   fi
    # Start chronyd — only reaches here when no instance is running
	# start chronyd will populate the config based on latest RFC configuration
    uptime=$(cut -d. -f1 /proc/uptime)
    uptime_ms=$((uptime*1000))
    echo_t "SERVICE_CHRONYD : starting chronyd daemon at $uptime_ms ms" >> $NTPD_LOG_NAME
	t2ValNotify "SYS_INFO_NTP_START_split" $uptime_ms
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
    echo_t "SERVICE_CHRONYD : chronyd started [pid=$(pidof $CHRONY_BIN)]" >> $NTPD_LOG_NAME

   # Stop the metrics collector service for ntpd if it is running
   if systemctl is-active --quiet ntp-data-collector.service; then
       systemctl stop ntp-data-collector.service
   fi
   set_chrony_sync_status &
}

# ──────────────────────────────────────────────────────────────────────────────
# service_stop
# ──────────────────────────────────────────────────────────────────────────────
service_stop() {

    # RFC guard — if chrony is not the active client, nothing to stop
     if ! systemctl is-active --quiet chronyd; then
        echo_t "SERVICE_CHRONYD : chronyd is not running — skipping chronyd stop" >> $NTPD_LOG_NAME
        return 0
    fi
	uptime=$(cut -d. -f1 /proc/uptime)
    uptime_ms=$((uptime*1000))
    echo_t "SERVICE_CHRONYD : stopping chronyd at $uptime_ms ms" >> $NTPD_LOG_NAME
    systemctl stop chronyd 2>/dev/null
    killall chronyd 2>/dev/null
    sysevent set ${SERVICE_NAME}-status "stopped"
	#Stop the chrony NTP metrics collection service
	systemctl stop chrony-ntp-metrics.timer
}


# ──────────────────────────────────────────────────────────────────────────────
# service_wan_iface_change: handler for the current_wan_ifname event.
#   Idempotent, flag-agnostic. Compares the live active WAN interface against the
#   marker recorded by build_chrony_conf.sh (the interface chronyd is bound to):
#     - chronyd not running          → service_start (pidof guard dedupes)
#     - interface unchanged / no mark → strict no-op (no chronyc probing)
#     - interface changed (failover)  → per-interface network-ready gate, then
#                                        restart via service_restart (ExecStartPre
#                                        rebuilds config + re-emits bindacqdevice
#                                        and restamps the marker)
# ──────────────────────────────────────────────────────────────────────────────
service_wan_iface_change() {
    # RFC guard — only act if the chrony path is active
   if ! chrony_rfc_enabled; then 
        echo_t "SERVICE_CHRONYD : current_wan_ifname — RFC flag absent, skipping" >> $NTPD_LOG_NAME
        return 0
        
    fi
    local new old
    new=$(getWanInterfaceName)
    old=$(cat "$WAN_IFACE_MARKER" 2>/dev/null)
    if ! pidof "$CHRONY_BIN" > /dev/null 2>&1; then
        echo_t "SERVICE_CHRONYD : current_wan_ifname — chronyd not running, calling service_start" >> $NTPD_LOG_NAME
        service_start
        return 0
    fi
    if [ -z "$old" ] || [ "$new" = "$old" ]; then
        echo_t "SERVICE_CHRONYD : current_wan_ifname — interface unchanged ('$new'), no action" >> $NTPD_LOG_NAME
        return 0
    fi
    # Interface changed (failover) — rebind chronyd to the new Interface.
    echo_t "SERVICE_CHRONYD : current_wan_ifname — interface changed '$old' -> '$new', restarting chronyd" >> $NTPD_LOG_NAME
    service_stop
        service_start force
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
		  if pidof "$CHRONY_BIN" > /dev/null 2>&1 && [ -f "$NTP_SYNCED_FILE" ]; then
                # Reconnect after a prior sync — fast-resync without restarting chronyd
                echo_t "SERVICE_CHRONYD : wan-status=started pid=$(pidof $CHRONY_BIN) is running (Network Recovery), Resync" >> $NTPD_LOG_NAME
                chrony_fast_resync
            else
                # First sync this boot — service_start() guards against duplicate instances via pidof
                echo_t "SERVICE_CHRONYD : wan-status=started, start chronyd" >> $NTPD_LOG_NAME
                service_start
			fi
        fi
        ;;
		current_wan_ifname)
        echo_t "SERVICE_CHRONYD : current_wan_ifname received. Invoke chrony Handling" >> $NTPD_LOG_NAME
        service_wan_iface_change
        ;;
    *)
        echo "Usage: $SELF_NAME [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart | wan-status | current_wan_ifname ]" >&2
        rm -f "$LOCKFILE"
        exit 3
        ;;
esac

echo_t "SERVICE_CHRONYD : end of script" >> $NTPD_LOG_NAME
rm -f "$LOCKFILE"
