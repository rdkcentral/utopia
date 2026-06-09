#!/bin/sh

##################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

#Script to put the private LAN into pseudo bridge mode

source /etc/utopia/service.d/hostname_functions.sh
source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/event_handler_functions.sh
source /etc/utopia/service.d/log_capture_path.sh

# Runtime/default knobs for bridge mode behavior.
POSTD_START_FILE="/tmp/.postd_started"

SERVICE_NAME="bridge"

#Mode passed in by commandline, can be "enable" or "disable"
SCRIPT_MODE="$1"

wait_till_steady_state ()
{
    LSERVICE=$1
    TRIES=1
    while [ "30" -ge "$TRIES" ] ; do
        LSTATUS=`sysevent get "${LSERVICE}"-status`
        if [ "starting" = "$LSTATUS" ] || [ "stopping" = "$LSTATUS" ] || [ "partial" = "$LSTATUS" ] ; then
            sleep 1
            TRIES=`expr $TRIES + 1`
        else
            return
        fi
    done
    echo "$0: Timed out waiting for $LSERVICE to be in a steady state"
}

flush_connection_info(){
    #Flush connection tracking - This will also flush packet processor sessions
    conntrack_flush
}

# Local GUI management veth pair interface definitions for bridge mode.
GUI_IF="lan0"
GUI_PEER_IF="llan0"
LAN_IP=`syscfg get lan_ipaddr`
LAN_NETMASK=`syscfg get lan_netmask`
BRIDGE_NAME=`syscfg get lan_ifname`

# Separate routing table used to ensure responses from the web UI
# go directly to the LAN interface, not out the WAN.
BRIDGE_MODE_TABLE=69

#--------------------------------------------------------------
# setup_gui_iface
#   Create the lan0/llan0 veth pair for local GUI access in bridge mode,
#   disable IPv6 on them, bring up llan0 in promisc mode, and assign
#   management IP to lan0.
#--------------------------------------------------------------
setup_gui_iface(){
    # Create veth pair
    ip link add ${GUI_IF} type veth peer name ${GUI_PEER_IF}
    if [ $? -ne 0 ]; then
        echo "Failed to create veth pair ${GUI_IF} <-> ${GUI_PEER_IF}"
        return 1
    fi

    # Disable IPv6 on both ends
    echo 1 > /proc/sys/net/ipv6/conf/${GUI_IF}/disable_ipv6
    echo 1 > /proc/sys/net/ipv6/conf/${GUI_PEER_IF}/disable_ipv6

    # Bring up llan0 in promiscuous mode (bridge_util adds it to brlan0 via getVendorIfaces)
    ifconfig ${GUI_PEER_IF} promisc up

    # Assign management IP to lan0 so local GUI is reachable
    ifconfig ${GUI_IF} ${LAN_IP} netmask ${LAN_NETMASK} up
}

#--------------------------------------------------------------
# teardown_gui_iface
#   Remove the lan0/llan0 veth pair when moving back to router mode.
#   Deleting lan0 automatically destroys its peer llan0.
#--------------------------------------------------------------
teardown_gui_iface(){
    ifconfig ${GUI_IF} down 2>/dev/null
    ip link delete ${GUI_IF} 2>/dev/null
}

#--------------------------------------------------------------
# routing_rules
#   Add/remove policy routing so replies from management IP (10.0.0.1)
#   go back out lan0 instead of the default WAN route.
#--------------------------------------------------------------
routing_rules(){
    if [ "$1" = "enable" ] ; then
        ip rule add from ${LAN_IP} lookup ${BRIDGE_MODE_TABLE}
        ip route add table ${BRIDGE_MODE_TABLE} default dev ${GUI_IF}
    else
        ip rule del from ${LAN_IP} lookup ${BRIDGE_MODE_TABLE} 2>/dev/null
        ip route flush table ${BRIDGE_MODE_TABLE} 2>/dev/null
    fi
}

#Enable pseudo bridge mode.  If already enabled, just refresh parameters (in case bridges were torn down and rebuilt)
service_start(){
    wait_till_steady_state ${SERVICE_NAME}
    STATUS=`sysevent get ${SERVICE_NAME}-status`
    if [ "started" != "$STATUS" ] ; then
        sysevent set ${SERVICE_NAME}-errinfo
        sysevent set ${SERVICE_NAME}-status starting

        # Create lan0/llan0 veth pair before sync so bridge_util can attach llan0 to brlan0.
        setup_gui_iface

        # Policy routing so replies from management IP go back out lan0.
        routing_rules enable

        sysevent set  multinet-syncMembers $INSTANCE

        prepare_hostname

        #Flush connection tracking and packet processor sessions to avoid stale information
        flush_connection_info

        sysevent set ${SERVICE_NAME}-errinfo
        sysevent set ${SERVICE_NAME}-status started
    fi
}

service_stop(){
    wait_till_steady_state ${SERVICE_NAME}
    STATUS=`sysevent get ${SERVICE_NAME}-status`
    if [ "stopped" != "$STATUS" ] ; then

        sysevent set ${SERVICE_NAME}-errinfo
        sysevent set ${SERVICE_NAME}-status stopping

        #Sync bridge members
        MULTILAN_FEATURE=$(syscfg get MULTILAN_FEATURE)
        if [ "$MULTILAN_FEATURE" = "1" ]; then
            sysevent set multinet-down "$INSTANCE"
            sysevent set multinet-up "$INSTANCE"
        else
            sysevent set  multinet-syncMembers $INSTANCE
        fi

        #Flush connection tracking and packet processor sessions to avoid stale information
        flush_connection_info

        # Remove policy routing and tear down lan0/llan0 veth pair.
        routing_rules disable
        teardown_gui_iface
        
        sysevent set ${SERVICE_NAME}-errinfo
        sysevent set ${SERVICE_NAME}-status stopped

    fi
}

#--------------------------------------------------------------
# service_init
#--------------------------------------------------------------
service_init ()
{
    # Get all provisioning data
    # Figure out the names and addresses of the lan interface
    #
    # SYSCFG_lan_ethernet_physical_ifnames is the physical ethernet interfaces that
    # will be part of the lan
    #
    # SYSCFG_lan_wl_physical_ifnames is the names of each wireless interface as known
    # to the operating system

    SYSCFG_FAILED='false'
    FOO=`utctx_cmd get bridge_mode lan_ifname lan_ethernet_physical_ifnames lan_wl_physical_ifnames wan_physical_ifname bridge_ipaddr bridge_netmask bridge_default_gateway bridge_nameserver1 bridge_nameserver2 bridge_nameserver3 bridge_domain hostname`
    eval "$FOO"
    if [ $SYSCFG_FAILED = 'true' ] ; then
        ulog bridge status "$PID utctx failed to get some configuration data"
        ulog bridge status "$PID BRIDGE CANNOT BE CONTROLLED"
        exit
    fi

    if [ -z "$SYSCFG_hostname" ] ; then
        SYSCFG_hostname="Utopia"
    fi

    LAN_IFNAMES="$SYSCFG_lan_ethernet_physical_ifnames"

    # if we are using wireless interfafes then add them
    if [ "" != "$SYSCFG_lan_wl_physical_ifnames" ] ; then
        LAN_IFNAMES="$LAN_IFNAMES $SYSCFG_lan_wl_physical_ifnames"
    fi
}


echo "service_bridge_generic.sh called with $1 $2"
service_init

# Determine the primary LAN l2net instance used for multinet sync operations.
INSTANCE=`sysevent get primary_lan_l2net`
if [ -z "$INSTANCE" ];then
    INSTANCE=`psmcli get dmsb.MultiLAN.PrimaryLAN_l2net`
fi

# Service dispatcher for bridge mode lifecycle transitions.
case "$1" in
    "${SERVICE_NAME}-start")

        firewall firewall-stop
        service_start
        if [ ! -f "$POSTD_START_FILE" ];
        then
            touch $POSTD_START_FILE
            execute_dir /etc/utopia/post.d/
        fi
        gw_lan_refresh
        sysevent set firewall-restart

    ;;
    "${SERVICE_NAME}-stop")

        service_stop
        if [ ! -f "$POSTD_START_FILE" ];
        then
            touch $POSTD_START_FILE
            execute_dir /etc/utopia/post.d/
        fi
        gw_lan_refresh
        sysevent set firewall-restart
    ;;
    "${SERVICE_NAME}-restart")

        firewall firewall-stop
        sysevent set lan-restarting "$INSTANCE"
        service_stop
        service_start
        sysevent set lan-restarting 0
        gw_lan_refresh
        sysevent set firewall-restart
    ;;
    *)
        echo "Usage: service-${SERVICE_NAME} [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart]" > /dev/console
        exit 3
    ;;
esac
