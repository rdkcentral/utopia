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

#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
#
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

#source /etc/utopia/service.d/interface_functions.sh
#source /etc/utopia/service.d/ulog_functions.sh
#source /etc/utopia/service.d/service_lan/wlan.sh
#source /etc/utopia/service.d/event_handler_functions.sh
#source /etc/utopia/service.d/service_lan/lan_hooks.sh
#source /etc/utopia/service.d/brcm_ethernet_helper.sh

source /etc/utopia/service.d/ut_plat.sh
source /etc/utopia/service.d/log_capture_path.sh
source /lib/rdk/t2Shared_api.sh

. /etc/device.properties
IOT_SERVICE_PATH="/etc/utopia/service.d"
SERVICE_MULTINET_PATH="/etc/utopia/service.d/service_multinet"

THIS=/etc/utopia/service.d/lan_handler.sh
SERVICE_NAME="lan_handler"

POSTD_START_FILE="/tmp/.postd_started"

RPI_SPECIFIC=$BOX_TYPE
#args: router IP, subnet mask
ap_addr() {
    if [ "$2" ]; then
        NM="$2"
    else
        NM="255.255.255.0"
    fi
    if [ "$1" ]; then
        IP="$1"
    else
        IP="255.253.252.100"
    fi
    #
    n="${NM%.*}";m="${NM##*.}"
    l="${IP%.*}";r="${IP##*.}";c=""
    if [ "$m" = "0" ]; then
        c=".254"
        m="${n##*.}";n="${n%.*}"
        r="${l##*.}";l="${l%.*}"
        if [ "$m" = "0" ]; then
            c=".255$c"
            m="${n##*.}";n="${n%.*}"
            r="${l##*.}";l="${l%.*}"
            if [ "$m" = "0" ]; then
                c=".255$c"
                m=$n
                r=$l;l=""
            fi
        fi
    else
        let m=$m+1
    fi
    let s=256-$m
    let r=$r/$s*$s
    let r=$r+$s-1
    if [ "$l" ]; then
        SNW="$l.$r$c"
    else
        SNW="$r$c"
    fi

    echo $SNW
}

#Find all instances of bridges that are enabled
find_active_brg_instances(){
    L3NET_ACTIVE_LIST=""
    L3NET_INST=`psmcli getallinst ${IPV4_NV_PREFIX}.`
    for i in $L3NET_INST
    do
        ETH_INST=`psmcli get ${IPV4_NV_PREFIX}.$i.EthLink`
        BRG_INST=`psmcli get ${ETH_DM_PREFIX}.$ETH_INST.l2net`
        isEnabled=`psmcli get dmsb.l2net.$BRG_INST.Enable`
        if [ "$isEnabled" = "TRUE" -o "$isEnabled" = "1" ];
        then
            L3NET_ACTIVE_LIST="${L3NET_ACTIVE_LIST} $i"
        fi
    done

    #This sysevent is checked by ccsp-gwprovapp and it brings up the bridges
    sysevent set l3net_instances "${L3NET_ACTIVE_LIST}"
}

#------------------------------------------------------------------
# ENTRY
#------------------------------------------------------------------


#service_init
echo_t "RDKB_SYSTEM_BOOT_UP_LOG : lan_handler called with $1 $2"
if [ "$1" = "lan-stop" ] && [ "$2" = "NULL" ] ; then
    t2CountNotify "RF_ERROR_LAN_stop"
fi
#echo "lan_handler called with $1 $2" > /dev/console

case "$1" in
   ${SERVICE_NAME}-start)
      service_start
      ;;
   ${SERVICE_NAME}-stop)
      service_stop
      ;;
   ${SERVICE_NAME}-restart)
      echo "service_init : setting lan-restarting to 1"
      sysevent set lan-restarting 1
      service_stop
      service_start
      echo "service_init : setting lan-restarting to 0"
      sysevent set lan-restarting 0
      ;;
   erouter_mode-updated)
      #last_erouter_mode code in ipv4-*-status) may be wrong, when erouter_mode-updated happens after ipv4_*-status event
      SYSCFG_last_erouter_mode=`syscfg get last_erouter_mode`
      SYSCFG_bridge_mode=`syscfg get bridge_mode`
      #if below value is 1, we already used old last_erouter_mode in ipv4_4-status
      SYSEVENT_ipv4_4_status_configured=`sysevent get ipv4_4_status_configured`
      if [ "0" == "$SYSCFG_bridge_mode" ]; then
      if [ "0" != "$SYSCFG_last_erouter_mode" ] && [ 1x = "${SYSEVENT_ipv4_4_status_configured}"x ]; then
          echo_t "lan_handler.sh: erouter_mode-updated, restart lan"
          LAN_INST=`sysevent get primary_lan_l3net`
          LAN_IFNAME=`sysevent get ipv4_${LAN_INST}-ifname`
          sysevent set ipv4-down $LAN_INST
          sysevent set ipv4-up $LAN_INST
      fi
      fi
      ;;
   ipv4_*-status)
        if [ x"up" = x${2} ]; then
            INST=${1#*_}
            INST=${INST%-*}
            RG_MODE=`syscfg get last_erouter_mode`

            LAN_IFNAME=`sysevent get ipv4_${INST}-ifname`
            #if it's ipv4 only, not enable link local
            SYSCFG_last_erouter_mode=`syscfg get last_erouter_mode`
            echo "lan_handler.sh last_erouter_mode: $SYSCFG_last_erouter_mode"


            if [ "1" = "$SYSCFG_last_erouter_mode" ]; then
                echo 0 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/autoconf     # Do not do SLAAC
            else
                echo 1 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/autoconf
                echo 1 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/disable_ipv6
                echo 0 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/disable_ipv6
                echo 1 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/forwarding
            fi


    if [ xbrlan0 = x${LAN_IFNAME} ]; then
        SYSEVT_lan_ipaddr_v6_prev=`sysevent get lan_ipaddr_v6_prev`

        if [ "1" = "$(sysevent get ula_ipv6_enabled)" ] && [ "1" != "$(syscfg get Device_Mode)" ]; then
            SYSEVT_lan_ipaddr_v6=$(sysevent get ipv6_prefix_ula | cut -d "/" -f 1)
            SYSEVT_lan_ipaddr_v6=${SYSEVT_lan_ipaddr_v6}1
        else
            SYSEVT_lan_ipaddr_v6=`sysevent get lan_ipaddr_v6`
        fi
        SYSEVT_lan_prefix_v6=`sysevent get lan_prefix_v6`

        if [ x$SYSEVT_lan_ipaddr_v6_prev != x$SYSEVT_lan_ipaddr_v6 ] && [ -n "$SYSEVT_lan_ipaddr_v6" ]
	 then
            if [ -n "$SYSEVT_lan_ipaddr_v6_prev" ]; then
                ip -6 addr del $SYSEVT_lan_ipaddr_v6_prev/64 dev $LAN_IFNAME valid_lft forever preferred_lft forever
            fi
            ip -6 addr add $SYSEVT_lan_ipaddr_v6/64 dev $LAN_IFNAME valid_lft forever preferred_lft forever
        fi
    fi

            sysevent set current_lan_ipaddr `sysevent get ipv4_${INST}-ipv4addr`

            if [ "$RG_MODE" = "2" -a x"ready" != x`sysevent get start-misc` ]; then
				echo_t "LAN HANDLER : Triggering DHCP server using LAN status based on RG_MODE:2"
                sysevent set lan-status started
                firewall
                if [ ! -f "$POSTD_START_FILE" ];
                then
                    touch $POSTD_START_FILE
                    execute_dir /etc/utopia/post.d/
                fi
            elif [ x"ready" != x`sysevent get start-misc` -a x != x`sysevent get current_wan_ipaddr` -a "0.0.0.0" != `sysevent get current_wan_ipaddr` ]; then
				echo_t "LAN HANDLER : Triggering DHCP server using LAN status based on start misc"
				sysevent set lan-status started
                STARTED_FLG=`sysevent get parcon_nfq_status`

                if [ x"$STARTED_FLG" != x"started" ]; then
		    #l2sd0 interface only applicable for XB3 box.TCXB6-5310
		    if [ "$BOX_TYPE" = "XB3" ]; then
                         BRLAN0_MAC=`ifconfig l2sd0 | grep HWaddr | awk '{print $5}'`
                         ( ( nfq_handler 4 $BRLAN0_MAC & ) & )
                         ( ( nfq_handler 6 $BRLAN0_MAC & ) & )
		    else
			 #dont pass mac address for XB6 box_type, nfq_handler internally will take brlan0 mac.
                         ( ( nfq_handler 4 & ) & )
                         ( ( nfq_handler 6 & ) & )
		    fi
                    sysevent set parcon_nfq_status started
                fi
                isAvailablebrlan1=`ifconfig | grep brlan1`
                if [ -n "$isAvailablebrlan1" ]
                then
                    echo_t "LAN HANDLER : Refreshing LAN from handler"
                    gw_lan_refresh&
                fi
               	firewall
                if [ ! -f "$POSTD_START_FILE" ];
                then
                    touch $POSTD_START_FILE
                    execute_dir /etc/utopia/post.d/
                fi

	elif [ x"ready" != x`sysevent get start-misc` ] && ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ) ; then
               #TCH XBx/TCCBR based startup post.d scripts which includes Firewall restart and dhcp start.
               sysevent set lan-status started
               firewall
               if [ ! -f "$POSTD_START_FILE" ];
                then
                    touch $POSTD_START_FILE
                    execute_dir /etc/utopia/post.d/
                fi
	   else
		echo_t "LAN HANDLER : Triggering DHCP server using LAN status"
                sysevent set lan-status started
		echo_t "LAN HANDLER : Triggering RDKB_FIREWALL_RESTART"
		t2CountNotify "RF_INFO_RDKB_FIREWALL_RESTART"
                sysevent set firewall-restart
            fi

            #sysevent set desired_moca_link_state up

            #firewall_nfq_handler.sh &

            sysevent set lan_start_time $(cut -d. -f1 /proc/uptime)

            if [ "4" = $INST ];then
                sysevent set ipv4_4_status_configured 1
            fi

            #disable dnsmasq when ipv6 only mode and DSlite is disabled
            DSLITE_ENABLED=`sysevent get dslite_enabled`
	    	DHCP_PROGRESS=`sysevent get dhcp_server-progress`
			echo_t "LAN HANDLER : DHCP configuration status got is : $DHCP_PROGRESS"
            if [ "2" = "$SYSCFG_last_erouter_mode" ] && [ "x1" != x$DSLITE_ENABLED ]; then
                sysevent set dhcp_server-stop
            elif [ "0" != "$SYSCFG_last_erouter_mode" ] && [ "$DHCP_PROGRESS" != "inprogress" ] ; then
				echo_t "LAN HANDLER : Triggering dhcp start based on last erouter mode"
                sysevent set dhcp_server-start
            fi

            LAN_IPV6_PREFIX=`sysevent get ipv6_prefix`
            if [ -n "$LAN_IPV6_PREFIX" ] ; then
                    ip -6 route add $LAN_IPV6_PREFIX dev $LAN_IFNAME
            fi
        else
            if [ x"started" = x`sysevent get lan-status` ]; then
				#kill `pidof CcspHomeSecurity`
                sysevent set lan-status stopped
		echo_t "LAN HANDLER : setting lan status stopped"
                #sysevent set desired_moca_link_state down
            fi
        fi

        HOME_LAN_ISOLATION=`psmcli get dmsb.l2net.HomeNetworkIsolation`
        if [ "$HOME_LAN_ISOLATION" = "1" ];then
            echo "Setting up brlan10 for HOME_LAN_ISOLATION"
            sysevent set multinet-up 9
        fi

        echo_t "LAN HANDLER : Triggering RDKB_FIREWALL_RESTART after nfqhandler"
	t2CountNotify "RF_INFO_RDKB_FIREWALL_RESTART"
        sysevent set firewall-restart
	if [ -e "/usr/bin/print_uptime" ]; then
	    /usr/bin/print_uptime "Laninit_complete"
	fi

        uptime=$(cut -d. -f1 /proc/uptime)
	if [ -e "/usr/bin/onboarding_log" ]; then
	    /usr/bin/onboarding_log "Lan_init_complete:$uptime"
	fi
	t2ValNotify "btime_laninit_split" "$uptime"
     ;;

   ipv4-resync)
        LAN_INST=`sysevent get primary_lan_l3net`
        if [ x"$2" = x"$LAN_INST" ]; then
            eval "`psmcli get -e LAN_IP ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_IP LAN_SUB ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_SUBNET`"
            AP_ADDR="`ap_addr $LAN_IP $LAN_SUB`"
            psmcli set dmsb.atom.l3net.${LAN_INST}.$IPV4_NV_IP $AP_ADDR dmsb.atom.l3net.${LAN_INST}.$IPV4_NV_SUBNET $LAN_SUB
            dmcli eRT setv Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting bool 'true' 'true'
            if [ "$BOX_TYPE" = "XB3" ]; then
                rpcclient $ATOM_ARPING_IP "sh /usr/ccsp/wifi/br0_ip.sh $AP_ADDR $LAN_SUB"
            fi

        fi
   ;;
   multinet-resync)
        dmcli eRT setv Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting bool 'true' 'true'

   ;;

   pnm-status | bring-lan)
	if [ -e "/usr/bin/print_uptime" ]; then
            /usr/bin/print_uptime "Lan_init_start"
        fi
        uptime=$(cut -d. -f1 /proc/uptime)
	if [ -e "/usr/bin/onboarding_log" ]; then
	    /usr/bin/onboarding_log "Lan_init_start:$uptime"
	fi
   	if [ x = x"`sysevent get lan_handler_async`" ]; then
        eval `psmcli get -e INST dmsb.MultiLAN.PrimaryLAN_l3net L2INST dmsb.MultiLAN.PrimaryLAN_l2net BRPORT dmsb.MultiLAN.PrimaryLAN_brport HSINST dmsb.MultiLAN.HomeSecurity_l3net`
	if [ -z "$INST" ]
	    then
		echo_t "THE INSTANT=$INST"
		echo_t "THE INSTANT=$INST"
        #(use a simpler test than this -- but Hacky, since it assumes everything we want is not XB3!!)if [ "$BOX_TYPE" = "TCCBR" ] || [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Technicolor" ] || [ "$BOX_TYPE" = "XB7" -a "$MANUFACTURE" = "Technicolor" ] ; then
	if ( [ "$BOX_TYPE" != "XB3" ] && ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ) )  || [ "$BOX_TYPE" = "rpi" ] ; then
                	COUNTER=1
			while [ $COUNTER -lt 10 ]; do
				echo_t "RDKB_SYSTEM_BOOT_UP_LOG : INST returned null , retrying $COUNTER"
				INST=`psmcli get dmsb.MultiLAN.PrimaryLAN_l3net`
				echo_t "THE INSTANCE=$INST"
				sleep 1
				if [ x != x$INST ]; then
					echo_t "BREAK THE INSTANCE=$INST"
		   			break
				fi
			        COUNTER=`expr $COUNTER + 1`
				echo_t "THE COUNTER =$COUNTER"
			done
		else
			echo_t "RDKB_SYSTEM_BOOT_UP_LOG : INST rerurned null, retrying"
			INST=`psmcli get dmsb.MultiLAN.PrimaryLAN_l3net`
		fi

	fi
	if [ -z "$L2INST" ]
	    then
		echo_t "RDKB_SYSTEM_BOOT_UP_LOG : L2INST returned null, retrying"
		L2INST=`psmcli get dmsb.MultiLAN.PrimaryLAN_l2net`
	fi
	if [ -z "$BRPORT" ]
	    then
		echo_t "RDKB_SYSTEM_BOOT_UP_LOG : BRPORT returned null, retrying"
		BRPORT=`psmcli get dmsb.MultiLAN.PrimaryLAN_brport`
	fi
	if [ -z "$HSINST" ]
	    then
		echo_t "RDKB_SYSTEM_BOOT_UP_LOG : HSINST returned null, retrying"
		HSINST=`psmcli get dmsb.MultiLAN.HomeSecurity_l3net`
	fi
   	if [ x != x$INST ]; then
		echo_t "SO FAR SO GOOD ALL IS WELL SENDING L3 NET EVENT"
                async="`sysevent async ipv4_${INST}-status $THIS`"
                sysevent set lan_handler_async "$async"
                sysevent set primary_lan_l2net ${L2INST}
                sysevent set primary_lan_brport ${BRPORT}
                sysevent set homesecurity_lan_l3net ${HSINST}
                sysevent set primary_lan_l3net ${INST}
	#BRLAN0 ISSUE : Manually invoking lan-start to fix brlan0 failure during intial booting. Root cause for event has to be identified
	   	if [ "$RPI_SPECIFIC" = "rpi" ]; then
        		        sleep 2
                                L3NET=`sysevent get primary_lan_l3net`
                                if [ -z "$L3NET" ]; then
                                     L3NET=4
                                     sysevent set primary_lan_l3net $L3NET
                                fi
                fi
	elif [ "$BOX_TYPE" = "TCCBR" ]; then
		if [ -z "$INST" ]; then
			echo "*****SET THE PRIMARY LAN ******" > /dev/null
  			syseven set primary_lan_l3net 4
		fi
	fi

        fi
    #Assuming we have a variable set in system defaults for Multilan enabled build
    MULTILAN_FEATURE=$(syscfg get MULTILAN_FEATURE)
	if [ "$MULTILAN_FEATURE" = "1" ]; then
    #This is to check for all the active instances of bridges that are created
    find_active_brg_instances
	fi
      
        # Laninit complete happens as part of the service_dhcp_server.sh itself.Firewall restart happens as part of service_ip4 itself.In the above code we #are setting many sysevents related to LAN hence adding the lan_init complete logs here.Also as oer the logs , we moving to bring the eth interface after this.Hence lan in
	# compelte can brought in here.
        if [ "$RPI_SPECIFIC" = "rpi" ]; then
            if [ -e "/usr/bin/print_uptime" ]; then
                /usr/bin/print_uptime "Laninit_complete"
            fi
        fi



   ;;

   iot_status)
            echo_t "IOT_LOG : lan_handler received $2 status"

            if [ "$2" = "up" ]
            then
               $SERVICE_MULTINET_PATH/handle_sw.sh "addIotVlan" 0 106 "-t"
               echo_t "IOT_LOG : lan_handler done with handle_sw call"
               $IOT_SERVICE_PATH/iot_service.sh "up"
            elif [ "$2" = "down" ]
            then
               $IOT_SERVICE_PATH/iot_service.sh "down"
            elif [ "$2" = "bootup" ]
            then
               $IOT_SERVICE_PATH/iot_service.sh "bootup"
            fi
            echo_t "IOT_LOG : lan_handler done with IOT service call"

   ;;

   lan-restart)
        syscfg_lanip=`syscfg get lan_ipaddr`
        syscfg_lansub=`syscfg get lan_netmask`
        LAN_INST=`sysevent get primary_lan_l3net`
        eval "`psmcli get -e LAN_IP ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_IP LAN_SUB ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_SUBNET`"

        if [ x$syscfg_lanip != x$LAN_IP -o x$syscfg_lansub != x$LAN_SUB ]; then
            psmcli set ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_IP $syscfg_lanip ${IPV4_NV_PREFIX}.${LAN_INST}.$IPV4_NV_SUBNET $syscfg_lansub

            # TODO check for lan network being up ?
            sysevent set ipv4-resync $LAN_INST
        fi

        #handle ipv6 address on brlan0. Because it's difficult to add ipv6 operation in ipv4 process. So just put here as a temporary method
        SYSEVT_lan_ipaddr_v6_prev=`sysevent get lan_ipaddr_v6_prev`

        if [ "1" = "$(sysevent get ula_ipv6_enabled)" ] && [ "1" != "$(syscfg get Device_Mode)" ]; then
            SYSEVT_lan_ipaddr_v6=$(sysevent get ipv6_prefix_ula | cut -d "/" -f 1)
            SYSEVT_lan_ipaddr_v6=${SYSEVT_lan_ipaddr_v6}1
        else
            SYSEVT_lan_ipaddr_v6=`sysevent get lan_ipaddr_v6`
        fi

        SYSEVT_lan_prefix_v6=`sysevent get lan_prefix_v6`
        LAN_IFNAME=`sysevent get ipv4_${LAN_INST}-ifname`
	    LAN_RESTARTED=`sysevent get lan_restarted`
            echo_t "LAN_RESTART : Check Lan Restart Status"

        if [ x$SYSEVT_lan_ipaddr_v6_prev != x$SYSEVT_lan_ipaddr_v6 ] || [ x"true" = x$LAN_RESTARTED ]; then
            if [ -n "$SYSEVT_lan_ipaddr_v6_prev" ]; then
                ip -6 addr del $SYSEVT_lan_ipaddr_v6_prev/64 dev $LAN_IFNAME valid_lft forever preferred_lft forever
            fi
            ip -6 addr add $SYSEVT_lan_ipaddr_v6/64 dev $LAN_IFNAME valid_lft forever preferred_lft forever
        fi
	lan_restarted_value="true"
	sysevent set lan_restarted $lan_restarted_value

   ;;
   # TODO: register for lan-stop and lan-start
   lan-stop)
        LAN_INST=`sysevent get primary_lan_l3net`
        LAN_IFNAME=`sysevent get ipv4_${LAN_INST}-ifname`
        sysevent set ipv4-down $LAN_INST
        echo 1 > /proc/sys/net/ipv6/conf/$LAN_IFNAME/disable_ipv6

        SYSEVT_lan_ipaddr_v6_prev=`sysevent get lan_ipaddr_v6_prev`
        SYSEVT_lan_prefix_v6=`sysevent get lan_prefix_v6`
        ip -6 addr flush dev $LAN_IFNAME

        #we need to restart necessary application when lan restart
        #monitor will start dibbler
        dibbler-server stop
   ;;

   lan-start)
        if [ "$RPI_SPECIFIC" = "rpi" ] || [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "SCER11BEL" ]; then
             L3Net=`sysevent get primary_lan_l3net`
             if [ -z "$L3Net" ]; then
                 echo_t "RDKB_SYSTEM_BOOT_UP_LOG : L3Net is null"
                     if [ "$RPI_SPECIFIC" = "rpi" ]; then
                         L3Net=4
                         sysevent set primary_lan_l3net $L3Net
                     else
                         COUNTER=1
                         while [ $COUNTER -le 5 ]; do
                             echo_t "RDKB_SYSTEM_BOOT_UP_LOG : L3Net is null retrying $COUNTER"
                             sleep 1
                             L3Net=`sysevent get primary_lan_l3net`
                             if [ x != x$L3Net ]; then
                                 break
                             fi
                             COUNTER=`expr $COUNTER + 1`
                         done
                     fi
             fi
        fi
        # TODO call the restart routine
        sysevent set ipv4-up `sysevent get primary_lan_l3net`
   ;;
   *)
      echo "Usage: service-${SERVICE_NAME} [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart]" > /dev/console
      exit 3
      ;;
esac
