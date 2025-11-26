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

#------------------------------------------------------------------
#------------------------------------------------------------------

source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/log_capture_path.sh
source /etc/log_timestamp.sh    # define 'echo_t' ASAP!
source /etc/waninfo.sh
source /etc/device.properties

SERVICE_NAME="ntpd"
SELF_NAME="`basename "$0"`"
NTP_CONF=/etc/ntp.conf
NTP_CONF_TMP=/tmp/ntp.conf
NTP_CONF_QUICK_SYNC=/tmp/ntp_quick_sync.conf
LOCKFILE=/var/tmp/service_ntpd.pid
BIN=ntpd
WAN_IPv6_UP=0
QUICK_SYNC_PID=""
QUICK_SYNC_DONE=0

STATIC_INTERFACE=$NTPD_INTERFACE
WAN_INTERFACE=$(getWanInterfaceName)

LANIPV6Support=`sysevent get LANIPv6GUASupport`
ntpHealthCheck=`sysevent get NTPHealthCheckSupport`

if [ -f /lib/rdk/t2Shared_api.sh ]; then
      source /lib/rdk/t2Shared_api.sh
fi

CONNCHECK_FILE="/tmp/connectivity_check_done" #This file will be created once connection check success with comcast connectivity server


if [ -z "$NTPD_LOG_NAME" ];then
NTPD_LOG_NAME=/rdklogs/logs/ntpLog.log
fi
NSLOOKUP=nslookup
NTP_SERVER_MODE="DEFAULT"
#Function to  check if given ntp server supports ipv4 or ipv6 or both
#returns:
#1: v4 only
#2: v6 only
#3: both v4 and v6

function check_ntp_server_mode()
{
    local ipv4
    local ipv4_support 
    local NTP_SERVER
    local ret

    NTP_SERVER=$1

    echo_t "NTPD Quick sync : Initiating DNS lookup for server $NTP_SERVER " >> $NTPD_LOG_NAME
    echo "$NTP_SERVER" | grep -i '^[a-z].[a-z]'
    ret=$?

    if [ $ret -eq 1 ]; then
        echo_t "NTPD Quick sync : NTP server configured is not in URL format " >> $NTPD_LOG_NAME
        echo_t "NTPD Quick sync :  Skipping DNS lookup" >> $NTPD_LOG_NAME
        #This is not in URL format.
        echo "$NTP_SERVER" | grep -q ".*:.*"
        ret=$?
        if [ $ret -eq 0 ]; then
            NTP_SERVER_MODE="IPV6_ONLY"
            return
        else
            ipv4=$(echo "$NTP_SERVER" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            if [ -n "$ipv4" ]; then
                NTP_SERVER_MODE="IPV4_ONLY"
                return
            fi
        fi
    fi

    if ! which "$NSLOOKUP"  >/dev/null; then
        echo_t "NTPD Quick sync : $NSLOOKUP utility not present" >> $NTPD_LOG_NAME
        echo_t "NTPD Quick sync :  Skipping DNS lookup" >> $NTPD_LOG_NAME
        return
    fi

    $NSLOOKUP "$NTP_SERVER" > /tmp/ntp_server_lookup

    sed '/'"$NTP_SERVER"'/,$!d' /tmp/ntp_server_lookup | grep "Address" | awk '{ print $3 }' > /tmp/ntp_address
    #check if atleast one ipv6 address available
    while IFS= read -r line
    do
        echo $line | grep -q ".*:.*"
        ret=$?
        if [ $ret -eq 0 ]; then
            ipv6_support=1
            break
        fi
    done < /tmp/ntp_address

    #check if atleast one ipv4 address available
    while IFS= read -r line
    do
        ipv4=$(echo $line | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
        if [ -n "$ipv4" ]; then
            ipv4_support=1
            break
        fi
    done < /tmp/ntp_address

    if [ "$ipv6_support" = "1" ] && [ "$ipv4_support" = "1" ]; then
        NTP_SERVER_MODE="IPV4_IPV6"
    elif [ "$ipv4_support" = "1" ]; then
        NTP_SERVER_MODE="IPV4_ONLY"
    elif [ "$ipv6_support" = "1" ]; then
        NTP_SERVER_MODE="IPV6_ONLY"
    else
        #NTP server is down
        NTP_SERVER_MODE="ERROR"
    fi

    rm -f /tmp/ntp_server_lookup
    rm -f /tmp/ntp_address

    return
}

wan_wait () 
{
    local WAN_UP=""
    local WAN_IPv4=""
    local WAN_IPv6=""
    retry=0
    MAX_RETRY=20

    while [ ! "$WAN_UP" ]
    do
       retry=`expr $retry + 1`

       #Make sure WAN interface has an IPv4 or IPv6 address before telling NTP to listen on Interface
       WAN_IPv4=`ifconfig -a "$WAN_INTERFACE" | grep inet | grep -v inet6 | tr -s " " | cut -d ":" -f2 | cut -d " " -f1 | head -n1`

       if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$LANIPV6Support" = "true" ]; then
           CURRENT_WAN_IPV6_STATUS=`sysevent get ipv6_connection_state`
           if [ "up" = "$CURRENT_WAN_IPV6_STATUS" ] ; then
               ULAprefix=`sysevent get ula_address |cut -d ':' -f1`
               if [ -z "$ULAprefix" ]; then
                   WAN_IPv6=`ifconfig "$NTPD_IPV6_INTERFACE" | grep inet6 | grep Global | awk '/inet6/{print $3}' | grep -v 'fdd7' | cut -d '/' -f1 | head -n1`
                else
                    WAN_IPv6=`ifconfig "$NTPD_IPV6_INTERFACE" | grep inet6 | grep Global | awk '/inet6/{print $3}' | grep -v 'fdd7' | grep -v "$ULAprefix" | cut -d '/' -f1 | head -n1`
               fi
               WAN_IPv6_UP=1
		# SHARMAN-2301
                #This change is for UK MAP-T SR213. When  NTP servers are IPv4 only and there is no IPv4 WAN IP on the interface we will use $NTPD_IPV6_INTERFACE(currently brlan0) ipv4 ip to sort ntpd daemon socket problems and routing.
		if [ "$BOX_TYPE" = "SR213" ] || [ "$LANIPV6Support" == "true" ]; then
		    MAPT_STATS=$(sysevent get mapt_config_flag)
		    echo_t "SERVICE_NTPD : MAPT_STATS=$MAPT_STATS"
		    if [ x"$MAPT_STATS" = x"set" ]; then
			IPV4_CONN_STATE=$(sysevent get ipv4_connection_state)
			echo_t "SERVICE_NTPD : IPV4_CONN_STATE=$IPV4_CONN_STATE"
                        if [ x"$IPV4_CONN_STATE" != x"up" ]; then
			    WAN_IPv4=`ifconfig "$NTPD_IPV6_INTERFACE" | grep inet\ \addr | cut -d ':' -f2 |cut -d ' ' -f1`
			fi
		    fi
		fi
           fi
       else
           WAN_IPv6=`ifconfig "$WAN_INTERFACE" | grep inet6 | grep Global | awk '/inet6/{print $3}' | cut -d '/' -f1 | head -n1`
       fi

       if [ -n "$WAN_IPv4" ] || [ -n "$WAN_IPv6" ]; then
          if [ "$2" = "quickSync" ];then
          	# Quick Sync Needs an IP and Not Interface As changes in Interface as Quick Sync Runs Causes Errors
                check_ntp_server_mode "$SYSCFG_ntp_server1"
          	if [ "$NTP_SERVER_MODE" = "IPV4_IPV6" ];then
                    #dual stack mode
                    echo_t "NTPD Quick sync : NTP server supports IPV4 and IPV6" >> $NTPD_LOG_NAME
                    if [ -n "$WAN_IPv6" ]; then
                        echo_t "NTPD Quick sync : Using wan interface IPV6 address $WAN_IPv6" >> $NTPD_LOG_NAME
          		WAN_UP=$WAN_IPv6
                    else
                        echo_t "NTPD Quick sync : No IPV6 address configured on WAN. Using IPV4 address $WAN_IPv4" >> $NTPD_LOG_NAME
          		WAN_UP=$WAN_IPv4
                    fi
          	elif [ "$NTP_SERVER_MODE" = "IPV4_ONLY" ]; then
                    #V4 only mode
                    echo_t "NTPD Quick sync : NTP server supports IPV4 only" >> $NTPD_LOG_NAME
                    if [ -n "$WAN_IPv4" ]; then
                        echo_t "NTPD Quick sync : Using wan interface IPV4 address $WAN_IPv4" >> $NTPD_LOG_NAME
          		WAN_UP=$WAN_IPv4
                    else
                        echo_t "NTPD Quick sync : No IPV4 address configured on WAN" >> $NTPD_LOG_NAME
                    fi
          	elif [ "$NTP_SERVER_MODE" = "IPV6_ONLY" ]; then
                    #V6 only mode
                    echo_t "NTPD Quick sync : NTP server supports IPV6 only" >> $NTPD_LOG_NAME
                    if [ -n "$WAN_IPv6" ]; then
                        echo_t "NTPD Quick sync : Using wan interface IPV6 address $WAN_IPv6" >> $NTPD_LOG_NAME
          	        WAN_UP=$WAN_IPv6
                    else
                        echo_t "NTPD Quick sync : No WAN IPV6 configured" >> $NTPD_LOG_NAME
                    fi
          	elif [ "$NTP_SERVER_MODE" = "DEFAULT" ]; then
                    #If a pltform does not have the uitlity to check DNS, set default values
                    if [ -n "$WAN_IPv6" ];then
                        WAN_UP=$WAN_IPv6
                    else
                        WAN_UP=$WAN_IPv4
                    fi
                else
                    echo_t "NTPD Quick sync : NTP server DNS lookup failed for URL $SYSCFG_ntp_server1" >> $NTPD_LOG_NAME
          	fi
          else
          	WAN_UP=$WAN_INTERFACE
          fi
          break
       fi
       sleep 6
       WAN_INTERFACE=$(getWanInterfaceName)
       if [ $retry -eq $MAX_RETRY ];then
          echo_t "SERVICE_NTPD : WAN IP not acquired after max etries. Exiting !!!" >> $NTPD_LOG_NAME
          break
       fi
    done

 eval $1=\$WAN_UP
}

set_ntp_quicksync_status ()
{
    ### -gq the expectation is ntpd exits once it successfully sets the clock, which may happen as quick as 10 sec
    ### reap the exit code of ntpd quick sync,set the ntp status accordingly..
    ### in problematic case,wait for 120 seconds,then break off.
    retry_timeout=1
    while true
    do
       if [ "$retry_timeout" -gt "24" ]; then
          echo_t "NTP quick sync not succeeded,retry exceeded" >> $NTPD_LOG_NAME
          break
       fi
       if [ ! -d "/proc/$QUICK_SYNC_PID" ]; then
          wait $QUICK_SYNC_PID
          ntpd_exit_code=$?
		  
          if [ "$ntpd_exit_code" -eq 0 ]; then
		     uptime=$(cut -d. -f1 /proc/uptime)
             uptime_ms=$((uptime*1000))  
			 sh /lib/rdk/logMilestone.sh "QUICK_SYNC-DONE"
             echo_t "NTP quick sync succeeded,set ntp status at $uptime_ms" >> $NTPD_LOG_NAME
			 t2ValNotify  "SYST_INFO_NTP_SYNC_split" $uptime_ms
             systemctl restart ntp-data-collector.service
             syscfg set ntp_status 3
             #Set FirstUseDate in Syscfg if this is the first time we are doing a successful NTP Sych
             DEVICEFIRSTUSEDATE=`syscfg get device_first_use_date`
             if [ -z "$DEVICEFIRSTUSEDATE" ] || [ "0" = "$DEVICEFIRSTUSEDATE" ]; then
                FIRSTUSEDATE=`date +%Y-%m-%dT%H:%M:%S`
                syscfg set device_first_use_date "$FIRSTUSEDATE"
             fi
             sysevent set ntp_time_sync 1
             QUICK_SYNC_DONE=1
			  uptime=$(cut -d. -f1 /proc/uptime)
             uptime_ms=$((uptime*1000))  
	         touch /tmp/clock-event
		     sh /lib/rdk/logMilestone.sh "TIMESYNC_SUCCESS"
             echo_t "DEBUG : clock-event file created in /tmp. Time Sync is successful. Xconf is good to start at $uptime_ms" >> $NTPD_LOG_NAME
             break
	  elif [ "$ntpd_exit_code" -eq 127 ]; then
             echo_t "NTP quick sync not succeeded,PID has terminated or is unknown by the shell" >> $NTPD_LOG_NAME
			 t2CountNotify "SYST_ERROR_NTP_UNSYNC"
	     break
          fi
       else
         retry_timeout=`expr $retry_timeout + 1`
         sleep 5
       fi
    done
}

set_ntp_driftsync_status ()
{
  ####QUICK SYNC not succeeded,lets wait for ntpd daemon to adjust the clock
  ####this may slow set compared to ntpd -gq, ntpd takes some ntp poll intervals(def 64s)
  ####our local clock,stratum will be 16,until synchronised with the server.
  ####in worst case if we are not synced with server, break the loop after 20 mins
  #### Note we can't wait more than 300 secs in sysevent context, this supposed to be run
  #### in background
   if [ -n "$(which ntpq)" ];then
      retry=1
      while true
      do
      #Check if ntpq -c rv returns any value
        ntpq_value=`ntpq -c rv`
        if [ -z "$ntpq_value" ]; then
            ntpq_value=`ntpq -4 -c rv`
        fi
        if [ -n "$ntpq_value" ]; then
            sync_status=`"$ntpq_value" | grep "stratum=16"`
            if [ -z "$sync_status" ]; then
            echo_t "SERVICE_NTPD : ntpd time synced , setting the status" >> $NTPD_LOG_NAME
            syscfg set ntp_status 3
            sysevent set ntp_time_sync 1
            touch /tmp/clock-event
            echo_t "DEBUG : clock-event file created in /tmp. Time Sync is successful. Xconf is good to start" >> $NTPD_LOG_NAME
            #Set FirstUseDate in Syscfg if this is the first time we are doing a successful NTP Sych
            DEVICEFIRSTUSEDATE=`syscfg get device_first_use_date`
            if [ -z "$DEVICEFIRSTUSEDATE" ] || [ "0" = "$DEVICEFIRSTUSEDATE" ]; then
                FIRSTUSEDATE=`date +%Y-%m-%dT%H:%M:%S`
                syscfg set device_first_use_date "$FIRSTUSEDATE"
            fi
            break
            elif [ "$retry" -gt "20" ]; then
                echo_t "Time is not synced after 20 min retry. Breaking loop" >> $NTPD_LOG_NAME
                break
            else
                echo_t "SERVICE_NTPD : Time not yet synced, Sleeping. Retry:$retry" >> $NTPD_LOG_NAME
                retry=`expr $retry + 1`
                sleep 60
            fi
        elif [ "$retry" -gt "20" ]; then
                echo_t "Time is not synced after 20 min retry. Breaking loop" >> $NTPD_LOG_NAME
                break
        else
            echo_t "SERVICE_NTPD : Time not yet synced, Sleeping. Retry:$retry" >> $NTPD_LOG_NAME
            retry=`expr $retry + 1`
            sleep 60
        fi
      done
   else
      echo_t "SERVICE_NTPD : ntpq not available,unable to check sync status" >> $NTPD_LOG_NAME
   fi
   exit
}

service_start ()
{

   local NTP_SERVER_URL_RESTORE="false"
   # Wait for connectivitycheck to complete
   if [ -f $CONNCHECK_FILE ]; then
       echo_t "SERVICE_NTPD CONNCHK: connectivity success $CONNCHECK_FILE present" >> $NTPD_LOG_NAME
   else
       # Exclude XLE device from connectivity check. TODO
       if [ "$BOX_TYPE" != "WNXL11BWL" ];then
           echo_t "SERVICE_NTPD CONNCHK: start connectivity check waiting for $CONNCHECK_FILE file" >> $NTPD_LOG_NAME
           waitForConnChkFile
	   fi
   fi

    # this needs to be hooked up to syscfg for specific timezone
   if [ -n "$SYSCFG_ntp_enabled" ] && [ "0" = "$SYSCFG_ntp_enabled" ] ; then
# RDKB-37275 setting status as unsynchronised.
      syscfg set ntp_status 2
      sysevent set ${SERVICE_NAME}-status "stopped"
      if [ -z "`pidof $BIN`" ]; then
          if [ "$MULTI_CORE" = "yes" ] && [ "$NTPD_IMMED_PEER_SYNC" != "true" ]; then
             echo_t "SERVICE_NTPD : NTPD is not running, starting in Server mode" >> $NTPD_LOG_NAME
             cp $NTP_CONF $NTP_CONF_TMP
             echo "interface ignore wildcard" >> $NTP_CONF_TMP
             echo "interface listen $HOST_INTERFACE_IP" >> $NTP_CONF_TMP

             if [ "$BOX_TYPE" = "XB3" ]; then
                ntpd -c $NTP_CONF_TMP -l $NTPD_LOG_NAME
             else
                systemctl start ntpd.service
             fi
          fi
      fi

      return 0
   fi

# Setting Time status as Unsynchronized
   syscfg set ntp_status 2

   if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] ||  [ "$BOX_TYPE" = "SR213" ] || [ "$LANIPV6Support" = "true" ]; then
       WAN_IPV6_STATUS=`sysevent get ipv6_connection_state`
       if [ "started" != "$CURRENT_WAN_STATUS" ] && [ "up" != "$WAN_IPV6_STATUS" ] ; then
           syscfg set ntp_status 2
           sysevent set ${SERVICE_NAME}-status "wan-down"
           return 0
       fi
   else
       if [ "started" != "$CURRENT_WAN_STATUS" ] ; then
# Setting Time status as unsynchronised,as per RDKB-37275
           syscfg set ntp_status 2
           sysevent set ${SERVICE_NAME}-status "wan-down"
           return 0
       fi
   fi

   rm -rf $NTP_CONF_TMP $NTP_CONF_QUICK_SYNC

   # Add Initial Interface Security Rules
   echo "restrict default kod nomodify notrap nopeer noquery" >> $NTP_CONF_TMP
   echo "restrict -6 default kod nomodify notrap nopeer noquery" >> $NTP_CONF_TMP
   echo "restrict 127.0.0.1" >> $NTP_CONF_TMP
   echo "restrict -6 ::1" >> $NTP_CONF_TMP

   if [ "$SYSCFG_new_ntp_enabled" = "true" ]; then
       # Start NTP Config Creation with Multiple Server Setup
       echo_t "SERVICE_NTPD : Creating NTP config with New NTP Enabled" >> $NTPD_LOG_NAME
       if [ -n "$SYSCFG_ntp_server1" ] && [ "$SYSCFG_ntp_server1" != "no_ntp_address" ]; then
           device_mode=$(syscfg get Device_Mode)
           ntp_not_synced=$(sysevent get ntpd-syncTimeFromPrimary)
           if [ "$BOX_TYPE" = "WNXL11BWL" ] && [ "$WanFailOverSupportEnable" = "true" ] && [ "$device_mode" = "1" ] && [ "$ntp_not_synced" = "syncfromPrimaryGateway" ]; then
               #setting ntpd-syncTimeFromPrimary to empty to avoid xle sync from xb if ntpd restarted for different reason
               sysevent set ntpd-syncTimeFromPrimary
               # Extract default route interface IP
               gateway_ip=$(ip route show | awk '/default/ {print $3}')
               echo "server $gateway_ip true" >> $NTP_CONF_TMP
               echo "restrict $gateway_ip nomodify notrap noquery" >> $NTP_CONF_TMP
               NTP_SERVER_URL_RESTORE="true"
           else
               echo "server $SYSCFG_ntp_server1 true" >> $NTP_CONF_TMP
               echo "restrict $SYSCFG_ntp_server1 nomodify notrap noquery" >> $NTP_CONF_TMP
           fi
           VALID_SERVER="true"
       fi
       if [ -n "$SYSCFG_ntp_server2" ] && [ "$SYSCFG_ntp_server2" != "no_ntp_address" ]; then
           echo "server $SYSCFG_ntp_server2" >> $NTP_CONF_TMP
           echo "restrict $SYSCFG_ntp_server2 nomodify notrap noquery" >> $NTP_CONF_TMP
           VALID_SERVER="true"
       fi
       if [ -n "$SYSCFG_ntp_server3" ] && [ "$SYSCFG_ntp_server3" != "no_ntp_address" ]; then
           echo "server $SYSCFG_ntp_server3" >> $NTP_CONF_TMP
           echo "restrict $SYSCFG_ntp_server3 nomodify notrap noquery" >> $NTP_CONF_TMP
           VALID_SERVER="true"
       fi
       if [ -n "$SYSCFG_ntp_server4" ] && [ "$SYSCFG_ntp_server4" != "no_ntp_address" ]; then
           echo "server $SYSCFG_ntp_server4" >> $NTP_CONF_TMP
           echo "restrict $SYSCFG_ntp_server4 nomodify notrap noquery" >> $NTP_CONF_TMP
           VALID_SERVER="true"
       fi
       if [ -n "$SYSCFG_ntp_server5" ] && [ "$SYSCFG_ntp_server5" != "no_ntp_address" ]; then
           echo "server $SYSCFG_ntp_server5" >> $NTP_CONF_TMP
           echo "restrict $SYSCFG_ntp_server5 nomodify notrap noquery" >> $NTP_CONF_TMP
           VALID_SERVER="true"
       fi

       if [ -z "$VALID_SERVER" ]; then
           if [ -f "/nvram/ETHWAN_ENABLE" ]; then
              echo_t "SERVICE_NTPD : NTP SERVERS 1-5 not available, using the default ntp server." >> $NTPD_LOG_NAME
              SYSCFG_ntp_server1="time1.google.com"
           else
              echo_t "SERVICE_NTPD : NTP SERVERS 1-5 not available, not starting ntpd" >> $NTPD_LOG_NAME
              return 0
           fi
       fi
   else

       PARTNER_ID=`syscfg get PartnerID`

       if [ -z "$SYSCFG_ntp_server1" ] || [ "$SYSCFG_ntp_server1" = "no_ntp_address" ]; then
           if [ -z "$PARTNER_ID" ]; then
               echo_t "SERVICE_NTPD : NTP SERVER 1 not available & PARTNER_ID is null, using the default ntp server." >> $NTPD_LOG_NAME
               SYSCFG_ntp_server1="time1.google.com"
           else
               if [ -f "/nvram/ETHWAN_ENABLE" ]; then
                  echo_t "SERVICE_NTPD : NTP SERVER 1 not available, using the default ntp server." >> $NTPD_LOG_NAME
                  SYSCFG_ntp_server1="time1.google.com"
               else
                  echo_t "SERVICE_NTPD : NTP SERVER 1 not available, not starting ntpd" >> $NTPD_LOG_NAME
                  return 0
               fi
           fi
       fi

       # Start NTP Config Creation with Legacy Single Server Setup
       echo_t "SERVICE_NTPD : Creating NTP config" >> $NTPD_LOG_NAME
       device_mode=$(syscfg get Device_Mode)
       ntp_not_synced=$(sysevent get ntpd-syncTimeFromPrimary)
       if [ "$BOX_TYPE" = "WNXL11BWL" ] && [ "$WanFailOverSupportEnable" = "true" ] && [ "$device_mode" = "1" ] && [ "$ntp_not_synced" = "syncfromPrimaryGateway" ]; then
           #setting ntpd-syncTimeFromPrimary to empty to avoid xle sync from xb if ntpd restarted for different reason
           sysevent set ntpd-syncTimeFromPrimary
           # Extract default route interface IP
           gateway_ip=$(ip route show | awk '/default/ {print $3}')
           echo "server $gateway_ip true" >> $NTP_CONF_TMP
           echo "restrict $gateway_ip nomodify notrap noquery" >> $NTP_CONF_TMP
           NTP_SERVER_URL_RESTORE="true"
       else
           echo "server $SYSCFG_ntp_server1 true" >> $NTP_CONF_TMP
           echo "restrict $SYSCFG_ntp_server1 nomodify notrap noquery" >> $NTP_CONF_TMP
       fi

   fi # if [ "$SYSCFG_new_ntp_enabled" = "true" ]; then

   PARTNER_ID=$(syscfg get PartnerID)
   if [[ "$PARTNER_ID" != sky-* ]]; then
	MAPT_STATUS=$(sysevent get mapt_config_flag)
	if [ "$MAPT_STATUS" = "set" ]; then
		sed -i 's/^server/server -6/g' $NTP_CONF_TMP
		echo_t "SERVICE_NTPD : Configuring ipv6 for NTP sync" >> $NTPD_LOG_NAME
	fi
   fi

   # Continue with Rest of NTP Config Creation
   WAN_IP=""
   QUICK_SYNC_WAN_IP=""

   # Enable Basic NTPD Daemon Logging in Newer Devices
   echo "logconfig =syncall +clockall +sysall +peerall" >> $NTP_CONF_TMP

   sleep 30
   wan_wait QUICK_SYNC_WAN_IP quickSync
   wan_wait WAN_IP

   # If WAN_IP is still empty potentially Database of WAN Interface Failed. As one last ditch effort try legacy device.properties interface
   if [ -z "$WAN_IP" ]; then
       PROVISIONED_TYPE=$(dmcli eRT retv Device.X_CISCO_COM_CableModem.ProvIpType)

       echo_t "SERVICE_NTPD : WAN_IP Empty Trying device.properties interface: $STATIC_INTERFACE" >> $NTPD_LOG_NAME

       if [ "$PROVISIONED_TYPE" == "IPV4" ]; then
           WAN_IP=`ifconfig -a $STATIC_INTERFACE | grep inet | grep -v inet6 | tr -s " " | cut -d ":" -f2 | cut -d " " -f1`
       else
           WAN_IP=`ifconfig $STATIC_INTERFACE | grep inet6 | grep Global | awk '/inet6/{print $3}' | cut -d '/' -f1`
       fi
   fi

   if [ -n "$QUICK_SYNC_WAN_IP" ]; then
       # Quick Sync doesn't allow NIC Rules in Configuration File So create Quick Sync Version Prior to writing NIC rules.
       echo_t "SERVICE_NTPD : Creating NTP Quick Sync Conf file: $NTP_CONF_QUICK_SYNC" >> $NTPD_LOG_NAME
       cp $NTP_CONF_TMP $NTP_CONF_QUICK_SYNC  
   fi #if [ -n "$QUICK_SYNC_WAN_IP" ]; then

   if [ -n "$PEER_INTERFACE_IP" ]; then
       if [ "$BOX_TYPE" != "HUB4" ]  && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$NTPD_IMMED_PEER_SYNC" != "true" ] && [ "$BOX_TYPE" != "SCER11BEL" ] && [ "$BOX_TYPE" != "SCXF11BFL" ]; then
           if [ -z "$SOURCE_PING_INTF" ]; then
               MASK="255.255.255.0"
           else
               MASK=$(ifconfig $SOURCE_PING_INTF | sed -rn '2s/ .*:(.*)$/\1/p')
           fi
           echo "restrict $PEER_INTERFACE_IP mask $MASK nomodify notrap" >> $NTP_CONF_TMP
       fi
   fi

   #since the XLE sync with XB time is needed only for quick sync , restored NTP server URLs instead of xb br403 IP
   if [ "$NTP_SERVER_URL_RESTORE" = "true" ]; then
       # Extract default route interface IP
       gateway_ip=$(ip route show | awk '/default/ {print $3}')
       sed -i "s/server $gateway_ip true/server $SYSCFG_ntp_server1 true/" $NTP_CONF_TMP
       sed -i "s/restrict $gateway_ip nomodify notrap noquery/restrict $SYSCFG_ntp_server1 nomodify notrap noquery/"  $NTP_CONF_TMP
   fi

   # interface rules can't be written to quick sync conf file so write here after quick sync conf file creation.
   echo "interface ignore wildcard" >> $NTP_CONF_TMP
   echo "interface listen 127.0.0.1" >> $NTP_CONF_TMP
   echo "interface listen ::1" >> $NTP_CONF_TMP
   #SHARMAN-2301
   #This change is for UK MAP-T SR213. Since we will not have any of the global IP on WAN interface, We need to add the IPv6 interface (currently brlan0) to the config file
   if [ "$BOX_TYPE" = "SR213" ] || [ "$LANIPV6Support" = "true" ]; then
       MAPT_STATS=$(sysevent get mapt_config_flag)
       echo_t "SERVICE_NTPD : MAPT_STATS=$MAPT_STATS"
       if [ x"$MAPT_STATS" = x"set" ]; then
           IPV4_CONN_STATE=$(sysevent get ipv4_connection_state)
           echo_t "SERVICE_NTPD : IPV4_CONN_STATE=$IPV4_CONN_STATE"
           if [ x"$IPV4_CONN_STATE" != x"up" ]; then
               echo "interface listen $NTPD_IPV6_INTERFACE" >> $NTP_CONF_TMP
           fi
       fi
   fi

   if [ -n "$WAN_IP" ]; then
       echo "interface listen $WAN_IP" >> $NTP_CONF_TMP
       if [ "$WanFailOverSupportEnable" = "true" ] && [ "$BOX_TYPE" = "XB6" ]; then
           echo "interface listen br403" >> $NTP_CONF_TMP
       fi
   fi  

   if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$LANIPV6Support" = "true" ]; then
       # SKYH4-2006: To listen v6 server, update the conf file after getting valid v6 IP(CURRENT_WAN_V6_PREFIX)
       CURRENT_WAN_IPV6_STATUS=`sysevent get ipv6_connection_state`

       if [ "up" = "$CURRENT_WAN_IPV6_STATUS" ] ; then
           CURRENT_WAN_V6_PREFIX=`syscfg get ipv6_prefix_address`
           if [ -n "$CURRENT_WAN_V6_PREFIX" ]; then
               echo "interface listen $CURRENT_WAN_V6_PREFIX" >> $NTP_CONF_TMP
               sysevent set ntp_ipv6_listen "set"
           else
               sysevent set ntp_ipv6_listen "unset"
           fi
       fi
   fi

   if [ "$MULTI_CORE" = "yes" ]  && [ "$NTPD_IMMED_PEER_SYNC" != "true" ]; then
       echo "interface listen $HOST_INTERFACE_IP" >> $NTP_CONF_TMP
   fi

   if [ "$BOX_TYPE" = "XB3" ]; then
       kill -9 "`pidof $BIN`" > /dev/null 2>&1
       echo_t "SERVICE_NTPD : Starting NTP Daemon" >> $NTPD_LOG_NAME
       $BIN -c $NTP_CONF_TMP -l $NTPD_LOG_NAME -g
       ret_val=$? ### To ensure proper ret_val is obtained
   else
       systemctl stop $BIN

       echo_t "SERVICE_NTPD : Killing All Instances of NTP" >> $NTPD_LOG_NAME
       killall $BIN ### This to ensure there is no instance of NTPD running because of multiple wan-start events
       sleep 5

       if [ -n "$QUICK_SYNC_WAN_IP" ]; then
           # Try and Force Quick Sync to Run on a single interface
		   uptime=$(cut -d. -f1 /proc/uptime)
           uptime_ms=$((uptime*1000))
		   sh /lib/rdk/logMilestone.sh "QUICK_SYNC-START"
           echo_t "SERVICE_NTPD : Starting NTP Quick Sync at $uptime_ms" >> $NTPD_LOG_NAME
		   t2ValNotify "SYST_INFO_NTP_START_split" $uptime_ms
           if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$ntpHealthCheck" = "true" ]; then
               if [ $WAN_IPv6_UP -eq 1 ]; then
                   $BIN -c $NTP_CONF_QUICK_SYNC --interface "$QUICK_SYNC_WAN_IP" -x -gq -l $NTPD_LOG_NAME & 
                   QUICK_SYNC_PID=$!
               else
                   $BIN -c $NTP_CONF_QUICK_SYNC --interface "$QUICK_SYNC_WAN_IP" -x -gq -4 -l $NTPD_LOG_NAME &
                   QUICK_SYNC_PID=$!
               fi
           else
               $BIN -c $NTP_CONF_QUICK_SYNC --interface "$QUICK_SYNC_WAN_IP" -x -gq -l $NTPD_LOG_NAME &
               QUICK_SYNC_PID=$!
           fi
           if [ -n "$QUICK_SYNC_PID" ];then
              set_ntp_quicksync_status
           fi
       else
           echo_t "SERVICE_NTPD : Quick Sync Not Run" >> $NTPD_LOG_NAME
       fi

       echo_t "SERVICE_NTPD : Killing All Instances of NTP" >> $NTPD_LOG_NAME
       killall $BIN

       uptime=$(cut -d. -f1 /proc/uptime)
       uptime_ms=$((uptime*1000))
	   sh /lib/rdk/logMilestone.sh "NTP_DAEMON-START"
       echo_t "SERVICE_NTPD : Starting NTP Daemon at $uptime_ms" >> $NTPD_LOG_NAME
       systemctl start $BIN
       ret_val=$? ### To ensure proper ret_val is obtained
       if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$BOX_TYPE" == "SCER11BEL" ] || [ "$BOX_TYPE" == "SCXF11BFL" ]; then
           sysevent set firewall-restart
       fi
   fi

   if [ "$ret_val" -ne 0 ]; then
       echo_t "SERVICE_NTPD : NTP failed to start, retrying" >> $NTPD_LOG_NAME
       if [ "$BOX_TYPE" = "XB3" ]; then
           echo_t "SERVICE_NTPD : Starting NTP Daemon" >> $NTPD_LOG_NAME
           $BIN -c $NTP_CONF_TMP -l $NTPD_LOG_NAME -g
       else
           echo_t "SERVICE_NTPD : Killing All Instances of NTP" >> $NTPD_LOG_NAME
           killall $BIN ### This to ensure there is no instance of NTPD running because of multiple wan-start events
           sleep 5

           if [ -n "$QUICK_SYNC_WAN_IP" ]; then
               # Try and Force Quick Sync to Run on a single interface
               echo_t "SERVICE_NTPD : Starting NTP Quick Sync" >> $NTPD_LOG_NAME
               $BIN -c $NTP_CONF_QUICK_SYNC --interface "$QUICK_SYNC_WAN_IP" -x -gq -l $NTPD_LOG_NAME &
	       QUICK_SYNC_PID=$!
	       if [ -n "$QUICK_SYNC_PID" ];then
                  set_ntp_quicksync_status
               fi
           else
               echo_t "SERVICE_NTPD : Quick Sync Not Run" >> $NTPD_LOG_NAME
           fi

           echo_t "SERVICE_NTPD : Killing All Instances of NTP" >> $NTPD_LOG_NAME
           killall $BIN

           echo_t "SERVICE_NTPD : Starting NTP Daemon" >> $NTPD_LOG_NAME
           systemctl start $BIN
       fi
   fi

   if [ "$BOX_TYPE" = "XB3" ]; then
       # Setting Time status as synchronized
       syscfg set ntp_status 3

       #Set FirstUseDate in Syscfg if this is the first time we are doing a successful NTP Sych
       DEVICEFIRSTUSEDATE=`syscfg get device_first_use_date`
       if [ -z "$DEVICEFIRSTUSEDATE" ] || [ "0" = "$DEVICEFIRSTUSEDATE" ]; then
           FIRSTUSEDATE=`date +%Y-%m-%dT%H:%M:%S`
           syscfg set device_first_use_date "$FIRSTUSEDATE"
       fi
   else
       ####QUICK SYNC not succeeded,lets wait for ntpd daemon to adjust the clock
       if [ "$QUICK_SYNC_DONE" -eq 0 ];then
          set_ntp_driftsync_status &
       fi

   fi
   echo_t "SERVICE_NTPD : ntpd started , setting the status as started" >> $NTPD_LOG_NAME
   sysevent set ${SERVICE_NAME}-status "started"
}

service_stop ()
{
   if [ "$BOX_TYPE" = "XB3" ]; then
   	kill -9 "`pidof $BIN`" > /dev/null 2>&1
   else
   	systemctl stop $BIN
   fi
   sysevent set ${SERVICE_NAME}-status "stopped"
}


service_init ()
{
    FOO=`utctx_cmd get ntp_server1 ntp_server2 ntp_server3 ntp_server4 ntp_server5 ntp_enabled new_ntp_enabled`
    eval "$FOO"
}

waitForWanInitStatusEvent()
{
    echo_t "SERVICE_NTPD : Waiting for wan init completion..."
    wan_init_complete=1
    MAX_WAIT_TIME=60
    counter=0 
    while [ "$(sysevent get wan-status)" != "started" ] ; do
        counter=$((counter+1))
        if [ $counter -ge $MAX_WAIT_TIME ];then
            echo_t "SERVICE_NTPD : wan status is not started, breaking the loop"
            wan_init_complete=0 
            break
        fi
        sleep 1
    done

    return $wan_init_complete;
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

# service_ntpd.sh Entry
while [ -e ${LOCKFILE} ] ; do
    #See if process is still running
    kill -0 "`cat ${LOCKFILE}`"
    if [ $? -ne 0 ]
    then
        break
    fi
    echo_t "SERVICE_NTPD : Waiting for parallel instance of $0 to finish..."
    sleep 1
done

#make sure the lockfile is removed when we exit and then claim it
trap 'rm -f ${LOCKFILE}; exit' INT TERM EXIT
echo $$ > ${LOCKFILE}

service_init

CURRENT_WAN_STATUS=`sysevent get wan-status`
case "$1" in
  "${SERVICE_NAME}-start")
      echo_t "SERVICE_NTPD : ${SERVICE_NAME}-start calling service_start" >> $NTPD_LOG_NAME
      service_start
      ;;
  "${SERVICE_NAME}-stop")
      echo_t "SERVICE_NTPD : ${SERVICE_NAME}-stop called" >> $NTPD_LOG_NAME
      service_stop
      ;;
  "${SERVICE_NAME}-restart")
      echo_t "SERVICE_NTPD : ${SERVICE_NAME}-restart called" >> $NTPD_LOG_NAME
      service_stop
      service_start
      ;;
  wan-status)
      if [ "started" = "$CURRENT_WAN_STATUS" ] ; then
         if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$ntpHealthCheck" = "true" ]; then
            NTPD_PROCESS=`pidof $BIN`
            NTP_STATUS=`syscfg get ntp_status`
            if [ $NTP_STATUS == 3 ] && [ -n "$NTPD_PROCESS" ];then
               echo_t "SERVICE_NTPD : ntp process is already running and pid is = $NTPD_PROCESS" >> $NTPD_LOG_NAME
            else
               echo_t "SERVICE_NTPD : wan-status calling service_start" >> $NTPD_LOG_NAME
               service_start
            fi
         else
            echo_t "SERVICE_NTPD : wan-status calling service_start" >> $NTPD_LOG_NAME
            service_start
         fi
      fi
      ;;
  current_wan_ifname)
      if [ "$BOX_TYPE" = "WNXL11BWL" ];then
          restart_ntp=1
          echo_t "SERVICE_NTPD : Received current_wan_ifname event" >> $NTPD_LOG_NAME
          if [ "started" != "$CURRENT_WAN_STATUS" ] ; then
                waitForWanInitStatusEvent
                restart_ntp=$?
          fi
          if [ "$restart_ntp" = "1" ];then
              CURRENT_WAN_STATUS=`sysevent get wan-status`
              echo_t "SERVICE_NTPD : current_wan_ifname calling service_restart" >> $NTPD_LOG_NAME
              service_stop
              service_start
          fi
      fi
      ;;
  ipv6_connection_state)
      if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$ntpHealthCheck" = "true" ]; then
         NTPD_PROCESS=`pidof $BIN`
         NTP_STATUS=`syscfg get ntp_status`
         #SKYH4-6932: When IPv6 comes up after ipv4, IPv6 listners won't be added and hence with ipv6 only ntp servers, we will have time syncing problems. So checking time sync status along with ntpd process, if time  isn't  synced there will conf update and ntpd restart.
         if [ $NTP_STATUS == 3 ] && [ -n "$NTPD_PROCESS" ];then
             echo_t "SERVICE_NTPD : ntp process is already running and pid is = $NTPD_PROCESS" >> $NTPD_LOG_NAME
         else
             WAN_IPV6_STATUS=`sysevent get ipv6_connection_state`
             if [ "up" = "$WAN_IPV6_STATUS" ] ; then
                  CURRENT_WAN_V6_PREFIX=`syscfg get ipv6_prefix_address`
                  NTP_PREFIX=`sysevent get ntp_prefix`
                  NTP_IPV6_LISTEN=`sysevent get ntp_ipv6_listen`
                  if [ -n "$CURRENT_WAN_V6_PREFIX" ] && ([ "$NTP_PREFIX" != "$CURRENT_WAN_V6_PREFIX" ] || [ "set" != "$NTP_IPV6_LISTEN" ]) ; then
                      echo_t "SERVICE_NTPD : ipv6_connection_state calling service_start" >> $NTPD_LOG_NAME
                      sysevent set ntp_prefix $CURRENT_WAN_V6_PREFIX
                      service_start
                  fi
              fi
          fi
      fi
      ;;
  *)
      echo "Usage: $SELF_NAME [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart | wan-status ]" >&2
      rm -f ${LOCKFILE}
      exit 3
      ;;
esac

echo_t "SERVICE_NTPD : End of shell script" >> $NTPD_LOG_NAME

#Script finished, remove lock file
rm -f ${LOCKFILE}
