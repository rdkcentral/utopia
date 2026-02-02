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

# ----------------------------------------------------------------------------
# This script prepares cron files and brings up a crond
# The prepared configuration files will have the cron daemon
# execute all files in a well-known directory at predictables times.
# 
# Also this script creates a script to be run by the cron daemon on 
# a daily basis. The purpose of that script will be to trigger the
# ddns-start event
# ----------------------------------------------------------------------------

source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/log_capture_path.sh
if [ -f /lib/rdk/utils.sh ];then
     . /lib/rdk/utils.sh
fi
source /etc/device.properties

SERVICE_NAME="crond"
SELF_NAME="`basename "$0"`"
ntpHealthCheck=`sysevent get NTPHealthCheckSupport`
service_start () 
{
   echo_t "SERVICE_CROND : starting ${SERVICE_NAME} service"
   ulog ${SERVICE_NAME} status "starting ${SERVICE_NAME} service" 

   killall crond
   
   CRONTAB_DIR="/var/spool/cron/crontabs/"
   CRONTAB_FILE=$CRONTAB_DIR"root"
   if [ ! -e $CRONTAB_FILE ] || [ ! -e "/etc/cron/cron.monthly" ]  ; then
      echo_t "SERVICE_CROND : creating cron files"
      # make a pseudo random seed from our mac address
      # we will get the same values of random over reboots
      # but there will be divergence of values accross hosts
      # which is the property we are looking for
      if [ "$WAN0_IS_DUMMY" = "true" ]; then
            INT="privbr"
      else
            INT="wan0"
      fi
      OUR_MAC=`ip link show $INT | grep link | awk '{print $2}'`
      MAC1=`echo "$OUR_MAC" | awk 'BEGIN { FS = ":" } ; { printf ("%d", "0x"$6) }'`
      MAC2=`echo "$OUR_MAC" | awk 'BEGIN { FS = ":" } ; { printf ("%d", "0x"$5) }'`
      RANDOM=`expr "$MAC1" \* "$MAC2"`
   
      mkdir -p $CRONTAB_DIR
   
      echo "* * * * *  execute_dir /etc/cron/cron.everyminute" > $CRONTAB_FILE
      echo "1,6,11,16,21,26,31,36,41,46,51,56 * * * *  execute_dir /etc/cron/cron.every5minute" >> $CRONTAB_FILE
      echo "2,12,22,32,42,52 * * * *  execute_dir /etc/cron/cron.every10minute" >> $CRONTAB_FILE
      num1=$RANDOM
      rand1=`expr "$num1" % 60`
      rand4=`expr "$RANDOM" \* 2`
      rand4=`expr "$rand4" % 60`
      echo "$rand1 * * * * execute_dir /etc/cron/cron.hourly" >> $CRONTAB_FILE
      echo "$rand4 * * * * /usr/ccsp/tad/xfinity_health_test.sh" >> $CRONTAB_FILE
      echo "1 */1 * * *  /usr/bin/RxTx100" >> $CRONTAB_FILE
      echo "10 */6 * * *  /usr/ccsp/tad/getSsidNames.sh" >> $CRONTAB_FILE
#rdkb-4297 Runs on the 1st minute of every 12th hour
      if [ "$MOCA_SUPPORTED" != "false" ]; then
          echo "1 */12 * * *  /usr/ccsp/pam/moca_status.sh" >> $CRONTAB_FILE
      fi
#RDKB-17984: Runs every 12 hours and prints mesh status
      if [ "$BOX_TYPE" != "XB3" ]; then
       echo "1 */12 * * *  /usr/ccsp/wifi/mesh_status.sh" >> $CRONTAB_FILE
      fi

      if [ "$BOX_TYPE" == "XB3" ]; then
       echo "*/10 * * * * /rdklogger/log_ps_cpu_mem_host.sh" >> $CRONTAB_FILE
      fi
      #zqiu: monitor lan client traffic
      echo "* * * * *   /usr/ccsp/tad/rxtx_lan.sh" >> $CRONTAB_FILE

      if [ "$BOX_TYPE" == "SR300" ] || [ "$BOX_TYPE" == "SR213" ] || [ "$BOX_TYPE" == "SCER11BEL" ]; then
        echo "* * * * *   /etc/sky/set_dscp_lan.sh" >> $CRONTAB_FILE
      fi

      if [ "$BOX_TYPE" == "SCXF11BFL" ]; then
	      echo "* * * * *   /etc/comcast/set_dscp_lan.sh" >> $CRONTAB_FILE
      fi

      echo "1 */6 * * *   /usr/ccsp/tad/log_sixhourly.sh" >> $CRONTAB_FILE
#RDKB-9367, file handle monitor, needs to be run every 12 hours
      echo "1 */12 * * *   /usr/ccsp/tad/FileHandle_Monitor.sh" >> $CRONTAB_FILE


      if [ "$MODEL_NUM" = "DPC3941B" ] || [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "CGA4131COM" ] || [ "$MODEL_NUM" = "CGA4332COM" ]; then
            echo "*/15 * * * *  /usr/ccsp/tad/log_staticIP_client_info.sh" >> $CRONTAB_FILE
      fi

      echo "1 */12 * * *   /usr/ccsp/tad/log_twice_day.sh" >> $CRONTAB_FILE
#RDKB-45059 log the zebra.conf status for every 12 hours
      echo "0 */12 * * *  /usr/ccsp/tad/Zebra_conf_status.sh" >> $CRONTAB_FILE

     if [ "$BOX_TYPE" == "WNXL11BWL" ] || [ "$BOX_TYPE" == "XB6" ] || [ "$BOX_TYPE" == "VNTXER5" ] || [ "$BOX_TYPE" == "SCER11BEL" ] || [ "$BOX_TYPE" == "SCXF11BFL" ]; then
        #run idm recovery for each 10 minutes
        echo "*/10 * * * *   /etc/idm/idm_recovery.sh" >> $CRONTAB_FILE
     fi

     if [ "$BOX_TYPE" == "VNTXER5" ]; then
        #run thermal monitoring script every 5 minutes
        echo "*/5 * * * *   /etc/get_XER5_thermal.sh" >> $CRONTAB_FILE
     fi

      num1=$RANDOM
      num2=$RANDOM
      rand1=`expr "$num1" % 60`
      rand2=`expr "$num2" % 24`
      echo "$rand1 $rand2 * * * execute_dir /etc/cron/cron.daily" >> $CRONTAB_FILE
      num1=$RANDOM
      num2=$RANDOM
      num3=$RANDOM
      rand1=`expr "$num1" % 60`
      rand2=`expr "$num2" % 24`
      rand3=`expr "$num3" % 7`
      echo "$rand1 $rand2 * * $rand3 execute_dir /etc/cron/cron.weekly" >> $CRONTAB_FILE
      num1=$RANDOM
      num2=$RANDOM
      num3=$RANDOM
      rand1=`expr "$num1" % 60`
      rand2=`expr "$num2" % 24`
      rand3=`expr "$num3" % 28`
      echo "$rand1 $rand2 $rand3 * * execute_dir /etc/cron/cron.monthly" >> $CRONTAB_FILE
      
      # update mso potd every midnight at 00:05
      echo "5 0 * * * sysevent set potd-start" >> $CRONTAB_FILE

      echo "*/15 * * * * /bin/sh /usr/ccsp/tad/gui_session_expiry.sh" >> $CRONTAB_FILE 

      # Generate Firewall statistics hourly
      # Don't Zero iptable Counter
      echo "58 * * * * /usr/bin/GenFWLog -nz" >> $CRONTAB_FILE

      # Monitor syscfg DB every 15minutes 
      echo "*/15 * * * * /usr/ccsp/tad/syscfg_recover.sh" >> $CRONTAB_FILE

      # Monitor selfheal_aggressive.sh based on syscfg value
     AGGRESIVE_INTERVAL=$(syscfg get AggressiveInterval)
      echo "AggressiveInterval value = $AGGRESIVE_INTERVAL"
      if [ "$AGGRESIVE_INTERVAL" == "" ]; then
          echo "*/5 * * * * /usr/ccsp/tad/selfheal_aggressive.sh" >> $CRONTAB_FILE
          echo "Selfheal aggressive interval set to default 5 minutes"
      else
          echo "*/$AGGRESIVE_INTERVAL * * * * /usr/ccsp/tad/selfheal_aggressive.sh" >> $CRONTAB_FILE
          echo "Selfheal aggressive interval set to $AGGRESIVE_INTERVAL minutes"

      fi
	  
	  # Monitor resource_monitor.sh based on syscfg value 
     RESOURCE_MONITOR_INTERVAL=$(syscfg get resource_monitor_interval)
     echo "Resource Monitor interval value = $RESOURCE_MONITOR_INTERVAL"
       if [ "$RESOURCE_MONITOR_INTERVAL" == "" ]; then
            echo "*/15 * * * * /usr/ccsp/tad/resource_monitor.sh" >> $CRONTAB_FILE
            echo "Resource Monitor interval set to default 15 minutes"
       else
            echo "*/$RESOURCE_MONITOR_INTERVAL * * * * /usr/ccsp/tad/resource_monitor.sh" >> $CRONTAB_FILE
            echo "Resource Monitor interval set to $RESOURCE_MONITOR_INTERVAL minutes"
       fi
	  
	  # Monitor resource_monitor.sh based on syscfg value 
     SELFHEAL_PING_INTERVAL=$(syscfg get ConnTest_PingInterval)
     echo "Selfheal connectivity test ping interval value = $SELFHEAL_PING_INTERVAL"
       if [ "$SELFHEAL_PING_INTERVAL" == "" ]; then
          echo "0 * * * * /usr/ccsp/tad/self_heal_connectivity_test.sh" >> $CRONTAB_FILE
          echo "Selfheal connectivity test ping interval set to default 60 minutes"
       else
          echo "*/$SELFHEAL_PING_INTERVAL * * * * /usr/ccsp/tad/self_heal_connectivity_test.sh" >> $CRONTAB_FILE
          echo "Selfheal connectivity test ping interval set to $SELFHEAL_PING_INTERVAL minutes"
       fi
   
	  # Monitor rdkbLogMonitor.sh every 1 minute
	  echo "* * * * * flock -n /tmp/rdkb_cron.lock /rdklogger/rdkbLogMonitor.sh" >> $CRONTAB_FILE

      # Monitor resource_monitor.sh every 5 minutes TCCBR-3288
#      if [ "$BOX_TYPE" = "TCCBR" ]; then 
    #     echo "*/5 * * * * /usr/ccsp/tad/resource_monitor_recover.sh" >> $CRONTAB_FILE
#      fi

      # RDKB-23651
      if [ "$THERMALCTRL_ENABLE" = "true" ]; then
         echo "*/15 * * * * /usr/ccsp/tad/check_fan.sh" >> $CRONTAB_FILE
      fi

      if [ "$BOX_TYPE" == "HUB4" ] || [ "$BOX_TYPE" == "SR300" ] || [ "$BOX_TYPE" == "SE501" ] || [ "$BOX_TYPE" == "SR213" ] || [ "$BOX_TYPE" == "WNXL11BWL" ]; then
          # add syncing the timeoffset everyday at 01:00 AM
          echo "0 1 * * * /etc/sky/sync_timeoffset.sh" >> $CRONTAB_FILE

          #To monitor all wifi interface packets in every 15minutes
          echo "*/15 * * * * /etc/sky/monitor_wifi_packets.sh" >> $CRONTAB_FILE

	  #To monitor /tmp directory every 10 minutes
	  echo "*/10 * * * * /etc/sky/monitor_tmp.sh" >> $CRONTAB_FILE

          #To monitor all wifi interface dhd dump in every 1hour
          addCron "48 * * * *  sh /etc/sky/monitor_dhd_dump.sh &"
      fi

      if [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$BOX_TYPE" != "SCER11BEL" ] && [ "$BOX_TYPE" != "SCXF11BFL" ]; then
         #RDKB-43895 log the firmware bank informations in selfheal log
         echo "5 */12  * * *  /usr/bin/FwBankInfo" >> $CRONTAB_FILE
      fi

      if [ "$BOX_TYPE" == "HUB4" ]; then
	      addCron "51 * * * *  sh /etc/utopia/service.d/handle_log_monitor_pause.sh &"
              #To monitor endpoint failure every 15 minutes
              echo "*/15 3-4 * * *  /etc/sky/monitor_voice_endpoint.sh" >> $CRONTAB_FILE
      fi
 
      if [ "$BOX_TYPE" == "HUB4" ] || [ "$BOX_TYPE" == "SR213" ] || [ "$ntpHealthCheck" == "true" ]; then
              #To monitor ntp sync failure every 2 hrs
              if [ -e "/etc/sky/ntp_health_check.sh" ]; then
                  echo "1 */2 * * *  /etc/sky/ntp_health_check.sh" >> $CRONTAB_FILE
              fi
      fi

      if [ "$BOX_TYPE" == "SCER11BEL" ] && [ "$ntpHealthCheck" == "true" ]; then
          # Add syncing the timeoffset everyday at 01:00 AM
          echo "0 1 * * * /etc/sky/sync_timeoffset.sh" >> $CRONTAB_FILE
      fi

      # Logging current chain mask value of 2G - runs on 1st minute of every 12th hour - only for 3941 box
      if [ -n "$(echo "$MODEL_NUM" | grep 3941)" ]; then
         echo "1 */12 * * *  rpcclient 169.254.101.2 \"/etc/ath/CurrentChainMask_Logging.sh\"" >> $CRONTAB_FILE
      fi

      # Add Unique Telemetry ID if enabled
      telemtery_enable=`syscfg get unique_telemetry_enable`
      telemtery_time_interval=`syscfg get unique_telemetry_interval`
      telemtery_tag=`syscfg get unique_telemetry_tag`

      if [ "$telemtery_enable" = "true" ] && [ 0"$telemtery_time_interval" -gt 0 ] && [ ! -z "$telemtery_tag" -a "$telemtery_tag" != " " ] ; then
        #Convert time interval(in minutes) to days, hours and minutes
        d=$(($telemtery_time_interval / (60*24)))
        h=$((($telemtery_time_interval % (60*24)) / 60))
        m=$((($telemtery_time_interval % (60*24)) % 60))

        if [ $d -gt 0 ] ; then
          day="*/$d"
          hour="$h"
          mins="$m"
        elif [ $h -gt 0 ] ; then
          day="*"
          hour="*/$h"
          mins="$m"
        else
          day="*"
          hour="*"
          mins="*/$m"
        fi

        echo "$mins $hour $day * * /usr/ccsp/pam/unique_telemetry_id.sh" >> $CRONTAB_FILE
      fi

      # monitor syslog every 5 minute
#      echo "#! /bin/sh" > /etc/cron/cron.every5minute/log_every5minute.sh
#     echo "/usr/sbin/log_handle.sh" >> /etc/cron/cron.every5minute/log_every5minute.sh
#      chmod 700 /etc/cron/cron.every5minute/log_every5minute.sh

	  #monitor start-misc in case wan is not online
      addCron "* * * * *  /etc/utopia/service.d/misc_handler.sh"

      addCron "* * * * * /usr/ccsp/tad/selfheal_bootup.sh"

	  #monitor cosa_start_rem triggered state in case its not triggered on 
	  #bootup even after 10 minutes then we have to trigger this via cron
      addCron "2,12,22,32,42,52 * * * * /usr/ccsp/tad/selfheal_cosa_start_rem.sh"

   # Adding RemotePortUsage script if it is enabled
   REMOTE_PORT_USAGE=`syscfg get TrackRemotePortUsage`
   if [ "$REMOTE_PORT_USAGE" != "NULL" ]; then
      interval=$(echo "$REMOTE_PORT_USAGE" | cut -d';' -f1)
      echo "*/$interval * * * * /usr/ccsp/tad/remote_port_usage.sh" >> $CRONTAB_FILE
   fi

	#This variable is to check RFC WANLinkHeal Enabled/Disabled from syscfg DB
	rfc_wanlinkheal_status=""
	rfc_wanlinkheal_status=`syscfg get wanlinkheal`

	#To invoke start_gw_health script on bootup-check, Follwing condition need to statisfy
	#RFC ETHWAN should be false/null and WAN_TYPE should be DOCSIS
	#RF WANLinkHeal should be true and BOX_TYPE should be plaftorm specfic
	#In CISCOXB3 platform, does not have WAN_TYPE paramenter in /etc/device.properties file, So added MODEL_NUM Check along with WAN_TYPE.
		if [ "$WAN_TYPE" = "DOCSIS" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "DPC3941B" ] || [ "$MODEL_NUM" = "DPC3939B" ]; then
			if [ "$rfc_wanlinkheal_status" = "true" ]; then
				if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "XB6" ] || [ "$BOX_TYPE" = "TCCBR" ]; then
					echo_t "RFC WANLinkHeal Feature is Enabled"
                                        addCron "2,12,22,32,42,52 * * * * /usr/ccsp/tad/start_gw_heath.sh"
				else
					echo_t "RFC WANLinkHeal Feature is not Enabled"
				fi
			else
				echo_t "Set RFC WANLinkHeal flag to Enable for WANLinkHeal Feature support"
			fi
		else
			echo_t "This Device WAN TYPE is not DOCSIS, Needed DOCSIS type Device for WANLinkHeal"
		fi

   fi
 


 
   # start the cron daemon
   # echo "[utopia][registration] Starting cron daemon"
   echo_t "SERVICE_CROND : Starting cron daemon"
   crond -l 9

   sysevent set ${SERVICE_NAME}-status "started"
}

service_stop () 
{
   echo_t "SERVICE_CROND : stopping ${SERVICE_NAME} service"
   ulog ${SERVICE_NAME} status "stopping ${SERVICE_NAME} service" 
   killall crond
   sysevent set ${SERVICE_NAME}-status "stopped"
}

# Entry
echo_t "SERVICE_CROND : event $1"
case "$1" in
  "${SERVICE_NAME}-start")
      service_start
      ;;
  "${SERVICE_NAME}-stop")
      service_stop
      ;;
  "${SERVICE_NAME}-restart")
      service_stop
      service_start
      ;;
   ntpclient-status)
      STATUS=`sysevent get ntpclient-status`
      if [ "started" = "$STATUS" ] ; then 
        ulog ${SERVICE_NAME} status "restarting ${SERVICE_NAME} service" 
        killall crond
        crond -l 9
      fi
      ;;
  *)
      echo "Usage: $SELF_NAME [${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart]" >&2
      exit 3
      ;;
esac



