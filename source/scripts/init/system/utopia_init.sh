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
#   This file contains the code to initialize the board
#------------------------------------------------------------------
UTOPIA_PATH=/etc/utopia/service.d
source /etc/device.properties
if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
	SWITCH_HANDLER=$UTOPIA_PATH/service_multinet/handle_sw.sh
fi
INIT_DIR=/etc/utopia/registration.d
BINPATH="/usr/bin"
CCSPPATH="/usr/ccsp"

ls /tmp/pam_initialized* > /tmp/pam_init_status

source $UTOPIA_PATH/log_capture_path.sh


dmesg -n 5

TR69TLVFILE="/nvram/TLVData.bin"
REVERTFLAG="/nvram/reverted"
MAINT_START="/nvram/.FirmwareUpgradeStartTime"
MAINT_END="/nvram/.FirmwareUpgradeEndTime"

echo_t "*******************************************************************"
echo_t "*                                                                  "
echo_t "[utopia][init] P-UNIT status"
cat /proc/P-UNIT/status
echo_t "*                                                                  "
echo_t "*******************************************************************"

echo "[utopia][init] Tweaking network parameters" > /dev/console

echo 60 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream
echo 60 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent
echo 60 > /proc/sys/net/netfilter/nf_conntrack_generic_timeout
echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close
echo 20 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
echo 7440 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
echo 8192 > /proc/sys/net/netfilter/nf_conntrack_max
echo 400 > /proc/sys/net/netfilter/nf_conntrack_expect_max

if [ "$BOX_TYPE" = "XB3" ];then
    RESERVED_PORTS="58081,50755,50757,50759,50760"
    sysctl -w net.ipv4.ip_local_reserved_ports="$RESERVED_PORTS"

fi

# Do not accept ICMP redirects and source routed packets (prevent MITM attacks)

if [ "$BOX_TYPE" = "XB3" ];then
    conf_file="/etc/traffic-filter.conf"
    if [ -e $conf_file ] 
    then
        echo_t "Setup sysctl config from file \"$conf_file\" "
        sysctl -p $conf_file
    fi
fi

echo_t "Starting log module.."
/usr/sbin/log_start.sh

BUTTON_THRESHOLD=15
FACTORY_RESET_KEY=factory_reset
FACTORY_RESET_RGWIFI=y
FACTORY_RESET_WIFI=w
SYSCFG_MOUNT=/nvram
SYSCFG_TMP_LOCATION=/tmp
SYSCFG_FILE=$SYSCFG_TMP_LOCATION/syscfg.db
SYSCFG_BKUP_FILE=$SYSCFG_MOUNT/syscfg.db
SYSCFG_OLDBKUP_FILE=$SYSCFG_MOUNT/syscfg_bkup.db
SYSCFG_ENCRYPTED_PATH=/opt/secure/
SYSCFG_PERSISTENT_PATH=/opt/secure/data/
SYSCFG_NEW_FILE=$SYSCFG_PERSISTENT_PATH/syscfg.db
SYSCFG_NEW_BKUP_FILE=$SYSCFG_PERSISTENT_PATH/syscfg_bkup.db
PSM_CUR_XML_CONFIG_FILE_NAME="$SYSCFG_TMP_LOCATION/bbhm_cur_cfg.xml"
PSM_BAK_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_bak_cfg.xml"
PSM_TMP_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_tmp_cfg.xml"
PSM_DEF_XML_CONFIG_FILE_NAME="/usr/ccsp/config/bbhm_def_cfg.xml"
XDNS_DNSMASQ_SERVERS_CONFIG_FILE_NAME="$SYSCFG_MOUNT/dnsmasq_servers.conf"
FACTORY_RESET_REASON=false

HOTSPOT_BLOB="/nvram/hotspot_blob"
HOTSPOT_JSON="/nvram/hotspot.json"
MWO_PATH="/nvram/mwo"
CHANNEL_KEEPOUT_PATH="/nvram/mesh"

ENCRYPT_SYSCFG=false
if [ "$MODEL_NUM" = "VTER11QEL" ] || [ "$MODEL_NUM" = "SCER11BEL" ]; then
   ENCRYPT_SYSCFG=true
fi

if [ -d $SYSCFG_ENCRYPTED_PATH ]; then
       if [ ! -d $SYSCFG_PERSISTENT_PATH ]; then
               echo "$SYSCFG_PERSISTENT_PATH path not available creating directory and touching $SYSCFG_NEW_FILE file"
               mkdir $SYSCFG_PERSISTENT_PATH
               if [ "$ENCRYPT_SYSCFG" = false ] ; then
                  touch $SYSCFG_NEW_FILE
               fi
       fi
fi

if [ "$MODEL_NUM" = "SCER11BEL" ]; then
     if [ "$ENCRYPT_SYSCFG" = false ]; then
             if [ ! -f $SYSCFG_BKUP_FILE ] && [ -f $SYSCFG_NEW_FILE ]; then
                 echo_t "[utopia][init] DOWNGRADE to unsecured syscfg.db"
                 touch $SYSCFG_BKUP_FILE
                 cp $SYSCFG_NEW_FILE $SYSCFG_BKUP_FILE

             fi

     else
              if [ -f $SYSCFG_BKUP_FILE ] && [ ! -f $SYSCFG_NEW_FILE ]; then
                 echo_t "[utopia][init] UPGRADE to secured syscfg.db"
                 touch $SYSCFG_NEW_FILE
                 cp $SYSCFG_BKUP_FILE $SYSCFG_NEW_FILE
              fi
     fi
fi

changeFilePermissions() {
       if [ -e "$1" ]; then
               filepermission=$(stat -c %a "$1")
               if [ "$filepermission" -ne "$2" ]
               then
                       chmod "$2" "$1"
                       echo "[utopia][init] Modified File Permission to $2 for file - $1"
               fi
       else
               echo "[utopia][init] changeFilePermissions: file $1 doesn't exist"
       fi
}

CheckAndReCreateDB()
{
	NVRAMFullStatus=`df -h $SYSCFG_MOUNT | grep "100%"`
	if [ -n "$NVRAMFullStatus" ]; then
		if [ -f "/rdklogger/rdkbLogMonitor.sh" ]
		then
			  #Remove Old backup files if there	
			  sh /rdklogger/rdkbLogMonitor.sh "remove_old_logbackup"		 

		  	  #Re-create syscfg create again
			  syscfg_create -f $SYSCFG_FILE
			  if [ $? != 0 ]; then
				  NVRAMFullStatus=`df -h $SYSCFG_MOUNT | grep "100%"`
				  if [ -n "$NVRAMFullStatus" ]; then
					 echo_t "[utopia][init] NVRAM Full(100%) and below is the dump"
					 du -h $SYSCFG_MOUNT 
					 ls -al $SYSCFG_MOUNT	 
				  fi
			  fi 
		fi
	fi 
}

if [ "$ENCRYPT_SYSCFG" = false ] ; then
   echo_t "[utopia][init] Starting syscfg using file store ($SYSCFG_BKUP_FILE)"
   if [ -f $SYSCFG_BKUP_FILE ]; then
      cp $SYSCFG_BKUP_FILE $SYSCFG_FILE
      syscfg_create -f $SYSCFG_FILE
      if [ $? != 0 ]; then
         CheckAndReCreateDB
      fi
   else
      echo -n > $SYSCFG_FILE
      echo -n > $SYSCFG_BKUP_FILE
      syscfg_create -f $SYSCFG_FILE
      if [ $? != 0 ]; then
         CheckAndReCreateDB
      fi
      #>>zqiu
      echo_t "[utopia][init] need to reset wifi when($SYSCFG_BKUP_FILE) and ($SYSCFG_NEW_FILE) files are not available"
      syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_WIFI
      syscfg commit
      #<<zqiu
      touch /nvram/.apply_partner_defaults
      # Put value 204 into networkresponse.txt file so that
      # all LAN services start with a configuration which will
      # redirect everything to Gateway IP.
      # This value again will be modified from network_response.sh 
      echo_t "[utopia][init] Echoing network response during Factory reset"
      echo 204 > /var/tmp/networkresponse.txt
   fi
else
   echo_t "[utopia][init] Starting syscfg using file store ($SYSCFG_NEW_FILE)"
   if [ -f $SYSCFG_NEW_FILE ]; then
       # Check and remove immutable attribute on syscfg.db if set
       attr_flag=$(lsattr "$SYSCFG_NEW_FILE" 2>/dev/null | awk '{print $1}')
       if echo "$attr_flag" | grep -q "i"; then
           echo "[utopia][init] Immutable flag is set on $SYSCFG_NEW_FILE, removing it"
           chattr -i "$SYSCFG_NEW_FILE"
       fi
      cp $SYSCFG_NEW_FILE $SYSCFG_FILE
      syscfg_create -f $SYSCFG_FILE
      if [ $? != 0 ]; then
         CheckAndReCreateDB
      fi
   else
      echo -n > $SYSCFG_FILE
      echo -n > $SYSCFG_NEW_FILE
      syscfg_create -f $SYSCFG_FILE
      if [ $? != 0 ]; then
         CheckAndReCreateDB
      fi
      #>>zqiu
      echo_t "[utopia][init] need to reset wifi when($SYSCFG_NEW_FILE) files is not available"
      syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_WIFI
      syscfg commit
      #<<zqiu
      touch /nvram/.apply_partner_defaults
      # Put value 204 into networkresponse.txt file so that
      # all LAN services start with a configuration which will
      # redirect everything to Gateway IP.
      # This value again will be modified from network_response.sh 
      echo_t "[utopia][init] Echoing network response during Factory reset"
      echo 204 > /var/tmp/networkresponse.txt
   fi
fi

SYSCFG_LAN_DOMAIN=`syscfg get lan_domain` 

if [ "$SYSCFG_LAN_DOMAIN" == "utopia.net" ]; then
   echo_t "[utopia][init] Setting lan domain to NULL"
   syscfg set lan_domain ""
   syscfg commit
fi

if [ -f $SYSCFG_OLDBKUP_FILE ];then
	rm -rf $SYSCFG_OLDBKUP_FILE
fi
if [ -f $SYSCFG_NEW_BKUP_FILE ];then
	rm -rf $SYSCFG_NEW_BKUP_FILE
fi
if [ "$ENCRYPT_SYSCFG" = false ] ; then
   if [ -f $SYSCFG_NEW_FILE ];then
      rm -rf $SYSCFG_NEW_FILE
   fi
else
   if [ -f $SYSCFG_BKUP_FILE ]; then
         rm -rf $SYSCFG_BKUP_FILE
   fi
fi

# Read reset duration to check if the unit was rebooted by pressing the HW reset button
if cat /proc/P-UNIT/status | grep -q "Reset duration from shadow register"; then
   # Note: Only new P-UNIT firmwares and Linux drivers (>= 1.1.x) support this.
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Reset duration from shadow register"|awk -F '[ |\.]' '{ print $9 }'`
   # Clear the Reset duration from shadow register value
   # echo "1" > /proc/P-UNIT/clr_reset_duration_shadow
    touch /var/tmp/utopia_cleared_shadow_reg.txt
   clean_reset_duration;
elif cat /proc/P-UNIT/status | grep -q "Last reset duration"; then
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Last reset duration"|awk -F '[ |\.]' '{ print $7 }'`
else
   echo_t "[utopia][init] Cannot read the reset duration value from /proc/P-UNIT/status"
fi

# Set the factory reset key if it was pressed for longer than our threshold
if [ x != x$PUNIT_RESET_DURATION ]; then
    if test "$BUTTON_THRESHOLD" -le "$PUNIT_RESET_DURATION"; then
       syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_RGWIFI && BUTTON_FR="1"
       syscfg commit
    fi
fi

SYSCFG_FR_VAL="`syscfg get $FACTORY_RESET_KEY`"

if [ "$FACTORY_RESET_RGWIFI" = "$SYSCFG_FR_VAL" ]; then
   echo_t "[utopia][init] Performing factory reset"

SYSCFG_PARTNER_FR="`syscfg get PartnerID_FR`"
if [ "1" = "$SYSCFG_PARTNER_FR" ]; then
   echo_t "[utopia][init] Performing factory reset due to PartnerID change"
fi
# Remove log file first because it need get log file path from syscfg   
   /usr/sbin/log_handle.sh reset
   syscfg_destroy -f

# Remove syscfg and PSM storage files
#mark the factory reset flag 'on'
   FACTORY_RESET_REASON=true 
   if [ -e "$MWO_PATH" ]; then
      rm -rf $MWO_PATH
   fi
   if [ -f /nvram/steering.json ]; then
      rm -f /nvram/steering.json
   fi
   if [ -f /nvram/device_profile.json ]; then
      rm -f /nvram/device_profile.json
   fi
   if [ -e "$CHANNEL_KEEPOUT_PATH" ]; then
      rm -rf $CHANNEL_KEEPOUT_PATH
   fi
   rm -f /nvram/partners_defaults.json 
   rm -f /nvram/bootstrap.json
   rm -f /opt/secure/bootstrap.json
   rm -f /opt/secure/RFC/tr181store.json
   rm -f /opt/secure/Blocklist_file.txt
   rm -f /nvram/Blocklist_XB3.txt
   rm -f $SYSCFG_BKUP_FILE
   rm -f $SYSCFG_FILE
   rm -f $SYSCFG_NEW_FILE
   rm -f $PSM_BAK_XML_CONFIG_FILE_NAME
   rm -f $PSM_TMP_XML_CONFIG_FILE_NAME
   rm -f $TR69TLVFILE
   rm -f $REVERTFLAG
   rm -f $XDNS_DNSMASQ_SERVERS_CONFIG_FILE_NAME
   rm -f $MAINT_START
   rm -f $MAINT_END
   # Remove DHCP lease file
   rm -f /nvram/dnsmasq.leases
   rm -f /nvram/server-IfaceMgr.xml
   rm -f /nvram/server-AddrMgr.xml
   rm -f /nvram/server-CfgMgr.xml
   rm -f /nvram/server-TransMgr.xml
   rm -f /nvram/server-cache.xml
   rm -f /nvram/server-duid
   rm -f /nvram/.keys/*
   if [ -f /etc/ONBOARD_LOGGING_ENABLE ]; then
    # Remove onboard files
    rm -f /nvram/.device_onboarded
    rm -f /nvram/DISABLE_ONBOARD_LOGGING
    rm -rf /nvram2/onboardlogs
   fi
   if [ -f /etc/WEBCONFIG_ENABLE ]; then
   # Remove webconfig_db.bin on factory reset on all RDKB platforms
     rm -f /nvram/webconfig_db.bin     
   fi
   if [ -f /etc/AKER_ENABLE ]; then
    # Remove on factory reset, Aker schedule pcs.bin and pcs.bin.md5 on all RDKB platforms 
      rm -f /nvram/pcs.bin
      rm -f /nvram/pcs.bin.md5
   fi

    if [ -f "$HOTSPOT_BLOB" ];then
      rm -f "$HOTSPOT_BLOB"
   fi

    if [ -f "$HOTSPOT_JSON" ];then
        rm -f "$HOTSPOT_JSON"
    fi

    if [ -f "/nvram/dnsmasq.vendorclass" ];then
      rm -f /nvram/dnsmasq.vendorclass
    fi

    if [ -f /nvram/rfc.json ]; then
      rm -f /nvram/rfc.json
    fi

    if [ -f /opt/secure/RFC/.RFC_SSHWhiteList.list ]; then
       rm -f /opt/secure/RFC/.RFC_SSHWhiteList.list
    fi

     touch /nvram/.apply_partner_defaults   
   #>>zqiu
   if declare -f create_wifi_default > /dev/null 2>&1; then
      create_wifi_default
   fi
   #<<zqiu
   if [ "$ENCRYPT_SYSCFG" = false ] ; then
      echo_t "[utopia][init] Retarting syscfg using file store ($SYSCFG_BKUP_FILE)"
      touch $SYSCFG_BKUP_FILE
   else
      echo_t "[utopia][init] Retarting syscfg using file store ($SYSCFG_NEW_FILE)"
      touch $SYSCFG_NEW_FILE
   fi
   touch $SYSCFG_FILE
   
   syscfg_create -f $SYSCFG_FILE
   if [ $? != 0 ]; then
	   CheckAndReCreateDB
   fi
   
#>>zqiu
   # Put value 204 into networkresponse.txt file so that
   # all LAN services start with a configuration which will
   # redirect everything to Gateway IP.
   # This value again will be modified from network_response.sh 
   echo_t "[utopia][init] Echoing network response during Factory reset"
   echo 204 > /var/tmp/networkresponse.txt
    

elif [ "$FACTORY_RESET_WIFI" = "$SYSCFG_FR_VAL" ]; then
    echo_t "[utopia][init] Performing wifi reset"
    if declare -f create_wifi_default > /dev/null 2>&1; then
        create_wifi_default
    fi
    syscfg unset $FACTORY_RESET_KEY
#<<zqiu
fi
#echo_t "[utopia][init] Cleaning up vendor nvram"
# /etc/utopia/service.d/nvram_cleanup.sh

echo_t "*** HTTPS root certificate for TR69 ***"

if [ ! -f /etc/cacert.pem ]; then
	echo_t "HTTPS root certificate for TR69 is missing..."

fi
if [ -f /nvram/cacert.pem ]; then
        echo "Remove HTTPS root certificate for TR69 if available in NVRAM to prevent updating cert"
	rm -f /nvram/cacert.pem
fi

#CISCOXB3-6085:Removing current configuration from nvram as a part of PSM migration.
if [ -f /nvram/bbhm_cur_cfg.xml  ]; then
       mv /nvram/bbhm_cur_cfg.xml $PSM_CUR_XML_CONFIG_FILE_NAME
elif [ -f $PSM_BAK_XML_CONFIG_FILE_NAME  ]; then	
	cp -f $PSM_BAK_XML_CONFIG_FILE_NAME $PSM_CUR_XML_CONFIG_FILE_NAME
fi

#echo_t "[utopia][init] Starting system logging"
#$UTOPIA_PATH/service_syslog.sh syslog-start

# update max number of msg in queue based on system maximum queue memory.
# This update will be used for presence detection feature.
MSG_SIZE_MAX=`cat /proc/sys/fs/mqueue/msgsize_max`
MSG_MAX_SYS=`ulimit -q`
TOT_MSG_MAX=50
if [ -z "$MSG_MAX_SYS" ]; then
echo "ulimit cmd not avail assign mq msg_max :$TOT_MSG_MAX"
else
TOT_MSG_MAX=$((MSG_MAX_SYS/MSG_SIZE_MAX))
echo "mq msg_max :$TOT_MSG_MAX"
fi

echo $TOT_MSG_MAX > /proc/sys/fs/mqueue/msg_max


echo_t "[utopia][init] Starting sysevent subsystem"
#syseventd --threads 18
syseventd
sleep 1
sysevent_pid="$(pidof syseventd)"
sysevent_status="$(sysevent ping)"
if [ "$sysevent_status" != "SUCCESS" ]; then
   echo_t "[utopia][init] ERROR Syseventd subsystem is not started properly: ${sysevent_status}, pid: ${sysevent_pid}"
else
   echo_t "[utopia][init] Syseventd subsystem started with pid: ${sysevent_pid} successfully"
fi

echo_t "[utopia][init] Setting any unset system values to default"
apply_system_defaults
changeFilePermissions $SYSCFG_BKUP_FILE 400
if [ "$ENCRYPT_SYSCFG" = false ] ; then
   echo "[utopia][init] SEC: Syscfg stored in $SYSCFG_BKUP_FILE"
else
   changeFilePermissions $SYSCFG_NEW_FILE 400
   echo "[utopia][init] SEC: Syscfg stored in $SYSCFG_NEW_FILE"
fi


syscfg unset UpdateNvram
syscfg commit
syscfg unset NonRootSupport
syscfg commit

#Added log to check the DHCP range corruption after system defaults applied.
lan_ipaddr=`syscfg get lan_ipaddr`
lan_netmask=`syscfg get lan_netmask`
echo_t "[utopia][init] lan_ipaddr = $lan_ipaddr lan_netmask = $lan_netmask"

lost_and_found_enable=`syscfg get lost_and_found_enable`
echo_t "[utopia][init] lost_and_found_enable = $lost_and_found_enable"
if [ "$lost_and_found_enable" == "true" ]
then
    iot_ifname=`syscfg get iot_ifname`
    if [ "$iot_ifname" == "l2sd0.106" ]; then
     echo_t "[utopia][init] changing over to new LnF bridge: br106"
     syscfg set iot_brname br106
     syscfg commit
    fi
    iot_dhcp_start=`syscfg get iot_dhcp_start`
    iot_dhcp_end=`syscfg get iot_dhcp_end`
    iot_netmask=`syscfg get iot_netmask`
    echo_t "[utopia][init] [DHCPCORRUPT_TRACE] configuring for IOT iot_ifname = $iot_ifname "
    echo_t "[utopia][init] [DHCPCORRUPT_TRACE] iot_dhcp_start = $iot_dhcp_start iot_dhcp_end=$iot_dhcp_end iot_netmask=$iot_netmask"
else
    touch /tmp/lnf_disable
fi

ForwardSSH=`syscfg get ForwardSSH`
Log_file="/rdklogs/logs/FirewallDebug.txt"
if $ForwardSSH;then
   echo "SSH: Forward SSH changed to enabled" >> $Log_file
else
   echo "SSH: Forward SSH changed to disabled" >> $Log_file
fi

# Get the syscfg value which indicates whether unit is activated or not.
# This value is set from network_response.sh based on the return code received.
activated=`syscfg get unit_activated`
echo_t "[utopia][init] Value of unit_activated got is : $activated"
if [ "$activated" = "1" ]
then
    echo_t "[utopia][init] Echoing network response during Reboot"
    echo 204 > /var/tmp/networkresponse.txt
fi 

echo_t "[utopia][init] Applying iptables settings"

lan_ifname=`syscfg get lan_ifname`
cmdiag_ifname=`syscfg get cmdiag_ifname`
ecm_wan_ifname=`syscfg get ecm_wan_ifname`
wan_ifname=`sysevent get wan_ifname`

#disable telnet / ssh ports
iptables -A INPUT -i "$lan_ifname" -p tcp --dport 23 -j DROP
iptables -A INPUT -i "$lan_ifname" -p tcp --dport 22 -j DROP
iptables -A INPUT -i "$cmdiag_ifname" -p tcp --dport 23 -j DROP
iptables -A INPUT -i "$cmdiag_ifname" -p tcp --dport 22 -j DROP

ip6tables -A INPUT -i "$lan_ifname" -p tcp --dport 23 -j DROP
ip6tables -A INPUT -i "$lan_ifname" -p tcp --dport 22 -j DROP
ip6tables -A INPUT -i "$cmdiag_ifname" -p tcp --dport 23 -j DROP
ip6tables -A INPUT -i "$cmdiag_ifname" -p tcp --dport 22 -j DROP

#protect from IPv6 NS flooding
ip6tables -t mangle -A PREROUTING -i "$ecm_wan_ifname" -d ff00::/8 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j DROP
ip6tables -t mangle -A PREROUTING -i "$wan_ifname" -d ff00::/8 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j DROP

#/sbin/ulogd -c /etc/ulogd.conf -d

echo_t "[utopia][init] Processing registration"
# run all executables in the sysevent registration directory
# echo_t "[utopia][init] Running registration using $INIT_DIR"
execute_dir $INIT_DIR&
#init_inter_subsystem&

#--------Set up private IPC vlan----------------
vconfig add l2sd0 500
if [ "$BOX_TYPE" = "XB3" ];then
	$UTOPIA_PATH/service_multinet_exec add_ipc_vlan &
else
	if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
		$SWITCH_HANDLER addVlan 0 500 sw_6
	fi
fi
ifconfig l2sd0.500 192.168.101.1

export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/run/dbus/system_bus_socket

if [ "$BOX_TYPE" = "XB3" ];then
	$BINPATH/dbus-daemon --config-file=$CCSPPATH/basic.conf --fork
fi
#start  ntpd server on ARM
NTP_CONF=/etc/ntp.conf
NTP_CONF_TMP=/tmp/ntp.conf
if [ "$BOX_TYPE" = "XB3" ]
then
	cp $NTP_CONF $NTP_CONF_TMP
	echo "interface ignore wildcard" >> $NTP_CONF_TMP
	echo "interface listen $ARM_INTERFACE_IP" >> $NTP_CONF_TMP
	ntpd -c $NTP_CONF_TMP 
fi
#--------Set up Radius vlan -------------------
vconfig add l2sd0 4090
if [ "$BOX_TYPE" = "XB3" ];then
	$UTOPIA_PATH/service_multinet_exec add_radius_vlan &
else
	if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
		$SWITCH_HANDLER addVlan 0 4090 sw_6 
	fi
fi
ifconfig l2sd0.4090 192.168.251.1 netmask 255.255.255.0 up
ip rule add from all iif l2sd0.4090 lookup erouter


# RDKB-15951 : Dedicated l2sd0 vlan for Mesh Bhaul
vconfig add l2sd0 1060
if [ "$BOX_TYPE" == "XB3" ];then
        $UTOPIA_PATH/service_multinet_exec add_meshbhaul_vlan &
else
	if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
	        $SWITCH_HANDLER addVlan 0 1060 sw_6
	fi
fi
ifconfig l2sd0.1060 up
ip rule add from all iif l2sd0.1060 lookup erouter

# Add QinQ for pod ethernet backhaul traffic
brctl addbr br403
ifconfig br403 192.168.245.1 netmask 255.255.255.0 up
brctl addif br403 l2sd0.1060
ip rule add from all iif br403 lookup erouter

# Add a new bridge for ethernet bhaul delivery
brctl addbr brebhaul
ifconfig brebhaul 169.254.85.1 netmask 255.255.255.0 up

#--------Marvell LAN-side egress flood mitigation----------------
echo_t "88E6172: Do not egress flood unicast with unknown DA"
if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
	swctl -c 11 -p 5 -r 4 -b 0x007b
fi

# Creating IOT VLAN on ARM
if [ -z "$SWCTL_BIN_NOT_SUPPORTED" ] || [ "$SWCTL_BIN_NOT_SUPPORTED" == "false" ]; then
	swctl -c 16 -p 0 -v 106 -m 2 -q 1
	swctl -c 16 -p 7 -v 106 -m 2 -q 1
fi
vconfig add l2sd0 106
brctl addbr br106
ifconfig l2sd0.106 up
ifconfig br106 192.168.106.1 netmask 255.255.255.0 up
brctl addif br106 l2sd0.106
ip rule add from all iif l2sd0.106 lookup erouter
ip rule add from all iif br106 lookup erouter

# Check and set factory-reset as reboot reason 
if [ "$FACTORY_RESET_REASON" = "true" ]; then
   if [ -f /nvram/.image_upgrade_and_FR_done ] && [ "$BOX_TYPE" = "VNTXER5" ]; then
       echo "[utopia][init] Detected last reboot reason as FirmwareDownloadAndFactoryReset"
       if [ -e "/usr/bin/onboarding_log" ]; then
           /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as FirmwareDownloadAndFactoryReset"
       fi
       syscfg set X_RDKCENTRAL-COM_LastRebootReason "FirmwareDownloadAndFactoryReset"
       syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
       rm -f /nvram/.image_upgrade_and_FR_done
   elif [ -f "/nvram/.Invalid_PartnerID" ]; then
       echo "[utopia][init] Detected last reboot reason as Reboot-DueTo-InvalidPartnerID"
       syscfg set X_RDKCENTRAL-COM_LastRebootReason "Reboot-DueTo-InvalidPartnerID"
       syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
       rm -f /nvram/.Invalid_PartnerID
   else
       echo_t "[utopia][init] Detected last reboot reason as factory-reset"
       if [ -e "/usr/bin/onboarding_log" ]; then
          /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as factory-reset"
       fi
       syscfg set X_RDKCENTRAL-COM_LastRebootReason "factory-reset"
       syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
   fi
else
   rebootReason=`syscfg get X_RDKCENTRAL-COM_LastRebootReason`
   rebootCounter=`syscfg get X_RDKCENTRAL-COM_LastRebootCounter`
   echo_t "[utopia][init] X_RDKCENTRAL-COM_LastRebootReason ($rebootReason)"
   if [ "$rebootReason" = "factory-reset" ]; then
      echo_t "[utopia][init] Setting last reboot reason as unknown"
      syscfg set X_RDKCENTRAL-COM_LastRebootReason "unknown"
   fi
      if [ "`cat /proc/P-UNIT/status|grep "Last reset origin"|awk '{ print $9 }'`" == "RESET_ORIGIN_HW" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	 if [ -e "/usr/bin/onboarding_log" ]; then
	     /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as HW or Power-On Reset"
	 fi
#ifdef CISCO_XB3_PLATFORM_CHANGES
         ##Work around: RDKB3939-500: /nvram/RDKB3939-500_RebootNotByPwrOff file not created by utopia.service(atom side) in case of power off shut down
      elif ( [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3939B" ] ) && [ "`cat /proc/P-UNIT/status|grep "Last reset origin"|awk '{ print $9 }'`" == "RESET_ORIGIN_ATOM" ] && [ ! -f "/nvram/RDKB3939-500_RebootNotByPwrOff" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	 if [ -e "/usr/bin/onboarding_log" ]; then
	     /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as HW or Power-On Reset"
	 fi
      # created by docsis module when detect low queue condition that can lead to non-ssh 
      elif [ -f "/nvram/low_level_queue_stuck_reboot" ];then
      	if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "queue-stuck-reboot"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm -f /nvram/low_level_queue_stuck_reboot
      	fi
##LastRebootReason is set as BBU-Reset if the file /nvram/reboot.txt is present
      elif [ -f "/nvram/reboot.txt" ]; then
      	if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "BBU-Reset"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/reboot.txt
      	fi
	  #Last reboot reason set as "PCD-reboot"  if the file /nvram/pcd_reboot_reason.txt is present
      elif [ -f "/nvram/pcd_reboot_reason.txt" ]; then
#        if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         echo_t "[utopia][init] Setting last reboot reason as PCD-reboot"
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "PCD-reboot"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/pcd_reboot_reason.txt
#        fi
#endif
##LastRebootReason is set as DOCSIS_SNMP_REBOOT if the file /nvram/CISCO_DOCSIS_SNMP_REBOOT is present
      elif [ -f "/nvram/CISCO_DOCSIS_SNMP_REBOOT" ]; then
      	if [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ] ||[ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
         syscfg set X_RDKCENTRAL-COM_LastRebootReason "DOCSIS_SNMP_REBOOT"
         syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
         rm /nvram/CISCO_DOCSIS_SNMP_REBOOT
      	fi
      else
         RESET_DURATION=`cat /proc/P-UNIT/status|grep "Last reset duration"|awk '{ print $7 }'`
         result=`echo "$RESET_DURATION $BUTTON_THRESHOLD"| awk '{if ($1 > 0 && $1 < $2) print $1}'`
         if [ -n "$result" ]; then
            syscfg set X_RDKCENTRAL-COM_LastRebootReason "pin-reset"
            syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	    if [ -e "/usr/bin/onboarding_log" ]; then
	        /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as pin-reset"
	    fi
         fi

#ifdef CISCO_XB3_PLATFORM_CHANGES
      	  if [ -e "/proc/P-UNIT/status" ]; then
	         Punit_status=`grep -i "Last reset origin" /proc/P-UNIT/status | awk '{print $9}'`
	         if [ "$Punit_status" = "RESET_ORIGIN_DOCSIS_WATCHDOG" ] && [ "$rebootReason" = "Software_upgrade" ] && [ "$rebootCounter" = "1" ] && [ -e "/nvram/reboot_due_to_sw_upgrade" ];then
                     echo_t "[utopia][init] Setting last reboot reason as Software_upgrade_Watchdog_Reboot"
                     syscfg set X_RDKCENTRAL-COM_LastRebootReason "Software_upgrade_Watchdog_Reboot"
                     syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	         elif ( [ "$rebootCounter" = "0" ] ) && ( [ "$Punit_status" = "RESET_ORIGIN_ATOM_WATCHDOG" ] || [ "$Punit_status" = "RESET_ORIGIN_DOCSIS_WATCHDOG" ] || [ "$Punit_status" = "RESET_ORIGIN_ATOM" ] );then
	             syscfg set X_RDKCENTRAL-COM_LastRebootReason "$Punit_status"
	             syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
		     if [ -e "/usr/bin/onboarding_log" ]; then
		         /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as $Punit_status"
		     fi
		fi
	         if [ "$BOX_TYPE" = "XB3" ];then
	             Punit_Reset_Reason=`grep -i "Last reset reason" /proc/P-UNIT/status | awk '{print $9}'`
	             if [ "$Punit_Reset_Reason" = "RESET_WARM" ] && [ "$Punit_status" = "RESET_ORIGIN_DOCSIS" ];then
	                   syscfg set X_RDKCENTRAL-COM_LastRebootReason "HOST-OOPS-REBOOT"
	                   syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	             fi
	         fi
         fi
#endif
      fi
fi

if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
    if [ -f /nvram/restore_reboot ];then
	syscfg set X_RDKCENTRAL-COM_LastRebootReason "restore-reboot"
	syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"

        if [ -f /nvram/bbhm_cur_cfg.xml-temp ]; then
            ##Work around: TCCBR-4087 Restored saved configuration is not restoring wan Static IP.
            ##after untar the new bbhm current config is overrriden/corrupted at times.
            ##Hence we are storing a backup and replacing it to current config upon such cases
            a=`md5sum /nvram/bbhm_cur_cfg.xml-temp`
            a=$(echo "$a" | cut -f 1 -d " ")
            b=`md5sum $PSM_CUR_XML_CONFIG_FILE_NAME`
            b=$(echo "$b" | cut -f 1 -d " ")
            if [[ $a != "$b" ]]; then
               cp /nvram/bbhm_cur_cfg.xml-temp $PSM_CUR_XML_CONFIG_FILE_NAME
            fi
            rm -f /nvram/bbhm_cur_cfg.xml-temp
        fi
    fi
    rm -f /nvram/restore_reboot
    rm -f /nvram/bbhm_bak_cfg.xml.prev
    rm -f /nvram/syscfg.db.prev
fi

CBF_Defaulted=`syscfg get CodeBigFirstDefaulted`
if [ "$CBF_Defaulted" != "true" ]; then
    if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ] || [ "$MODEL_NUM" = "DPC3939" ] || [ "$MODEL_NUM" = "DPC3941" ]; then
         syscfg set CodeBigFirstEnabled "true"
    fi
    syscfg set CodeBigFirstDefaulted "true"
fi

syscfg commit

#ifdef CISCO_XB3_PLATFORM_CHANGES
## Remove after setting last reboot reason
if [ -f "/nvram/RDKB3939-500_RebootNotByPwrOff" ]; then
	rm /nvram/RDKB3939-500_RebootNotByPwrOff
fi

# Start Fixing CISCOXB3-5905
if [ -e "/tmp/.nvmnt.log" ]; then
    cat /tmp/.nvmnt.log >> /rdklogs/logs/Consolelog.txt.0
    rm -rf /tmp/.nvmnt.log
    touch /nvram/.nvmnt.log
fi
# Ending Fixing CISCOXB3-5905

#endif 

# starting the rpcserver
echo_t "[utopia][init] Starting rpcserver in arm" 
if [ -f /usr/bin/rpcserver ];then
    /usr/bin/rpcserver &
fi

# Remove webconfig_db.bin on factory reset on XB3 platforms,CISCOXB3-6731
if [ "$FACTORY_RESET_REASON" = "true" ] && [ "$BOX_TYPE" = "XB3" ];then
        ATOM_RPC_IP=`grep ATOM_ARPING_IP /etc/device.properties | cut -f 2 -d"="`
        rpcclient $ATOM_RPC_IP "rm -f /nvram/webconfig_db.bin"
        rpcclient $ATOM_RPC_IP "rm -f /nvram/Blocklist_XB3.txt"
fi

#set ntp status as unsynchronized on bootup
syscfg set ntp_status 2

echo_t "[utopia][init] setting Multicast MAC before any switch configs"
$UTOPIA_PATH/service_multinet_exec set_multicast_mac &

if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
	echo_t "[utopia][init] started dropbear process"
	/etc/utopia/service.d/service_sshd.sh sshd-start &
fi

if [ "$BOX_TYPE" = "VNTXER5" ]; then
       /etc/vbv_reboot_reason.sh &
fi

if [ "$BOX_TYPE" = "VNTXER5" ]; then
   if [ "$FACTORY_RESET_REASON" = "false" ]; then
      wanifcount=`sed -n "/dmsb.wanmanager.wan.interfacecount/p" $PSM_CUR_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
      if [ "$wanifcount" != "" ]; then
         wanifdefcount=`sed -n "/dmsb.wanmanager.wan.interfacecount/p" $PSM_DEF_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
         if [ "$wanifdefcount" != "" ]; then
            echo "[utopia][init] No. of WAN Interface from $PSM_DEF_XML_CONFIG_FILE_NAME:"$wanifdefcount
            echo "[utopia][init] No. of WAN Interface from $PSM_CUR_XML_CONFIG_FILE_NAME:"$wanifcount
            if [ "$wanifcount" != "$wanifdefcount" ]; then
               delCmd=`sed -i "/dmsb.wanmanager.wan.interfacecount/d" $PSM_CUR_XML_CONFIG_FILE_NAME`
               echo "[utopia][init] WAN interface count mismatched so deleting this dmsb.wanmanager.wan.interfacecount entry from $PSM_CUR_XML_CONFIG_FILE_NAME to make sure proper interface count"
            fi
         fi
      fi
   fi
fi

if [ "$BOX_TYPE" = "SCER11BEL" ]; then
       /etc/reset_reason_log.sh &
fi
