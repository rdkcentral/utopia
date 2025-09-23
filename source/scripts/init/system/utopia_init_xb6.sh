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

echo "*******************************************************************"
echo "*                                                                  "
echo "* Copyright 2014 Cisco Systems, Inc. 				 "
echo "* Licensed under the Apache License, Version 2.0                   "
echo "*                                                                  "
echo "*******************************************************************"

source /etc/utopia/service.d/log_capture_path.sh
source /etc/device.properties

dmesg -n 5

TR69TLVFILE="/nvram/TLVData.bin"
TR69KEYS="/nvram/.keys"
REVERTFLAG="/nvram/reverted"
MAINT_START="/nvram/.FirmwareUpgradeStartTime"
MAINT_END="/nvram/.FirmwareUpgradeEndTime"
MQTT_URL_MIGRATEDFILE="/nvram/.mqtturl_migrated"
# determine the distro type (GAP or GNP)
#distro not used
#if [ -n "$(grep TPG /etc/drg_version.txt)" ]; then
#    distro=GAP
#else
#    distro=GNP
#fi

# determine the build type (debug or production)
if [ -f /etc/debug_build ] ; then
    debug_build=1
else
    debug_build=0
fi

firmware_name=$(sed -n 's/^imagename[:=]"\?\([^"]*\)"\?/\1/p' /version.txt)
utc_time=`date -u`
echo "[$utc_time] [utopia][init] DEVICE_INIT:$firmware_name"
if [ -e "/usr/bin/onboarding_log" ]; then
    /usr/bin/onboarding_log "[utopia][init] DEVICE_INIT:$firmware_name"
fi

echo "[utopia][init] Tweaking network parameters" > /dev/console

KERNEL_VERSION=`uname -r | cut -c 1`

if [ "$KERNEL_VERSION" -lt 4 ] ; then
	echo "60" > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout_stream
	echo "60" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_syn_sent
	echo "60" > /proc/sys/net/ipv4/netfilter/ip_conntrack_generic_timeout
	echo "10" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait
	echo "10" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_close
	echo "20" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_close_wait
        if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ] ; then
		#Intel Proposed RDKB Generic Bug Fix from XB6 SDK
		echo "16384" > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
		echo "7440" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established
	else
		# TCCBR-1849 - don't override nf_conntrack_max here, this value is set at /lib/rdk/brcm.networking
		#echo "8192" > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
		echo "[$utc_time] [utopia][init] don't override nf_conntrack_max here, value is set at /lib/rdk/brcm.networking"
		echo "7440" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established
	fi

else
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_generic_timeout
	echo "10" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
	echo "10" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close
	echo "20" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
	if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ] ; then
		#Intel Proposed RDKB Generic Bug Fix from XB6 SDK
		echo "16384" > /proc/sys/net/netfilter/nf_conntrack_max
		echo "7440" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
	else
		# TCCBR-1849 - don't override nf_conntrack_max here, this value is set at /lib/rdk/brcm.networking
		#echo "8192" > /proc/sys/net/netfilter/ip_conntrack_max
		echo "[$utc_time] [utopia][init] don't override nf_conntrack_max here, value is set at /lib/rdk/brcm.networking"
		echo "7440" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
	fi
fi

echo "400" > /proc/sys/net/netfilter/nf_conntrack_expect_max

if [ "$MODEL_NUM" = "TG4482A" ]; then
   echo "8192" > /proc/sys/vm/min_free_kbytes
fi


# RDKB-26160
#echo 4096 > /proc/sys/net/ipv6/neigh/default/gc_thresh1
#echo 8192 > /proc/sys/net/ipv6/neigh/default/gc_thresh2
#echo 8192 > /proc/sys/net/ipv6/neigh/default/gc_thresh3

#echo "[utopia][init] Loading drivers"
#MODULE_PATH=/lib/modules/`uname -r`/
#insmod $MODULE_PATH/drivers/net/erouter_ni.ko netdevname=erouter0

#if [ "$distro" = "GAP" ]; then
#    #
#    # ---- GAP: boot sequence (TPG)
#    #
#
#    sh /etc/rcS.d/11platform-init.sh
#
#    echo "*******************************************************************"
#    echo "*                                                                  "
#    echo "* Booting Cisco DRG `getFlashValue model -d`                       "
#    echo "* Hardware ID: `getFlashValue hwid -d` Hardware Version: `getFlashValue hwversion -d`"
#    echo "* Unit Serial Number: `getFlashValue unitsn`                       "
#    echo "* Board Serial Number: `getFlashValue boardsn`                     "
#    echo "* Manufacture Date: `getFlashValue mfgdate -d`                     "
#    echo "* Software Version: `cat /etc/drg_version.txt`                     "
#    echo "*                                                                  "
#    echo "*******************************************************************"
#
#else
#    #
#    # ---- GNP: boot sequence (CNS)
#    #
#
#    echo "*******************************************************************"
#    echo "* Software Version: `cat /etc/drg_version.txt`                     "
#    echo "*******************************************************************"
#
#    insmod /lib/modules/`uname -r`/kernel/drivers/wifi/wl.ko
#    cp /etc/utopia/service.d/nvram.dat /tmp
#fi
echo "Starting log module.."
/usr/sbin/log_start.sh

echo "[utopia][init] Starting udev.."

# Spawn telnet daemon only for production images
#if [ $debug_build -ne 0 ]; then
    #echo "[utopia][init] Starting telnetd"
    #service telnet start
    #utelnetd -d
#fi

#echo "[utopia][init]  Starting syslogd"
#/sbin/syslogd && /sbin/klogd

# echo "[utopia][init] Provisioning loopback interface"
#ip addr add 127.0.0.1/255.0.0.0 dev lo
#ip link set lo up
#ip route add 127.0.0.0/8 dev lo

# create our passwd/shadow/group files
#mkdir -p /tmp/etc/.root
#chmod 711 /tmp/etc/.root

#chmod 644 /tmp/etc/.root/passwd
#chmod 600 /tmp/etc/.root/shadow
#chmod 600 /tmp/etc/.root/group

# create the default profile. This is linked to by /etc/profile 
#echo "export setenv PATH=/bin:/sbin:/usr/sbin:/usr/bin:/opt/sbin:/opt/bin" > /tmp/profile
#echo "export setenv LD_LIBRARY_PATH=/lib:/usr/lib:/opt/lib" >> /tmp/profile
#echo "if [ \$(tty) != \"/dev/console\"  -a  \${USER} != \"root\" ]; then cd /usr/cosa; ./cli_start.sh; fi" >> /tmp/profile

# create other files that are linked to by etc
#echo -n > /tmp/hosts
#echo -n > /tmp/hostname
#echo -n > /tmp/resolv.conf
#echo -n > /tmp/igmpproxy.conf
#echo -n > /tmp/ez-ipupdate.conf
#echo -n > /tmp/ez-ipupdate.out
#echo -n > /tmp/TZ
#echo -n > /tmp/.htpasswd
#echo -n > /tmp/dnsmasq.conf
#echo -n > /tmp/dhcp_options
#echo -n > /tmp/dhcp_static_hosts
#echo -n > /tmp/dnsmasq.leases
#echo -n > /tmp/zebra.conf
#echo -n > /tmp/ripd.conf
#echo -n > /tmp/dhcp6c.conf

mkdir -p /tmp/cron

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
SYSCFG_PERSISTENT_PATH=/opt/secure/data
SYSCFG_NEW_FILE=$SYSCFG_PERSISTENT_PATH/syscfg.db
SYSCFG_NEW_BKUP_FILE=$SYSCFG_PERSISTENT_PATH/syscfg_bkup.db
PSM_CUR_XML_CONFIG_FILE_NAME="$SYSCFG_TMP_LOCATION/bbhm_cur_cfg.xml"
PSM_BAK_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_bak_cfg.xml"
PSM_TMP_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_tmp_cfg.xml"
XDNS_DNSMASQ_SERVERS_CONFIG_FILE_NAME="$SYSCFG_MOUNT/dnsmasq_servers.conf"
FACTORY_RESET_REASON=false
HOTSPOT_BLOB="/nvram/hotspot_blob"
HOTSPOT_JSON="/nvram/hotspot.json"
MWO_PATH="/nvram/mwo"
CHANNEL_KEEPOUT_PATH="/nvram/mesh"

if [ -d $SYSCFG_ENCRYPTED_PATH ]; then
       if [ ! -d $SYSCFG_PERSISTENT_PATH ]; then
               echo "$SYSCFG_PERSISTENT_PATH path not available creating directory"
               mkdir $SYSCFG_PERSISTENT_PATH
       fi
fi

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
			  syscfg_oldDB=$?
			  if [ $syscfg_oldDB -ne 0 ]; then
				  NVRAMFullStatus=`df -h $SYSCFG_MOUNT | grep "100%"`
				  if [ -n "$NVRAMFullStatus" ]; then
					 echo "[utopia][init] NVRAM Full(100%) and below is the dump"
					 du -h $SYSCFG_MOUNT 
					 ls -al $SYSCFG_MOUNT	 
				  fi
			  fi 
		fi
	fi 
}

echo "[utopia][init] Starting syscfg using file store ($SYSCFG_NEW_FILE)"
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

if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ] ; then
   # ARRIS ADD - Add a call to reset the CM's factory defaults
   arris_rpc_client arm nvm_reset
   # END ARRIS ADD
fi

   #>>zqiu
   echo "[utopia][init] need to reset wifi when ($SYSCFG_NEW_FILE) file is not available"
   syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_WIFI
   syscfg commit
   #<<zqiu
   touch /nvram/.apply_partner_defaults
   # Put value 204 into networkresponse.txt file so that
   # all LAN services start with a configuration which will
   # redirect everything to Gateway IP.
   # This value again will be modified from network_response.sh 
   echo "[utopia][init] Echoing network response during Factory reset"
   echo 204 > /var/tmp/networkresponse.txt
fi

if [ -f $SYSCFG_OLDBKUP_FILE ];then
	rm -rf $SYSCFG_OLDBKUP_FILE
fi
if [ -f $SYSCFG_NEW_BKUP_FILE ]; then
	rm -rf $SYSCFG_NEW_BKUP_FILE
fi
if [ -f $SYSCFG_BKUP_FILE ]; then
          rm -rf $SYSCFG_BKUP_FILE
fi

SYSCFG_LAN_DOMAIN=`syscfg get lan_domain` 

if [ "$SYSCFG_LAN_DOMAIN" == "utopia.net" ]; then
   echo "[utopia][init] Setting lan domain to NULL"
   syscfg set lan_domain ""
   syscfg commit
fi

if [ "$MANUFACTURE" = "Technicolor" ]; then
    PROCESS_TRACE_FILE="/nvram/process_trace.log"
    if [ "$MODEL_NUM" = "CVA601ZCOM" ]; then
        reboot_type=$(latticecli -n reason | awk '{print $5}')
        if [ "power_on_reset" == $reboot_type ]; then
            if [ "unknown" == $(syscfg get X_RDKCENTRAL-COM_LastRebootReason) ] || [ "0" == $(syscfg get X_RDKCENTRAL-COM_LastRebootCounter) ]; then
                syscfg set X_RDKCENTRAL-COM_LastRebootReason "power-on-reset"
                syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
            fi
        fi
    else
        BL_LAST_RESET_REASON=$(hexdump -e '16/1 "%02x" "\n"' /proc/device-tree/bolt/reset-history)
        BL_LAST_RESET_REASON=${BL_LAST_RESET_REASON:0:8} # Strip everything but first four bytes

        if [ "00000003" == ${BL_LAST_RESET_REASON} ] || [ "00000001" == ${BL_LAST_RESET_REASON} ]
        then
            if [ "unknown" == $(syscfg get X_RDKCENTRAL-COM_LastRebootReason) ] || [ "0" == $(syscfg get X_RDKCENTRAL-COM_LastRebootCounter) ]
            then
                syscfg set X_RDKCENTRAL-COM_LastRebootReason "power-on-reset"
                syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
            fi
        fi
        if [ "00002000" == ${BL_LAST_RESET_REASON} ] && [ ! -f $PROCESS_TRACE_FILE ]
        then
            syscfg set X_RDKCENTRAL-COM_LastRebootReason "power-restoration"
            syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
        fi
     fi

    RESET_BUTTON_FILE="/nvram/resetdefaults.rdkb"

    if [ -f $RESET_BUTTON_FILE ]; then
        echo "[utopia][init] ${RESET_BUTTON_FILE} exists, utopia needs to factory reset"
        PUNIT_RESET_DURATION=`cat ${RESET_BUTTON_FILE}`
        echo "[utopia][init] removing ${RESET_BUTTON_FILE}, PUNIT_RESET_DURATION ${PUNIT_RESET_DURATION}"
        rm -f ${RESET_BUTTON_FILE}
	if [ "$MODEL_NUM" != “CGM4140COM” ]; then
           rm -f /nvram/.bcmwifi* 
	fi   
    else
        echo "[utopia][init] No ${RESET_BUTTON_FILE}, assuming non FR init"
        PUNIT_RESET_DURATION=0
    fi    
else
   if [ -s /sys/bus/acpi/devices/INT34DB:00/reset_btn_dur ]; then
       #Note: /sys/bus/acpi/devices/INT34DB:00/reset_btn_dur is an Arris XB6 File created by Arris and Intel by reading ARM
       PUNIT_RESET_DURATION=`cat /sys/bus/acpi/devices/INT34DB:00/reset_btn_dur`
    else
       echo "[utopia][init] /sys/bus/acpi/devices/INT34DB:00/reset_btn_dur is empty or missing"
       PUNIT_RESET_DURATION=0
    fi
fi

#ForwardSSH log print

ForwardSSH=`syscfg get ForwardSSH`
Log_file="/rdklogs/logs/FirewallDebug.txt"
if $ForwardSSH;then
   echo "SSH: Forward SSH changed to enabled" >> $Log_file
else
   echo "SSH: Forward SSH changed to disabled" >> $Log_file
fi

#IGMP PROXY Disbaling on migration
IGMP_MIGRATE="`syscfg get igmp_migrate`"
if [ -z "$IGMP_MIGRATE" ]; then
  echo "Disabling igmp proxy " >> $Log_file
  syscfg set igmpproxy_enabled "0"
  syscfg commit
  syscfg set igmp_migrate "1"
  syscfg commit
fi

# Set the factory reset key if it was pressed for longer than our threshold
if test "$BUTTON_THRESHOLD" -le "$PUNIT_RESET_DURATION"; then
   syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_RGWIFI && BUTTON_FR="1"
   syscfg commit
fi

SYSCFG_FR_VAL="`syscfg get $FACTORY_RESET_KEY`"

if [ "$FACTORY_RESET_RGWIFI" = "$SYSCFG_FR_VAL" ]; then
   echo "[utopia][init] Performing factory reset"
   
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
   rm -f /nvram/.keys/*
   rm -f /nvram/ble-enabled
   touch /nvram/.apply_partner_defaults
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
   rm -f /nvram/partners_defaults.json 
   rm -f /nvram/bootstrap.json
   rm -f /opt/secure/bootstrap.json
   rm -f /opt/secure/RFC/tr181store.json
   rm -f /opt/secure/Blocklist_file.txt
   if [ -f /nvram/.CMchange_reboot_count ];then
      rm -f /nvram/.CMchange_reboot_count
   fi

    if [ -f "$HOTSPOT_BLOB" ];then
      rm -f "$HOTSPOT_BLOB"
   fi

    if [ -f "$HOTSPOT_JSON" ];then
        rm -f "$HOTSPOT_JSON"
    fi

   if [ -f /nvram/dnsmasq.vendorclass ]; then
      rm -f /nvram/dnsmasq.vendorclass
   fi

   #Remove hwselftest.results file if present
   rm -f /nvram/hwselftest.results

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

    # Remove on factory reset, prioratized schedule pcs.bin and pcs.bin.md5 on all RDKB platforms 
    rm -f /nvram/pcs-now-priomac.dat
    rm -f /nvram/pcs-now-priomac.dat.md5
   if [ -f /nvram/speedboost-mac.dat ]; then
      rm -f /nvram/speedboost-mac.dat
   fi
   if [ -f /nvram/speedboost-mac.dat.md5 ]; then
      rm -f /nvram/speedboost-mac.dat.md5
   fi

   if [ -f /nvram/rfc.json ]; then
    rm -f /nvram/rfc.json
   fi

   if [ -f /opt/secure/RFC/.RFC_SSHWhiteList.list ]; then
      rm -f /opt/secure/RFC/.RFC_SSHWhiteList.list
   fi

   echo "[utopia][init] Retarting syscfg using file store ($SYSCFG_NEW_FILE)"
   touch $SYSCFG_NEW_FILE
   touch $SYSCFG_FILE
   syscfg_create -f $SYSCFG_FILE
   syscfg_oldDB=$?
   if [ $syscfg_oldDB -ne 0 ];then
	 CheckAndReCreateDB
   fi
   
#>>zqiu
   # Put value 204 into networkresponse.txt file so that
   # all LAN services start with a configuration which will
   # redirect everything to Gateway IP.
   # This value again will be modified from network_response.sh 
   echo "[utopia][init] Echoing network response during Factory reset"
   echo 204 > /var/tmp/networkresponse.txt
    

elif [ "$FACTORY_RESET_WIFI" = "$SYSCFG_FR_VAL" ]; then
    echo "[utopia][init] Performing wifi reset"
    create_wifi_default
    syscfg unset $FACTORY_RESET_KEY
#<<zqiu
fi
#echo "[utopia][init] Cleaning up vendor nvram"
# /etc/utopia/service.d/nvram_cleanup.sh

echo "*** HTTPS root certificate for TR69 ***"

if [ ! -f /etc/cacert.pem ]; then
	echo "HTTPS root certificate for TR69 is missing..."

fi

if [ -f /nvram/cacert.pem ]; then
        echo "Remove HTTPS root certificate for TR69 if available in NVRAM to prevent updating cert"
	rm -f /nvram/cacert.pem
fi

#echo "[utopia][init] Starting system logging"
#/etc/utopia/service.d/service_syslog.sh syslog-start

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


echo "[utopia][init] Starting sysevent subsystem"
#syseventd --threads 18
syseventd

# we want plugged in usb devices to propagate events to sysevent
#echo "[utopia][init] Late loading usb drivers"
#MODULE_PATH=/lib/modules/`uname -r`/
#insmod $MODULE_PATH/usbcore.ko
#insmod $MODULE_PATH/ehci-hcd.ko
#insmod $MODULE_PATH/scsi_mod.ko
#insmod $MODULE_PATH/sd_mod.ko
#insmod $MODULE_PATH/libusual.ko
#insmod $MODULE_PATH/usb-storage.ko
#insmod $MODULE_PATH/nls_cp437.ko
#insmod $MODULE_PATH/nls_iso8859-1.ko
#insmod $MODULE_PATH/fat.ko
#insmod $MODULE_PATH/vfat.ko

#ARRISXB6-1554: apply_system_defaults calls sysevent API. Logs showed binaries weren't fully started
attemptCounter=0

until [ -e "/tmp/syseventd_connection" ]; do
    
    if [ $attemptCounter -lt 3 ]
    then
       sleep 2
       let "attemptCounter++"
    else
       break
    fi
done

# check if new_ntp_init_val is empty or not
#If user changes new_ntp_enabled to false, then new_ntp_init_val will block from overwriting the new_ntp_enabled value.
SYSCFG_NEW_NTP_INIT_VAL="`syscfg get new_ntp_init_val`"
if [ -z "$SYSCFG_NEW_NTP_INIT_VAL" ]; then
   syscfg set new_ntp_init_val "true"
   # Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.newNTP.Enable
   SYSCFG_NEW_NTP_VAL="`syscfg get new_ntp_enabled`"
   if [ "$SYSCFG_NEW_NTP_VAL" == "false" ]; then
      syscfg set new_ntp_enabled "true"
   fi
   syscfg commit
   sync
fi

echo "[utopia][init] Setting any unset system values to default"
apply_system_defaults
#ARRISXB6-2998
changeFilePermissions $SYSCFG_BKUP_FILE 400
changeFilePermissions $SYSCFG_NEW_FILE 400
echo "[utopia][init] SEC: Syscfg stored in $SYSCFG_NEW_FILE"
syscfg unset UpdateNvram
syscfg commit
syscfg unset NonRootSupport
syscfg commit
if [ -s /nvram/.secure_mount_failure ]; then
     if [ `cat /nvram/.secure_mount_failure` -gt 3 ]; then
           echo "[utopia][init] Device needs to be replaced as it is unable to recover /opt/secure mount issue"
           rm -f /nvram/.secure_mount_failure
     fi
fi

# Get the syscfg value which indicates whether unit is activated or not.
# This value is set from network_response.sh based on the return code received.
activated=`syscfg get unit_activated`
echo "[utopia][init] Value of unit_activated got is : $activated"
if [ "$activated" = "1" ]
then
    echo "[utopia][init] Echoing network response during Reboot"
    echo 204 > /var/tmp/networkresponse.txt
fi 

echo "[utopia][init] Applying iptables settings"

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


#echo "[utopia][init] Starting telnetd"
#TELNET_ENABLE=`syscfg get mgmt_wan_telnetaccess`
#if [ "$TELNET_ENABLE" = "1" ]; then
#    if [ -e /bin/login ]; then
#        /usr/sbin/telnetd -l /bin/login
#    else
#        /usr/sbin/telnetd
#    fi
#fi


echo "[utopia][init] Processing registration"

if [ "$rdkb_extender" = "true" ];then
    device_mode=`syscfg get Device_Mode`
    if [ -z "$device_mode" ]; then
        device_mode=`cat PSM_BAK_XML_CONFIG_FILE_NAME | grep dmsb.device.NetworkingMode | cut -d ">" -f 2 | cut -d "<" -f 1`
        if [ -z "$device_mode" ]; then
        device_mode=`cat /usr/ccsp/config/bbhm_def_cfg.xml | grep dmsb.device.NetworkingMode | cut -d ">" -f 2 | cut -d "<" -f 1`
        fi
        if [ -n "$device_mode" ]; then
            syscfg set Device_Mode $device_mode
            syscfg commit
        fi
    fi

    if [ "$device_mode" = "1" ]; then
        INIT_DIR=/etc/utopia/extender
    else
        INIT_DIR=/etc/utopia/registration.d
    fi
    echo "[utopia][init] sysevent Init Dir: $INIT_DIR"
else
    INIT_DIR=/etc/utopia/registration.d
fi
# run all executables in the sysevent registration directory
# echo "[utopia][init] Running registration using $INIT_DIR"
execute_dir $INIT_DIR&
#init_inter_subsystem&

#--------Set up private IPC vlan----------------
#SWITCH_HANDLER=/etc/utopia/service.d/service_multinet/handle_sw.sh
#vconfig add l2sd0 500
#$SWITCH_HANDLER addVlan 0 500 sw_6
#ifconfig l2sd0.500 192.168.101.1

#--------Set up Radius vlan -------------------
#vconfig add l2sd0 4090
#$SWITCH_HANDLER addVlan 0 4090 sw_6
#ifconfig l2sd0.4090 192.168.251.1 netmask 255.255.255.0 up
#ip rule add from all iif l2sd0.4090 lookup erouter

#--------Marvell LAN-side egress flood mitigation----------------
#echo "88E6172: Do not egress flood unicast with unknown DA"
#swctl -c 11 -p 5 -r 4 -b 0x007b

# Creating IOT VLAN on ARM
#swctl -c 16 -p 0 -v 106 -m 2 -q 1
#swctl -c 16 -p 7 -v 106 -m 2 -q 1
#vconfig add l2sd0 106
#ifconfig l2sd0.106 192.168.106.1 netmask 255.255.255.0 up
#ip rule add from all iif l2sd0.106 lookup erouter

cause_file="/sys/bus/acpi/devices/INT34DB:00/reset_cause"
type_file="/sys/bus/acpi/devices/INT34DB:00/reset_type"
COLD_REBOOT=false
if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ]; then
   if [ -e $cause_file ] && [ -e $type_file ];then
      value_c=$(cat $cause_file)
      value_t=$(cat $type_file)
      if [ "$value_t" = "0" ] && [ "$value_c" = "0" ];then
         COLD_REBOOT=true
      fi
   fi
fi


# Check and set factory-reset as reboot reason
if [ "$FACTORY_RESET_REASON" = "true" ]; then

   if [ "$MODEL_NUM" = "TG3482G" ]; then
	rm -f /nvram/mesh_enabled
   fi
   syscfg set X_RDKCENTRAL-COM_LastRebootReason "factory-reset"
   syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
   if [ "$MODEL_NUM" = "CGM4331COM" ] || [ "$MODEL_NUM" = "CGM4981COM" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ] ||  [ "$MODEL_NUM" = "CGM4140COM" ] || [ "$MODEL_NUM" = "CGA4332COM" ] || [  "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ]; then
   # Enable AUTOWAN by default for XB7, change is made here so that it will take effect only after FR
      syscfg set selected_wan_mode "0"
   fi
   if [ -f /nvram/WPS_Factory_Reset ]; then
       echo "[utopia][init] Detected last reboot reason as WPS-Factory-Reset"
       if [ -e "/usr/bin/onboarding_log" ]; then
          /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as WPS-Factory-Reset"
       fi
       #syscfg set X_RDKCENTRAL-COM_LastRebootReason "WPS-Factory-Reset"
       #syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
       rm -f /nvram/WPS_Factory_Reset
   elif ([ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ] || [ "${MODEL_NUM}" = "CVA601ZCOM" ]) && [ -f /nvram/.image_upgrade_and_FR_done ]; then
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
       echo "[utopia][init] Detected last reboot reason as factory-reset"
       if [ -e "/usr/bin/onboarding_log" ]; then
          /usr/bin/onboarding_log "[utopia][init] Detected last reboot reason as factory-reset"
       fi
    fi
elif [ "$PUNIT_RESET_DURATION" -gt "0" ]; then
   echo "[utopia][init] Detected last reboot reason as pin-reset"
   if [ -e "/usr/bin/onboarding_log" ]; then
       /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as pin-reset"
   fi
   syscfg set X_RDKCENTRAL-COM_LastRebootReason "pin-reset"
   syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
elif [ -f /nvram/restore_reboot ]; then
     if [ -e "/usr/bin/onboarding_log" ]; then
             /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as restore-reboot"
     fi
     syscfg set X_RDKCENTRAL-COM_LastRebootReason "restore-reboot"
     syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
     
     if [ "$BOX_TYPE" == "TCCBR" ];then
	syscfg set CodeBigFirstEnabled false
         if [ -f /nvram/bbhm_bak_cfg.xml-temp ]; then
              ##Work around: TCCBR-4087 Restored saved configuration is not restoring wan Static IP.
              ##after untar the new bbhm current config is overrriden/corrupted at times.
              ##Hence we are storing a backup and replacing it to backup config upon such cases
              a=`md5sum /nvram/bbhm_bak_cfg.xml-temp`
              a=$(echo $a | cut -f 1 -d " ")
              b=`md5sum $PSM_CUR_XML_CONFIG_FILE_NAME`  
              b=$(echo $b | cut -f 1 -d " ")
              if [[ $a != $b ]]; then
                  cp /nvram/bbhm_bak_cfg.xml-temp /nvram/bbhm_bak_cfg.xml
              fi
			 rm -f /nvram/bbhm_bak_cfg.xml-temp
         fi
     fi
     rm -f /nvram/restore_reboot
     rm -f /nvram/syscfg.db.prev
elif [ "$COLD_REBOOT" == "true" ]; then
     #Temporarily exclude Arris XB6 Products until ARRISXB6-12791 is fixed
     if [ "$MODEL_NUM" != "TG3482G" ]; then
        if [ -e "/usr/bin/onboarding_log" ]; then
         /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as HW or Power-On Reset"
        fi
        syscfg set X_RDKCENTRAL-COM_LastRebootReason "HW or Power-On Reset"
        syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
     fi
else
   rebootReason=`syscfg get X_RDKCENTRAL-COM_LastRebootReason` 
   reboot_counter=`syscfg get X_RDKCENTRAL-COM_LastRebootCounter`
   echo "[utopia][init] X_RDKCENTRAL-COM_LastRebootReason ($rebootReason)"
   #TCCBR-4220 To handle wrong reboot reason
   if ( [ "$rebootReason" = "factory-reset" ] ) || ( [ "$BOX_TYPE" = "TCCBR" ] && [ "$reboot_counter" -eq "0" ] ); then
      echo "[utopia][init] Setting last reboot reason as unknown"
      syscfg set X_RDKCENTRAL-COM_LastRebootReason "unknown"
      if [ -e "/usr/bin/onboarding_log" ]; then
          /usr/bin/onboarding_log "[utopia][init] Last reboot reason set as unknown"
      fi
   fi
fi
syscfg commit

#Removing mqtt broker url entry only on first software_upgrade. 
#Default value which is empty URL will be populated from partners_defaults.json
if [ ! -f $MQTT_URL_MIGRATEDFILE ]; then
        touch $MQTT_URL_MIGRATEDFILE
        sed -i '/Device.X_RDK_MQTT.BrokerURL/d' $PSM_BAK_XML_CONFIG_FILE_NAME
        echo "[utopia][init] Created /nvram/.mqtturl_migrated file, deleted broker url entry from psm DB on initial software upgrade."
fi

#CISCOXB3-6085:Removing current configuration from nvram as a part of PSM migration.
if [ -f /nvram/bbhm_cur_cfg.xml  ]; then
       mv /nvram/bbhm_cur_cfg.xml $PSM_CUR_XML_CONFIG_FILE_NAME
elif [ -f $PSM_BAK_XML_CONFIG_FILE_NAME  ]; then
        cp -f $PSM_BAK_XML_CONFIG_FILE_NAME $PSM_CUR_XML_CONFIG_FILE_NAME
fi

#set ntp status as unsynchronized on bootup
syscfg set ntp_status 2

#RDKB-24155 - TLVData.bin should not be used in EWAN mode
eth_wan_enable=`syscfg get eth_wan_enabled`
if [ "$eth_wan_enable" = "true" ] && [ -f $TR69TLVFILE ]; then
  rm -f $TR69TLVFILE
  #RDKB-30774 - Remove existing ACS server URL and passwords, when migrating from DOCSIS to EWAN
  #Default ACS URL from partners_defaults would be populated when booting in EWAN mode for the first time
  rm -rf $TR69KEYS
  sed -i '/eRT.com.cisco.spvtg.ccsp.tr069pa.Device.ManagementServer.URL.Value/d' $PSM_CUR_XML_CONFIG_FILE_NAME
fi

if [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ]; then
	/bin/sh -c '(/usr/sbin/tch_traceKernelPanic.sh)'
fi

echo "[utopia][init] completed creating utopia_inited flag"
touch /tmp/utopia_inited

if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ] || [ "$MANUFACTURE" = "Technicolor" ]; then
    if [ -f /tmp/.secure_mount_flag ]; then
        echo "[utopia][init] Detected last reboot reason as secure-mount failure"
        syscfg set X_RDKCENTRAL-COM_LastRebootReason "secure-mount-failure"
        syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
        rm -f /tmp/.secure_mount_flag
    fi
fi

if [ "$MODEL_NUM" = "TG3482G" ]; then
    echo "[utopia][init] completed creating utopia_inited flag"
    touch /tmp/utopia_inited

    #!/bin/bash
    RESET_FILE=/nvram/6/arris_reset.log
    REBOOT_LOG=/nvram/6/atom_reboot_log.txt

    if [ -e $RESET_FILE ]
    then
       echo "arris_reset_reason_log:File exists"
    else
       echo "arris_reset_reason_log:File does not exist"
       echo "arris_reset_reason_log:Creating last reset reason log file"
       mkdir -p /nvram/6
       echo "" > "$RESET_FILE"
    fi
    if [ -e $REBOOT_LOG ]
    then
       echo "$REBOOT_LOG:File exists"
    else
       echo "$REBOOT_LOG:File does not exist"
       echo "$REBOOT_LOG:Creating atom reboot log file"
       mkdir -p /nvram/6
       echo "" > "$REBOOT_LOG"
    fi
fi

IsFirmwareUpgrade()
{
    rebootReason=`syscfg get X_RDKCENTRAL-COM_LastRebootReason`
    if [ "$rebootReason" = "Software_upgrade" ] || [ "$rebootReason" = "Forced_Software_upgrade" ]; then
        return 0
    else
        return 1
    fi
}

if [ "$(syscfg get MAPT_Enable)" != "true" ] && [ ! -f "/nvram/.mapt_enabled" ]; then
    partnerID=`syscfg get PartnerID`
    if [ "$MAPT_SUPPORT" == "true" ] && [ "$partnerID" = "cox" ] && IsFirmwareUpgrade; then
        syscfg set MAPT_Enable true
        syscfg commit
        touch /nvram/.mapt_enabled
        echo_t "MAPT_Enable is $(syscfg get MAPT_Enable) for $partnerID"
    fi
fi

if [ "$FACTORY_RESET_REASON" = "false" ]; then
   #WAN Interface Count
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

   #WAN Group Count
   wangrpcount=`sed -n "/dmsb.wanmanager.group.Count/p" $PSM_CUR_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
   if [ "$wangrpcount" != "" ]; then
      wangrpdefcount=`sed -n "/dmsb.wanmanager.group.Count/p" $PSM_DEF_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
      if [ "$wangrpdefcount" != "" ]; then
         echo "[utopia][init] No. of WAN Group from $PSM_DEF_XML_CONFIG_FILE_NAME:"$wangrpdefcount
         echo "[utopia][init] No. of WAN Group from $PSM_CUR_XML_CONFIG_FILE_NAME:"$wangrpcount
         if [ "$wangrpcount" != "$wangrpdefcount" ]; then
            delCmd=`sed -i "/dmsb.wanmanager.group.Count/d" $PSM_CUR_XML_CONFIG_FILE_NAME`
            echo "[utopia][init] WAN group count mismatched so deleting this dmsb.wanmanager.group.Count entry from $PSM_CUR_XML_CONFIG_FILE_NAME to make sure proper group count"
         fi
      fi
   fi

   #DHCP MGR v4 Client Count
   dhcpmgrCltcount=`sed -n "/dmsb.dhcpmanager.ClientNoOfEntries/p" $PSM_CUR_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
   if [ "$dhcpmgrCltcount" != "" ]; then
      dhcpmgrCltdefcount=`sed -n "/dmsb.dhcpmanager.ClientNoOfEntries/p" $PSM_DEF_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
      if [ "$dhcpmgrCltdefcount" != "" ]; then
         echo "[utopia][init] No. of DHCP MGR v4 client count from $PSM_DEF_XML_CONFIG_FILE_NAME:"$dhcpmgrCltdefcount
         echo "[utopia][init] No. of DHCP MGR v4 client count from $PSM_CUR_XML_CONFIG_FILE_NAME:"$dhcpmgrCltcount
         if [ "$dhcpmgrCltcount" != "$dhcpmgrCltdefcount" ]; then
            delCmd=`sed -i "/dmsb.dhcpmanager.ClientNoOfEntries/d" $PSM_CUR_XML_CONFIG_FILE_NAME`
            echo "[utopia][init] DHCP MGR v4 client count mismatched so deleting this dmsb.dhcpmanager.ClientNoOfEntries entry from $PSM_CUR_XML_CONFIG_FILE_NAME to make sure proper v4 client count"
         fi
      fi
   fi

   #DHCP MGR v6 Client Count
   dhcpmgrv6Cltcount=`sed -n "/dmsb.dhcpmanager.dhcpv6.ClientNoOfEntries/p" $PSM_CUR_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
   if [ "$dhcpmgrv6Cltcount" != "" ]; then
      dhcpmgrv6Cltdefcount=`sed -n "/dmsb.dhcpmanager.dhcpv6.ClientNoOfEntries/p" $PSM_DEF_XML_CONFIG_FILE_NAME | awk -F"[><]" '{print $3}'`
      if [ "$dhcpmgrv6Cltdefcount" != "" ]; then
         echo "[utopia][init] No. of DHCP MGR v6 client count from $PSM_DEF_XML_CONFIG_FILE_NAME:"$dhcpmgrv6Cltdefcount
         echo "[utopia][init] No. of DHCP MGR v6 client count from $PSM_CUR_XML_CONFIG_FILE_NAME:"$dhcpmgrv6Cltcount
         if [ "$dhcpmgrv6Cltcount" != "$dhcpmgrv6Cltdefcount" ]; then
            delCmd=`sed -i "/dmsb.dhcpmanager.dhcpv6.ClientNoOfEntries/d" $PSM_CUR_XML_CONFIG_FILE_NAME`
            echo "[utopia][init] DHCP MGR v6 client count mismatched so deleting this dmsb.dhcpmanager.dhcpv6.ClientNoOfEntries entry from $PSM_CUR_XML_CONFIG_FILE_NAME to make sure proper v6 client count"
         fi
      fi
   fi
fi