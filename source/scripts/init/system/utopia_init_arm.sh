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

echo "*******************************************************************"
echo "*                                                                  "
echo "* Copyright 2014 Cisco Systems, Inc. 				 "
echo "* Licensed under the Apache License, Version 2.0                   "
echo "*                                                                  "
echo "*******************************************************************"

source /etc/utopia/service.d/log_capture_path.sh

dmesg -n 5

TR69TLVFILE="/nvram/TLVData.bin"
REVERTFLAG="/nvram/reverted"
MAINT_START="/nvram/.FirmwareUpgradeStartTime"
MAINT_END="/nvram/.FirmwareUpgradeEndTime"
# determine the distro type (GAP or GNP)
if [ -n "$(grep TPG /etc/drg_version.txt)" ]; then
    distro=GAP
else
    distro=GNP
fi

# determine the build type (debug or production)
if [ -f /etc/debug_build ] ; then
    debug_build=1
else
    debug_build=0
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
	echo "7440" > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established
	echo "8192" > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
else
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent
	echo "60" > /proc/sys/net/netfilter/nf_conntrack_generic_timeout
	echo "10" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
	echo "10" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close
	echo "20" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
	echo "7440" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
	echo "8192" > /proc/sys/net/netfilter/nf_conntrack_max
fi

echo "400" > /proc/sys/net/netfilter/nf_conntrack_expect_max

echo 4096 > /proc/sys/net/ipv6/neigh/default/gc_thresh1
echo 8192 > /proc/sys/net/ipv6/neigh/default/gc_thresh2
echo 8192 > /proc/sys/net/ipv6/neigh/default/gc_thresh3

#echo "[utopia][init] Loading drivers"
#MODULE_PATH=/fss/gw/lib/modules/`uname -r`/
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
/fss/gw/usr/sbin/log_start.sh

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

# BUTTON_THRESHOLD=5 in GA/others
BUTTON_THRESHOLD=15
FACTORY_RESET_KEY=factory_reset
FACTORY_RESET_RGWIFI=y
FACTORY_RESET_WIFI=w
SYSCFG_MOUNT=/nvram
SYSCFG_TMP_LOCATION=/tmp
SYSCFG_FILE=$SYSCFG_TMP_LOCATION/syscfg.db
SYSCFG_BKUP_FILE=$SYSCFG_MOUNT/syscfg.db
SYSCFG_OLDBKUP_FILE=$SYSCFG_MOUNT/syscfg_bkup.db
PSM_CUR_XML_CONFIG_FILE_NAME="$SYSCFG_TMP_LOCATION/bbhm_cur_cfg.xml"
PSM_BAK_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_bak_cfg.xml"
PSM_TMP_XML_CONFIG_FILE_NAME="$SYSCFG_MOUNT/bbhm_tmp_cfg.xml"  
HOTSPOT_BLOB="/nvram/hotspot_blob"
HOTSPOT_JSON="/nvram/hotspot.json"
MWO_PATH="/nvram/mwo"
CHANNEL_KEEPOUT_PATH="/nvram/mesh"

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

echo "[utopia][init] Starting syscfg using file store ($SYSCFG_BKUP_FILE)"
if [ -f $SYSCFG_BKUP_FILE ]; then
	cp $SYSCFG_BKUP_FILE $SYSCFG_FILE
	syscfg_create -f $SYSCFG_FILE
	if [ $? != 0 ]; then
		CheckAndReCreateDB
	fi
else
   echo -n > $SYSCFG_FILE
   syscfg_create -f $SYSCFG_FILE
   if [ $? != 0 ]; then
	  CheckAndReCreateDB
   fi
   touch /nvram/.apply_partner_defaults
   #>>zqiu
   echo "[utopia][init] need to reset wifi when ($SYSCFG_BKUP_FILE) is not avaliable (for 1st time boot up)"
   syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_WIFI
   #<<zqiu
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

# Read reset duration to check if the unit was rebooted by pressing the HW reset button
if cat /proc/P-UNIT/status | grep -q "Reset duration from shadow register"; then
   # Note: Only new P-UNIT firmwares and Linux drivers (>= 1.1.x) support this.
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Reset duration from shadow register"|awk -F ' |\.' '{ print $9 }'`
   # Clear the Reset duration from shadow register value
   # echo "1" > /proc/P-UNIT/clr_reset_duration_shadow
   clean_reset_duration;
elif cat /proc/P-UNIT/status | grep -q "Last reset duration"; then
   PUNIT_RESET_DURATION=`cat /proc/P-UNIT/status|grep "Last reset duration"|awk -F ' |\.' '{ print $7 }'`
else
   echo "[utopia][init] Cannot read the reset duration value from /proc/P-UNIT/status"
fi

#ForwardSSH debug print
ForwardSSH=`syscfg get ForwardSSH`
Log_file="/rdklogs/logs/FirewallDebug.txt"
if $ForwardSSH;then
   echo "SSH: Forward SSH changed to enabled" >> $Log_file
else
   echo "SSH: Forward SSH changed to disabled" >> $Log_file
fi

# Set the factory reset key if it was pressed for longer than our threshold
if test "$BUTTON_THRESHOLD" -le "$PUNIT_RESET_DURATION"; then
   syscfg set $FACTORY_RESET_KEY $FACTORY_RESET_RGWIFI && BUTTON_FR="1"
fi

SYSCFG_FR_VAL="`syscfg get $FACTORY_RESET_KEY`"

if [ "$FACTORY_RESET_RGWIFI" = "$SYSCFG_FR_VAL" ]; then
   echo "[utopia][init] Performing factory reset"
   
SYSCFG_PARTNER_FR="`syscfg get PartnerID_FR`"
if [ "1" = "$SYSCFG_PARTNER_FR" ]; then
   echo_t "[utopia][init] Performing factory reset due to PartnerID change"
fi
# Remove log file first because it need get log file path from syscfg   
   /fss/gw/usr/sbin/log_handle.sh reset
   echo -e "\n" | syscfg_destroy 
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
# Remove syscfg and PSM storage files
   rm -f $SYSCFG_BKUP_FILE
   rm -f $SYSCFG_FILE
   rm -f $PSM_CUR_XML_CONFIG_FILE_NAME
   rm -f $PSM_BAK_XML_CONFIG_FILE_NAME
   rm -f $PSM_TMP_XML_CONFIG_FILE_NAME
   rm -f $TR69TLVFILE
   rm -f $REVERTFLAG
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

   if [ -f /nvram/dnsmasq.vendorclass ]; then
      rm -f /nvram/dnsmasq.vendorclass
   fi

     touch /nvram/.apply_partner_defaults   
   #>>zqiu
   create_wifi_default
   #<<zqiu
   echo "[utopia][init] Retarting syscfg using file store ($SYSCFG_FILE)"
   syscfg_create -f $SYSCFG_FILE
   if [ $? != 0 ]; then
	 CheckAndReCreateDB
   fi
#>>zqiu
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

#CISCOXB3-6085:Removing current configuration from nvram as a part of PSM migration.
if [ -f /nvram/bbhm_cur_cfg.xml  ]; then
       mv /nvram/bbhm_cur_cfg.xml $PSM_CUR_XML_CONFIG_FILE_NAME
elif [ -f $PSM_BAK_XML_CONFIG_FILE_NAME  ]; then	
	cp -f $PSM_BAK_XML_CONFIG_FILE_NAME $PSM_CUR_XML_CONFIG_FILE_NAME
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

echo "[utopia][init] Setting any unset system values to default"
apply_system_defaults

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

#/fss/gw/sbin/ulogd -c /fss/gw/etc/ulogd.conf -d

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
INIT_DIR=/etc/utopia/registration.d
# run all executables in the sysevent registration directory
# echo "[utopia][init] Running registration using $INIT_DIR"
execute_dir $INIT_DIR&
#init_inter_subsystem&

#--------Set up private IPC vlan----------------
SWITCH_HANDLER=/etc/utopia/service.d/service_multinet/handle_sw.sh
vconfig add l2sd0 500
$SWITCH_HANDLER addVlan 0 500 sw_6
ifconfig l2sd0.500 192.168.101.1 

#--------Marvell LAN-side egress flood mitigation----------------
echo "88E6172: Do not egress flood unicast with unknown DA"
swctl -c 11 -p 5 -r 4 -b 0x007b

#--------Default value hack---------------
# overwrite the current value in the nvram and only run once
WAN_SSHACCESS_CHD="/nvram/mgmt_wan_sshaccess_chd"

if [ ! -f $WAN_SSHACCESS_CHD ];then
    syscfg set mgmt_wan_sshaccess 0
    syscfg commit
    touch $WAN_SSHACCESS_CHD
fi
WAN_HTTPACCESS_CHD="/nvram/mgmt_wan_httpaccess_chd"
if [ ! -f $WAN_HTTPACCESS_CHD ];then
    syscfg set mgmt_wan_httpaccess 1
    syscfg commit
    touch $WAN_HTTPACCESS_CHD
fi

WAN_HTTPPORT_CHD="/nvram/mgmt_wan_httpport_chd"
if [ ! -f $WAN_HTTPPORT_CHD ];then
    syscfg set mgmt_wan_httpport 80
    syscfg commit
    touch $WAN_HTTPPORT_CHD
fi

WAN_HTTPACCESS_ERT_CHD="/nvram/mgmt_wan_httpaccess_ert_chd"
if [ ! -f $WAN_HTTPACCESS_ERT_CHD ];then
    syscfg set mgmt_wan_httpaccess_ert 0
    syscfg commit
    touch $WAN_HTTPACCESS_ERT_CHD
fi

WAN_HTTPPORT_ERT_CHD="/nvram/mgmt_wan_httpport_ert_chd"
if [ ! -f $WAN_HTTPPORT_ERT_CHD ];then
    syscfg set mgmt_wan_httpport_ert 8080
    syscfg commit
    touch $WAN_HTTPPORT_ERT_CHD
fi

# Remove webconfig_db.bin on factory reset on XB3 platforms,CISCOXB3-6731
if [ "$BOX_TYPE" = "XB3" ];then
        ATOM_RPC_IP=`grep ATOM_ARPING_IP /etc/device.properties | cut -f 2 -d"="`
        rpcclient "$ATOM_RPC_IP" "rm -f /nvram/webconfig_db.bin"
fi

#set ntp status as unsynchronized on bootup
syscfg set ntp_status 2
