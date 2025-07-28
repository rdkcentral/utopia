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
# This script sets up the device mode
#--------------------------------------------------------------

source /etc/utopia/service.d/log_capture_path.sh

echo_t "---------------------------------------------------------"
echo_t "-------------------- service_devicemode.sh ---------------------"
echo_t "---------------------------------------------------------"

SERVICE_NAME=devicemode

echo "service_devicemode.sh arg1 is $1 arg2 is $2"
Ipv4_Gateway_Addr=""
Ipv6_Gateway_Addr=""
mesh_wan_ifname=$(psmcli get dmsb.Mesh.WAN.Interface.Name)
mesh_bhaul_ifname="br-home"

cellular_ifname=$(sysevent get cellular_ifname)

MESH_IFNAME_DEF_ROUTE=$(psmcli get dmsb.l3net.9.V4Addr)
DEVICE_MODE=$(syscfg get Device_Mode)

DEF_RESOLV_CONF="/etc/resolv.conf"
TMP_RESOLV_CONF="/tmp/lte_resolv.conf"

v6_dns_configured="/tmp/.v6dnsconfigured"
v4_dns_configured="/tmp/.v4dnsconfigured"

DEV_MODE_SWITCHED="/tmp/.deviceMode_switched"

update_v4route()
{
    backup_v4_dns1=$(sysevent get backup_cellular_wan_v4_dns1)
    backup_v4_dns2=$(sysevent get backup_cellular_wan_v4_dns2)
    backup_wan_v4_gw=$(sysevent get backup_cellular_wan_v4_gw)

    cellular_manager_gw=$(sysevent get cellular_wan_v4_gw)
    cellular_manager_dns1=$(sysevent get cellular_wan_v4_dns1)
    cellular_manager_dns2=$(sysevent get cellular_wan_v4_dns2)
    if [ "$cellular_manager_gw" = "0.0.0.0" ] || [ -z "$cellular_manager_gw" ] ;then
        # delete route
        echo "Deleting rule to resolve dns packets"
        ip route del "$backup_v4_dns1" via "$backup_wan_v4_gw" dev "$cellular_ifname" proto static metric 100
        ip route del "$backup_v4_dns2" via "$backup_wan_v4_gw" dev "$cellular_ifname" proto static metric 100

        if [ "1" = "$DEVICE_MODE" ] ; then
            #ip rule del from all dport 53 lookup 12
            ip rule del iif "$cellular_ifname" lookup 11
            ip route del default via $backup_wan_v4_gw dev "$cellular_ifname" table 12
        fi

    else
        echo "Adding rule to resolve dns packets"

        route_table=$(ip route show)
        dns1_missing=$(echo "$route_table" | grep $cellular_manager_dns1)
        dns2_missing=$(echo "$route_table" | grep $cellular_manager_dns2)

        if [ "$cellular_manager_gw" != "$backup_wan_v4_gw" ] || [ "$cellular_manager_dns1" != "$backup_v4_dns1" ] || [ "$cellular_manager_dns2" != "$backup_v4_dns2" ];
        then
            if [ -n "$backup_wan_v4_gw" ] || [ "$backup_wan_v4_gw" != "0.0.0.0" ];then

                if [ -n "$backup_v4_dns1" ];then
                    ip route del "$backup_v4_dns1" via "$backup_wan_v4_gw" dev "$cellular_ifname" proto static metric 100
                fi
                if [ -n "$backup_v4_dns2" ];then
                    ip route del "$backup_v4_dns2" via "$backup_wan_v4_gw" dev "$cellular_ifname" proto static metric 100
                fi
            fi
            ip route add "$cellular_manager_dns1" via "$cellular_manager_gw" dev "$cellular_ifname" proto static metric 100
            ip route add "$cellular_manager_dns2" via "$cellular_manager_gw" dev "$cellular_ifname" proto static metric 100
        elif [ -z "$dns1_missing" ] || [ -z "$dns2_missing" ] ;then
            echo "v4 dns entries missing in route, adding it"
            ip route add "$cellular_manager_dns1" via "$cellular_manager_gw" dev "$cellular_ifname" proto static metric 100 > /dev/null
            ip route add "$cellular_manager_dns2" via "$cellular_manager_gw" dev "$cellular_ifname" proto static metric 100 > /dev/null
        fi
        if [ "1" = "$DEVICE_MODE" ] ; then
            #ip rule add from all dport 53 lookup 12
            ip rule del iif "$cellular_ifname" lookup 11 > /dev/null
            ip rule add iif "$cellular_ifname" lookup 11
            ip route del default dev "$cellular_ifname" table 12 > /dev/null
            ip route add default via $cellular_manager_gw dev "$cellular_ifname" table 12
        fi
    fi
    sysevent set backup_cellular_wan_v4_gw "$cellular_manager_gw"
    sysevent set backup_cellular_wan_v4_dns1 "$cellular_manager_dns1"
    sysevent set backup_cellular_wan_v4_dns2 "$cellular_manager_dns2"

}

update_v6route()
{
    backup_v6_dns1=$(sysevent get backup_cellular_wan_v6_dns1)
    backup_v6_dns2=$(sysevent get backup_cellular_wan_v6_dns2)
    backup_wan_v6_gw=$(sysevent get backup_cellular_wan_v6_gw)

    cellular_manager_v6_gw=$(sysevent get cellular_wan_v6_gw | cut -d "/" -f 1)

    cellular_manager_dns1=$(sysevent get cellular_wan_v6_dns1)
    cellular_manager_dns2=$(sysevent get cellular_wan_v6_dns2)

    if [ "$cellular_manager_v6_gw" = "::" ] || [ -z "$cellular_manager_v6_gw" ] ;then
        # delete route
        ip -6 route del "$backup_v6_dns1" via "$backup_wan_v6_gw" dev "$cellular_ifname" proto static metric 100
        ip -6 route del "$backup_v6_dns2" via "$backup_wan_v6_gw" dev "$cellular_ifname" proto static metric 100

        if [ "1" = "$DEVICE_MODE" ] ; then
            ip -6 rule del iif "$cellular_ifname" lookup 11
        fi
    else

        routev6_table=$(ip -6 route show)
        dns1_missing=$(echo "$routev6_table" | grep $cellular_manager_dns1)
        dns2_missing=$(echo "$routev6_table" | grep $cellular_manager_dns2)

        echo "Adding v6 rule to resolve dns packets"

        if [ "$cellular_manager_v6_gw" != "$backup_wan_v6_gw" ] || [ "$cellular_manager_dns1" != "$backup_v6_dns1" ] || [ "$cellular_manager_dns2" != "$backup_v6_dns2" ];
        then
            if [ -n "$backup_wan_v6_gw" ] || [ "$backup_wan_v6_gw" != "0.0.0.0" ];then

                if [ -n "$backup_v6_dns1" ];then
                    ip -6 route del "$backup_v6_dns1" via "$backup_wan_v6_gw" dev "$cellular_ifname" proto static metric 100
                fi
                if [ -n "$backup_v6_dns2" ];then
                    ip -6 route del "$backup_v6_dns2" via "$backup_wan_v6_gw" dev "$cellular_ifname" proto static metric 100
                fi
            fi
            ip -6 route add "$cellular_manager_dns1" via "$cellular_manager_v6_gw" dev "$cellular_ifname" proto static metric 100
            ip -6 route add "$cellular_manager_dns2" via "$cellular_manager_v6_gw" dev "$cellular_ifname" proto static metric 100
        elif [ -z "$dns1_missing" ] || [ -z "$dns2_missing" ] ;then
            echo "v6 dns entries missing in route, adding it"
            ip -6 route add "$cellular_manager_dns1" via "$cellular_manager_v6_gw" dev "$cellular_ifname" proto static metric 100 > /dev/null
            ip -6 route add "$cellular_manager_dns2" via "$cellular_manager_v6_gw" dev "$cellular_ifname" proto static metric 100 > /dev/null
        fi
        
        if [ "1" = "$DEVICE_MODE" ] ; then
            ip -6 rule del iif "$cellular_ifname" lookup 11 > /dev/null
            ip -6 rule add iif "$cellular_ifname" lookup 11
        else 
            echo "Adding v6 route in router mode"
            ip -6 route add default via "$cellular_manager_v6_gw" dev "$cellular_ifname"

        fi
    fi

    sysevent set backup_cellular_wan_v6_gw "$cellular_manager_v6_gw"
    sysevent set backup_cellular_wan_v6_dns1 "$cellular_manager_dns1"
    sysevent set backup_cellular_wan_v6_dns2 "$cellular_manager_dns2"

}

update_dns_conf()
{
  devMode=`syscfg get Device_Mode`

  RESOLV_CONF_override_needed=0
    if [ "1" = "$devMode" ] ; then
        RESOLV_CONF=/tmp/lte_resolv.conf   
    else
        RESOLV_CONF="/etc/resolv.conf"
    fi

  RESOLV_CONF_TMP="/tmp/resolv_tmp.conf"

    ip_dns="$2"
    cp $RESOLV_CONF $RESOLV_CONF_TMP
    echo "comapring old and new dns IPV6 configuration " 
     RESOLV_CONF_override_needed=0
     for i in $ip_dns
     do
        new_ipv6_dns_server="nameserver $i"
        dns_matched=`grep "$new_ipv6_dns_server" "$RESOLV_CONF_TMP"`
        if [ -z "$dns_matched" ]; then
                echo "$new_ipv6_dns_server is not present in old dns config so resolv_conf file overide is required " 
                RESOLV_CONF_override_needed=1
                break
        fi
     done

     if [ "$RESOLV_CONF_override_needed" -eq 1 ]; then
     sed -i '/nameserver 127.0.0.1/d' "$RESOLV_CONF_TMP"
     if [ "$1" = "ipv6" ];then
        dns=$(sysevent get wan6_ns_backup)
     elif [ "$1" = "ipv4" ];then  
        dns=$(sysevent get wan4_ns_backup)
     else
        return
     fi

     if [ -n "$dns" ]; then
        echo "Removing old DNS IPV6 SERVER configuration from resolv.conf " 
        for i in $dns; do
                dns_server="nameserver $i"
                sed -i "/$dns_server/d" "$RESOLV_CONF_TMP"
        done
     fi
         R=""
        for i in $ip_dns; do
         R="${R}nameserver $i
"
        done

        echo -n "$R" >> "$RESOLV_CONF_TMP"
        echo "Adding new DNS SERVER to resolv.conf" 
        N=""
        while read line; do
        N="${N}$line
"
        done < $RESOLV_CONF_TMP
        echo -n "$N" > "$RESOLV_CONF"

   else
        echo "Old and New dns are same" 
   fi

    rm -rf $RESOLV_CONF_TMP
        if [ "$1" = "ipv6" ];then
            sysevent set wan6_ns_backup "$ip_dns"
            touch "$v6_dns_configured"
        elif [ "$1" = "ipv4" ];then  
            sysevent set wan4_ns_backup "$ip_dns"
            touch "$v4_dns_configured"
        fi
}

sync_dns()
{
    echo "Syncing v4 and v6 dns"
    ipv4_dns=$(sysevent get ipv4_nameserver)
    if [ -n "$ipv4_dns" ];then
        update_dns_conf "ipv4" "$ipv4_dns"
    fi
    ipv6_dns=$(sysevent get ipv6_nameserver)
    if [ -n "$ipv6_dns" ];then
        update_dns_conf "ipv6" "$ipv6_dns"
    fi
}
set_dummy_route()
{
    ip link add dummy1 type dummy 
    ifconfig dummy1 up
    ip route add default dev dummy1 scope link metric 1026 table MODEM
    ip route add default dev dummy1 scope link metric 1026 table 12
    #ip -6 route add default dev dummy1 scope link metric 1 table MODEM
    ip -6 route add default dev dummy1 scope link metric 1026 table 12
}                    
case "$1" in
    "${SERVICE_NAME}-start")
        service_devicemode start $2
        ;;
    "${SERVICE_NAME}-stop")
        service_devicemode stop $2
        ;;
    "${SERVICE_NAME}-restart")
        service_devicemode stop $2
        service_devicemode start $2
        ;;
    DeviceMode)
        service_devicemode DeviceMode $2
        cell_manager_gw_addr=$(sysevent get cellular_wan_v4_gw)

        if [ "$2" = "1" ];then
            ip route del default via $cell_manager_gw_addr dev "$cellular_ifname" > /dev/null
            sysevent set routeunset-ula

            if [ ! -f "$v6_dns_configured" ] || [ ! -f "$v4_dns_configured" ];then
                sync_dns
            else
                cp "$DEF_RESOLV_CONF" "$TMP_RESOLV_CONF"
            fi
            # write null to DEF RESOLV CONF
            > "$DEF_RESOLV_CONF"
            mesh_wan_status=$(sysevent get mesh_wan_linkstatus)
            if [ "$mesh_wan_status" = "up" ];then
                def_gateway=$(ip route show | grep default | grep "$mesh_bhaul_ifname" | cut -d " " -f 3)
                if [ -z "$def_gateway" ];then
                    def_gateway=$MESH_IFNAME_DEF_ROUTE
                fi
                echo "nameserver $def_gateway" > "$DEF_RESOLV_CONF"
            fi
            echo "Adding rule to resolve dns packets"
        	if_status=`ifconfig "$cellular_ifname" | grep UP`
                if [ -n "$if_status" ];then
               	    #ip rule add from all dport 53 lookup 12
                    ip rule del iif "$cellular_ifname" lookup 11 > /dev/null
                    ip rule add iif "$cellular_ifname" lookup 11

                   	Ipv4_Gateway_Addr=$(sysevent get cellular_wan_v4_gw)
                   	if [ -n "$Ipv4_Gateway_Addr" ];then
                            ip route del default dev "$cellular_ifname" table 12 > /dev/null
                        	ip route add default via $Ipv4_Gateway_Addr dev "$cellular_ifname" table 12
                   	else
                        	ip route add default dev "$cellular_ifname" table 12
                   	fi

                   	#ip -6 rule add from all dport 53 lookup 12
                    ip -6 rule del iif "$cellular_ifname" lookup 11 > /dev/null
                    ip -6 rule add iif "$cellular_ifname" lookup 11

                   	Ipv6_Gateway_Addr=$(sysevent get cellular_wan_v6_gw)
                   	if [ -n "$Ipv6_Gateway_Addr" ];then
                        	Ipv6_Gateway_Addr=$(echo $Ipv6_Gateway_Addr | cut -d "/" -f 1)
                            ip -6 route del default dev "$cellular_ifname" table 12 > /dev/null
                        	ip -6 route add default via $Ipv6_Gateway_Addr dev "$cellular_ifname" table 12
                   	else
                        	ip -6 route add default dev "$cellular_ifname" table 12
                    	fi
                fi
       	elif [ "$2" = "0" ];then
               	echo "Deleting rule to resolve dns packets"
                #ip rule del from all dport 53 lookup 12
                ip rule del iif "$cellular_ifname" lookup 11
                Ipv4_Gateway_Addr=$(sysevent get cellular_wan_v4_gw)
                if [ -n "$Ipv4_Gateway_Addr" ];then
                        ip route del default via $Ipv4_Gateway_Addr dev "$cellular_ifname" table 12
                else
             		ip route del default dev "$cellular_ifname" table 12
                fi
                
                ip route del default via "$MESH_IFNAME_DEF_ROUTE" dev "$mesh_bhaul_ifname"
                ip route add default via "$cell_manager_gw_addr" dev "$cellular_ifname"

                #ip -6 rule del from all dport 53 lookup 12
                ip -6 rule del iif "$cellular_ifname" lookup 11
                Ipv6_Gateway_Addr=$(sysevent get cellular_wan_v6_gw)
                if [ -n "$Ipv6_Gateway_Addr" ];then
                	Ipv6_Gateway_Addr=$(echo $Ipv6_Gateway_Addr | cut -d "/" -f 1)
                        ip -6 route del default via $Ipv6_Gateway_Addr dev "$cellular_ifname" table 12
                else
                        ip -6 route del default dev "$cellular_ifname" table 12
                fi

                if [ ! -f "$v6_dns_configured" ] || [ ! -f "$v4_dns_configured" ];then
                    sync_dns
                else
                    if [ -f "$TMP_RESOLV_CONF" ];then
                        cat "$TMP_RESOLV_CONF" > "$DEF_RESOLV_CONF" 
                    fi                
                fi

                sysevent set routeset-ula
   	    fi
        update_v4route
        update_v6route
        touch "$DEV_MODE_SWITCHED" 
        ;;
    mesh_wan_linkstatus)

        if [ x"$(sysevent get last_known_mesh_wan_linkstatus)" != x"$2" ] || [ -f  "$DEV_MODE_SWITCHED" ] ;then
            DEVICE_MODE=`syscfg get Device_Mode`
            rm -rf $DEV_MODE_SWITCHED > /dev/null 
            if [ "1" = "$DEVICE_MODE" ] ; then
                sysevent set lan_status-dhcp "started"
                touch /var/tmp/lan_not_restart
                sysevent set dhcp_server-restart
            sleep 2
            def_gateway=$(ip route show | grep default | grep "$mesh_bhaul_ifname" | cut -d " " -f 3)
            if [ -z "$def_gateway" ];then
                def_gateway=$MESH_IFNAME_DEF_ROUTE
            fi
            echo "nameserver $def_gateway" > "$DEF_RESOLV_CONF"
            mesh_wan_ifname_ipaddr=$(ip -4 addr show dev "$mesh_wan_ifname" scope global | awk '/inet/{print $2}' | cut -d '/' -f1)
            if [ -z "$mesh_wan_ifname_ipaddr" ];then
                mesh_wan_ifname_ipaddr="192.168.246.1"
            fi
                mesh_wan_ula_pref=$(sysevent get MeshWanInterface_UlaPref)
                mesh_wan_ula_ipv6=$(sysevent get MeshWANInterface_UlaAddr)
                mesh_remote_wan_ula_ipv6=$(sysevent get MeshRemoteWANInterface_UlaAddr)
                if [ "$2" = "up" ];then
                    ip rule del from all iif "$mesh_wan_ifname" lookup 12 > /dev/null
                	ip rule add from all iif "$mesh_wan_ifname" lookup 12
                    ip route add default via "$mesh_wan_ifname_ipaddr" dev "$mesh_wan_ifname" table 11
                    ip -6 rule del from all iif "$mesh_wan_ifname" lookup 12 > /dev/null 
                    ip -6 rule add from all iif "$mesh_wan_ifname" lookup 12
                    ip -6 addr add "$mesh_wan_ula_ipv6" dev "$mesh_wan_ifname" 
                    if [ -n "$mesh_remote_wan_ula_ipv6" ];then
                        mesh_remote_wan_ula_ipv6=$(echo $mesh_remote_wan_ula_ipv6 | cut -d "/" -f 1)
                        ip -6 route add default via "$mesh_remote_wan_ula_ipv6" dev "$mesh_wan_ifname" table 11
                    fi
                    #ip -6 route add default dev "$mesh_wan_ifname" table 11

                    # we don't need zebra in ext mode, mesh bridges have static ula ip
                    #sysevent set ipv6_prefix "$mesh_wan_ula_pref"
                    #sysevent set zebra-restart
                elif [ "$2" = "down" ];then
                    ip rule del from all iif "$mesh_wan_ifname" lookup 12
                    ip route del default via "$mesh_wan_ifname_ipaddr" dev "$mesh_wan_ifname" table 11
                    ip -6 rule del from all iif "$mesh_wan_ifname" lookup 12
                    if [ -n "$mesh_remote_wan_ula_ipv6" ];then
                        mesh_remote_wan_ula_ipv6=$(echo $mesh_remote_wan_ula_ipv6 | cut -d "/" -f 1)
                        ip -6 route del default via "$mesh_remote_wan_ula_ipv6" dev "$mesh_wan_ifname" table 11
                    fi
                    ip -6 addr del "$mesh_wan_ula_ipv6" dev "$mesh_wan_ifname" 
                    #ip -6 route del default dev "$mesh_wan_ifname" table 11
                    sysevent set zebra-stop
                fi
                sysevent set firewall-restart
            fi
            sysevent set last_known_mesh_wan_linkstatus "$2"
        fi
        ;;

    ipv6_nameserver)
        if [ -n "$2" ] && [ "$2" != "NULL" ] ;then
            update_dns_conf "ipv6" "$2"
        fi
    ;;
    ipv4_nameserver)
        if [ -n "$2" ] && [ "$2" != "NULL" ] ;then
            update_dns_conf "ipv4" "$2"
        fi
    ;;
    cellular_wan_v4_ip)
        update_v4route
    ;;  
    cellular_wan_v6_ip)
        update_v6route
    ;;
    correct_dns_route)
        update_v4route
        update_v6route
    ;; 
    correct_resolve_conf)
        sync_dns
    ;;
    dummy_route)
        set_dummy_route
    ;; 
    *)
        echo "Usage: service-${SERVICE_NAME} [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart]" > /dev/console
        exit 3
        ;;
esac
