#!/bin/sh

####################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2018 RDK Management
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
##################################################################################

source /etc/device.properties

getWanInterfaceName()
{
  interface_name=`sysevent get current_wan_ifname`
  sysevent_ret=`echo $?`
  #TCXB7-5773 - checking sysevent returns any value other than interface name by return status
  if [ -z "$interface_name" ] || [ $sysevent_ret -ne 0 ];then
      interface_name="erouter0"
  fi
  echo "$interface_name"
}
getWanMacInterfaceName()
{
  if [ "$rdkb_extender" = "true" ];then
        mac_interface="eth0"
  else
    mac_interface=`syscfg get wan_physical_ifname`
    if [ -z "$mac_interface" ];then
        mac_interface="erouter0"
    fi  
  fi
  echo "$mac_interface"
}
IsGWinWFO()
{
  cur_ifname=`sysevent get current_wan_ifname`
  wan_ifname=`sysevent get wan_ifname`
  wan_status=0

  if [ "$cur_ifname" != "$wan_ifname" ]; then
        wan_status=1
  fi
  echo "$wan_status" 
}