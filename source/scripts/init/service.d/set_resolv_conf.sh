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

RESOLV_CONF=/etc/resolv.conf
RESOLV_CONF_TMP="/tmp/resolv_tmp.conf"
NVRAM_RESOLV="/nvram/resolv.conf"

#-----------------------------------------------------------------
# set the resolv.conf file
#-----------------------------------------------------------------

prepare_resolv_conf () {
   WAN_DOMAIN=`syscfg get  wan_domain`
   NAMESERVER1=`syscfg get nameserver1`
   NAMESERVER2=`syscfg get nameserver2`

   # Default target file is /etc/resolv.conf
   TARGET_RESOLV="$RESOLV_CONF"

   # If static DNS enabled, switch target to nvram/resolv.conf
   if [ x"1" = x"`syscfg get staticdns_enable`" ]; then
       TARGET_RESOLV="$NVRAM_RESOLV"
   fi

   cp $TARGET_RESOLV $RESOLV_CONF_TMP 2>/dev/null || : > $RESOLV_CONF_TMP
 
   if [ -n "$WAN_DOMAIN" ] ; then
       sed -i '/domain/d' "$RESOLV_CONF_TMP"
   fi

       
   if ( [ "0.0.0.0" != "$NAMESERVER1" ] && [ -n "$NAMESERVER1" ] ) || ( [ "0.0.0.0" != "$NAMESERVER2" ] && [ -n "$NAMESERVER2" ] ) ; then
   	sed -i '/nameserver [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/d' "$RESOLV_CONF_TMP"
   fi

   N=""
   while read line; do
   N="${N}$line
"
   done < $RESOLV_CONF_TMP
   echo -n "$N" > "$TARGET_RESOLV"
   rm -rf $RESOLV_CONF_TMP

   
   if [ x"1" = x"`syscfg get staticdns_enable`" ];then
   
         WAN_DNS=
         if [ -n "$WAN_DOMAIN" ] ; then
            echo "search $WAN_DOMAIN" >> $TARGET_RESOLV
         fi
         if [ "0.0.0.0" != "$NAMESERVER1" ] && [ -n "$NAMESERVER1" ] ; then
            echo "nameserver $NAMESERVER1" >> $TARGET_RESOLV
            WAN_DNS=`echo "$WAN_DNS" "$NAMESERVER1"`
         fi
         if [ "0.0.0.0" != "$NAMESERVER2" ]  && [ -n "$NAMESERVER2" ]; then
            echo "nameserver $NAMESERVER2" >> $TARGET_RESOLV
            WAN_DNS=`echo "$WAN_DNS" "$NAMESERVER2"`
         fi
         if [ "0.0.0.0" != "$NAMESERVER3" ]  && [ -n "$NAMESERVER3" ]; then
            echo "nameserver $NAMESERVER3" >> $TARGET_RESOLV
            WAN_DNS=`echo "$WAN_DNS" "$NAMESERVER3"`
         fi

         sysevent set wan_dhcp_dns "${WAN_DNS}"
         # sysevent set dhcp_server-restart
         # Avoiding restart, inorder to honor the running dhcp server (RDKB-49696)
         sysevent set dhcp_server-start

   fi

}

prepare_resolv_conf
