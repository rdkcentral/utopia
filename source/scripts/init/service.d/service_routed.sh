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
# This script is used to start the routing daemons (zebra and ripd)
# $1 is the calling event (current_wan_state  current_lan_state  ipv6_prefix)
#------------------------------------------------------------------
#!/bin/sh

source /etc/device.properties

SERVICE_NAME="routed"

LANULASupport=$(sysevent get LANULASupport)

# Helper: check IPv6 delegation support
is_ipv6_pd_supported() {
    rdkb_feature_check -q IPv6_Delegation > /dev/null 2>&1
    rc=$?
    [ "$rc" -eq 0 ] || [ "$rc" -eq 127 ]
}

# Helper: check if model needs unconditional radv restart
is_legacy_model() {
    [ "$MODEL_NUM" = "DPC3941B" ] || \
    [ "$MODEL_NUM" = "DPC3939B" ] || \
    [ "$MODEL_NUM" = "CGA4131COM" ] || \
    [ "$MODEL_NUM" = "CGA4332COM" ]
}

case "$1" in
   "${SERVICE_NAME}-start")
      service_routed start
      ;;

   "${SERVICE_NAME}-stop")
      service_routed stop
      ;;

   "${SERVICE_NAME}-restart")
      service_routed restart
      ;;

   wan-status)
       status=$(sysevent get wan-status)
       if [ "$status" = "started" ]; then
           service_routed start
       elif [ "$status" = "stopped" ]; then
           service_routed stop
       fi
       ;;

   lan-status)
       status=$(sysevent get lan-status)

       if [ "$status" = "started" ]; then
           service_routed start

           # Residential-specific radv-start
           if [ "$BOX_TYPE" = "WNXL11BWL" ]; then
               service_routed radv-start
           fi

       elif [ "$status" = "stopped" ]; then

           # Residential ULA exception
           if [ "$BOX_TYPE" != "HUB4" ] && \
              [ "$BOX_TYPE" != "SR300" ] && \
              [ "$BOX_TYPE" != "SE501" ] && \
              [ "$BOX_TYPE" != "SR213" ] && \
              [ "$BOX_TYPE" != "WNXL11BWL" ] && \
              [ "$LANULASupport" != "true" ]; then
               service_routed stop
           else
               # Default commercial behavior
               service_routed stop
           fi
       fi
       ;;

   ripd-restart)
       service_routed rip-restart
       ;;

   zebra-restart|staticroute-restart)
       service_routed radv-restart
       ;;

   ipv6_prefix|ipv6_nameserver)

       if is_legacy_model || is_ipv6_pd_supported; then
           service_routed radv-restart
       fi
       ;;

   dhcpv6_option_changed)
       service_routed radv-restart
       ;;

   *)
       echo "Usage: $SERVICE_NAME [ ${SERVICE_NAME}-start | ${SERVICE_NAME}-stop | ${SERVICE_NAME}-restart]" > /dev/console
       exit 3
       ;;
esac

exit 0+
