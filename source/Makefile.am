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
SUBDIRS = ulog syscfg sysevent services utctx utapi util

#if FIREWALL_NFT
SUBDIRS += firewall_nft
#else
SUBDIRS += firewall
#endif

SUBDIRS += firewall_log newhost macclone pal pmon services service_wan trigger igd service_routed service_ipv6 scripts service_multinet service_udhcpc

#SUBDIRS += dhcpproxy

if DSLITE_FEATURE_SUPPORT
SUBDIRS += service_dslite
endif

if UNIT_TEST_DOCKER_SUPPORT
SUBDIRS += test
endif

if CORE_NET_LIB_FEATURE_SUPPORT
SUBDIRS += service_dhcp
SUBDIRS += service_dhcpv6_client
endif

if FEATURE_RDKB_EXTENDER
SUBDIRS += service_deviceMode
endif

#if FEATURE_RDKB_WANFAILOVER
#SUBDIRS += NetworkMonitor
#endif

if DDNS_BINARY_CLIENT_SUPPORT
SUBDIRS += service_ddns
endif
