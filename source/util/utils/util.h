/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef __SERV_UTIL__
#define __SERV_UTIL__
#include <sysevent/sysevent.h>

#define SE_SERV         "127.0.0.1"

#ifndef NELEMS
#define NELEMS(arr)     (sizeof(arr) / sizeof((arr)[0]))
#endif

#if defined (WIFI_MANAGE_SUPPORTED)
#define MANAGE_WIFI_PSM_STR "dmsb.MultiLAN.ManageWiFi_l3net"
#define MANAGE_WIFI_BRIDGE_NAME "dmsb.l2net.%s.Name"
#define MANAGE_WIFI_V4_ADDR "dmsb.l3net.%s.V4Addr"
void updateDhcpPoolData(void * bus_handle, char * pIndex, FILE * pFile);
#endif /* WIFI_MANAGE_SUPPORTED*/

void psmGet(void *bus_handle, char *pParamName, char *pParamValue, size_t len);
int vsystem(const char *fmt, ...);
int sysctl_iface_set(const char *path, const char *ifname, const char *content);
int iface_get_hwaddr(const char *ifname, char *mac, size_t size);
int iface_get_ipv4addr(const char *ifname, char *ipv4Addr, size_t size);
int is_iface_present(const char *ifname);

int serv_can_start(int sefd, token_t tok, const char *servname);
int serv_can_stop(int sefd, token_t tok, const char *servname);
int pid_of(const char *name, const char *keyword);
#endif /* __SW_UTIL__ */
