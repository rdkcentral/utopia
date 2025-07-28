/**
* Copyright 2024 Comcast Cable Communications Management, LLC
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
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "print_uptime.h"
#include <sys/sysinfo.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_messagebus.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_rdklogger.h>
#define IFNAMSIZ 16
#define SW_PROT_TIMO   675
#define RESOLV_CONF_FILE  "resolv.conf"
#define VENDOR_SPEC_FILE "udhcpc.txt"
#define VENDOR_OPTIONS_LENGTH 100

using namespace std;
using namespace testing;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::SetArrayArgument;

SyscfgMock* g_syscfgMock = nullptr;
SecureWrapperMock* g_securewrapperMock = nullptr;
SafecLibMock* g_safecLibMock = nullptr;
utopiaMock* g_utopiaMock = nullptr;
telemetryMock* g_telemetryMock = nullptr;
SyseventMock* g_syseventMock = nullptr;
PsmMock * g_psmMock = nullptr;
MessageBusMock * g_messagebusMock = nullptr;
AnscMemoryMock * g_anscMemoryMock = nullptr;
FileIOMock * g_fileIOMock = nullptr;
rdkloggerMock * g_rdkloggerMock = nullptr;

enum wan_prot {
    WAN_PROT_DHCP,
    WAN_PROT_STATIC,
};

enum wan_rt_mod {
    WAN_RTMOD_UNKNOW,
    WAN_RTMOD_IPV4, // COSA_DML_DEVICE_MODE_Ipv4 - 1
    WAN_RTMOD_IPV6, // COSA_DML_DEVICE_MODE_Ipv6 - 1
    WAN_RTMOD_DS,   // COSA_DML_DEVICE_MODE_Dualstack - 1
};
struct serv_wan {
    int sefd;
    int setok;
    char ifname[IFNAMSIZ];
    enum wan_rt_mod rtmod;
    enum wan_prot prot;
    int timo;
};

extern "C" 
{
#include "util.h"
void usage(void);
int serv_wan_term(struct serv_wan *sw);
int serv_wan_init(struct serv_wan *sw, const char *ifname, const char *prot);
int wan_static_stop_v6(struct serv_wan *sw);
int wan_static_start_v6(struct serv_wan *sw);
int resolv_static_deconfig(struct serv_wan *sw);
int resolv_static_config(struct serv_wan *sw);
int wan_static_stop(struct serv_wan *sw);
int wan_static_start(struct serv_wan *sw);
int Getdhcpcpidfile(char *pidfile,int size );
int wan_dhcp_renew(struct serv_wan *sw);
int dhcp_stop(const char* ifname);
int route_config(const char *ifname);
int route_config_v6(const char *ifname);
int route_deconfig_v6(const char *ifname);
int checkFileExists(const char *fname);
int route_deconfig(const char *ifname);
int wan_iface_down(struct serv_wan *sw);
int wan_iface_up(struct serv_wan *sw);
int wan_dhcp_release(struct serv_wan *sw);
int wan_dhcp_stop(struct serv_wan *sw);
int wan_addr_unset(struct serv_wan *sw);
int dhcp_parse_vendor_info( char *options, const int length, char *ethWanMode );
int dhcp_start(struct serv_wan *sw) ;
int wan_start(struct serv_wan *sw);
int wan_stop(struct serv_wan *sw);
int wan_restart(struct serv_wan *sw);
int wan_dhcp_start(struct serv_wan *sw);
int wan_addr_set(struct serv_wan *sw);
int wan_dhcp_restart(struct serv_wan *sw);
FILE* logfptr;
}