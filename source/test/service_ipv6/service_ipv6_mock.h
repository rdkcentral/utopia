/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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
#ifndef SERVICE_IPV6_MOCK
#define SERVICE_IPV6_MOCK
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdlib>
#include <filesystem>
#include <stdbool.h>
#include <errno.h>
#include <arpa/inet.h>
#include <functional>
#include <mocks/mock_utopia.h>
#include <mocks/mock_util.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_messagebus.h>
#include <mocks/mock_ansc_memory.h>
#include <experimental/filesystem>
#include <mocks/mock_libnet.h>
#ifndef MULTILAN_FEATURE
#define MAX_LAN_IF_NUM              3
#else
#define MAX_LAN_IF_NUM             64
#endif

#define CCSP_SUCCESS  100
#define CCSP_FAILURE  102


extern utopiaMock *g_utopiaMock;
extern UtilMock *g_utilMock;
extern SyseventMock *g_syseventMock;
extern SyscfgMock * g_syscfgMock;
extern SafecLibMock* g_safecLibMock;
extern SecureWrapperMock *g_securewrapperMock;
extern PsmMock *g_psmMock;
extern MessageBusMock *g_messagebusMock;
extern AnscMemoryMock *g_anscMemoryMock;
extern LibnetMock *g_libnetMock;

using namespace std;
using std::experimental::filesystem::exists;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::AnyNumber;

extern "C" {
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if.h>
#include <netinet/in.h>
enum {
    DHCPV6S_TYPE_STATEFUL = 1,
    DHCPV6S_TYPE_STATELESS,
};

typedef struct dhcpv6s_cfg {
    int     enable;
    int     pool_num;
    int     server_type;
} dhcpv6s_cfg_t;
   int get_dhcpv6s_conf(dhcpv6s_cfg_t *cfg);
   int get_prefix_info(const char *prefix,  char *value, unsigned int val_len, unsigned int *prefix_len);
   enum tp_mod {
    TPMOD_UNKNOWN,
    FAVOR_DEPTH,
    FAVOR_WIDTH,
    };

    typedef struct pd_pool {
        char start[INET6_ADDRSTRLEN];
        char end[INET6_ADDRSTRLEN];
        int  prefix_length;
        int  pd_length;
     } pd_pool_t;

    struct serv_ipv6 {
    int         sefd;
    int         setok;

    bool        wan_ready;

    char        mso_prefix[INET6_ADDRSTRLEN];
    enum tp_mod tpmod;
    };


   int get_pd_pool(struct serv_ipv6 *si6, pd_pool_t *pool);
   int serv_ipv6_init(struct serv_ipv6 *si6);
   int serv_ipv6_restart(struct serv_ipv6 *si6);
   int serv_ipv6_start(struct serv_ipv6 *si6);
   int serv_ipv6_stop(struct serv_ipv6 *si6);
   int dhcpv6s_restart(struct serv_ipv6 *si6);
   int dhcpv6s_stop(struct serv_ipv6 *si6);
   int dhcpv6s_start(struct serv_ipv6 *si6);
   int format_dibbler_option(char *option);
   int getLanUlaInfo(int *ula_enable);
   int lan_addr6_unset(struct serv_ipv6 *si6);
   int lan_addr6_set(struct serv_ipv6 *si6);
   void update_mtu(void);
   void report_no_lan_prefixes(struct serv_ipv6 *si6);
   int compute_global_ip(char *prefix, char *if_name, char *ipv6_addr, unsigned int addr_len);
   int iface_get_hwaddr(const char *ifname, char *mac, size_t size);
   int daemon_stop(const char *pid_file, const char *prog);

}

#endif

