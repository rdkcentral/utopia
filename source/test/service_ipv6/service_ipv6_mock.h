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

/**
* @brief Get the DHCPv6 server configuration.
*
* This function retrieves DHCPv6 server configuration parameters from syscfg,
* including server enable status, pool number, and server type.
*
* @param[out] cfg - Pointer to a dhcpv6s_cfg_t structure where the configuration will be stored.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
   int get_dhcpv6s_conf(dhcpv6s_cfg_t *cfg);

/**
* @brief Extract IPv6 prefix value and length from a prefix string.
*
* This function parses an IPv6 prefix string in CIDR notation and extracts
* the prefix value and prefix length separately.
*
* @param[in] prefix - Pointer to a string containing the IPv6 prefix in CIDR notation.
*                    \n Format: "<IPv6_address>/<prefix_length>"
* @param[out] value - Pointer to a buffer where the IPv6 prefix value will be stored (without /length).
*                    \n Can be NULL if only prefix_len is needed.
* @param[in] val_len - Maximum length of the value buffer.
* @param[out] prefix_len - Pointer to an unsigned int where the prefix length will be stored.
*                    \n Can be NULL if only value is needed.
*
* @return The status of the operation.
* @retval 0 if the prefix was successfully parsed.
* @retval -1 if the prefix format is invalid (no '/' found).
*
*/
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

/**
* @brief Get the prefix delegation pool configuration.
*
* This function retrieves the prefix delegation pool parameters from sysevent,
* including start/end addresses and prefix lengths.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure containing sysevent connection.
* @param[out] pool - Pointer to a pd_pool_t structure where the pool configuration will be stored.
*
* @return The status of the operation.
* @retval 0 if all required sysevent values were successfully retrieved.
* @retval -1 if any required sysevent value is missing or empty.
*
*/
   int get_pd_pool(struct serv_ipv6 *si6, pd_pool_t *pool);

/**
* @brief Initialize the IPv6 service.
*
* This function initializes the IPv6 service by opening sysevent connection,
* initializing DBUS, reading configuration, and checking IPv6 enablement status.
*
* @param[in,out] si6 - Pointer to the serv_ipv6 structure to initialize.
*
* @return The status of the operation.
* @retval 0 if initialization was successful.
* @retval -1 if sysevent open failed, IPv6 is disabled, or MSO prefix is not available.
*
*/
   int serv_ipv6_init(struct serv_ipv6 *si6);

/**
* @brief Restart the IPv6 service.
*
* This function stops and then starts the IPv6 service.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the start operation.
* @retval 0 if service was successfully restarted.
* @retval -1 if the start operation failed.
*
*/
   int serv_ipv6_restart(struct serv_ipv6 *si6);

/**
* @brief Start the IPv6 service.
*
* This function starts the IPv6 service by dividing prefixes, assigning LAN addresses,
* updating MTU, and starting the DHCPv6 server.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if the service started successfully.
* @retval -1 if service cannot start, WAN is not ready, or any operation failed.
*
*/
   int serv_ipv6_start(struct serv_ipv6 *si6);

/**
* @brief Stop the IPv6 service.
*
* This function stops the IPv6 service by stopping the DHCPv6 server
* and unsetting LAN IPv6 addresses.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if the service stopped successfully.
* @retval -1 if service cannot stop or any operation failed.
*
*/
   int serv_ipv6_stop(struct serv_ipv6 *si6);

/**
* @brief Restart the DHCPv6 server.
*
* This function stops and then starts the DHCPv6 server (dibbler).
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the start operation.
* @retval 0 if DHCPv6 server was successfully restarted.
* @retval -1 if the start operation failed.
*
*/
   int dhcpv6s_restart(struct serv_ipv6 *si6);

/**
* @brief Stop the DHCPv6 server.
*
* This function stops the DHCPv6 server daemon (dibbler).
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if the DHCPv6 server was successfully stopped.
* @retval -1 if the stop operation failed.
*
*/
   int dhcpv6s_stop(struct serv_ipv6 *si6);

/**
* @brief Start the DHCPv6 server.
*
* This function generates the dibbler configuration file and starts the DHCPv6 server.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if the DHCPv6 server started successfully or is disabled.
* @retval -1 if dibbler configuration generation failed.
*
*/
   int dhcpv6s_start(struct serv_ipv6 *si6);

/**
* @brief Format dibbler options by replacing spaces with commas.
*
* This function modifies a dibbler option string by replacing all space characters
* with commas, which is the format required by the dibbler configuration.
*
* @param[in,out] option - Pointer to a string containing the option to format.
*                    \n The string is modified in place.
*
* @return The status of the operation.
* @retval 0 if the option was successfully formatted.
* @retval -1 if the option pointer is NULL.
*
*/
   int format_dibbler_option(char *option);

/**
* @brief Get LAN ULA (Unique Local Address) enablement status.
*
* This function retrieves the LAN ULA enablement flag from the PSM database.
*
* @param[out] ula_enable - Pointer to an integer where the ULA enable status will be stored.
*                    \n Set to TRUE if ULA is enabled, FALSE otherwise.
*
* @return The status of the operation.
* @retval 0 if the ULA enable status was successfully retrieved.
* @retval -1 if PSM read failed.
*
*/
   int getLanUlaInfo(int *ula_enable);

/**
* @brief Unset IPv6 addresses from LAN interfaces.
*
* This function removes IPv6 addresses from all active LAN interfaces and
* clears related sysevent parameters.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if IPv6 addresses were successfully removed from all interfaces.
* @retval -1 if operation failed.
*
*/
   int lan_addr6_unset(struct serv_ipv6 *si6);

/**
* @brief Assign IPv6 addresses to LAN interfaces.
*
* This function divides the MSO-delegated prefix, assigns IPv6 addresses to LAN
* interfaces based on their interface-prefixes, and configures interface parameters.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return The status of the operation.
* @retval 0 if IPv6 addresses were successfully assigned to all interfaces.
* @retval -1 if prefix division failed or no active LAN interfaces found.
*
*/
   int lan_addr6_set(struct serv_ipv6 *si6);

/**
* @brief Update MTU for all enabled IPv6 L3 instances.
*
* This function iterates through all enabled Layer 3 IPv6 network instances
* and sets the appropriate MTU value for each interface.
*
* @return None
*
*/
   void update_mtu(void);

/**
* @brief Report prefix assignment failure for all LAN interfaces.
*
* This function reports that IPv6 prefix assignment completely failed by
* invoking the no-prefix reporting for all active LAN interfaces.
*
* @param[in] si6 - Pointer to the serv_ipv6 structure.
*
* @return None
*
*/
   void report_no_lan_prefixes(struct serv_ipv6 *si6);

/**
* @brief Compute a global IPv6 address based on a /64 interface prefix.
*
* This function generates a global IPv6 address by combining a /64 prefix with
* an EUI-64 identifier derived from the interface's MAC address.
*
* @param[in] prefix - Pointer to a string containing the IPv6 prefix in CIDR notation (e.g., "2001:db8::/64").
* @param[in] if_name - Pointer to a string containing the interface name.
* @param[out] ipv6_addr - Pointer to a buffer where the computed IPv6 address will be stored.
* @param[in] addr_len - Maximum length of the ipv6_addr buffer.
*
* @return The status of the operation.
* @retval 0 if the global IPv6 address was successfully computed.
* @retval -1 if the prefix format is invalid, prefix length > 64, MAC address retrieval failed, or invalid format.
*
*/
   int compute_global_ip(char *prefix, char *if_name, char *ipv6_addr, unsigned int addr_len);

/**
* @brief Get the hardware (MAC) address of a network interface.
*
* This function retrieves the MAC address of the specified network interface
* using ioctl system call.
*
* @param[in] ifname - Pointer to a string containing the interface name.
* @param[out] mac - Pointer to a buffer where the MAC address will be stored.
*                    \n Format: "XX:XX:XX:XX:XX:XX"
*                    \n Buffer must be at least 18 bytes ("00:00:00:00:00:00" + null terminator).
* @param[in] size - Size of the mac buffer.
*
* @return The status of the operation.
* @retval 0 if the MAC address was successfully retrieved.
* @retval -1 if parameters are invalid, socket creation failed, or ioctl failed.
*
*/
   int iface_get_hwaddr(const char *ifname, char *mac, size_t size);

/**
* @brief Stop a daemon process.
*
* This function stops a daemon by reading its PID from a file or searching
* by process name, sending SIGTERM, and removing the PID file.
*
* @param[in] pid_file - Pointer to a string containing the path to the PID file.
*                    \n Can be NULL if only prog name is provided.
* @param[in] prog - Pointer to a string containing the process/program name.
*                    \n Can be NULL if only pid_file is provided.
*
* @return The status of the operation.
* @retval 0 on success
* @retval -1 if both pid_file and prog are NULL.
*
*/
   int daemon_stop(const char *pid_file, const char *prog);

}

#endif

