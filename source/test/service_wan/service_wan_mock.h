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

/**
* @brief Display usage information for the service_wan utility.
*
* This function prints command-line usage information and available commands
* to the standard output.
*
* @return None
*
*/
void usage(void);

/**
* @brief Terminate the WAN service.
*
* This function closes the sysevent connection for the WAN service.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int serv_wan_term(struct serv_wan *sw);

/**
* @brief Initialize the WAN service.
*
* This function initializes the WAN service by opening sysevent connection,
* setting interface name, protocol, routing mode, and timeout.
*
* @param[in,out] sw - Pointer to the serv_wan structure to initialize.
* @param[in] ifname - Pointer to a string containing the WAN interface name.
* @param[in] prot - Pointer to a string containing the protocol type.
*
* @return The status of the operation.
* @retval 0 if initialization was successful.
* @retval -1 if sysevent open failed or invalid protocol specified.
*
*/
int serv_wan_init(struct serv_wan *sw, const char *ifname, const char *prot);

/**
* @brief Stop static IPv6 WAN configuration.
*
* This function stops static IPv6 WAN service by deconfiguring routes
* and unsetting static IPv6 resolv configuration.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 if operation failed.
*
*/
int wan_static_stop_v6(struct serv_wan *sw);

/**
* @brief Start static IPv6 WAN configuration.
*
* This function starts static IPv6 WAN service by configuring routes
* and setting static IPv6 resolv configuration.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if configuration was successful.
* @retval -1 if any operation failed.
*
*/
int wan_static_start_v6(struct serv_wan *sw);

/**
* @brief Deconfigure static resolv.conf.
*
* This function removes DNS nameserver entries from /etc/resolv.conf
* for static WAN configuration.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 if operation failed.
*
*/
int resolv_static_deconfig(struct serv_wan *sw);

/**
* @brief Configure static resolv.conf.
*
* This function writes DNS nameserver entries to /etc/resolv.conf
* for static WAN configuration.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if configuration was successful.
* @retval -1 if resolv.conf could not be opened.
*
*/
int resolv_static_config(struct serv_wan *sw);

/**
* @brief Stop static IPv4 WAN configuration.
*
* This function stops static IPv4 WAN service by deconfiguring IPv6 (if enabled),
* unsetting WAN address, bringing interface down, and clearing sysevent status.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success
*
*/
int wan_static_stop(struct serv_wan *sw);

/**
* @brief Start static IPv4 WAN configuration.
*
* This function starts static IPv4 WAN service by bringing interface up,
* setting WAN address, and configuring IPv6 (if enabled).
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if configuration was successful.
* @retval -1 if any operation failed.
*
*/
int wan_static_start(struct serv_wan *sw);

/**
* @brief Get the DHCP client PID file path.
*
* This function determines and returns the appropriate DHCP client PID file path
* based on platform and configuration.
*
* @param[out] pidfile - Pointer to a buffer where the PID file path will be stored.
* @param[in] size - Size of the pidfile buffer.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int Getdhcpcpidfile(char *pidfile,int size );

/**
* @brief Trigger DHCP renew for WAN interface.
*
* This function sends SIGUSR1 signal to the DHCP client to trigger
* lease renewal.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int wan_dhcp_renew(struct serv_wan *sw);

/**
* @brief Stop the DHCP client.
*
* This function stops the DHCP client by sending SIGUSR2 (release) and SIGTERM,
* then removes the PID file.
*
* @param[in] ifname - Pointer to a string containing the interface name.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int dhcp_stop(const char* ifname);

/**
* @brief Configure IPv4 routing rules for WAN interface.
*
* This function adds IP routing rules for the WAN interface to route traffic
* through appropriate routing tables.
*
* @param[in] ifname - Pointer to a string containing the interface name.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int route_config(const char *ifname);

/**
* @brief Configure IPv6 routing rules for WAN interface.
*
* This function adds IPv6 routing rules for the WAN interface to route traffic
* through appropriate routing tables.
*
* @param[in] ifname - Pointer to a string containing the interface name.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int route_config_v6(const char *ifname);

/**
* @brief Deconfigure IPv6 routing rules for WAN interface.
*
* This function removes IPv6 routing rules for the WAN interface.
*
* @param[in] ifname - Pointer to a string containing the interface name.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int route_deconfig_v6(const char *ifname);

/**
* @brief Check if a file exists.
*
* This function checks whether a specified file exists in the filesystem.
*
* @param[in] fname - Pointer to a string containing the file path to check.
*
* @return The file existence status.
* @retval 1 if the file exists.
* @retval 0 if the file does not exist.
*
*/
int checkFileExists(const char *fname);

/**
* @brief Deconfigure IPv4 routing rules for WAN interface.
*
* This function removes IP routing rules for the WAN interface.
*
* @param[in] ifname - Pointer to a string containing the interface name.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int route_deconfig(const char *ifname);

/**
* @brief Bring WAN interface down.
*
* This function brings down the WAN interface.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if the interface was successfully brought down.
* @retval -1 if the operation failed.
*
*/
int wan_iface_down(struct serv_wan *sw);

/**
* @brief Bring WAN interface up.
*
* This function brings up the WAN interface, configures IPv6 settings,
* and sets MTU.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int wan_iface_up(struct serv_wan *sw);

/**
* @brief Release DHCP lease for WAN interface.
*
* This function sends SIGUSR2 signal to the DHCP client to trigger
* lease release without terminating the client.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 if operation failed.
*
*/
int wan_dhcp_release(struct serv_wan *sw);

/**
* @brief Stop WAN DHCP client service.
*
* This function stops the DHCP client and clears WAN status.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int wan_dhcp_stop(struct serv_wan *sw);

/**
* @brief Unset WAN address and clear sysevent parameters.
*
* This function removes the WAN IP address from the interface and
* clears related sysevent variables.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 if operation failed.
*
*/
int wan_addr_unset(struct serv_wan *sw);

/**
* @brief Parse vendor-specific DHCP options from file.
*
* This function reads and parses vendor-specific DHCP options from
* a configuration file and formats them as DHCP option 43.
*
* @param[out] options - Pointer to a buffer where the formatted options will be stored.
* @param[in] length - Maximum length of the options buffer.
* @param[in] ethWanMode - Pointer to a string indicating Ethernet WAN mode.
*
* @return The status of the operation.
* @retval 0 if options were successfully parsed.
* @retval -1 if file cannot be opened, parsing error, or buffer overflow.
*
*/
int dhcp_parse_vendor_info( char *options, const int length, char *ethWanMode );

/**
* @brief Start DHCP client for WAN interface.
*
* This function starts the DHCP client on the WAN interface with vendor-specific options.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if DHCP client started successfully.
* @retval -1 if operation failed.
*
*/
int dhcp_start(struct serv_wan *sw) ;

/**
* @brief Start WAN service.
*
* This function starts the WAN service by initializing interfaces, starting
* protocol services, and configuring firewall and routing.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if WAN service started successfully.
* @retval -1 if any operation failed.
*
*/
int wan_start(struct serv_wan *sw);

/**
* @brief Stop WAN service.
*
* This function stops the WAN service by stopping protocol services,
* unsetting addresses, and bringing down the interface.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if WAN service stopped successfully.
* @retval -1 if any operation failed.
*
*/
int wan_stop(struct serv_wan *sw);

/**
* @brief Restart WAN service.
*
* This function restarts the WAN service by stopping and then starting it.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the start operation.
* @retval 0 if WAN service restarted successfully.
* @retval -1 if start operation failed.
*
*/
int wan_restart(struct serv_wan *sw);

/**
* @brief Start WAN DHCP service.
*
* This function starts the DHCP-based WAN service.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if DHCP service started successfully.
* @retval -1 if any operation failed.
*
*/
int wan_dhcp_start(struct serv_wan *sw);

/**
* @brief Set WAN address and configure routing.
*
* This function sets the WAN IP address and configures routing tables
* after DHCP or static configuration is complete.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the operation.
* @retval 0 if address was set successfully.
* @retval -1 if any operation failed.
*
*/
int wan_addr_set(struct serv_wan *sw);

/**
* @brief Restart WAN DHCP service.
*
* This function restarts the DHCP-based WAN service by stopping and starting it.
*
* @param[in] sw - Pointer to the serv_wan structure.
*
* @return The status of the start operation.
* @retval 0 if DHCP service restarted successfully.
* @retval -1 if start operation failed.
*
*/
int wan_dhcp_restart(struct serv_wan *sw);
FILE* logfptr;
}