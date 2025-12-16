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
#include <experimental/filesystem>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_fd.h>
#include <mocks/mock_util.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_messagebus.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_libnet.h>
#include <mocks/mock_file_io.h>

#define SERVICE_DHCP_JSON      "/tmp/service_dhcp.json"
#define DEVICE_PROPS_FILE      "/etc/device.properties"

extern SyscfgMock* g_syscfgMock;
extern SecureWrapperMock* g_securewrapperMock;
extern SafecLibMock* g_safecLibMock;
extern utopiaMock* g_utopiaMock;
extern telemetryMock* g_telemetryMock;
extern SyseventMock* g_syseventMock;
extern PsmMock * g_psmMock;
extern MessageBusMock * g_messagebusMock;
extern AnscMemoryMock * g_anscMemoryMock;
extern LibnetMock * g_libnetMock;
extern FileIOMock * g_fileIOMock;

using namespace std;
using namespace testing;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArrayArgument;
using std::experimental::filesystem::exists;
using ::testing::DoAll;

extern "C" {
#include "syscfg.h"
#include "secure_wrapper.h"
#include "safec_lib.h"
#include <string.h>
#include <sys/sysinfo.h>
#include "sysevent/sysevent.h"
#include "syscfg/syscfg.h"
#include "lan_handler.h"
#include "util.h"
#include <sys/time.h>
#include "print_uptime.h"
#include <telemetry_busmessage_sender.h>
#include "safec_lib_common.h"
#include "service_dhcp_server.h"
#include "dhcp_server_functions.h"
#include "service_ipv4.h"

/**
* @brief Convert a subnet mask to CIDR notation.
*
* This function converts an IPv4 subnet mask in dotted decimal notation to
* its equivalent CIDR (Classless Inter-Domain Routing) prefix length by counting
* the number of set bits in the subnet mask.
*
* @param[in] subnetMask - Pointer to a string containing the subnet mask in dotted decimal notation.
*                    \n The subnet mask must be in valid IPv4 format with continuous 1s starting from MSB.
*
* @return The CIDR prefix length.
* @retval 0-32 The number of set bits representing the network prefix length.
*
*/
unsigned int mask2cidr(char *subnetMask);

/**
* @brief Initialize sysevent and syscfg for the DHCP service.
*
* This function opens a connection to the sysevent daemon, initializes DBUS,
* and opens the ARM console log file for the service_dhcp component.
*
* @return The status of the initialization operation.
* @retval SUCCESS if both sysevent and DBUS initialization are successful.
* @retval ERROR if sysevent open fails or DBUS initialization fails.
*
*/
int sysevent_syscfg_init();

/**
* @brief Count the number of set bits in a byte.
*
* This function counts the number of bits set to 1 in a given byte value.
* It validates that the byte represents a valid subnet mask byte before counting.
*
* @param[in] byte - The byte value to count set bits in.
*                    \n Must be a valid subnet byte or 0.
*
* @return The number of set bits in the byte.
* @retval 0-8 The count of bits set to 1 in the byte.
* @retval 0 If the byte is not a valid subnet mask byte.
*
*/
unsigned int countSetBits(int byte);

/**
* @brief Calculate the network subnet from an IPv4 address and subnet mask.
*
* This function performs a bitwise AND operation between an IPv4 address and
* its subnet mask to derive the network subnet address.
*
* @param[in] ipv4Addr - Pointer to a string containing the IPv4 address in dotted decimal notation.
* @param[in] ipv4Subnet - Pointer to a string containing the subnet mask in dotted decimal notation.
* @param[out] subnet - Pointer to a buffer where the calculated subnet address will be stored.
*                    \n The buffer should be at least 16 bytes to hold the subnet address string.
*
* @return None
*
*/
void subnet(char *ipv4Addr, char *ipv4Subnet, char *subnet);

/**
* @brief Wait until a process reaches an end state (not starting/stopping).
*
* This function polls the sysevent status of a specified process up to 9 times,
* waiting 1 second between attempts, until the process is no longer in a transitional state.
*
* @param[in] process_to_wait - Pointer to a string containing the process name to wait for.
*                    \n The function will check <process_name>-status sysevent.
*
* @return None
*
*/
void wait_till_end_state (char *process_to_wait);

/**
* @brief Compare two files line by line for equality.
*
* This function reads two files and compares them line by line to determine
* if they are identical.
*
* @param[in] input_file1 - Pointer to a string containing the path to the first file.
* @param[in] input_file2 - Pointer to a string containing the path to the second file.
*
* @return Boolean indicating whether the files are identical.
* @retval TRUE if the two files are identical (all lines match).
* @retval FALSE if the files differ or if either file cannot be opened.
*
*/
BOOL compare_files(char *input_file1, char *input_file2);

/**
* @brief Copy command output from a file pointer to a buffer.
*
* This function reads one line from the provided file pointer and copies it
* to the output buffer, removing any trailing newline character.
*
* @param[in] fp - File pointer to read the command output from.
* @param[out] out - Pointer to a buffer where the output will be stored.
* @param[in] len - Maximum length of the output buffer.
*
* @return None.
*
*/
void copy_command_output(FILE *fp, char *out, int len);

/**
* @brief Print the contents of a file to the ARM console log.
*
* This function opens a file and writes all its contents line by line
* to the ARM console log file.
*
* @param[in] to_print_file - Pointer to a string containing the path to the file to be printed.
*
* @return None
*
*/
void print_file(char *to_print_file);

/**
* @brief Remove a file from the filesystem.
*
* This function deletes the specified file and logs an error message
* if the removal fails.
*
* @param[in] tb_removed_file - Pointer to a string containing the path to the file to be removed.
*
* @return None
*
*/
void remove_file(char *tb_removed_file);

/**
* @brief Copy the contents of one file to another.
*
* This function reads all lines from the input file and writes them to the target file.
* The target file is opened in write mode, overwriting any existing content.
*
* @param[in] input_file - Pointer to a string containing the path to the source file.
* @param[in] target_file - Pointer to a string containing the path to the destination file.
*
* @return None
*
*/
void copy_file(char *input_file, char *target_file);

/**
* @brief Execute a shell command using the system() function.
*
* This function executes the provided shell command and logs an error
* if the command execution fails.
*
* @param[in] cmd - Pointer to a string containing the command to execute.
*
* @return The status of the command execution.
* @retval 0 if the command executed successfully or errno is ECHILD.
* @retval non-zero The system() return value if execution failed.
*
*/
int executeCmd(char *cmd);

/**
* @brief Read device properties from the device properties file.
*
* This function parses the device properties file (DEVICE_PROPS_FILE) and extracts
* values for BOX_TYPE, XDNS_ENABLE, MIG_CHECK, and ATOM_ARPING_IP into global variables.
*
* @return None
*
*/
void get_device_props();

/**
* @brief Print a message with system uptime and local time.
*
* This function retrieves the current system uptime and local time,
* then prints the input message along with formatted time information to the ARM console log.
*
* @param[in] input - Pointer to a string containing the message to be printed.
*
* @return None
*
*/
void print_with_uptime(const char* input);

/**
* @brief Get shell command output from a file pointer.
*
* This function reads output from a file pointer, removes trailing newlines, and closes
* the file pointer using v_secure_pclose().
*
* @param[in] fp - File pointer to read output from.
* @param[out] buf - Pointer to a buffer where the output will be stored.
* @param[in] len - Maximum length of the output buffer.
*
* @return None
*
*/
void _get_shell_output(FILE *fp, char *buf, int len);

/**
* @brief Get a value from the device properties file.
*
* This function searches the device properties file for a specified key and
* returns the corresponding value.
*
* @param[in] str - Pointer to a string containing the key to search for.
* @param[out] value - Pointer to a pointer that will point to the value string in the buffer.
*                    \n The pointer will reference data in a static buffer.
*
* @return The status of the operation.
* @retval 0 if the key was found and value was set successfully.
* @retval -1 if the key was not found or the file could not be opened.
*
*/
int getValueFromDevicePropsFile(char *str, char **value);

/**
* @brief Get pool count from a pipe stream.
*
* This function reads pool identifiers from a pipe stream and stores them in an array,
* returning the total count of valid pool entries found.
*
* @param[out] arr - Two-dimensional array to store pool identifiers (up to 15 entries of 2 characters each).
* @param[in] pipe - File pointer to the pipe stream to read from.
*
* @return The number of valid pool entries found.
* @retval -1 if the pipe is NULL.
* @retval 0-15 The count of valid pool identifiers read from the pipe.
*
*/
int get_Pool_cnt(char arr[15][2],FILE *pipe);

/**
* @brief Get DNS strict order RFC value from syscfg.
*
* This function checks the DNSStrictOrder configuration and sets the dnsOption
* parameter to " -o " if DNS strict order is enabled.
*
* @param[out] dnsOption - Pointer to a buffer where the DNS option string will be stored.
*                    \n Will be set to " -o " if DNSStrictOrder is "true", otherwise remains unchanged.
*
* @return None
*
*/
void getRFC_Value(const char* dnsOption);

/**
* @brief Start the dnsmasq DNS/DHCP server.
*
* This function constructs the appropriate dnsmasq command line based on
* device configuration (XDNS, DNSSEC, model type) and executes it.
*
* @return The status of the dnsmasq server start operation.
* @retval 0 if dnsmasq started successfully.
* @retval non-zero if the command execution failed.
*
*/
int dnsmasq_server_start();

/**
* @brief Check if the DHCP configuration file has any interface defined.
*
* This function scans the dnsmasq configuration file (DHCP_CONF) to determine
* if it contains at least one "interface=" directive.
*
* @return Boolean indicating whether an interface is defined.
* @retval TRUE if the DHCP configuration file contains at least one interface directive.
* @retval FALSE if no interface directive is found or the file cannot be opened.
*
*/
BOOL IsDhcpConfHasInterface(void);

/**
* @brief Remove IPv4 configuration for a Layer 3 network instance.
*
* This function removes IP address, routing rules, and routes associated with
* the specified L3 network instance. It also stops UPNP services if removing
* configuration for the LAN interface.
*
* @param[in] l3_inst - The Layer 3 network instance number.
*                    \n Typically ranges from 1-5 for different network segments.
*
* @return None
*
*/
void remove_config(int l3_inst);

/**
* @brief Load static IPv4 configuration for a Layer 3 network instance.
*
* This function retrieves static IPv4 address and subnet mask from PSM database
* and applies the configuration to the specified L3 network instance.
*
* @param[in] l3_inst - The Layer 3 network instance number.
*                    \n Typically ranges from 1-5 for different network segments.
*
* @return None
*
*/
void load_static_l3 (int l3_inst);

/**
* @brief Validate if an IP address is a valid private LAN IP.
*
* This function checks if the provided IP address is a valid IPv4 address
* and falls within private IP address ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x).
*
* @param[in] ipStr - Pointer to a string containing the IP address to validate.
*
* @return Status indicating whether the IP is a valid LAN IP.
* @retval 0 if the IP address is invalid or not in a private LAN range.
* @retval 1 if the IP address is valid and within a private LAN range.
*
*/
int isValidLANIP(const char* ipStr);

/**
* @brief Write dynamic DHCP configuration list to the configuration file.
*
* This function reads all dynamic DHCP configuration changes from sysevent
* and writes them to the provided DHCP configuration file.
*
* @param[in] l_fLocal_Dhcp_ConfFile - File pointer to the DHCP configuration file.
*
* @return None
*
*/
void UpdateConfigListintoConfFile(FILE *l_fLocal_Dhcp_ConfFile);

/**
* @brief Add a new configuration entry to the dynamic DHCP configuration list.
*
* This function adds a new DHCP configuration token to sysevent storage and
* increments the configuration change counter.
*
* @param[in] confToken - Pointer to a string containing the configuration token to add.
*                    \n Format: "interface=<name>|dhcp-range=<range>"
*
* @return None
*
*/
void AddConfList(char *confToken);

/**
* @brief Update an existing configuration entry in the dynamic DHCP configuration list.
*
* This function updates a specific DHCP configuration entry identified by its index.
*
* @param[in] confTok - Pointer to a string containing the configuration token to update.
*                    \n Format: "interface=<name>|dhcp-range=<range>"
* @param[in] ct - The index of the configuration entry to update (1-based).
*
* @return None
*
*/
void UpdateConfList(char *confTok, int ct);

/**
* @brief Validate if a string represents a valid subnet mask.
*
* This function validates that a subnet mask has the correct format and structure,
* ensuring continuous 1s from MSB followed by continuous 0s in the host part.
*
* @param[in] subnetMask - Pointer to a string containing the subnet mask in dotted decimal notation.
*
* @return Status indicating whether the subnet mask is valid.
* @retval 0 if the subnet mask is invalid.
* @retval 1 if the subnet mask is valid.
*
*/
unsigned int isValidSubnetMask(char *subnetMask);

enum interface{
    ExistWithSameRange,
    ExistWithDifferentRange,
    NotExists
};

/**
* @brief Check if an interface exists in the dynamic DHCP configuration list.
*
* This function searches the dynamic DHCP configuration list to determine if
* a specified interface exists and whether its configuration matches.
*
* @param[in] confTok - Pointer to a string containing the configuration token to check.
*                    \n Format: "interface=<name>|dhcp-range=<range>"
* @param[in] confInf - Pointer to a string containing the interface name to search for.
* @param[out] inst - Pointer to an integer where the matching instance index will be stored.
*
* @return Enumeration value indicating the interface existence status.
* @retval NotExists if dhcp_conf_change_counter is 0 or interface not found.
* @retval ExistWithSameRange if interface exists with matching configuration.
* @retval ExistWithDifferentRange if interface exists with different configuration.
*
*/
enum interface IsInterfaceExists(char *confTok, char * confInf, int* inst);
}