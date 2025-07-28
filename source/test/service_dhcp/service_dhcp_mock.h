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

unsigned int mask2cidr(char *subnetMask);
int sysevent_syscfg_init();
unsigned int countSetBits(int byte);
void subnet(char *ipv4Addr, char *ipv4Subnet, char *subnet);
void wait_till_end_state (char *process_to_wait);
BOOL compare_files(char *input_file1, char *input_file2);
void copy_command_output(FILE *fp, char *out, int len);
void print_file(char *to_print_file);
void remove_file(char *tb_removed_file);
void copy_file(char *input_file, char *target_file);
int executeCmd(char *cmd);
void get_device_props();
void print_with_uptime(const char* input);
void _get_shell_output(FILE *fp, char *buf, int len);
int getValueFromDevicePropsFile(char *str, char **value);
int get_Pool_cnt(char arr[15][2],FILE *pipe);
void getRFC_Value(const char* dnsOption);
int dnsmasq_server_start();
BOOL IsDhcpConfHasInterface(void);
void remove_config(int l3_inst);
void load_static_l3 (int l3_inst);
int isValidLANIP(const char* ipStr);
void UpdateConfigListintoConfFile(FILE *l_fLocal_Dhcp_ConfFile);
void AddConfList(char *confToken);
void UpdateConfList(char *confTok, int ct);
unsigned int isValidSubnetMask(char *subnetMask);
enum interface{
    ExistWithSameRange,
    ExistWithDifferentRange,
    NotExists
};
enum interface IsInterfaceExists(char *confTok, char * confInf, int* inst);
}