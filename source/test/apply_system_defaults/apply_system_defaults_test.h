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
#include <mocks/mock_sysevent.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_cJSON.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_messagebus.h>

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
SyseventMock* g_syseventMock = nullptr;
PsmMock * g_psmMock = nullptr;
cjsonMock* g_cjsonMock = nullptr;
telemetryMock *g_telemetryMock = nullptr;
AnscMemoryMock * g_anscMemoryMock = nullptr;
MessageBusMock * g_messagebusMock = nullptr;

int syscfg_supported;
int psm_supported;

extern "C" 
{
void addInSysCfgdDB (char *key, char *value);
void updateSysCfgdDB (char *key, char *value);
int compare_partner_json_param (char *partner_nvram_bs_obj, char *partner_etc_obj, char *PartnerID);
}