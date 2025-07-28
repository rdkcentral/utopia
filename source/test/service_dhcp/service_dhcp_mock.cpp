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

#include "service_dhcp_mock.h"

SyscfgMock *g_syscfgMock = NULL;
SecureWrapperMock *g_securewrapperMock = NULL;
SafecLibMock *g_safecLibMock = NULL;
utopiaMock *g_utopiaMock = NULL;
telemetryMock *g_telemetryMock = NULL;
SyseventMock *g_syseventMock = NULL;
PsmMock * g_psmMock = NULL;
MessageBusMock * g_messagebusMock = NULL;
AnscMemoryMock *g_anscMemoryMock = NULL;
LibnetMock * g_libnetMock = NULL;
FileIOMock *g_fileIOMock = NULL;
UserTimeMock *g_usertimeMock = NULL;
TraceMock *g_traceMock = NULL;
FileDescriptorMock *g_fdMock = NULL;