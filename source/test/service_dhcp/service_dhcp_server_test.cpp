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

#include "service_dhcp_mock.h"

class ServiceDhcpServerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_safecLibMock = new SafecLibMock();
        g_utopiaMock = new utopiaMock();
        g_telemetryMock = new telemetryMock();
        g_syseventMock = new SyseventMock();
        g_psmMock = new PsmMock();
        g_messagebusMock = new MessageBusMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_libnetMock = new LibnetMock();
        g_fileIOMock = new FileIOMock();
    }

    void TearDown() override
    {
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_safecLibMock;
        delete g_utopiaMock;
        delete g_telemetryMock;
        delete g_syseventMock;
        delete g_psmMock;
        delete g_messagebusMock;
        delete g_anscMemoryMock;
        delete g_libnetMock;
        delete g_fileIOMock;

        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_safecLibMock = nullptr;
        g_utopiaMock = nullptr;
        g_telemetryMock = nullptr;
        g_syseventMock = nullptr;
        g_psmMock = nullptr;
        g_messagebusMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_libnetMock = nullptr;
        g_fileIOMock = nullptr;
    }
};

TEST_F(ServiceDhcpServerTest, _get_shell_output)
{
    FILE *fp = (FILE *)0x1;
    char buf[10] = {0};

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    _get_shell_output(fp, buf, sizeof(buf));

    EXPECT_STREQ(buf, "");
}

TEST_F(ServiceDhcpServerTest, getValueFromDevicePropsFile)
{
    char *value = nullptr;
    char str[] = "BOX_TYPE";

    int ret = getValueFromDevicePropsFile(str, &value);

    EXPECT_EQ(ret, -1);
    EXPECT_EQ(value, nullptr);
}

TEST_F(ServiceDhcpServerTest, get_Pool_cnt)
{
    char arr[15][2] = {0};
    FILE *pipe = (FILE *)0x1;
    char sg_buff[2] = "1";

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(sg_buff, sg_buff + strlen(sg_buff) + 1),
            Return(static_cast<char*>(sg_buff))
        ))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(sg_buff, sg_buff + strlen(sg_buff) + 1),
            Return(nullptr)
        ));

    int ret = get_Pool_cnt(arr, pipe);

    EXPECT_NE(ret, 0);
}

TEST_F(ServiceDhcpServerTest, IsDhcpConfHasInterface)
{
    FILE *fp = (FILE *)0x1;
    char buf[512] = "interface=eth0";

    IsDhcpConfHasInterface();
}

TEST_F(ServiceDhcpServerTest, syslog_restart_request)
{
    char Dhcp_server_status[10] = "started";
    char l_cSyscfg_get[16] = {0};
    int l_cRetVal = 0;
    int l_crestart = 0;
    char l_cCurrent_PID[8] = {0};
    FILE *expectedFd = reinterpret_cast<FILE *>(0xffffffff);
    const char *Expectedcmd = "pidof dnsmasq";
    char mockOutput[] = "1234";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(1)
        .WillOnce(DoAll(
            SetArrayArgument<3>(Dhcp_server_status, Dhcp_server_status + strlen(Dhcp_server_status) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_server_errinfo"), StrEq(""), 0))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("sysevent get dns-status"), _, _))
        .Times(1)
        .WillOnce(DoAll(
            SetArrayArgument<3>(Dhcp_server_status, Dhcp_server_status + strlen(Dhcp_server_status) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("sysevent get dhcp_server-status"), _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .Times(AnyNumber())
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(StrEq("/var/dnsmasq.conf"), 0))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(StrEq("/tmp/dnsmasq.conf.orig"), 0))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(StrEq("/var/run/dnsmasq.pid"), 0))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));


    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_server_enabled"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("hostname"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("SecureWebUI_LocalFqdn"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("SecureWebUI_Enable"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("DNSStrictOrder"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("XDNS_RefacCodeEnable"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_XDNS"), _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dns-status"), StrEq("started"), 0))
        .Times(AtLeast(1));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dns-errinfo"), StrEq(""), 0))
        .Times(AnyNumber());

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_server-status"), StrEq("started"), _)).Times(AtLeast(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_server_enabled"), _, _)).Times(AtLeast(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("hostname"), _, _)).Times(AtLeast(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("SecureWebUI_LocalFqdn"), _, _)).Times(AtLeast(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_lan_ipaddr"), _, _)).Times(AtLeast(1)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(StrEq("/var/dnsmasq.conf"), 0)).Times(AtLeast(1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(StrEq("/tmp/dnsmasq.conf.orig"), 0)).Times(AtLeast(1)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Return(0));

    EXPECT_EQ(0, syslog_restart_request());
}

TEST_F(ServiceDhcpServerTest, ResyncToNonvolWithNullRemPools)
{

    EXPECT_CALL(*g_syseventMock, sysevent_get(testing::_, testing::_, testing::StrEq("dhcp_server_current_pools"), testing::_, testing::_))
        .WillRepeatedly([](int, unsigned, const char*, char* value, int) {
            strcpy(value, "pool1 pool2");
            return 0;
        });

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly([](void*, const char*, const char*, unsigned int*, char** pValue) {
            *pValue = strdup("test_value");
            return 0;
        });

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));

    char* nullArg = nullptr;
    resync_to_nonvol(nullArg);
}

TEST_F(ServiceDhcpServerTest, ServiceDhcpInitSuccess)
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_server_propagate_wan_nameserver"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1", "1" + 1), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_server_propagate_wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1", "1" + 1), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_server_slow_start"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1", "1" + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>("0.0.0.0", "0.0.0.0" + 7), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_hsd_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>("primary", "primary" + 7), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("primary_temp_ip_prefix"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("2", "2" + 1), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("byoi_enabled"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1", "1" + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_slow_start_quanta"), _, _))
        .Times(1);

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_lease_time"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("24h", "24h" + 3), Return(0)));

    int result = service_dhcp_init();

    ASSERT_EQ(result, SUCCESS);
}

TEST_F(ServiceDhcpServerTest, LanStatusChangeWithLanNotRestart)
{
    const char* input = "lan_not_restart";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(3)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(8)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Return(0));

    lan_status_change((char *)input);
}