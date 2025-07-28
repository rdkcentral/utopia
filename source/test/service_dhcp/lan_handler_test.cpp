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


extern "C"
{
    extern void get_dateanduptime(char *buffer, int *uptime);
    extern char * app_addr(char *ip, char *nm);
    extern void find_active_brg_instances();
}

class LanHandlerTest : public ::testing::TestWithParam<int> {
protected:
    void SetUp() override {
        g_syscfgMock = new SyscfgMock();
        g_syseventMock = new SyseventMock();
        g_psmMock = new PsmMock();
        g_safecLibMock = new SafecLibMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_telemetryMock = new telemetryMock();
        g_fileIOMock = new FileIOMock();
        g_securewrapperMock = new SecureWrapperMock();
    }

    void TearDown() override {
        delete g_syscfgMock;
        delete g_syseventMock;
        delete g_psmMock;
        delete g_safecLibMock;
        delete g_anscMemoryMock;
        delete g_telemetryMock;
        delete g_fileIOMock;
        delete g_securewrapperMock;

        g_syscfgMock = nullptr;
        g_syseventMock = nullptr;
        g_psmMock = nullptr;
        g_safecLibMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_telemetryMock = nullptr;
        g_fileIOMock = nullptr;
        g_securewrapperMock = nullptr;
    }
};

ACTION_P(SetPsmValueArg4, value)
{
    *static_cast<char**>(arg4) = strdup(*value);
}

TEST_F(LanHandlerTest, get_dateanduptime) {
    char buffer[25] = {0};
    int uptime = 0;

    char mockBuffer[] = "241122-05:31:51.189177";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    get_dateanduptime(buffer, &uptime);

    EXPECT_STREQ(buffer, mockBuffer);
}

TEST_F(LanHandlerTest, app_addr_CASE_1) {
    char ip[] = "";
    char nm[] = "";
    char expectedResult[] = "255.253.252.254";

    char* result = app_addr(ip, nm);

    EXPECT_STREQ(result, expectedResult);
}

TEST_F(LanHandlerTest, app_addr_CASE_2) {
    char ip[] = "192.168.1.10";
    char nm[] = "";
    char expectedResult[] = "192.168.1.254";

    char* result = app_addr(ip, nm);

    EXPECT_STREQ(result, expectedResult);
}

TEST_F(LanHandlerTest, app_addr_CASE_3) {
    char ip[] = "172.16.5.30";
    char nm[] = "255.0.0.0";
    char expectedResult[] = "172.255.255.254";

    char* result = app_addr(ip, nm);

    EXPECT_STREQ(result, expectedResult);
}

TEST_F(LanHandlerTest, app_addr_CASE_4) {
    char ip[] = "192.168.1.10";
    char nm[] = "255.255.255.128";
    char expectedResult[] = "192.168.1.126";

    char* result = app_addr(ip, nm);

    EXPECT_STREQ(result, expectedResult);
}

TEST_F(LanHandlerTest, find_active_brg_instances_CASE_1) {

    EXPECT_CALL(*g_psmMock, PsmGetNextLevelInstances(_, _, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::Invoke([&](void*, char const * const, char const * const, unsigned int* inst, unsigned int** arr) {
                *inst = 1;
                *arr = new unsigned int[1];
                (*arr)[0] = 1;
            }),
            Return(0)
        ));

    EXPECT_CALL(*g_anscMemoryMock, Ansc_FreeMemory_Callback(_)).Times(1);

    find_active_brg_instances();
}

TEST_F(LanHandlerTest, find_active_brg_instances_CASE_2) {
    char mockValue[] = "1";
    char mockTrue[] = "TRUE";

    EXPECT_CALL(*g_psmMock, PsmGetNextLevelInstances(_, _, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::Invoke([&](void*, char const * const, char const * const, unsigned int* inst, unsigned int** arr) {
                *inst = 99;
                *arr = new unsigned int[1];
                (*arr)[0] = 1;
            }),
            Return(CCSP_SUCCESS)
        ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("EthLink"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("l2net"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("l3net_instances"), _, _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_anscMemoryMock, Ansc_FreeMemory_Callback(_)).Times(1);

    find_active_brg_instances();
}

TEST_F(LanHandlerTest, find_active_brg_instances_CASE_3) {
    char mockValue[] = "1";
    char mockTrue[] = "TRUE";

    EXPECT_CALL(*g_psmMock, PsmGetNextLevelInstances(_, _, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::Invoke([&](void*, char const * const, char const * const, unsigned int* inst, unsigned int** arr) {
                *inst = 1;
                *arr = new unsigned int[1];
                (*arr)[0] = 1;
            }),
            Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("EthLink"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockValue),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockValue),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.1.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockTrue),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("l3net_instances"), _, _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_anscMemoryMock, Ansc_FreeMemory_Callback(_)).Times(1);

    find_active_brg_instances();
}

TEST_F(LanHandlerTest, bring_lan_up_CASE_1) {
    char mockBuffer[] = "241122-05:31:51.189177";
    char mockSyncID[] = "16777216 -21474";
    char mockMultiLanFeature[] = "1";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_handler_async"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockSyncID, mockSyncID + strlen(mockSyncID) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("MULTILAN_FEATURE"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMultiLanFeature, mockMultiLanFeature + strlen(mockMultiLanFeature) + 1),
              Return(0)
    ));

    //Mock for find_active_brg_instances
    EXPECT_CALL(*g_psmMock, PsmGetNextLevelInstances(_, _, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::Invoke([&](void*, char const * const, char const * const, unsigned int* inst, unsigned int** arr) {
                *inst = 1;
                *arr = new unsigned int[1];
                (*arr)[0] = 1;
            }),
            Return(0)
        ));

    EXPECT_CALL(*g_anscMemoryMock, Ansc_FreeMemory_Callback(_)).Times(1);

    bring_lan_up();
}

TEST_F(LanHandlerTest, bring_lan_up_CASE_2) {
    char mockBuffer[] = "241122-05:31:51.189177";
    char mockSyncID[] = {0};
    char mockMultiLanFeature[] = "0";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_handler_async"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockSyncID, mockSyncID + strlen(mockSyncID) + 1),
              Return(0)
    ));

    char mockVal[] = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l2net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_brport"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.HomeSecurity_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("MULTILAN_FEATURE"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMultiLanFeature, mockMultiLanFeature + strlen(mockMultiLanFeature) + 1),
              Return(0)
    ));

    bring_lan_up();
}

TEST_F(LanHandlerTest, bring_lan_up_CASE_3) {
    char mockBuffer[] = "241122-05:31:51.189177";
    char mockSyncID[] = {0};
    char mockMultiLanFeature[] = "0";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_handler_async"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockSyncID, mockSyncID + strlen(mockSyncID) + 1),
              Return(0)
    ));

    char mockVal[] = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l3net"), _, _)).Times(2)
    .WillOnce(Return(CCSP_FAILURE))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l2net"), _, _)).Times(2)
    .WillOnce(Return(CCSP_FAILURE))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_brport"), _, _)).Times(2)
    .WillOnce(Return(CCSP_FAILURE))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.HomeSecurity_l3net"), _, _)).Times(2)
    .WillOnce(Return(CCSP_FAILURE))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("MULTILAN_FEATURE"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMultiLanFeature, mockMultiLanFeature + strlen(mockMultiLanFeature) + 1),
              Return(0)
    ));

    bring_lan_up();
}

TEST_F(LanHandlerTest, bring_lan_up_CASE_4) {
    char mockBuffer[] = "241122-05:31:51.189177";
    char mockSyncID[] = {0};
    char mockMultiLanFeature[] = "0";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_handler_async"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockSyncID, mockSyncID + strlen(mockSyncID) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l3net"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_l2net"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.PrimaryLAN_brport"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.HomeSecurity_l3net"), _, _))
    .WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("MULTILAN_FEATURE"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMultiLanFeature, mockMultiLanFeature + strlen(mockMultiLanFeature) + 1),
              Return(0)
    ));

    bring_lan_up();
}

TEST_F(LanHandlerTest, lan_restart_CASE_1) {
    char lanIP[] = "10.0.0.1";
    char lanSubnet[] = "255.255.255.0";
    char mockVal[] = "1";
    char mockCmd[] = "ipv4_1-ifname";
    char mockIfName[] = "brlan0";
    char mockIPv6[] = "2001:db8:0:1::1";
    char mockPrefix[] = "64";
    char mockTrue[] = "true";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_ipaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(lanIP, lanIP + strlen(lanIP) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_netmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(lanSubnet, lanSubnet + strlen(lanSubnet) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4Addr"), _, _)).Times(1)
    .WillOnce(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4SubnetMask"), _, _)).Times(1)
    .WillOnce(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockCmd, mockCmd + strlen(mockCmd) + 1),
              Return(-1)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(mockCmd), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_restarted"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockTrue, mockTrue + strlen(mockTrue) + 1),
              Return(0)
    ));

    lan_restart();
}

TEST_F(LanHandlerTest, lan_restart_CASE_2) {
    char lanIP[] = "10.0.0.1";
    char lanSubnet[] = "255.255.255.0";
    char mockVal[] = "1";
    char mockCmd[] = "ipv4_1-ifname";
    char mockIfName[] = "brlan0";
    char l_cLan_IpAddrv6_prev[65] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    char l_cLan_IpAddrv6[65] = "fe80::1";
    char mockPrefix[] = "64";
    char mockTrue[] = "true";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_ipaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(lanIP, lanIP + strlen(lanIP) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_netmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(lanSubnet, lanSubnet + strlen(lanSubnet) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4Addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&lanIP),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4SubnetMask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&lanSubnet),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).WillRepeatedly(Return(CCSP_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockCmd, mockCmd + strlen(mockCmd) + 1),
              Return(EOK)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(mockCmd), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_restarted"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockTrue, mockTrue + strlen(mockTrue) + 1),
              Return(0)
    ));


    lan_restart();
}

TEST_F(LanHandlerTest, lan_stop) {
    char mockVal[] = "1";
    char mockIfName[] = "brlan0";
    char mockIPv6[] = "fe80::1";
    char mockPrefix[] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_1-ifname"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4-down"), _, _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    lan_stop();
}

TEST_F(LanHandlerTest, erouter_mode_updated) {
    char mockVal[] = "0";
    char mockVal1[] = "1";
    char mockIfName[] = "brlan0";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockVal1, mockVal1 + strlen(mockVal1) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("bridge_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_4_status_configured"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal1, mockVal1 + strlen(mockVal1) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal1, mockVal1 + strlen(mockVal1) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_1-ifname"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4-down"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4-up"), _, _)).Times(1).WillOnce(Return(0));

    erouter_mode_updated();
}

TEST_F(LanHandlerTest, ipv4_resync_CASE_1) {
    char lan_inst[] = "1";
    char lanIP[] = "10.0.0.1";
    char lanSubnet[] = "255.255.255.0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(lan_inst, lan_inst + strlen(lan_inst) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4Addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&lanIP),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, testing::HasSubstr("V4SubnetMask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&lanSubnet),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).Times(2).WillRepeatedly(Return(CCSP_SUCCESS));

    ipv4_resync(lan_inst);
}

TEST_F(LanHandlerTest, ipv4_resync_CASE_2) {
    char lan_inst[] = "1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(lan_inst, lan_inst + strlen(lan_inst) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(2).WillRepeatedly(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).Times(2).WillRepeatedly(Return(CCSP_FAILURE));

    ipv4_resync(lan_inst);
}

TEST_F(LanHandlerTest, ipv4_status_down_CASE_1) {
    char status[] = "down";
    char mockVal[] = "1";
    char mockLanStatus[] = "started";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan-status"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockLanStatus, mockLanStatus + strlen(mockLanStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("bridge_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("lan-status"), _, _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.HomeNetworkIsolation"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("multinet-up"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(_, _)).Times(2).WillRepeatedly(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("firewall-restart"), _, _)).Times(1).WillOnce(Return(0));

    char mockBuffer[] = "241122-05:31:51.189177";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    ipv4_status(1, status);
}

TEST_F(LanHandlerTest, ipv4_status_down_CASE_2) {
    char status[] = "down";
    char mockVal[] = "1";
    char mockBrMode[] = "0";
    char mockLanStatus[] = "started";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan-status"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockLanStatus, mockLanStatus + strlen(mockLanStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("bridge_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockBrMode, mockBrMode + strlen(mockBrMode) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("lan-status"), _, _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.HomeNetworkIsolation"), _, _)).Times(1)
    .WillOnce(Return(CCSP_FAILURE));

    EXPECT_CALL(*g_telemetryMock, t2_event_d(_, _)).Times(2).WillRepeatedly(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("firewall-restart"), _, _)).Times(1).WillOnce(Return(0));

    char mockBuffer[] = "241122-05:31:51.189177";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    ipv4_status(1, status);
}

TEST_F(LanHandlerTest, ipv4_status_up_CASE_1) {
    char status[] = "up";
    char mockVal[] = "4";
    char mockMode[] = "1";
    char mockCmd[] = "ipv4_4-ifname";
    char mockIfName[] = "brlan0";
    char l_cLan_IpAddrv6_prev[65] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    char l_cLan_IpAddrv6[65] = "fe80::1";
    char mockPrefix[] = "64";
    char mockIPv4[] = "10.0.0.1";
    char mockStartMisc[] = "init";
    char mockWanAddr[] = "192.168.1.1";
    char mockNfqStatus[] = "starting";
    char mockNfqStatus1[] = "started";
    char mockDsLite[] = "0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMode, mockMode + strlen(mockMode) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockCmd, mockCmd + strlen(mockCmd) + 1),
              Return(-1)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(mockCmd), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_4-ipv4addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv4, mockIPv4 + strlen(mockIPv4) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("start-misc"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockStartMisc, mockStartMisc + strlen(mockStartMisc) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockWanAddr, mockWanAddr + strlen(mockWanAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("parcon_nfq_status"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ))
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus1, mockNfqStatus1 + strlen(mockNfqStatus1) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dslite_enabled"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockDsLite, mockDsLite + strlen(mockDsLite) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server-progress"), _, _))
    .WillRepeatedly(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_fileIOMock, access(_, _)).WillRepeatedly(Return(1));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.HomeNetworkIsolation"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    //EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("multinet-up"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(_, _)).Times(2).WillRepeatedly(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("firewall-restart"), _, _)).Times(1).WillOnce(Return(0));

    char mockBuffer[] = "241122-05:31:51.189177";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    ipv4_status(4, status);
}

TEST_F(LanHandlerTest, ipv4_status_up_CASE_2) {
    char status[] = "up";
    char mockVal[] = "4";
    char mockMode[] = "2";
    char mockCmd[] = "ipv4_4-ifname";
    char mockIfName[] = "brlan0";
    char l_cLan_IpAddrv6_prev[65] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    char l_cLan_IpAddrv6[65] = "fe80::1";
    char mockPrefix[] = "64";
    char mockIPv4[] = "10.0.0.1";
    char mockStartMisc[] = "init";
    char mockWanAddr[] = "192.168.1.1";
    char mockNfqStatus[] = "starting";
    char mockDsLite[] = "0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMode, mockMode + strlen(mockMode) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockCmd, mockCmd + strlen(mockCmd) + 1),
              Return(-1)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(mockCmd), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_4-ipv4addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv4, mockIPv4 + strlen(mockIPv4) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("start-misc"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockStartMisc, mockStartMisc + strlen(mockStartMisc) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockWanAddr, mockWanAddr + strlen(mockWanAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("parcon_nfq_status"), _, _))
    .WillRepeatedly(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dslite_enabled"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockDsLite, mockDsLite + strlen(mockDsLite) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server-progress"), _, _))
    .WillRepeatedly(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_fileIOMock, access(_, _)).WillRepeatedly(Return(1));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.HomeNetworkIsolation"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    //EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("multinet-up"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(_, _)).Times(2).WillRepeatedly(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("firewall-restart"), _, _)).Times(1).WillOnce(Return(0));

    char mockBuffer[] = "241122-05:31:51.189177";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    ipv4_status(4, status);
}

TEST_F(LanHandlerTest, ipv4_status_up_CASE_3) {
    char status[] = "up";
    char mockVal[] = "4";
    char mockMode[] = "2";
    char mockCmd[] = "ipv4_4-ifname";
    char mockIfName[] = "brlan0";
    char l_cLan_IpAddrv6_prev[65] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    char l_cLan_IpAddrv6[65] = "fe80::1";
    char mockPrefix[] = "64";
    char mockIPv4[] = "10.0.0.1";
    char mockStartMisc[] = "ready";
    char mockWanAddr[] = "192.168.1.1";
    char mockNfqStatus[] = "starting";
    char mockDsLite[] = "0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("primary_lan_l3net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockMode, mockMode + strlen(mockMode) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<0>(mockCmd, mockCmd + strlen(mockCmd) + 1),
              Return(-1)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(mockCmd), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIfName, mockIfName + strlen(mockIfName) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6_prev"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_ipaddr_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("lan_prefix_v6"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_4-ipv4addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPv4, mockIPv4 + strlen(mockIPv4) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("start-misc"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockStartMisc, mockStartMisc + strlen(mockStartMisc) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockWanAddr, mockWanAddr + strlen(mockWanAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("parcon_nfq_status"), _, _))
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dslite_enabled"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockDsLite, mockDsLite + strlen(mockDsLite) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server-progress"), _, _))
    .WillRepeatedly(testing::DoAll(
              testing::SetArrayArgument<3>(mockNfqStatus, mockNfqStatus + strlen(mockNfqStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1),
              Return(0)
    ));


    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l2net.HomeNetworkIsolation"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(&mockVal),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_telemetryMock, t2_event_d(_, _)).WillRepeatedly(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("firewall-restart"), _, _)).WillRepeatedly(Return(0));

    char mockBuffer[] = "241122-05:31:51.189177";
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
    .WillRepeatedly(testing::DoAll(
              testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
              Return(EOK)
    ));

    ipv4_status(4, status);
}