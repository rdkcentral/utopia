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

#include "FopenMock.h"
#include "service_dhcp_mock.h"

class ServiceDhcpIpv4Test : public ::testing::Test 
{
protected:
    void SetUp() override
    {
        g_syscfgMock = new SyscfgMock();
        g_syseventMock = new SyseventMock();
        g_libnetMock = new LibnetMock();
        g_fileIOMock = new FileIOMock();
        g_fopenMock = new FopenMock();
        g_psmMock = new PsmMock();
        g_safecLibMock = new SafecLibMock();
    }

    void TearDown() override
    {
        delete g_syscfgMock;
        delete g_syseventMock;
        delete g_libnetMock;
        delete g_fileIOMock;
        delete g_fopenMock;
        delete g_psmMock;
        delete g_safecLibMock;

        g_syscfgMock = nullptr;
        g_syseventMock = nullptr;
        g_libnetMock = nullptr;
        g_fileIOMock = nullptr;
        g_fopenMock = nullptr;
        g_psmMock = nullptr;
        g_safecLibMock = nullptr;
    }
};

ACTION_P(SetPsmValueArg4, value)
{
    *static_cast<char**>(arg4) = strdup(value);
}

TEST_F(ServiceDhcpIpv4Test, remove_config)
{
    int l3_inst = 1;

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _)).Times(3).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_)).Times(1).WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_)).Times(3).WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_)).Times(2).WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).Times(4).WillRepeatedly(Return(0));

    remove_config(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, remove_config2)
{
    int l3_inst = 1;
    char l_cCur_Ipv4_Addr[16] = "192.168.0.1";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIfName[16] = "brlan0";

    char expectedArgs1[300];
    snprintf(expectedArgs1, sizeof(expectedArgs1), "table all_lans 192.168.0.0/24 dev %s", l_cIfName);

    char expectedAddrDelete[300];
    snprintf(expectedAddrDelete, sizeof(expectedAddrDelete), "192.168.0.1/24 dev %s", l_cIfName);

    char expectedRuleDelete1[300];
    snprintf(expectedRuleDelete1, sizeof(expectedRuleDelete1), "from 192.168.0.1 lookup %d", l3_inst + 10);

    char expectedRuleDelete2[300];
    snprintf(expectedRuleDelete2, sizeof(expectedRuleDelete2), "iif %s lookup erouter", l_cIfName);

    char expectedRuleDelete3[300];
    snprintf(expectedRuleDelete3, sizeof(expectedRuleDelete3), "iif %s lookup %d", l_cIfName, l3_inst + 10);

    char expectedRouteDelete1[300];
    snprintf(expectedRouteDelete1, sizeof(expectedRouteDelete1), "table %d 192.168.0.0/24 dev %s", l3_inst + 10, l_cIfName);

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, NotNull(), _))
        .Times(3)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)));

    EXPECT_CALL(*g_libnetMock, addr_delete(StrEq(expectedAddrDelete)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(StrEq(expectedRuleDelete1)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(StrEq(expectedRuleDelete2)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(StrEq(expectedRuleDelete3)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(StrEq(expectedRouteDelete1)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(StrEq(expectedArgs1)))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "true");
            return 1;
        }));

    FILE *file = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file));

    EXPECT_CALL(*g_libnetMock, interface_down(_)).Times(1).WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).Times(4).WillRepeatedly(Return(0));

    remove_config(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, teardown_instance)
{
    int l3_inst = 1;
    char l_cSysevent_Cmd[255] = {0};
    const char *l_cIpv4_Instances = "4 5";

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4_1-lower");
    char l_cLower[8] = "brlan0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1),
            Return(0)));

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4_1-l2async");
    char l_cAsyncIDString[16] = "brlan0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(l_cAsyncIDString, l_cAsyncIDString + strlen(l_cAsyncIDString) + 1),
            Return(0)));

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4_1-ipv4addr");
    char emptyString[16] = "";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)));

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4_1-ipv4subnet");

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)));

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4_1-ifname");
    char l_cIfName[16] = "erouter0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1),
            Return(0)));

    memset(l_cSysevent_Cmd, 0, sizeof(l_cSysevent_Cmd));
    snprintf(l_cSysevent_Cmd, sizeof(l_cSysevent_Cmd), "ipv4-instances");
    char l_cActiveInstances[16] = "1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(l_cSysevent_Cmd), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(l_cActiveInstances, l_cActiveInstances + strlen(l_cActiveInstances) + 1),
            Return(0)));

    EXPECT_CALL(*g_libnetMock, addr_delete(_)).Times(testing::AnyNumber()).WillRepeatedly(Return(CNL_STATUS_SUCCESS));
    EXPECT_CALL(*g_libnetMock, rule_delete(_)).Times(testing::AnyNumber()).WillRepeatedly(Return(CNL_STATUS_SUCCESS));
    EXPECT_CALL(*g_libnetMock, route_delete(_)).Times(testing::AnyNumber()).WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(7)
        .WillRepeatedly(Return(0));

    teardown_instance(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_config)
{
    const char* l_cNv_Tsip_Enable = "true";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_IpAddr = "192.169.1.2";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_Gateway = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(2)
        .WillRepeatedly(Return(0));

    remove_tsip_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_config2)
{
    const char* l_cNv_Tsip_Enable = "1234";
    int l_iNv_Tsip_Enable = 1234;

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_Enable) , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_Enable, l_cNv_Tsip_Enable + strlen(l_cNv_Tsip_Enable) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpAddr = "192.169.1.2";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNvTsip_IpAddr), _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNvTsip_IpAddr, l_cNvTsip_IpAddr + strlen(l_cNvTsip_IpAddr) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_Gateway = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_SUCCESS)
    ));

    remove_tsip_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_config3)
{
    const char* l_cNv_Tsip_Enable = "1234";
    int l_iNv_Tsip_Enable = 1234;

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, NotNull())).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpAddr = "192.169.1.2";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, NotNull())).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, NotNull())).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_Gateway = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, NotNull())).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_FAILURE)
    ));

    remove_tsip_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_config4)
{
    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(4)
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    remove_tsip_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config2)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 1;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CCSP_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config3)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_FAILURE)));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config4)
{
    unsigned int l_iTs_Asn_Count = 0;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config5)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config6)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_FAILURE)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, remove_tsip_asn_config7)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    remove_tsip_asn_config();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip)
{

    const char* l_cNv_Tsip_Enable = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_Enable) , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_Enable, l_cNv_Tsip_Enable + strlen(l_cNv_Tsip_Enable) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpAddr = "192.168.1.2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNvTsip_IpAddr), _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNvTsip_IpAddr, l_cNvTsip_IpAddr + strlen(l_cNvTsip_IpAddr) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_Gateway = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_SUCCESS)
    ));

    sync_tsip ();
}


TEST_F(ServiceDhcpIpv4Test, sync_tsip2)
{

    const char* l_cNv_Tsip_Enable = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpAddr = "192.168.1.2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_Gateway = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_FAILURE)
    ));

    sync_tsip();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip3)
{
    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(4)
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    sync_tsip();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn2)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 1;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CCSP_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn3)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_FAILURE)));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn4)
{
    unsigned int l_iTs_Asn_Count = 0;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn5)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn6)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_FAILURE)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, sync_tsip_asn7)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    sync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip)
{
    int tsip_enable = 1;
    const char* l_cNv_Tsip_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_Enable) , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_Enable, l_cNv_Tsip_Enable + strlen(l_cNv_Tsip_Enable) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpAddr = "192.168.1.2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNvTsip_IpAddr), _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNvTsip_IpAddr, l_cNvTsip_IpAddr + strlen(l_cNvTsip_IpAddr) + 1),
            Return(0)
        ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNvTsip_Gateway = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_SUCCESS)
    ));

    resync_tsip(tsip_enable);
}


TEST_F(ServiceDhcpIpv4Test, resync_tsip2)
{
    int tsip_enable = 1;
    const char* l_cNv_Tsip_Enable = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_Enable),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpAddr = "192.168.1.2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Ipaddress"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpAddr),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_IpSubnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Subnetmask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_IpSubnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNvTsip_Gateway = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.truestaticip.Gateway"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNvTsip_Gateway),
              Return(CCSP_FAILURE)
    ));

    resync_tsip(tsip_enable);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip3)
{
    int tsip_enable = 1;
    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(4)
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    resync_tsip(tsip_enable);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn2)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 1;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CCSP_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn3)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_FAILURE)));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn4)
{
    unsigned int l_iTs_Asn_Count = 0;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn5)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn6)
{
    unsigned int l_iTs_Asn_Count = 65;
    unsigned int l_iTs_Asn_Ins_Value = 5;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));


    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_FAILURE)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn7)
{
    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "2";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(l_cNv_Tsip_asn_Enable) , _)).Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
            testing::SetArrayArgument<0>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn();
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance)
{
    int instance = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";
    char l_cNv_Tsip_Asn_Ip[] = "192.168.1.2";
    char l_cNv_Tsip_Asn_Subnet[] = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, NotNull(), _))
        .Times(3)
        .WillOnce(DoAll(
            SetArrayArgument<3>(l_cNv_Tsip_asn_Enable, l_cNv_Tsip_asn_Enable + strlen(l_cNv_Tsip_asn_Enable) + 1),
            Return(0)
        ))
        .WillOnce(DoAll(
            SetArrayArgument<3>(l_cNv_Tsip_Asn_Ip, l_cNv_Tsip_Asn_Ip + strlen(l_cNv_Tsip_Asn_Ip) + 1),
            Return(0)
        ))
        .WillOnce(DoAll(
            SetArrayArgument<3>(l_cNv_Tsip_Asn_Subnet, l_cNv_Tsip_Asn_Subnet + strlen(l_cNv_Tsip_Asn_Subnet) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn_instance(instance);
}


TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance2)
{
    int instance = -1;
    resync_tsip_asn_instance(instance);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance3)
{
    int instance = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn_instance(instance);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance4)
{
    int instance = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn_instance(instance);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance5)
{
    int instance = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn_instance(instance);
}

TEST_F(ServiceDhcpIpv4Test, resync_tsip_asn_instance6)
{
    int instance = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(AnyNumber())
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
        ))
        .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
        ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_tsip_asn_instance(instance);
}

TEST_F(ServiceDhcpIpv4Test, apply_config)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = "192.168.2.1";
    char staticIpv4Subnet[] = "255.255.255.0";
    char l_cIfName[16] = "brlan0";
    char l_cDsliteEnabled[16] = "1";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(5)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_PrefixV6, l_cLan_PrefixV6 + strlen(l_cLan_PrefixV6) + 1), Return(0)));

    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "true");
            return 1;
        }));

    FILE *file2 = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(2)
        .WillRepeatedly(Return(file2));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, true);

}

TEST_F(ServiceDhcpIpv4Test, apply_config2)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = "";
    char staticIpv4Subnet[] = "0";
    char l_cIfName[16] = "brlan0";
    char l_cDsliteEnabled[16] = "1";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(3)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1), Return(0)));


    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    FILE *file1 = fopen("/proc/sys/net/ipv4/conf/1/arp_ignore", "w");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file1));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, true);

}

TEST_F(ServiceDhcpIpv4Test, apply_config3)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = "0";
    char staticIpv4Subnet[] = "";
    char l_cIfName[16] = "brlan0";
    char l_cDsliteEnabled[16] = "1";
    char l_cCur_Ipv4_Addr[16] = "0";
    char l_cCur_Ipv4_Subnet[16] = "0";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(3)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)));


    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    FILE *file1 = fopen("/proc/sys/net/ipv4/conf/0/arp_ignore", "w");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file1));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, true);

}

TEST_F(ServiceDhcpIpv4Test, apply_config4)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = "192.168.2.1";
    char staticIpv4Subnet[] = "255.255.255.0";
    char l_cIfName[16] = "brlan1";
    char l_cDsliteEnabled[16] = "0";
    char l_cCur_Ipv4_Addr[16] = "192.168.3.1";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(2)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)));


    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    FILE *file1 = fopen("/proc/sys/net/ipv4/conf/brlan1/arp_ignore", "w");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file1));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, true);

}

TEST_F(ServiceDhcpIpv4Test, apply_config5)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = {0};
    char staticIpv4Subnet[] = {0};
    char l_cIfName[16] = "brlan0";
    char l_cCur_Ipv4_Addr[16] = {0};
    char l_cCur_Ipv4_Subnet[16] = {0};

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(3)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, false);

}

TEST_F(ServiceDhcpIpv4Test, apply_config6)
{
    int l3_inst = 1;
    char staticIpv4Addr[] = "";
    char staticIpv4Subnet[] = "0";
    char l_cIfName[16] = "brlan0";
    char l_cDsliteEnabled[16] = "0";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(6)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_IpAddrv6_prev, l_cLan_IpAddrv6_prev + strlen(l_cLan_IpAddrv6_prev) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_IpAddrv6, l_cLan_IpAddrv6 + strlen(l_cLan_IpAddrv6) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_PrefixV6, l_cLan_PrefixV6 + strlen(l_cLan_PrefixV6) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLan_PrefixV6, l_cLan_PrefixV6 + strlen(l_cLan_PrefixV6) + 1), Return(0)));

    unsigned int l_iTs_Asn_Count = 66;
    unsigned int l_iTs_Asn_Ins_Value = 2;
    unsigned int *l_iTs_Asn_Ins = &l_iTs_Asn_Ins_Value;

    EXPECT_CALL(*g_psmMock,
                PsmGetNextLevelInstances(_,
                                         StrEq("eRT."),
                                         StrEq("dmsb.truestaticip.Asn."),
                                         _,
                                         _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgPointee<3>(l_iTs_Asn_Count),
            SetArgPointee<4>(l_iTs_Asn_Ins),
            Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "last_erouter_mode",_, _))
        .Times(1)
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "1");
            return 1;
        }));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .Times(1)
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "1");
            return 1;
        }));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_,_,_,_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    FILE *file2 = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file2));

    bool ret = apply_config(l3_inst, staticIpv4Addr, staticIpv4Subnet);
    EXPECT_EQ(ret, true);

}

TEST_F(ServiceDhcpIpv4Test, load_static_l3)
{
    int l3_inst = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";
    char l_cDsliteEnabled[16] = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(2)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    load_static_l3(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, load_static_l3_2)
{
    int l3_inst = 1;

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_FAILURE)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    load_static_l3(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, load_static_l3_3)
{
    int l3_inst = 1;

    char* mockValue = NULL;
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
        .WillRepeatedly(DoAll(SetArgPointee<4>(mockValue), Return(CCSP_SUCCESS)));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    load_static_l3(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, handle_l2_status)
{
    int l3_inst = 1;
    int l2_inst = 1;
    char net_status[10] = "stopped";
    int input = 1;

    char l_cLocalReady[16] = "1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    handle_l2_status(l3_inst, l2_inst, net_status, input);

}

TEST_F(ServiceDhcpIpv4Test, handle_l2_status2)
{
    int l3_inst = 1;
    int l2_inst = 1;
    char net_status[10] = "partial";
    int input = 1;

    char l_cLocalReady[16] = "1";
    char l_cIpv4_Status[16] = "none";
    char l_cIfName[16] = "brlan0";
    char l_cDsliteEnabled[16] = "1";
    char l_cLan_IpAddrv6_prev[16] = "2001:db8:2::1";
    char l_cLan_IpAddrv6[16] = "2001:db8:1::1";
    char l_cLan_PrefixV6[16] = "64";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(5)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Status, l_cIpv4_Status + strlen(l_cIpv4_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cDsliteEnabled, l_cDsliteEnabled + strlen(l_cDsliteEnabled) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    const char* l_cNv_Tsip_asn_Enable = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(AnyNumber())
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Tsip_asn_Enable),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_libnetMock, addr_derive_broadcast(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_add(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    FILE *file1 = fopen("/proc/sys/net/ipv4/conf/1/arp_ignore", "w");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file1));

    handle_l2_status(l3_inst, l2_inst, net_status, input);

}


TEST_F(ServiceDhcpIpv4Test, handle_l2_status3)
{
    int l3_inst = 1;
    int l2_inst = 1;
    char net_status[10] = "partial";
    int input = 1;

    char l_cLocalReady[16] = "1";
    char l_cIpv4_Status[16] = "up";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(2)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Status, l_cIpv4_Status + strlen(l_cIpv4_Status) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    handle_l2_status(l3_inst, l2_inst, net_status, input);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance)
{
    int l3_inst = 1;

    char l_cLower[16] = "0";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Ip),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Subnet),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Enabled),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Lower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_FAILURE)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(9)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)));


    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "true");
            return 1;
        }));

    FILE *file = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file));

    EXPECT_CALL(*g_libnetMock, interface_down(_))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance2)
{
    int l3_inst = 1;

    char l_cLower[16] = "erouter0";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Ip),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Subnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Enabled),
              Return(CCSP_FAILURE)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(6)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance3)
{
    int l3_inst = 1;

    char l_cLower[16] = "erouter0";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));


    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Lower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(9)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "true");
            return 1;
        }));

    FILE *file = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file));

    EXPECT_CALL(*g_libnetMock, interface_down(_))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance4)
{
    int l3_inst = 1;

    char l_cLower[16] = "erouter0";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));


    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Lower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(9)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "start_upnp_service",_, _))
        .WillOnce(Invoke([](const char*, const char*, char* out_value, int) {
            strcpy(out_value, "true");
            return 1;
        }));

    FILE *file = fopen("/lib/rdk/start-upnp-service", "r");

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(file));

    EXPECT_CALL(*g_libnetMock, interface_down(_))
        .Times(1)
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance5)
{
    int l3_inst = 1;

    char l_cLower[16] = {0};
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));


    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Lower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(6)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_instance6)
{
    int l3_inst = 1;

    char l_cLower[16] = "1";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cLocalReady[16] = "1";
    char l_cIfName[16] = "brlan0";


    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));


    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ))
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_SUCCESS)
    ));

    const char* l_cNv_Lower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.EthLink.1.l2net"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              SetPsmValueArg4(l_cNv_Lower),
              Return(CCSP_SUCCESS)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(9)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Addr, l_cCur_Ipv4_Addr + strlen(l_cCur_Ipv4_Addr) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCur_Ipv4_Subnet, l_cCur_Ipv4_Subnet + strlen(l_cCur_Ipv4_Subnet) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIpv4_Instances, l_cIpv4_Instances + strlen(l_cIpv4_Instances) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cIfName, l_cIfName + strlen(l_cIfName) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cNv_Lower_Status, l_cNv_Lower_Status + strlen(l_cNv_Lower_Status) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_rmcallback(_, _ , _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    resync_instance(l3_inst);

}

TEST_F(ServiceDhcpIpv4Test, resync_all_instance_1) {
    char mockInstances[] = "1 ";
    FILE* mockFP = (FILE *)0x1;
    char mockBuf[] = "4";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4-instances"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockInstances, mockInstances + strlen(mockInstances) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq("psmcli getallinst dmsb.l3net."), _)).Times(1)
    .WillOnce(Return(mockFP));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
             testing::SetArrayArgument<0>(mockBuf, mockBuf + strlen(mockBuf) + 1),
            Return(static_cast<char*>(mockBuf))
        ))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(_)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, testing::HasSubstr("lower"), _, _)).Times(1)
    .WillOnce(Return(0));

    resync_all_instance();
}

TEST_F(ServiceDhcpIpv4Test, resync_all_instance_2) {

    char mockInstances[] = "1 ";
    FILE* mockFP = (FILE *)0x1;
    char mockBuf[] = "1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4-instances"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockInstances, mockInstances + strlen(mockInstances) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq("psmcli getallinst dmsb.l3net."), _)).Times(1)
    .WillOnce(Return(mockFP));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
             testing::SetArrayArgument<0>(mockBuf, mockBuf + strlen(mockBuf) + 1),
            Return(static_cast<char*>(mockBuf))
        ))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(_)).Times(1).WillOnce(Return(0));

    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Ip),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Subnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Enabled),
              Return(CCSP_FAILURE)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, testing::HasSubstr("lower"), _, _)).Times(1)
    .WillOnce(Return(0));

    resync_all_instance();
}

TEST_F(ServiceDhcpIpv4Test, ipv4_up)
{
    char l3_inst[16] = "1";
    char l_cLower[16] = "1";
    char l_cL3Net_Status[16] = "partial";
    char l_cLocalReady[16] = "1";
    char l_cIpv4_Status[16] = "up";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(3)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalReady, l_cLocalReady + strlen(l_cLocalReady) + 1), Return(0)));


    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    ipv4_up(l3_inst);
}

TEST_F(ServiceDhcpIpv4Test, ipv4_up2)
{
    char l3_inst[16] = "1";
    char l_cLower[16] = {0};
    char l_cLocalReady[16] = "1";
    char l_cCur_Ipv4_Addr[16] = "192.168.4.2";
    char l_cCur_Ipv4_Subnet[16] = "255.255.255.0";
    char l_cIpv4_Instances[16] = "1";
    char l_cNv_Lower_Status[16] = "up";
    char l_cIfName[16] = "brlan0";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(2)
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLower, l_cLower + strlen(l_cLower) + 1), Return(0)));

    const char* l_cNv_EthLower = "1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.EthLink"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_EthLower),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Ip = "172.16.12.1";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4Addr"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Ip),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Subnet = "255.255.255.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.V4SubnetMask"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Subnet),
              Return(CCSP_FAILURE)
    ));

    const char* l_cNv_Enabled = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.l3net.1.Enable"), _, _)).Times(2)
    .WillRepeatedly(testing::DoAll(
              SetPsmValueArg4(l_cNv_Enabled),
              Return(CCSP_FAILURE)
    ));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, rule_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_libnetMock, route_delete(_))
        .Times(AnyNumber())
        .WillRepeatedly(Return(CNL_STATUS_SUCCESS));

    ipv4_up(l3_inst);
}