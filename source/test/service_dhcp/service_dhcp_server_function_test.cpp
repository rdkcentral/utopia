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

class ServiceDhcpServerFunctionTest : public ::testing::Test
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

TEST_F(ServiceDhcpServerFunctionTest, isValidSubnetMask)
{
    char buffer[16] = {0};
    strncpy(buffer, "255.255.255.0", sizeof(buffer));
    EXPECT_EQ(isValidSubnetMask(buffer), 1);

    strncpy(buffer, "255.255.0.0", sizeof(buffer));
    EXPECT_EQ(isValidSubnetMask(buffer), 1);

    strncpy(buffer, "255.0.0.0", sizeof(buffer));
    EXPECT_EQ(isValidSubnetMask(buffer), 1);
}

TEST_F(ServiceDhcpServerFunctionTest, isValidLANIP)
{
    EXPECT_EQ(isValidLANIP("10.0.0.1"), 1);
    EXPECT_EQ(isValidLANIP("172.16.0.1"), 1);
    EXPECT_EQ(isValidLANIP("172.31.255.255"), 1);
    EXPECT_EQ(isValidLANIP("192.168.0.1"), 1);
    EXPECT_EQ(isValidLANIP("192.168.147.0"), 0);
}

TEST_F(ServiceDhcpServerFunctionTest, prepare_hostname)
{
    char l_cHostName[16] = "hostname";
    char l_cCurLanIP[16] = "192.168.0.1";
    char l_clocFqdn[16] = "local.fqdn";
    char l_cSecWebUI_Enabled[8] = "true";
    int result = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "hostname", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cHostName, l_cHostName + strlen(l_cHostName)), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "SecureWebUI_LocalFqdn", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_clocFqdn, l_clocFqdn + strlen(l_clocFqdn)), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "SecureWebUI_Enable", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cSecWebUI_Enabled, l_cSecWebUI_Enabled + strlen(l_cSecWebUI_Enabled)), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, "current_lan_ipaddr", _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cCurLanIP, l_cCurLanIP + strlen(l_cCurLanIP)), Return(0)));

    result = prepare_hostname();

    EXPECT_EQ(result, 0);
}


TEST_F(ServiceDhcpServerFunctionTest, calculate_dhcp_range)
{
    char mockPrefix[] = "test-prefix-";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr);

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "lan_ipaddr", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.0.1", "192.168.0.1" + 11), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "lan_netmask", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 13), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "dhcp_start", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.0.2", "192.168.0.2" + 11), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "dhcp_end", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.0.254", "192.168.0.254" + 14), Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_set(_, _, _)).Times(::testing::AtMost(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _)).Times(::testing::AtMost(1));

    calculate_dhcp_range(mockFile, mockPrefix);

    fclose(mockFile);
}

TEST_F(ServiceDhcpServerFunctionTest, prepare_dhcp_options_wan_dns)
{
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(0));

    prepare_dhcp_options_wan_dns();
}

TEST_F(ServiceDhcpServerFunctionTest, PrepareWhitelistUrls_Success)
{
    char cloud_url[] = "http://internet.xfinity.com";
    char Erouter0_Ipv4Addr[] = "192.168.0.1";
    char nameserver[] = "8.8.8.8";
    char static_url[] = "static.example.com";
    char mockIfName[] = "erouter0";
    char redirect_url[] = "http://XfinityHomeNetworking.com";
    FILE *tempFile = tmpfile();
    char l_cErouter0_Ipv4Addr[16] = "192.168.1.1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .WillOnce(Invoke([&](const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
            strncpy(outbuf, "erouter0", outbytes - 1);
            outbuf[outbytes - 1] = '\0';
            return 0;
        }));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, _, _, _))
        .WillRepeatedly(Invoke([&](const char*, const char* name, char* out_value, int outbytes) {
            strcpy(out_value, "http://XfinityHomeNetworking.com");
            return 1;
        }));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, _, _, _))
        .WillRepeatedly(Invoke([&](const char*, const char*, char* out_value, int outbytes) {
            strncpy(out_value, "http://internet.xfinity.com", outbytes - 1);
            out_value[outbytes - 1] = '\0';
            return 0;
        }));


    EXPECT_CALL(*g_utopiaMock, iface_get_ipv4addr(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<1>(Erouter0_Ipv4Addr, Erouter0_Ipv4Addr + strlen(Erouter0_Ipv4Addr) + 1), Return(0)));


    prepare_whitelist_urls(tempFile);
}

TEST_F(ServiceDhcpServerFunctionTest, UpdateConfigListintoConfFile_Success)
{
    FILE *tempFile = tmpfile();

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .WillRepeatedly(Invoke([&](const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
            strncpy(outbuf, "1", outbytes - 1);
            outbuf[outbytes - 1] = '\0';
            return 0;
        }));

    UpdateConfigListintoConfFile(tempFile);
}

TEST_F(ServiceDhcpServerFunctionTest, AddConfList_Success)
{
    char confToken[] = "test-conf-token";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .WillOnce(Invoke([&](const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
            strncpy(outbuf, "0", outbytes - 1);
            outbuf[outbytes - 1] = '\0';
            return 0;
        }));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Return(0));

    AddConfList(confToken);
}

TEST_F(ServiceDhcpServerFunctionTest, UpdateConfList_Success)
{
    char confToken[] = "test-conf";

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    UpdateConfList(confToken, 1);
}

TEST_F(ServiceDhcpServerFunctionTest, IsInterfaceExists_Success)
{
    char confToken[] = "test-conf";
    char confTokenInst[] = "test-conf-inst";
    int confTokenInstInt = 0;

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .WillRepeatedly(Invoke([&](const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
            strncpy(outbuf, "1", outbytes - 1);
            outbuf[outbytes - 1] = '\0';
            return 0;
        }));


    IsInterfaceExists(confToken, confTokenInst, &confTokenInstInt);

}

TEST_F(ServiceDhcpServerFunctionTest, UpdateDhcpConfChangeBasedOnEvent_Success)
{
    char confToken[] = "test-conf";
    char confTokenInst[] = "test-conf-inst";
    int confTokenInstInt = 0;

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .WillRepeatedly(Invoke([&](const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
            strncpy(outbuf, "1", outbytes - 1);
            outbuf[outbytes - 1] = '\0';
            return 0;
        }));


    UpdateDhcpConfChangeBasedOnEvent();
}

TEST_F(ServiceDhcpServerFunctionTest, get_dhcp_option_for_brlan0_Success)
{
    char pDhcpNs_OptionString[1024] = {0};
    char l_cDhcpNs_1[128] = "192.168.1.1";
    char l_cDhcpNs_2[128] = "192.168.1.2";
    char l_cDhcpNs_3[128] = "192.168.1.3";
    char l_cLocalNs[128] = "0.0.0.0";

    char l_cWan_Dhcp_Dns[256] = {0};
    char l_cSecWebUI_Enabled[8] = "true";
    FILE *l_fResolv_Conf = tmpfile();
    char l_cLine[255] = {0};

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "dhcp_nameserver_1", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cDhcpNs_1, l_cDhcpNs_1 + strlen(l_cDhcpNs_1) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "dhcp_nameserver_2", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cDhcpNs_2, l_cDhcpNs_2 + strlen(l_cDhcpNs_2) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "dhcp_nameserver_3", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cDhcpNs_3, l_cDhcpNs_3 + strlen(l_cDhcpNs_3) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, "SecureWebUI_Enable", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cSecWebUI_Enabled, l_cSecWebUI_Enabled + strlen(l_cSecWebUI_Enabled) + 1), Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, "current_lan_ipaddr", _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cLocalNs, l_cLocalNs + strlen(l_cLocalNs) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, "wan_dhcp_dns", _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cWan_Dhcp_Dns, l_cWan_Dhcp_Dns + strlen(l_cWan_Dhcp_Dns) + 1), Return(0)));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(AtLeast(1));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _)).Times(AtLeast(1));

    get_dhcp_option_for_brlan0(pDhcpNs_OptionString);

}

TEST_F(ServiceDhcpServerFunctionTest, check_and_get_wan_dhcp_dns_Success)
{
    char pl_cWan_Dhcp_Dns[256] = {0};
    char l_cWan_Dhcp_Dns[256] = "192.168.1.2";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, "wan_dhcp_dns", _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(l_cWan_Dhcp_Dns, l_cWan_Dhcp_Dns + strlen(l_cWan_Dhcp_Dns) + 1), Return(0)));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(AtLeast(1));

    check_and_get_wan_dhcp_dns(pl_cWan_Dhcp_Dns);

}

TEST_F(ServiceDhcpServerFunctionTest, prepare_static_dns_urls_Success) {
    FILE *fp_local_dhcp_conf = tmpfile();
    char mockURL[128] = "http://example.com\n";

    FILE* mockFile = fopen("/tmp/static_dns_urls", "w");
    ASSERT_NE(mockFile, nullptr);

    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillRepeatedly(Return(0));

    prepare_static_dns_urls(fp_local_dhcp_conf);
    remove("/tmp/static_dns_urls");
}

TEST_F(ServiceDhcpServerFunctionTest, prepare_dhcp_conf_static_hosts) {
    char mockVal[]  = "1";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("/tmp/dhcp_static_hosts")))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "/tmp/dhcp_static_hosts%d", getpid());
            return strlen(buf);
        }));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_num_static_hosts"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("dhcp_static_host_")))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_static_host_1");
            return -1;
        }));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("dhcp_static_host_1"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillRepeatedly(Return(0));

    prepare_dhcp_conf_static_hosts();
}

TEST_F(ServiceDhcpServerFunctionTest, prepare_dhcp_conf_static_hosts_FAIL)
{
    char mockVal[]  = "1";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("/tmp/dhcp_static_hosts")))
        .WillOnce(Return(-1));

    prepare_dhcp_conf_static_hosts();
}


TEST_F(ServiceDhcpServerFunctionTest, DoExtraPools_Success)
{
    FILE *local_dhcpconf_file = tmpfile();
    char prefix[] = "lan0";
    unsigned char bDhcpNs_Enabled = 1;
    char pWan_Dhcp_Dns[] = "wan0";

    char mockPools[] = "1\n";
    char mockVal[] = "TRUE";
    char mockInst[] = "1";
    char mockStatus[] = "up";
    char mockIPAddr[] = "1.1.1.1";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_current_pools"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPools, mockPools + strlen(mockPools) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("enabled")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_enabled");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_enabled"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("ipv4inst")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_ipv4inst");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_ipv4inst"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockInst, mockInst + strlen(mockInst) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("ipv4_1-status")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "ipv4_1-status");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_1-status"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockStatus, mockStatus + strlen(mockStatus) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("startaddr")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_startaddr");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_startaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPAddr, mockIPAddr + strlen(mockIPAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("endaddr")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_endaddr");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_endaddr"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPAddr, mockIPAddr + strlen(mockIPAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("subnet")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_subnet");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_subnet"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockIPAddr, mockIPAddr + strlen(mockIPAddr) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("leasetime")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_leasetime");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_leasetime"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockInst, mockInst + strlen(mockInst) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("ifname")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "ipv4_1-ifname");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_1-ifname"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(prefix, prefix+ strlen(prefix) + 1),
              Return(0)
    ));

    do_extra_pools(local_dhcpconf_file, prefix, bDhcpNs_Enabled, pWan_Dhcp_Dns);
}

TEST_F(ServiceDhcpServerFunctionTest, DoExtraPools_CASE_1)
{
    FILE *local_dhcpconf_file = tmpfile();
    char prefix[] = "lan0";
    unsigned char bDhcpNs_Enabled = 1;
    char pWan_Dhcp_Dns[] = "wan0";

    char mockPools[] = "1\n";
    char mockVal[] = "TRUE";
    char mockInst[] = "1";
    char mockStatus[] = "down";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_current_pools"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPools, mockPools + strlen(mockPools) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("enabled")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_enabled");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_enabled"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockVal, mockVal + strlen(mockVal) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("ipv4inst")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "dhcp_server_1_ipv4inst");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_1_ipv4inst"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockInst, mockInst + strlen(mockInst) + 1),
              Return(0)
    ));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, testing::HasSubstr("ipv4_1-status")))
    .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "ipv4_1-status");
            return -1;
    }));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv4_1-status"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockStatus, mockStatus + strlen(mockStatus) + 1),
              Return(0)
    ));

    do_extra_pools(local_dhcpconf_file, prefix, bDhcpNs_Enabled, pWan_Dhcp_Dns);
}

TEST_F(ServiceDhcpServerFunctionTest, DoExtraPools_CASE_2)
{
    FILE *local_dhcpconf_file = tmpfile();
    char prefix[] = "lan0";
    unsigned char bDhcpNs_Enabled = 1;
    char pWan_Dhcp_Dns[] = "wan0";

    char mockPools[] = "\n";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("dhcp_server_current_pools"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<3>(mockPools, mockPools + strlen(mockPools) + 1),
              Return(0)
    ));

    do_extra_pools(local_dhcpconf_file, prefix, bDhcpNs_Enabled, pWan_Dhcp_Dns);
}