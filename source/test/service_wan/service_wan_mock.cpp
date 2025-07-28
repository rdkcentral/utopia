/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include "service_wan_mock.h"

class service_wan_test : public ::testing::Test
{
protected:
    SyscfgMock mockedsyscfg;
    SecureWrapperMock mockedSecureWrapper;
    SafecLibMock mockedSafecLib;
    utopiaMock mockedUtopia;
    telemetryMock mockedTelemetry;
    SyseventMock mockedSysevent;
    PsmMock mockedPsm;
    MessageBusMock mockedMessageBus;
    AnscMemoryMock mockedAnscMemory;
    FileIOMock mockedFileIO;
    rdkloggerMock mockedRdklogger;
    service_wan_test() 
    {
        g_syscfgMock = &mockedsyscfg;
        g_securewrapperMock = &mockedSecureWrapper;
        g_safecLibMock = &mockedSafecLib;
        g_utopiaMock = &mockedUtopia;
        g_telemetryMock = &mockedTelemetry;
        g_syseventMock = &mockedSysevent;
        g_psmMock = &mockedPsm;
        g_messagebusMock = &mockedMessageBus;
        g_anscMemoryMock = &mockedAnscMemory;
        g_fileIOMock = &mockedFileIO;
        g_rdkloggerMock = &mockedRdklogger;
    }
    virtual ~service_wan_test()
    {
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_safecLibMock = nullptr;
        g_utopiaMock = nullptr;
        g_telemetryMock = nullptr;
        g_syseventMock = nullptr;
        g_psmMock = nullptr;
        g_messagebusMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_fileIOMock = nullptr;
        g_rdkloggerMock = nullptr;
    }
    virtual void SetUp() override
    {
        printf("service_wan_test::SetUp\n");
    }
    virtual void TearDown() override
    {
        printf("service_wan_test::TearDown\n");
    }
    static void SetUpTestCase()
    {
        printf("%s %s\n", __func__,
               ::testing::UnitTest::GetInstance()->current_test_case()->name());
    }
    static void TearDownTestCase()
    {
        printf("%s %s\n", __func__,
               ::testing::UnitTest::GetInstance()->current_test_case()->name());
    }
};


TEST_F(service_wan_test, Test_usage)
{
    FILE* temp_stderr = freopen("test_stderr.txt", "w", stderr);
    EXPECT_NE(temp_stderr, nullptr) << "Failed to redirect stderr";
    logfptr = fopen("test_logfptr.txt", "w");
    EXPECT_NE(logfptr, nullptr) << "Failed to open log file";
    EXPECT_CALL(*g_fileIOMock, fclose(temp_stderr)).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(logfptr)).WillOnce(Return(0));
    usage();
    fclose(stderr);
    fclose(logfptr);
    remove("test_stderr.txt");
    remove("test_logfptr.txt");
}

TEST_F(service_wan_test, Test_serv_wan_term)
{
    struct serv_wan sw;
    sw.sefd = 1;
    sw.setok = 1;
    EXPECT_CALL(*g_syseventMock, sysevent_close(sw.sefd, sw.setok)).WillOnce(Return(0));
    int ret = serv_wan_term(&sw);
    EXPECT_EQ(ret, 0);
}

TEST_F(service_wan_test, Test_serv_wan_init)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char *ifname = "eth0";
    const char *prot = "dhcp";
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(-1));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, -1);
}

TEST_F(service_wan_test, Test_serv_wan_init_ifname)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = nullptr;
    const char* prot = "dhcp";
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_ifname[IFNAMSIZ] = "";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_physical_ifname"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_ifname, empty_ifname + IFNAMSIZ), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, -1);
}

TEST_F(service_wan_test, Test_serv_wan_init_prot)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, -1);
}

TEST_F(service_wan_test, Test_serv_wan_init_rtmod_ipv4)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "dhcp";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    char empty_buf[32] = "1";  // This should set rtmod to WAN_RTMOD_IPV4
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_buf, empty_buf + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sw.rtmod, WAN_RTMOD_IPV4);
    EXPECT_EQ(sw.timo, SW_PROT_TIMO);
}

TEST_F(service_wan_test, Test_serv_wan_init_rtmod_ipv6)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "dhcp";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    char empty_buf[32] = "2";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_buf, empty_buf + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sw.rtmod, WAN_RTMOD_IPV6);
    EXPECT_EQ(sw.timo, SW_PROT_TIMO);
}

TEST_F(service_wan_test, Test_serv_wan_init_rtmod_ds) 
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "dhcp";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    char empty_buf[32] = "3";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_buf, empty_buf + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sw.rtmod, WAN_RTMOD_DS);
    EXPECT_EQ(sw.timo, SW_PROT_TIMO);
}

TEST_F(service_wan_test, Test_serv_wan_init_rtmod_unknown)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "dhcp";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    char empty_buf[32] = "4";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_buf, empty_buf + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sw.rtmod, WAN_RTMOD_UNKNOW);
    EXPECT_EQ(sw.timo, SW_PROT_TIMO);
}

TEST_F(service_wan_test, Test_serv_wan_init_rtmod_empty)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    const char* prot = nullptr;
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .WillOnce(Return(0));
    char empty_prot[32] = "dhcp";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_proto"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_prot, empty_prot + 32), Return(0)));
    char empty_buf[32] = "";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(empty_buf, empty_buf + 32), Return(0)));
    int ret = serv_wan_init(&sw, ifname, prot);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sw.rtmod, WAN_RTMOD_UNKNOW);
    EXPECT_EQ(sw.timo, SW_PROT_TIMO);
}

TEST_F(service_wan_test, FileOpen)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    int result = resolv_static_deconfig(&sw);
    EXPECT_EQ(result, 0);
    remove(RESOLV_CONF_FILE);
}

TEST_F(service_wan_test, FileOpenConfig)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    int result = resolv_static_config(&sw);
    EXPECT_EQ(result,0);
}

TEST_F(service_wan_test, Test_wan_static_stop)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4_wan_ipaddr"), StrEq("0.0.0.0"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4_wan_subnet"), StrEq("0.0.0.0"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("default_router"), nullptr, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("current_ipv4_link_state"), StrEq("down"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 11), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip rule del from 192.168.1.1 lookup erouter"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 route del table erouter default dev eth0"),_))
        .WillOnce(Return(0));
    int result = wan_static_stop(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_static_start_failure_one)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.10", "192.168.1.10" + 16), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_netmask"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 19), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_default_gateway"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 16), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr add 192.168.1.10/255.255.255.0 broadcast + dev eth0"),_))
        .WillOnce(Return(-1));
    int result = wan_static_start(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, Test_wan_static_start_failure_two)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.10", "192.168.1.10" + 16), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_netmask"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 19), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_default_gateway"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 16), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr add 192.168.1.10/255.255.255.0 broadcast + dev eth0"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 link set eth0 up"),_))
        .WillOnce(Return(-1));
    int result = wan_static_start(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, Test_wan_static_start_failure_three)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.10", "192.168.1.10" + 16), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_netmask"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 19), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_default_gateway"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 16), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr add 192.168.1.10/255.255.255.0 broadcast + dev eth0"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 link set eth0 up"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 route add table erouter default dev eth0 via 192.168.1.1 && "
                                                          "ip rule add from 192.168.1.10 lookup erouter"),_))
        .WillOnce(Return(-1));
    int result = wan_static_start(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, Test_wan_static_start_success)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.10", "192.168.1.10" + 16), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_netmask"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 19), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_default_gateway"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 16), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr add 192.168.1.10/255.255.255.0 broadcast + dev eth0"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 link set eth0 up"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 route add table erouter default dev eth0 via 192.168.1.1 && "
                                                          "ip rule add from 192.168.1.10 lookup erouter"),_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("default_router"), StrEq("192.168.1.1"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("ipv4_wan_ipaddr"), StrEq("192.168.1.10"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("ipv4_wan_subnet"), StrEq("255.255.255.0"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_ipv4_link_state"), StrEq("up"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("dhcp_server-restart"), nullptr, 0))
        .WillOnce(Return(0));
    int result = wan_static_start(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Get_dhcp_pid)
{
    const size_t buffer_size = 100;
    char pidfile[buffer_size];
    int result = Getdhcpcpidfile(pidfile, buffer_size);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_dhcp_stop)
{
    const char* ifname = "eth0";
    const char* DHCPC_PID_FILE = "/tmp/udhcpc.erouter0.pid";
    const char* LOG_FILE = "/tmp/udhcp.log";
    char pid_str[10];
    int pid = -1;
    memset(pid_str, 0, sizeof(pid_str));
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq(ifname)))
        .WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(DHCPC_PID_FILE)))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(LOG_FILE)))
        .Times(1)
        .WillOnce(Return(0));
    int result = dhcp_stop(ifname);
    EXPECT_EQ(result, 0);
    remove(DHCPC_PID_FILE);
    remove(LOG_FILE);
}

TEST_F(service_wan_test, Test_route_config)
{
    const char* ifname = "eth0";
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip rule add iif eth0 lookup all_lans && ip rule add oif eth0 lookup erouter "),_))
        .WillOnce(Return(0));
    int result = route_config(ifname);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_route_deconfig)
{
    const char* ifname = "eth0";
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip rule del iif eth0 lookup all_lans && ip rule del oif eth0 lookup erouter "),_))
        .WillOnce(Return(0));
    int result = route_deconfig(ifname);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_checkFileExists)
{
    const char* fname = "/tmp/test.txt";
    FILE *fp = fopen(fname, "w+") ;
    if(fp != NULL) {
        EXPECT_CALL(*g_fileIOMock, fclose(NotNull()))
        .Times(1)
        .WillOnce(Return(0));
    int result = checkFileExists(fname);
    EXPECT_EQ(result, 1);
    }
}

TEST_F(service_wan_test, Test_wan_iface_down)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 link set eth0 down"),_))
        .WillOnce(Return(0));
    int result = wan_iface_down(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestWanIfaceUp)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.rtmod = WAN_RTMOD_DS;
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("router_adv_provisioning_enable"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1", "1" + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_mtu"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("1500", "1500" + 4), Return(0)));
    EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, _, _))
        .Times(11)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
        .Times(1)
        .WillRepeatedly(Return(0));
    int result = wan_iface_up(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_dhcp_release_fopen_fail)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    const size_t buffer_size = 100;
    char pidfile[buffer_size];
    const char* DHCPC_PID_FILE = "/tmp/udhcpc.erouter0.pid";
    remove(DHCPC_PID_FILE);
    int result = wan_dhcp_release(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, Test_wan_dhcp_stop)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq("eth0")))
        .WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq("/tmp/udhcpc.erouter0.pid")))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq("/tmp/udhcp.log")))
        .Times(1)
        .WillOnce(Return(0));
    int result = wan_dhcp_stop(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestWanAddrUnsetDHCP)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.prot = WAN_PROT_DHCP;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-status"), StrEq("stopping"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-errinfo"), nullptr, 0)).Times(1);
    char prev_ip[100] = "192.168.1.10";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("current_wan_ipaddr"), _, sizeof(prev_ip)))
        .WillOnce(DoAll(SetArrayArgument<3>(prev_ip, prev_ip + strlen(prev_ip) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("previous_wan_ipaddr"), StrEq("192.168.1.10"), sizeof(prev_ip))).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_ipaddr"), StrEq("0.0.0.0"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_subnet"), StrEq("0.0.0.0"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_state"), StrEq("down"), 0)).Times(1);
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq("eth0")))
        .WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq("/tmp/udhcpc.erouter0.pid"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq("/tmp/udhcp.log"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("firewall-restart"), nullptr, 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-status"), StrEq("stopped"), 0)).Times(1);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr flush dev eth0"), _)).WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("SYS_SH_RDKB_FIREWALL_RESTART"), 1)).WillOnce(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("killall -q dns_sync.sh"), _)).WillOnce(Return(0));
    int result = wan_addr_unset(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestWanAddrUnsetStatic)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.prot = WAN_PROT_STATIC;
    const char* ifname = "eth0";
    char prev_ip[100] = "192.168.1.10";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-status"), StrEq("stopping"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-errinfo"), nullptr, 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("current_wan_ipaddr"), _, sizeof(prev_ip)))
        .WillOnce(DoAll(SetArrayArgument<3>(prev_ip, prev_ip + strlen(prev_ip) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("previous_wan_ipaddr"), StrEq("192.168.1.10"), sizeof(prev_ip))).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_ipaddr"), StrEq("0.0.0.0"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_subnet"), StrEq("0.0.0.0"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_state"), StrEq("down"), 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4_wan_ipaddr"), StrEq("0.0.0.0"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv4_wan_subnet"), StrEq("0.0.0.0"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("default_router"), nullptr, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("current_ipv4_link_state"), StrEq("down"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 11), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr flush dev eth0"), _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("killall -q dns_sync.sh"), _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip rule del from 192.168.1.1 lookup erouter"), _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 route del table erouter default dev eth0"), _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("SYS_SH_RDKB_FIREWALL_RESTART"), 1)).WillOnce(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("firewall-restart"), nullptr, 0)).Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-status"), StrEq("stopped"), 0)).Times(1);
    int result = wan_addr_unset(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestFileReadFailure)
{
    char options[VENDOR_OPTIONS_LENGTH];
    char ethWanMode[8] = {0};
    int result = dhcp_parse_vendor_info(options, VENDOR_OPTIONS_LENGTH, ethWanMode);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, TestDhcpStartMapt)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char map_mode[16] = "MAPT";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    int result = dhcp_start(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestDhcpStartSuccess)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char map_mode[16] = "NOT_MAPT";
    char l_cErouter_Mode[16] = "eRouter";
    char l_cWan_if_name[16] = "erouter0";
    char cEthWanMode[8] = "1";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("last_erouter_mode"), _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("wan_physical_ifname"), _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("eth_wan_enabled"), _, _))
        .WillOnce(Return(0));
    int result = dhcp_start(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, TestDhcpStartFailure)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char map_mode[16] = "NOT_MAPT";
    sw.rtmod == WAN_RTMOD_IPV4;
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    char l_cErouter_Mode[16] = "eRouter";
    char l_cWan_if_name[16] = "erouter0";
    char cEthWanMode[8] = "1";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cErouter_Mode, l_cErouter_Mode + strlen(l_cErouter_Mode) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("wan_physical_ifname"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cWan_if_name, l_cWan_if_name + strlen(l_cWan_if_name) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("eth_wan_enabled"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(cEthWanMode, cEthWanMode + strlen(cEthWanMode) + 1), Return(0)));
    int result = dhcp_start(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_started)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    EXPECT_CALL(*g_utopiaMock, print_uptime(StrEq("Wan_init_start"), nullptr, nullptr))
        .Times(1);
    struct sysinfo si;
    si.uptime = 12345;
    char status[16] = "started";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("wan_service-status"), _, sizeof(status)))
        .WillOnce(DoAll(SetArrayArgument<3>(status, status + strlen(status)), Return(0)));
    int result = wan_start(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_stopping)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    EXPECT_CALL(*g_utopiaMock, print_uptime(StrEq("Wan_init_start"), nullptr, nullptr))
        .Times(1);
    struct sysinfo si;
    si.uptime = 12345;
    char status[] = "stopping";
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("wan_service-status"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(status, status + strlen(status)+1), Return(0)));
    int result = wan_start(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, Test_wan_stop_StatusStoppingOrStopped)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    char status[16] = "stopping";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("wan_service-status"), _, sizeof(status)))
        .WillOnce(DoAll(SetArrayArgument<3>(status, status + strlen(status)), Return(0)));
    int result = wan_stop(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_stop_StatusAlreadyStopped)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    char status[16] = "stopped";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("wan_service-status"), _, sizeof(status)))
        .WillOnce(DoAll(SetArrayArgument<3>(status, status + strlen(status)), Return(0)));
    int result = wan_stop(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_stop_StatusStarting)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    char status[16] = "starting";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("wan_service-status"), _, sizeof(status)))
        .WillOnce(DoAll(SetArrayArgument<3>(status, status + strlen(status)), Return(0)));
    int result = wan_stop(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, WanRestart)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    sw.rtmod = WAN_RTMOD_UNKNOW;
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-restarting"), StrEq("1"), 0))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan-restarting"), StrEq("0"), 0))
        .Times(1)
        .WillOnce(Return(0));
    char status1[16] = "stopped";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("wan_service-status"), _, sizeof(status1)))
        .WillOnce(DoAll(SetArrayArgument<3>(status1, status1 + strlen(status1)), Return(0)));
    int result = wan_restart(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, StaticStartFailure)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.prot = WAN_PROT_STATIC;
    const char* ifname = "eth0";
    strncpy(sw.ifname, ifname, sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char wan_domain[64] = "wan_domain";
    char name_server[3][64] = {"name_server1", "name_server2", "name_server3"};
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("dhcp_domain"), _, 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_domain"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(wan_domain, wan_domain + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver1"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[0], name_server[0] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver2"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[1], name_server[1] + 64), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("nameserver3"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(name_server[2], name_server[2] + 64), Return(0)));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_ipaddr"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.10", "192.168.1.10" + 16), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_netmask"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("255.255.255.0", "255.255.255.0" + 19), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wan_default_gateway"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>("192.168.1.1", "192.168.1.1" + 16), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq("ip -4 addr add 192.168.1.10/255.255.255.0 broadcast + dev eth0"),_))
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("wan-status"), StrEq("starting"), _))
    .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("wan-errinfo"), nullptr, _))
     .WillOnce(Return(0));

    int result = wan_addr_set(&sw);
    EXPECT_EQ(result, -1);
}

TEST_F(service_wan_test, DhcpAlreadyRunning)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq("eth0"))).WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, access(_, F_OK)).WillOnce(Return(0)); // PID file exists
    EXPECT_EQ(wan_dhcp_start(&sw), 0);
}

TEST_F(service_wan_test, StalePidFileWithNoRunningProcess) 
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    const char* DHCPC_PID_FILE = "/tmp/udhcpc.erouter0.pid";
    const char* LOG_FILE = "/tmp/udhcp.log";
    char map_mode[16] = "MAPT";
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq("eth0")))
        .Times(2)
        .WillOnce(Return(-1))
        .WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(DHCPC_PID_FILE), F_OK)).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(DHCPC_PID_FILE))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(LOG_FILE))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    EXPECT_EQ(wan_dhcp_start(&sw), 0);
}

TEST_F(service_wan_test, NoPidFileOrRunningProcess)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq("eth0"))).WillOnce(Return(-1));
    EXPECT_CALL(*g_fileIOMock, access(_, F_OK)).WillOnce(Return(-1));
    char map_mode[16] = "MAPT";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    EXPECT_EQ(wan_dhcp_start(&sw), 0);
}

TEST_F(service_wan_test, DhcpStopFailsButDhcpStartIsCalled)
{
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char map_mode[16] = "MAPT";
    const char* ifname = "eth0";
    const char* DHCPC_PID_FILE = "/tmp/udhcpc.erouter0.pid";
    const char* LOG_FILE = "/tmp/udhcp.log";
    FILE *fp = fopen(DHCPC_PID_FILE, "wb") ;
    char pid_str[10];
    int pid = -1;
    memset(pid_str, 0, sizeof(pid_str));
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("udhcpc"), StrEq(ifname)))
        .WillOnce(Return(1234));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(DHCPC_PID_FILE)))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, unlink(StrEq(LOG_FILE)))
        .Times(1)
        .WillOnce(Return(0));
    remove(DHCPC_PID_FILE);
    remove(LOG_FILE);
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    int result = wan_dhcp_restart(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_dhcp_renew_fail)
{
    struct sysinfo si;
    sysinfo(&si);
    char uptime[24];
    snprintf(uptime, sizeof(uptime), "%ld", si.uptime);
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    strncpy(sw.ifname, "eth0", sizeof(sw.ifname) - 1);
    sw.ifname[sizeof(sw.ifname) - 1] = '\0';
    char map_mode[16] = "NOT_MAPT";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sw.sefd, sw.setok, StrEq("map_transport_mode"), _, sizeof(map_mode)))
        .WillOnce(DoAll(SetArrayArgument<3>(map_mode, map_mode + strlen(map_mode)), Return(0)));
    char l_cErouter_Mode[16] = "eRouter";
    char l_cWan_if_name[16] = "erouter0";
    char cEthWanMode[8] = "1";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("last_erouter_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cErouter_Mode, l_cErouter_Mode + strlen(l_cErouter_Mode) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("wan_physical_ifname"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(l_cWan_if_name, l_cWan_if_name + strlen(l_cWan_if_name) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("eth_wan_enabled"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(cEthWanMode, cEthWanMode + strlen(cEthWanMode) + 1), Return(0)));
    char options[VENDOR_OPTIONS_LENGTH];
    int fd = open(VENDOR_SPEC_FILE, O_CREAT | O_RDWR, 0444);
    close(fd);
    int result = wan_dhcp_renew(&sw);
    EXPECT_EQ(result, 0);
}

TEST_F(service_wan_test, Test_wan_dhcp_renew)
{
    struct sysinfo si;
    sysinfo(&si);
    char uptime[24];
    snprintf(uptime, sizeof(uptime), "%ld", si.uptime);
    struct serv_wan sw;
    memset(&sw, 0, sizeof(sw));
    sw.sefd = 1;
    sw.setok = 2;
    FILE * fp = fopen("/tmp/udhcpc.erouter0.pid", "wb");
    char pid_str[10];
    int pid = -1;
    memset(pid_str, 0, sizeof(pid_str));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, NotNull()))
        .WillOnce(Return(pid_str));
    EXPECT_CALL(*g_fileIOMock, fclose(NotNull()))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("current_wan_state"), StrEq("up"), 0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sw.sefd, sw.setok, StrEq("wan_start_time"), StrEq(uptime), 0))
        .WillOnce(Return(0));
    int result = wan_dhcp_renew(&sw);
    EXPECT_EQ(result, 0);
}