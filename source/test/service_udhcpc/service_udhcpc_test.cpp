#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_messagebus.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_util.h>

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
UtilMock * g_utilMock = NULL;

    typedef struct udhcpc_script_t
    {
        char *wan_type;
        char *box_type;
        char *model_num;
        char *input_option; 
        char *dns;
        char *router;
        bool resconf_exist; // resolvconf bin
        bool ip_util_exist;
        bool broot_is_nfs;
    }udhcpc_script_t;
	
extern "C" {
    #include "print_uptime.h"
    #include "safec_lib.h"
    #include <string.h>
    #include <sys/sysinfo.h>
    #include "sysevent/sysevent.h"
    #include "syscfg/syscfg.h"
    #include "util.h"
    #include <sys/time.h>
    #include "print_uptime.h"
    #include <telemetry_busmessage_sender.h>
    #include "safec_lib_common.h"
    extern int sysevent_fd;
    extern token_t sysevent_token;
    extern bool dns_changed;
    void print_uptime(char *uptimeLog, char *bootfile, char *uptime);
    int sysevent_init (void);
    void udhcpc_sysevent_close (void);
    char *GetDeviceProperties (char *param);
    int set_dns_sysevents (udhcpc_script_t *pinfo);
    int update_dns_tofile (udhcpc_script_t *pinfo);
    int set_router_sysevents (udhcpc_script_t *pinfo);
    int read_cmd_output (char *cmd, char *output_buf, int size_buf);
    int add_route (udhcpc_script_t *pinfo);
    int handle_defconfig (udhcpc_script_t *pinfo);
    int set_wan_sysevents (void);
    int save_dhcp_offer (udhcpc_script_t *pinfo);
    int update_ipv4dns (udhcpc_script_t *pinfo);
    void compare_and_delete_old_dns (udhcpc_script_t *pinfo);
    int update_resolveconf (udhcpc_script_t *pinfo);
    int set_wan_sysevents (void);
}

class service_udhcpc_test : public ::testing::Test {
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
    UtilMock  mockedUtil;


    service_udhcpc_test() {
        g_syscfgMock = &mockedsyscfg;
        g_securewrapperMock = &mockedSecureWrapper;
        g_safecLibMock = &mockedSafecLib;
        g_utopiaMock = &mockedUtopia;
        g_telemetryMock = &mockedTelemetry;
        g_syseventMock = &mockedSysevent;
        g_psmMock = &mockedPsm;
        g_messagebusMock = &mockedMessageBus;
        g_anscMemoryMock = &mockedAnscMemory;
        g_utilMock = &mockedUtil;
	    g_fileIOMock = &mockedFileIO;
    }
    virtual ~service_udhcpc_test() {
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
        g_utilMock = NULL;
    }
    virtual void SetUp() override {
        printf("service_udhcpc_test::SetUp\n");
    }
    virtual void TearDown() override {
        printf("service_udhcpc_test::TearDown\n");
    }
    static void SetUpTestCase() {
        printf("%s %s\n", __func__,
               ::testing::UnitTest::GetInstance()->current_test_case()->name());
    }
    static void TearDownTestCase() {
        printf("%s %s\n", __func__,
               ::testing::UnitTest::GetInstance()->current_test_case()->name());
    }
};

TEST_F(service_udhcpc_test, SyseventInit_Success) {
    EXPECT_CALL(mockedSysevent, sysevent_open(StrEq("127.0.0.1"),
                                              SE_SERVER_WELL_KNOWN_PORT,
                                              SE_VERSION,
                                              StrEq("udhcpc"),
                                              NotNull()))
        .WillOnce(Return(10)); 

    int result = sysevent_init();

    EXPECT_EQ(result, 0);
    EXPECT_EQ(sysevent_fd, 10); 
}

TEST_F(service_udhcpc_test, SyseventInit_Failure) {
    EXPECT_CALL(mockedSysevent, sysevent_open(StrEq("127.0.0.1"),
                                              SE_SERVER_WELL_KNOWN_PORT,
                                              SE_VERSION,
                                              StrEq("udhcpc"),
                                              NotNull()))
        .WillOnce(Return(-1));

    int result = sysevent_init();

    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, UdhcpcSyseventClose_ValidFd) {
    sysevent_fd = 10;
    sysevent_token = 1234;

    EXPECT_CALL(mockedSysevent, sysevent_close(10, sysevent_token))
        .Times(1);

    udhcpc_sysevent_close();

    EXPECT_EQ(sysevent_fd, 10);
}

TEST_F(service_udhcpc_test, UdhcpcSyseventClose_InvalidFd) {
    sysevent_fd = -1;

    EXPECT_CALL(mockedSysevent, sysevent_close(_, _))
        .Times(0);

    udhcpc_sysevent_close();

}

TEST_F(service_udhcpc_test, SetDnsSysevents_ValidInput) {
    udhcpc_script_t mockInfo;
    mockInfo.dns = const_cast<char*>("8.8.8.8 8.8.4.4");  

    char mockInterface[] = "eth0";
    EXPECT_CALL(mockedUtil, getenv(StrEq("interface")))
        .Times(1)
        .WillOnce(Return(mockInterface));  

    EXPECT_CALL(mockedSysevent, sysevent_set(_, _, StrEq("ipv4_eth0_dns_0"), StrEq("8.8.8.8"), 0))
        .Times(1);
    EXPECT_CALL(mockedSysevent, sysevent_set(_, _, StrEq("ipv4_eth0_dns_1"), StrEq("8.8.4.4"), 0))
        .Times(1);
    EXPECT_CALL(mockedSysevent, sysevent_set(_, _, StrEq("ipv4_eth0_dns_number"), StrEq("2"), 0))
        .Times(1);

    int result = set_dns_sysevents(&mockInfo);

    EXPECT_EQ(result, 0);
}


TEST_F(service_udhcpc_test, SetDnsSysevents_NullInput) {
    EXPECT_EQ(set_dns_sysevents(nullptr), -1); 
}

TEST_F(service_udhcpc_test, SetDnsSysevents_NoDns) {
    udhcpc_script_t mockInfo = {};
    mockInfo.dns = nullptr; 

    EXPECT_EQ(set_dns_sysevents(&mockInfo), -1);
}

TEST_F(service_udhcpc_test, SetRouterSysevents_SingleRouter) {
    udhcpc_script_t pinfo;
    char router[256] = "192.168.1.1";  
    pinfo.router = router;  

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(testing::Return(const_cast<char*>("eth0")));

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("default_router"), StrEq("192.168.1.1"), 0))
        .Times(1);  

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("ipv4_eth0_gw_0"), StrEq("192.168.1.1"), 0))
        .Times(1);  

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("ipv4_eth0_gw_number"), StrEq("1"), 0))
        .Times(1);  

    int result = set_router_sysevents(&pinfo);

    EXPECT_EQ(result, 0);
    EXPECT_STREQ(pinfo.router, "192.168.1.1");  
}

TEST_F(service_udhcpc_test, SetRouterSysevents_MultipleRouters) {
    udhcpc_script_t pinfo;
    char router[256] = "192.168.1.1 192.168.1.2";  
    pinfo.router = router;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(testing::Return(const_cast<char*>("eth0"))); 

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("default_router"), StrEq("192.168.1.1"), 0))
        .Times(1);
    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("ipv4_eth0_gw_0"), StrEq("192.168.1.1"), 0))
        .Times(1);

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("default_router"), StrEq("192.168.1.2"), 0))
        .Times(1);
    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("ipv4_eth0_gw_1"), StrEq("192.168.1.2"), 0))
        .Times(1);

    EXPECT_CALL(mockedSysevent, sysevent_set(sysevent_fd, sysevent_token, StrEq("ipv4_eth0_gw_number"), StrEq("2"), 0))
        .Times(1);

    int result = set_router_sysevents(&pinfo);

    EXPECT_EQ(result, 0);
    EXPECT_STREQ(pinfo.router, "192.168.1.1 192.168.1.2");  
}

TEST_F(service_udhcpc_test, ValidSingleRouterWithIpUtil) {
    udhcpc_script_t pinfo;
    pinfo.router = const_cast<char*>("192.168.1.1");
    pinfo.ip_util_exist = true;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    char expectedCmd[256] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "ip route add default via %s metric %d", "192.168.1.1", 0);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    int result = add_route(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, ValidMultipleRoutersWithIpUtil) {
    udhcpc_script_t pinfo;
    pinfo.router = const_cast<char*>("192.168.1.1 192.168.1.2");
    pinfo.ip_util_exist = true;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    char expectedCmd1[256] = {0};
    snprintf(expectedCmd1, sizeof(expectedCmd1), "ip route add default via %s metric %d", "192.168.1.1", 0);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd1), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    char expectedCmd2[256] = {0};
    snprintf(expectedCmd2, sizeof(expectedCmd2), "ip route add default via %s metric %d", "192.168.1.2", 1);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd2), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    int result = add_route(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, ValidSingleRouterWithoutIpUtil) {
    udhcpc_script_t pinfo;
    pinfo.router = const_cast<char*>("192.168.1.1");
    pinfo.ip_util_exist = false;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    char expectedCmd[256] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "route add default gw %s dev %s metric %d 2>/dev/null", "192.168.1.1", "eth0", 0);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    int result = add_route(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, ValidMultipleRoutersWithNoIpUtil) {
    udhcpc_script_t pinfo;
    pinfo.router = const_cast<char*>("192.168.1.1 192.168.1.2");
    pinfo.ip_util_exist = false;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    char expectedCmd1[256] = {0};
    snprintf(expectedCmd1, sizeof(expectedCmd1), "route add default gw %s dev %s metric %d 2>/dev/null", "192.168.1.1", "eth0", 0);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd1), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    char expectedCmd2[256] = {0};
    snprintf(expectedCmd2, sizeof(expectedCmd2), "route add default gw %s dev %s metric %d 2>/dev/null", "192.168.1.2", "eth0", 1);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd2), _))
        .Times(1)
        .WillOnce(::testing::Return(0));

    int result = add_route(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, NullPinfoHandle) {
    int result = handle_defconfig(nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, NullInterface) {
    udhcpc_script_t pinfo;
    pinfo.resconf_exist = true;
    pinfo.broot_is_nfs = false;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(nullptr)); 

    int result = handle_defconfig(&pinfo);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, ResconfOnly) {
    udhcpc_script_t pinfo;
    pinfo.resconf_exist = true;
    pinfo.broot_is_nfs = true; 

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::StrEq("/sbin/resolvconf -d eth0.udhcpc"), nullptr))
        .Times(1);

    int result = handle_defconfig(&pinfo);
    EXPECT_EQ(result, 0);
}


TEST_F(service_udhcpc_test, IpUtilExistWithBrootFalse) {
    udhcpc_script_t pinfo;
    pinfo.resconf_exist = false;
    pinfo.broot_is_nfs = false;
    pinfo.ip_util_exist = true;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::StrEq("ip -4 addr flush dev eth0"), nullptr))
        .Times(1);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::StrEq("ip link set dev eth0 up"), nullptr))
        .Times(1);

    int result = handle_defconfig(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, NoIpUtilWithBrootFalse) {
    udhcpc_script_t pinfo;
    pinfo.resconf_exist = false;
    pinfo.broot_is_nfs = false;
    pinfo.ip_util_exist = false;

    EXPECT_CALL(mockedUtil, getenv("interface"))
        .WillOnce(::testing::Return(const_cast<char*>("eth0")));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::StrEq("/sbin/ifconfig eth0 0.0.0.0"), nullptr))
        .Times(1);

    int result = handle_defconfig(&pinfo);
    EXPECT_EQ(result, 0);
}

TEST_F(service_udhcpc_test, UpdateDnsToFileNullPinfo) {
    int result = update_dns_tofile(nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, UpdateDnsToFileNullDns) {
    udhcpc_script_t pinfo = {};
    pinfo.dns = nullptr;

    int result = update_dns_tofile(&pinfo);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, NullPinfoSaveDhcp) {
    int result = save_dhcp_offer(nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, NullCommand) {
    char buffer[128] = {0};
    int result = read_cmd_output(nullptr, buffer, sizeof(buffer));
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, NullPinfoUpdate_ipv4dns) {

    int result = update_ipv4dns(nullptr);
    EXPECT_EQ(result, -1);
}


TEST_F(service_udhcpc_test, MissingDnsEnvironmentVariableViaGetenv) {
    udhcpc_script_t pinfo = {};

    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("dns"))).WillOnce(::testing::Return(nullptr));

    int result = update_ipv4dns(&pinfo);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, NullParam_GetDeviceProperties) {
    char* result = GetDeviceProperties(nullptr);  
    EXPECT_EQ(result, nullptr);  
}


TEST_F(service_udhcpc_test, NullPinfoUpdate_resolvconf) {

    int result = update_resolveconf(nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(service_udhcpc_test, TestHandleWanValidPinfo) {
    udhcpc_script_t* pinfo;

    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("serverid"))).WillOnce(::testing::Return(const_cast<char*>("12345")));
    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("lease"))).WillOnce(::testing::Return(nullptr));  
    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("opt58"))).WillOnce(::testing::Return(nullptr));  
    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("opt59"))).WillOnce(::testing::Return(nullptr));  
    EXPECT_CALL(mockedUtil, getenv(::testing::StrEq("subnet"))).WillOnce(::testing::Return(const_cast<char*>("255.255.255.0")));

    EXPECT_CALL(mockedSysevent, sysevent_set(_, _, StrEq("wan_dhcp_svr"), StrEq("12345"), 0))
        .Times(1);
    EXPECT_CALL(mockedSysevent, sysevent_set(_, _, StrEq("wan_mask"), StrEq("255.255.255.0"), 0))
        .Times(1);

    int result = set_wan_sysevents();

    EXPECT_EQ(result, 0); 
}




