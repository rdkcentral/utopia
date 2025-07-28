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
#include <mocks/mock_libnet.h>

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
LibnetMock * g_libnetMock = nullptr;

struct serv_routed {
    int         sefd;
    int         setok;
    bool        lan_ready;
    bool        wan_ready;
};
extern "C" {
#include "util.h"
int fw_restart(struct serv_routed *sr);
int daemon_stop(const char *pid_file, const char *prog);
int is_daemon_running(const char *pid_file, const char *prog);
int radv_stop(struct serv_routed *sr);
int rip_stop(struct serv_routed *sr);
int serv_routed_term(struct serv_routed *sr);
int get_active_lanif(int sefd, token_t setok, unsigned int *insts, unsigned int *num);
void checkIfModeIsSwitched(int sefd, token_t setok);
int checkIfULAEnabled(int sefd, token_t setok);
int rip_restart(struct serv_routed *sr);
int serv_routed_init(struct serv_routed *sr);
void AssignIpv6Addr(char* ifname , char* ipv6Addr,int prefix_len);
int routeset_ula(struct serv_routed *sr);
int routeunset_ula(struct serv_routed *sr);
void SetV6Route(char* ifname , char* route_addr);
void UnSetV6Route(char* ifname , char* route_addr);
void DelIpv6Addr(char* ifname , char* ipv6Addr,int prefix_len);
int gen_ripd_conf(int sefd, token_t setok);
void usage(void);
int route_set(struct serv_routed *sr);
int route_unset(struct serv_routed *sr);
int rip_start(struct serv_routed *sr);
int serv_routed_start(struct serv_routed *sr);
int serv_routed_stop(struct serv_routed *sr);
int serv_routed_restart(struct serv_routed *sr);
int gen_zebra_conf(int sefd, token_t setok);
int radv_start(struct serv_routed *sr);
enum ipv6_mode {
    NO_SWITCHING = 0,
    GLOBAL_IPV6 = 1,
    ULA_IPV6 = 2,
};
}
extern int gModeSwitched;
extern char last_broadcasted_prefix[64] ;
extern FILE* logfptr;
class service_routed_test : public ::testing::Test {
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
    LibnetMock mockedLibnet;
    service_routed_test() {
        g_syscfgMock = &mockedsyscfg;
        g_securewrapperMock = &mockedSecureWrapper;
        g_safecLibMock = &mockedSafecLib;
        g_utopiaMock = &mockedUtopia;
        g_telemetryMock = &mockedTelemetry;
        g_syseventMock = &mockedSysevent;
        g_psmMock = &mockedPsm;
        g_messagebusMock = &mockedMessageBus;
        g_anscMemoryMock = &mockedAnscMemory;
        g_libnetMock = &mockedLibnet;
    }
    virtual ~service_routed_test() {
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
    }
    virtual void SetUp() override {
        printf("service_routed_test::SetUp\n");  
    }
    virtual void TearDown() override {
        printf("service_routed_test::TearDown\n");
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
//Test cases for fw_restart
TEST_F(service_routed_test, TestFwRestart) {
    struct serv_routed sr;
    sr.sefd = 1;  
    sr.setok = 1; 
    const char* parconStatus = "stopped";
    const char* wanIfName = "eth0";
    const char* macAddr = "00:11:22:33:44:55";
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, testing::StrEq("parcon_nfq_status"), testing::_, testing::_))
        .WillOnce(DoAll(testing::SetArrayArgument<3>(parconStatus, parconStatus + strlen(parconStatus) + 1), // Set output buffer with "stopped".
                        testing::Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, testing::StrEq("wan_physical_ifname"), testing::_, testing::_))
        .WillOnce(DoAll(testing::SetArrayArgument<2>(wanIfName, wanIfName + strlen(wanIfName) + 1), // Set output buffer with "eth0".
                        testing::Return(0)));
    EXPECT_CALL(*g_utopiaMock, iface_get_hwaddr(testing::StrEq(wanIfName), testing::_, testing::_))
        .WillOnce(DoAll(testing::SetArrayArgument<1>(macAddr, macAddr + strlen(macAddr) + 1), // Set output buffer with MAC address.
                        testing::Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sr.sefd, sr.setok, testing::StrEq("parcon_nfq_status"), testing::StrEq("started"), 0))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(sr.sefd, sr.setok, testing::StrEq("firewall-restart"), nullptr, 0))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(testing::StrEq("SYS_SH_RDKB_FIREWALL_RESTART"), 1))
        .WillOnce(testing::Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).Times(AtLeast(1)).WillOnce(Return(0));
    int result = fw_restart(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for daemon_stop
TEST_F(service_routed_test, StopsDaemonUsingValidPidFile) {
    const char* test_pid_file = "/tmp/test_pid_file";
    FILE* fp = fopen(test_pid_file, "w");
    fprintf(fp, "1234\n");  
    fclose(fp);
    int result = daemon_stop(test_pid_file, nullptr);
    EXPECT_EQ(result, 0);
    EXPECT_FALSE(access(test_pid_file, F_OK) == 0); 
}
TEST_F(service_routed_test, ReturnsErrorWhenNoArgumentsProvided) {
    int result = daemon_stop(nullptr, nullptr);
    EXPECT_EQ(result, -1);
}
TEST_F(service_routed_test, StopsDaemonUsingProg) {
    const char* test_prog = "test_program";
    EXPECT_CALL(*g_utopiaMock, pid_of(test_prog, nullptr))
        .WillOnce(testing::Return(5678));
    int result = daemon_stop(nullptr, test_prog);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, PidOfFailsToFindProcess) {
    const char* test_prog = "test_program";
    EXPECT_CALL(*g_utopiaMock, pid_of(test_prog, nullptr))
        .WillOnce(testing::Return(-1));
    int result = daemon_stop(nullptr, test_prog);
    EXPECT_EQ(result, 0); 
}
//Test cases for is_daemon_running
TEST_F(service_routed_test, ReturnsPidFromFileRunning) {
    const char* test_pid_file = "/tmp/test_pid_file";
    FILE* fp = fopen(test_pid_file, "w");
    fprintf(fp, "1234\n");  
    fclose(fp);
    int result = is_daemon_running(test_pid_file, nullptr);
    EXPECT_EQ(result, 1234);
}
TEST_F(service_routed_test, ReturnsPidFromProgRunning) {
    const char* test_prog = "test_program";
    EXPECT_CALL(*g_utopiaMock, pid_of(test_prog, nullptr))
        .WillOnce(testing::Return(5678));
    int result = is_daemon_running(nullptr, test_prog);
    EXPECT_EQ(result, 5678);
}
TEST_F(service_routed_test, ReturnsErrorWhenNoArgumentsProvidedRunning) {
    int result = is_daemon_running(nullptr, nullptr);
    EXPECT_EQ(result, -1);
}
TEST_F(service_routed_test, PidOfFailsToFindProcessRunning) {
    const char* test_prog = "test_program";
    EXPECT_CALL(*g_utopiaMock, pid_of(test_prog, nullptr))
        .WillOnce(testing::Return(-1));
    int result = is_daemon_running(nullptr, test_prog);
    EXPECT_EQ(result, 0);
}
//Test cases for radv_stop
TEST_F(service_routed_test, ReturnsZeroWhenZebraRunning) {
    EXPECT_CALL(*g_utopiaMock, pid_of(testing::StrEq("zebra"), nullptr))
        .WillOnce(testing::Return(1234));
    struct serv_routed sr;
    int result = radv_stop(&sr);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, ReturnsDaemonStopResultWhenZebraNotRunning) {
    EXPECT_CALL(*g_utopiaMock, pid_of(testing::StrEq("zebra"), nullptr))
        .Times(2)
        .WillOnce(testing::Return(-1)) 
        .WillOnce(testing::Return(-1)); 
    const char* test_prog = "zebra";
    struct serv_routed sr;
    int result = radv_stop(&sr);
    EXPECT_EQ(result, 0); 
}
//Test cases for rip_stop
TEST_F(service_routed_test, ReturnsErrorWhenServCanStopFails) {
    int result;
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(0));
    result = rip_stop(&sr);
    EXPECT_EQ(result, -1);
}
TEST_F(service_routed_test, WhenServCanStopSucceeds) {
    int result;
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, testing::StrEq("rip-status"), testing::StrEq("stopping"), 0))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, testing::StrEq("rip-status"), testing::StrEq("stopped"), 0))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_utopiaMock, pid_of(StrEq("ripd"), _)).WillOnce(Return(0));
    result = rip_stop(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for rip_start
TEST_F(service_routed_test, ReturnsErrorWhenServCanStartFails) {
    EXPECT_CALL(*g_utopiaMock, serv_can_start(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(0));
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    int result = rip_start(&sr);
    EXPECT_EQ(result, -1);
}
TEST_F(service_routed_test, ReturnsZeroWhenRipNotEnabled) {
    logfptr = fopen("test_logfptr.txt", "w");
    EXPECT_CALL(*g_utopiaMock, serv_can_start(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, testing::StrEq("rip_enabled"), testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArrayArgument<2>("0", "0" + strlen("0") + 1), testing::Return(0)));
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    sr.lan_ready = true;
    sr.wan_ready = true;
    int result = rip_start(&sr);
    EXPECT_EQ(result, 0);
    remove("test_logfptr.txt");
}
TEST_F(service_routed_test, ReturnsErrorWhenLanNotReady) {
    FILE* logfptr = fopen("test_logfptr.txt", "w");
    EXPECT_NE(logfptr, nullptr) << "Failed to open log file";
    EXPECT_CALL(*g_utopiaMock, serv_can_start(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(1));
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    sr.lan_ready = false;
    sr.wan_ready = true;
    int result = rip_start(&sr);
    EXPECT_EQ(result, -1);
    fclose(logfptr);
    remove("test_logfptr.txt"); 
}
TEST_F(service_routed_test, ReturnsZeroWhenAllConditionsMet) {
    logfptr = fopen("test_logfptr.txt", "w");
    EXPECT_CALL(*g_utopiaMock, serv_can_start(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, testing::StrEq("rip_enabled"), testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArrayArgument<2>("1", "1" + strlen("1") + 1), testing::Return(0)));
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    sr.lan_ready = true;
    sr.wan_ready = true;
    EXPECT_CALL(*g_syseventMock, sysevent_set(1, 1, testing::StrEq("rip-status"), testing::StrEq("starting"), 0))
        .WillOnce(testing::Return(0));
    int result = rip_start(&sr);
    EXPECT_EQ(result, 0);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
//Test cases for rip_restart
TEST_F(service_routed_test, ReturnsErrorWhenRipStopFails) {
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(_, _, testing::StrEq("rip")))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_utopiaMock, serv_can_start(_, _, StrEq("rip")))
    .WillOnce(Return(0));
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    int result = rip_restart(&sr);
    EXPECT_EQ(result, -1);
}
//Test cases for serv_routed_init
TEST_F(service_routed_test, ReturnsErrorWhenSyseventOpenFails) {
    logfptr = fopen("test_logfptr.txt", "w");
    struct serv_routed* sr = (struct serv_routed*)malloc(sizeof(struct serv_routed));
    ASSERT_NE(sr, nullptr); 
    memset(sr, 0, sizeof(struct serv_routed));
    EXPECT_CALL(*g_syseventMock, sysevent_open(testing::StrEq("127.0.0.1"), 52367, 1, testing::StrEq("SERVICE-ROUTED"), testing::_))
        .WillOnce(testing::Return(-1));
    int result = serv_routed_init(sr);
    EXPECT_EQ(result, -1);
    free(sr);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
TEST_F(service_routed_test, ReturnsSuccessWhenSyseventOpenSucceeds) {
    struct serv_routed* sr = (struct serv_routed*)malloc(sizeof(struct serv_routed));
    ASSERT_NE(sr, nullptr); 
    memset(sr, 0, sizeof(struct serv_routed));
    EXPECT_CALL(*g_syseventMock, sysevent_open(testing::StrEq("127.0.0.1"), 52367, 1, testing::StrEq("SERVICE-ROUTED"), testing::_))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*g_syseventMock, sysevent_get(testing::_, testing::_, testing::StrEq("wan-status"), testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArrayArgument<3>("started", "started" + strlen("started") + 1), testing::Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(testing::_, testing::_, testing::StrEq("lan-status"), testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArrayArgument<3>("started", "started" + strlen("started") + 1), testing::Return(0)));
    int result = serv_routed_init(sr);
    EXPECT_EQ(result, 0);
    free(sr);
}
//Test cases for routeset_ula
TEST_F(service_routed_test, SuccessfulSetIPv6RouteS) {
    const char* mockPrefix = "2001:db8::/64";
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "true";
    const char* mockIPv6Interfaces = "eth0,eth1";
    const char* cmd = "eth0_ipaddr_v6_ula";
    const char* cmd1 = "eth1_ipaddr_v6_ula";
    struct serv_routed sr;
    sr.sefd = 1; 
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "ipv6_prefix_ula", _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, 32))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok,"backup_wan_prefix_v6_len", _, 16))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6_Interface", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6Interfaces, mockIPv6Interfaces + strlen(mockIPv6Interfaces) + 1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, StrEq("eth0_ipaddr_v6_ula")))
        .WillOnce(DoAll(SetArrayArgument<0>(cmd, cmd + strlen(cmd) + 1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, StrEq("eth1_ipaddr_v6_ula")))
        .WillOnce(DoAll(SetArrayArgument<0>(cmd1, cmd1 + strlen(cmd1) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("eth0_ipaddr_v6_ula"), _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("eth1_ipaddr_v6_ula"), _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_libnetMock,route_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    EXPECT_CALL(*g_libnetMock,addr_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    int result = routeset_ula(&sr);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, IPv6RouteNotSetDueToEmptyPrefixS) {
    const char* mockPrefix = ""; 
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "true";
    const char* mockIPv6Interfaces = "";
    struct serv_routed sr;
    sr.sefd = 1;  
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("ipv6_prefix_ula"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("backup_wan_prefix_v6_len"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6_Interface", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6Interfaces, mockIPv6Interfaces + strlen(mockIPv6Interfaces) + 1), Return(0)));
    int result = routeset_ula(&sr);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, IPv6subPrefixIsFalseS) {
    const char* mockPrefix = "2001:db8::/64";
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "false";
    const char* mockIPv6Interfaces = "";
    struct serv_routed sr;
    sr.sefd = 1;  
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "ipv6_prefix_ula", _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, 32))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "backup_wan_prefix_v6_len", _, 16))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_libnetMock,route_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    EXPECT_CALL(*g_libnetMock,addr_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    int result = routeset_ula(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for serv_routed_term
TEST_F(service_routed_test, ReturnsZeroWhenSyseventCloseFails) {
    struct serv_routed sr;
    sr.sefd = 1;  
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_close(sr.sefd, sr.setok))
        .WillOnce(testing::Return(-1));
    int result = serv_routed_term(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for routeunset_ula
TEST_F(service_routed_test, SuccessfulUnsetIPv6Route) {
    const char* mockPrefix = "2001:db8::/64";
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "true";
    const char* mockIPv6Interfaces = "eth0,eth1";
    const char* cmd = "eth0_ipaddr_v6_ula";
    const char* cmd1 = "eth1_ipaddr_v6_ula";
    struct serv_routed sr;
    sr.sefd = 1; 
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "ipv6_prefix_ula", _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, 32))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "backup_wan_prefix_v6_len", _, 16))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6_Interface", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6Interfaces, mockIPv6Interfaces + strlen(mockIPv6Interfaces) + 1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _,StrEq("eth0_ipaddr_v6_ula")))
        .WillOnce(DoAll(SetArrayArgument<0>(cmd, cmd + strlen(cmd) + 1), Return(0)));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _,StrEq("eth1_ipaddr_v6_ula")))
        .WillOnce(DoAll(SetArrayArgument<0>(cmd1, cmd1 + strlen(cmd1) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("eth0_ipaddr_v6_ula"), _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("eth1_ipaddr_v6_ula"), _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_libnetMock,route_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillOnce(Return(CNL_STATUS_SUCCESS));  
    EXPECT_CALL(*g_libnetMock,addr_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillOnce(Return(CNL_STATUS_SUCCESS)); 
    int result = routeunset_ula(&sr);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, IPv6RouteNotSetDueToEmptyPrefix) {
    const char* mockPrefix = ""; 
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "true";
    const char* mockIPv6Interfaces = "";
    struct serv_routed sr;
    sr.sefd = 1; 
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("ipv6_prefix_ula"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, StrEq("backup_wan_prefix_v6_len"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6_Interface", _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6Interfaces, mockIPv6Interfaces + strlen(mockIPv6Interfaces) + 1), Return(0)));
    int result = routeunset_ula(&sr);
    EXPECT_EQ(result, 0);
}
TEST_F(service_routed_test, IPv6subPrefixIsFalse) {
    const char* mockPrefix = "2001:db8::/64";
    const char* mockLanIf = "eth0";
    const char* mockPrefixLen = "64";
    const char* mockIPv6subPrefix = "false";
    const char* mockIPv6Interfaces = "";
    struct serv_routed sr;
    sr.sefd = 1; 
    sr.setok = 1; 
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "ipv6_prefix_ula", _, 128))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefix, mockPrefix + strlen(mockPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "lan_ifname", _, 32))
        .WillOnce(DoAll(SetArrayArgument<2>(mockLanIf, mockLanIf + strlen(mockLanIf) + 1), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, "backup_wan_prefix_v6_len", _, 16))
        .WillOnce(DoAll(SetArrayArgument<3>(mockPrefixLen, mockPrefixLen + strlen(mockPrefixLen) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, "IPv6subPrefix", _, 100))
        .WillOnce(DoAll(SetArrayArgument<2>(mockIPv6subPrefix, mockIPv6subPrefix + strlen(mockIPv6subPrefix) + 1), Return(0)));
    EXPECT_CALL(*g_libnetMock,route_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));  
    EXPECT_CALL(*g_libnetMock,addr_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));  
    int result = routeunset_ula(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for SetV6Route
TEST_F(service_routed_test, ReturnsWhenVSecureSystemFailsSetV6Route) {
    const char* ifname = "brlan0";
    const char* route_addr = "2001:db8::1";
    EXPECT_CALL(*g_libnetMock,route_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    SetV6Route(const_cast<char*>(ifname), const_cast<char*>(route_addr));
}
//Test cases for UnSetV6Route
TEST_F(service_routed_test, ReturnsWhenVSecureSystemFailsUnSetV6Route) {
    const char* ifname = "brlan0";
    const char* route_addr = "2001:db8::1";
    EXPECT_CALL(*g_libnetMock,route_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    UnSetV6Route(const_cast<char*>(ifname), const_cast<char*>(route_addr));
}
//Test cases for AssignIpv6Addr
TEST_F(service_routed_test, ReturnsWhenVSecureSystemFailsAssignIpv6Addr) {
    const char* ifname = "brlan0";
    const char* ipv6Addr = "2001:db8::1";
    int prefix_len = 64;
    EXPECT_CALL(*g_libnetMock,addr_add(testing::_))
      .Times(testing::AtLeast(1))
      .WillOnce(Return(CNL_STATUS_FAILURE))
      .WillOnce(Return(CNL_STATUS_SUCCESS));
    AssignIpv6Addr(const_cast<char*>(ifname), const_cast<char*>(ipv6Addr), prefix_len);
}
//Test cases for DelIpv6Addr
TEST_F(service_routed_test, ReturnsWhenVSecureSystemFailsDelIpv6Addr) {
    const char* ifname = "brlan0";
    const char* ipv6Addr = "2001:db8::1";
    int prefix_len = 64;
    EXPECT_CALL(*g_libnetMock,addr_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE))
        .WillOnce(Return(CNL_STATUS_SUCCESS));
    DelIpv6Addr(const_cast<char*>(ifname), const_cast<char*>(ipv6Addr), prefix_len);
}
//Test cases for gen_ripd_conf
TEST_F(service_routed_test, ReturnsZeroWhenGenRipdConf) {
    int result = gen_ripd_conf(1, 1);
    EXPECT_EQ(result, 0);
}
//Test cases for void usage
TEST_F(service_routed_test, ExecutesWithoutError) {
    FILE* temp_stderr = freopen("test_stderr.txt", "w", stderr);
    EXPECT_NE(temp_stderr, nullptr) << "Failed to redirect stderr";
    logfptr = fopen("test_logfptr.txt", "w");
    EXPECT_NE(logfptr, nullptr) << "Failed to open log file";
    usage();
    fclose(stderr);
    fclose(logfptr);
    remove("test_stderr.txt");
    remove("test_logfptr.txt");
}
//Test cases for serv_routed_start
TEST_F(service_routed_test, CheckState) {
    struct serv_routed sr;
    EXPECT_CALL(*g_utopiaMock, serv_can_start(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(0));
    EXPECT_EQ(serv_routed_start(&sr), -1);
}
TEST_F(service_routed_test, LanNotReady) {
    EXPECT_CALL(*g_utopiaMock, serv_can_start(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(1));
    logfptr = fopen("test_logfptr.txt", "w");
    struct serv_routed sr;
    sr.sefd = 1;       
    sr.setok = 1;      
    sr.lan_ready = 0;  
    sr.wan_ready = 1;  
    EXPECT_EQ(serv_routed_start(&sr), -1);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
TEST_F(service_routed_test, Ipv4WanNotReady) {
    logfptr = fopen("test_logfptr.txt", "w");
    struct serv_routed sr;
    sr.sefd = 1;      
    sr.setok = 1;     
    sr.lan_ready = 1; 
    sr.wan_ready = 1;
    EXPECT_CALL(*g_utopiaMock, serv_can_start(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(-1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>("1", "1" + sizeof("1")), 
            testing::Return(0)
        ));
    sr.wan_ready = 0;
    EXPECT_EQ(serv_routed_start(&sr), -1);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
TEST_F(service_routed_test, Ipv6PrefixNotSet) {
    logfptr = fopen("test_logfptr.txt", "w");
    struct serv_routed sr;
    sr.sefd = 1;       
    sr.setok = 1;      
    sr.lan_ready = 1;  
    sr.wan_ready = 1;
    EXPECT_CALL(*g_utopiaMock, serv_can_start(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(-1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>("2", "2" + sizeof("2")), 
            testing::Return(0)
        ));   
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd, sr.setok, testing::StrEq("lan_prefix"), testing::_, testing::_))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>("", "" + 1), 
            testing::Return(0)
        ));
    EXPECT_EQ(serv_routed_start(&sr), -1);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
//Test cases for serv_routed_stop
TEST_F(service_routed_test, ServCanStopFail) {
    struct serv_routed sr;
    sr.sefd = 1;       
    sr.setok = 1;      
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(0));
    EXPECT_EQ(serv_routed_stop(&sr), -1);
}
//Test cases for serv_routed_restart
TEST_F(service_routed_test, ServRoutedStopFail) { 
    logfptr = fopen("test_logfptr.txt", "w");
    struct serv_routed sr;
    memset(&sr, 0, sizeof(sr));  
    sr.sefd = 1;       
    sr.setok = 1;      
    sr.lan_ready = 1;  
    sr.wan_ready = 1;
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(0));
    EXPECT_CALL(*g_utopiaMock, serv_can_start(testing::_, testing::_, testing::StrEq("routed")))
        .WillOnce(testing::Return(0));
    EXPECT_EQ(serv_routed_restart(&sr), -1);
    fclose(logfptr);
    remove("test_logfptr.txt");
}
//Test cases for checkIfULAEnabled
TEST_F(service_routed_test, ReturnsErrorWhenSyseventGetFailsUlaIpv6Enabled) {
    struct serv_routed sr; 
    sr.sefd = 1;       
    sr.setok = 1;      
    sr.lan_ready = 1;  
    sr.wan_ready = 1;
    EXPECT_CALL(*g_syseventMock, sysevent_get(sr.sefd , sr.setok, testing::StrEq("ula_ipv6_enabled"), testing::_, testing::_))
        .WillOnce(testing::Return(1));
    int result = checkIfULAEnabled(sr.sefd, sr.setok);
    EXPECT_EQ(result, -1);
}
//Test Cases for checkIfModeIsSwitched
TEST_F(service_routed_test, ModeIsNotSwitchedWhenDisabled) {
    char buf[16] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("disable_old_prefix_ra"), NotNull(), 16))
        .WillOnce(DoAll(SetArrayArgument<3>("false", "false" + 5), Return(0)));
    checkIfModeIsSwitched(1, 1);
    EXPECT_EQ(gModeSwitched, NO_SWITCHING);
}
TEST_F(service_routed_test, ModeSwitchedToGlobalIPv6) {
    char buf[16] = {0};
    char ipv6_pref_mode[16] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("disable_old_prefix_ra"), NotNull(), 16))
        .WillOnce(DoAll(SetArrayArgument<3>("true", "true" + 4), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("mode_switched"), NotNull(), 16))
        .WillOnce(DoAll(SetArrayArgument<3>("GLOBAL_IPV6", "GLOBAL_IPV6" + 11), Return(0)));
    checkIfModeIsSwitched(1, 1);
    EXPECT_EQ(gModeSwitched, GLOBAL_IPV6);
}
TEST_F(service_routed_test, ModeSwitchedToUlaIPv6) {
    char buf[16] = {0};
    char ipv6_pref_mode[16] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("disable_old_prefix_ra"), NotNull(), 16))
        .WillOnce(DoAll(SetArrayArgument<3>("true", "true" + 4), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("mode_switched"), NotNull(), 16))
        .WillOnce(DoAll(SetArrayArgument<3>("ULA_IPV6", "ULA_IPV6" + 8), Return(0)));
    checkIfModeIsSwitched(1, 1);
    EXPECT_EQ(gModeSwitched, ULA_IPV6);
}
//test cases for gen_zebra_conf
TEST_F(service_routed_test, FileOpenFailure) {
    EXPECT_EQ(fopen("/invalid/path/zebra.conf", "wb"), nullptr);
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
    .Times(AnyNumber())  
    .WillRepeatedly(Return(0));  
    EXPECT_CALL(*g_syscfgMock, syscfg_set_ns_commit(_, _, _))
    .Times(AnyNumber())
    .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
    .Times(AnyNumber())
    .WillRepeatedly(Return(0));
    int result = gen_zebra_conf(1, 1);
    EXPECT_EQ(result, -1) ;
}
TEST_F(service_routed_test, WriteFailure) {
    FILE* zebraConfFile = fopen("zebra.conf", "wb");
    ASSERT_NE(zebraConfFile, nullptr) ;
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
    .Times(AnyNumber())
    .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_ns_commit(_, _, _))
    .Times(AnyNumber())
    .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
    .Times(AnyNumber())
    .WillRepeatedly(Return(0));
    fclose(zebraConfFile); 
    int result = gen_zebra_conf(1, 1);
    EXPECT_EQ(result, -1) ;
}
//Test Case for get_active_lanif
TEST_F(service_routed_test, GetActiveLanIf) {
    unsigned int insts[32] = {0};
    unsigned int num = 0;
    EXPECT_CALL(*g_syseventMock, sysevent_get(1, 1, StrEq("ipv6_active_inst"), NotNull(), 32))
        .WillOnce(DoAll(SetArrayArgument<3>("1 2 3", "1 2 3" + 5), Return(0)));
    int result = get_active_lanif(1, 1, insts, &num);
    EXPECT_EQ(result, 3);
    EXPECT_EQ(num, 3);
    EXPECT_EQ(insts[0], 1);
    EXPECT_EQ(insts[1], 2);
    EXPECT_EQ(insts[2], 3);
}
//Test cases for route_set
TEST_F(service_routed_test, RouteSet) {
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    unsigned int enabled_iface_num = 3;  
    char evt_name[64] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_active_inst"), NotNull(), _))
        .WillOnce(DoAll(SetArrayArgument<3>("1 2 3", "1 2 3" + 6), Return(0)));
    for (int i = 0; i < enabled_iface_num; i++) {
        snprintf(evt_name, sizeof(evt_name), "multinet_%d-name", i + 1);
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(evt_name), NotNull(), _))
            .WillOnce(DoAll(SetArrayArgument<3>("eth0", "eth0" + 5), Return(0)));
        EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
            .WillRepeatedly(Return(0));
    }
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ifname"), NotNull(), _))
        .WillOnce(DoAll(SetArrayArgument<3>("eth0", "eth0" + 5), Return(0)));
    EXPECT_CALL(*g_libnetMock,rule_add(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillRepeatedly(Return(CNL_STATUS_FAILURE));
    EXPECT_CALL(*g_libnetMock,rule_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillRepeatedly(Return(CNL_STATUS_FAILURE));
    int result = route_set(&sr);
    EXPECT_EQ(result, 0);
}
//Test cases for route_unset
TEST_F(service_routed_test, RouteUnset) {
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    unsigned int enabled_iface_num = 3;  
    char evt_name[64] = {0};
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ifname"), NotNull(), _))
        .WillOnce(DoAll(SetArrayArgument<3>("eth0", "eth0" + 5), Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_active_inst"), NotNull(), _))
        .WillOnce(DoAll(SetArrayArgument<3>("1 2 3", "1 2 3" + 6), Return(0)));
    for (int i = 0; i < enabled_iface_num; i++) {
        snprintf(evt_name, sizeof(evt_name), "multinet_%d-name", i + 1);
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(evt_name), NotNull(), _))
            .WillOnce(DoAll(SetArrayArgument<3>("eth0", "eth0" + 5), Return(0)));
        EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
            .WillRepeatedly(Return(0));
    }
    EXPECT_CALL(*g_libnetMock,rule_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_SUCCESS))
        .WillRepeatedly(Return(CNL_STATUS_FAILURE));
    int result = route_unset(&sr);
    EXPECT_EQ(result, 0);
}
// Test Case for radv_start
TEST_F(service_routed_test, RadvStartLanNotReady) {
    struct serv_routed sr;
    sr.sefd = 1;
    sr.setok = 1;
    sr.lan_ready = 0;
    char bridgeMode[8] = "0";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("bridge_mode"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(bridgeMode, bridgeMode + strlen(bridgeMode) + 1), Return(0)));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _)).Times(0);
    int result = radv_start(&sr);
    EXPECT_EQ(result, -1);
}





