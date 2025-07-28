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
#include "service_ipv6_mock.h"

class Service_ipv6TestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        g_utopiaMock = new utopiaMock();
        g_utilMock = new UtilMock();
        g_syseventMock = new SyseventMock();
        g_syscfgMock = new SyscfgMock();
        g_safecLibMock = new SafecLibMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_psmMock = new PsmMock();
        g_messagebusMock = new MessageBusMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_libnetMock = new LibnetMock();
    }

    void TearDown() override {
        delete g_utopiaMock;
        delete g_utilMock;
        delete g_syseventMock;
        delete g_syscfgMock;
        delete g_safecLibMock;
        delete g_securewrapperMock;
        delete g_psmMock;
        delete g_messagebusMock;
        delete g_anscMemoryMock;
        delete g_libnetMock;

	g_utopiaMock=nullptr;
        g_utilMock=nullptr;
        g_syseventMock=nullptr;
        g_syscfgMock=nullptr;
        g_safecLibMock=nullptr;
        g_securewrapperMock=nullptr;
        g_psmMock=nullptr;
        g_messagebusMock=nullptr;
        g_anscMemoryMock=nullptr;
        g_libnetMock=nullptr;

    }
};

ACTION_TEMPLATE(SetArgNPointeeTo,HAS_1_TEMPLATE_PARAMS(unsigned ,uIndex),AND_2_VALUE_PARAMS(pData,uiDataSize))
{
   memcpy(std::get<uIndex>(args),pData,uiDataSize);
}


#ifdef  _CBR_PRODUCT_REQ_

TEST_F(Service_ipv6TestFixture,positivecasehelper_ntoh64)
{
	uint64_t input=0XF123456789a1a2a3;
	EXPECT_EQ(0Xa3a2a189674523f1,helper_ntoh64(&input));
	input=0XFa7d8c9b0a7b6c3a;
	EXPECT_EQ(0x3a6c7b0a9b8c7dfa,helper_ntoh64(&input));
	input=-677887877;
	EXPECT_EQ(0x7b4098d7ffffffff,helper_ntoh64(&input));
}


TEST_F(Service_ipv6TestFixture,positivecasehelper_hton64)
{
	uint64_t input=0XF123456789a1a2a3;
	EXPECT_EQ(0Xa3a2a189674523f1,helper_hton64(&input));
	input=0XFa7d8c9b0a7b6c3a;
	EXPECT_EQ(0x3a6c7b0a9b8c7dfa,helper_hton64(&input));
	input=-677887877;
	EXPECT_EQ(0x7b4098d7ffffffff,helper_hton64(&input));
}

#endif


TEST_F(Service_ipv6TestFixture,positivecase_1_get_dhcpv6s_conf64)
{
	dhcpv6s_cfg cfg;
	char data[16]="1";
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("serverenable"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(data),sizeof(data)),
                        ::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("poolnumber"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(data),sizeof(data)),
                        ::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("servertype"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(data),sizeof(data)),
                        ::testing::Return(0)
                        ));
	EXPECT_EQ(0,get_dhcpv6s_conf(&cfg));
	EXPECT_EQ(1,cfg.enable);
	EXPECT_EQ(1,cfg.pool_num);
	EXPECT_EQ(DHCPV6S_TYPE_STATEFUL,cfg.server_type);
}

TEST_F(Service_ipv6TestFixture,positivecase_2_get_dhcpv6s_conf64)
{
	dhcpv6s_cfg cfg;
	char data[16]="1";
	char buf[16]="2";
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("serverenable"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(data),sizeof(data)),
                        ::testing::Return(0)
                        ));

	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("poolnumber"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("servertype"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));
	EXPECT_EQ(0,get_dhcpv6s_conf(&cfg));
	EXPECT_EQ(1,cfg.enable);
	EXPECT_EQ(2,cfg.pool_num);
	EXPECT_EQ(DHCPV6S_TYPE_STATELESS,cfg.server_type);
}

TEST_F(Service_ipv6TestFixture,negtivecaseget_dhcpv6s_conf64)
{
	dhcpv6s_cfg cfg;
	char data[16] = "0";
	char buf[16]="2";
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("serverenable"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(data),sizeof(data)),
                        ::testing::Return(0)
                        ));
	
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("poolnumber"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));

	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("servertype"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));
	EXPECT_EQ(0,get_dhcpv6s_conf(&cfg));
	EXPECT_EQ(0,cfg.enable);
	EXPECT_EQ(2,cfg.pool_num);
	EXPECT_EQ(DHCPV6S_TYPE_STATELESS,cfg.server_type);
}

TEST_F(Service_ipv6TestFixture,Failedcaseget_dhcpv6s_conf64)
{
	dhcpv6s_cfg cfg;
	char buf[16]="4294967295";
	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("serverenable"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));

	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("poolnumber"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));

	EXPECT_CALL(*g_syscfgMock,syscfg_get( _,StrEq("servertype"), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                        SetArgNPointeeTo<2>(std::begin(buf),sizeof(buf)),
                        ::testing::Return(0)
                        ));
	EXPECT_EQ(0,get_dhcpv6s_conf(&cfg));
	EXPECT_EQ(-1,cfg.enable);
	EXPECT_EQ(-1,cfg.pool_num);
	EXPECT_EQ(-1,cfg.server_type);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseNoSlashInPrefix) {
    const char *prefix = "2601:647:4b00:c9d0::";
    char value[100];
    unsigned int prefix_len;

    EXPECT_EQ(-1, get_prefix_info(prefix, value, sizeof(value), &prefix_len));
}

TEST_F(Service_ipv6TestFixture, NegativeCaseEmptyPrefix) {
    const char *prefix = "";
    char value[100];
    unsigned int prefix_len;

    EXPECT_EQ(-1, get_prefix_info(prefix, value, sizeof(value), &prefix_len));
}

TEST_F(Service_ipv6TestFixture, PositiveCaseNullValue) {
    const char *prefix = "2601:647:4b00:c9d0::/64";
    unsigned int prefix_len;

    EXPECT_EQ(0, get_prefix_info(prefix, nullptr, 0, &prefix_len));
    EXPECT_EQ(64, prefix_len);
}

TEST_F(Service_ipv6TestFixture, PositiveCaseNullPrefixLen) {
    const char *prefix = "2601:647:4b00:c9d0::/64";
    char value[100];

    EXPECT_EQ(0, get_prefix_info(prefix, value, sizeof(value), nullptr));
    EXPECT_STREQ("2601:647:4b00:c9d0::", value);
}

TEST_F(Service_ipv6TestFixture, PositiveCaseExactValueLength) {
    const char *prefix = "2601:647:4b00:c9d0::/64";
    char value[100]={0}; // Exact length for "2601:647:4b00:c9d0::"
    unsigned int prefix_len;

    EXPECT_EQ(0, get_prefix_info(prefix, value, sizeof(value), &prefix_len));
    EXPECT_STREQ("2601:647:4b00:c9d0::", value);
    EXPECT_EQ(64, prefix_len);
}


// Placeholder for get_pd_pool tests
TEST_F(Service_ipv6TestFixture, PositiveCaseGetPdPool) {
    pd_pool_t pool;
    serv_ipv6 si6;
    char evt_val[256]="2001:db8::";

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_subprefix-start"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(evt_val, sizeof(evt_val)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));
    strcpy(pool.start,evt_val);
    strcpy(evt_val,"2001:db8::ffff");
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_subprefix-end"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(evt_val, sizeof(evt_val)),
            ::testing::Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));
    strcpy(pool.end,evt_val);
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix-length"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("64", sizeof("64")),
            ::testing::Return(0)
        ));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_pd-length"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("56", sizeof("56")),
            ::testing::Return(0)
        ));

    EXPECT_EQ(0, get_pd_pool(&si6, &pool));
    EXPECT_STREQ("2001:db8::", pool.start);
    EXPECT_STREQ("2001:db8::ffff", pool.end);
    EXPECT_EQ(64, pool.prefix_length);
    EXPECT_EQ(56, pool.pd_length);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseGetPdPool_NoStart) {
    pd_pool_t pool;
    serv_ipv6 si6;

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_subprefix-start"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("", sizeof("")),
            ::testing::Return(0)
        ));

    EXPECT_EQ(-1, get_pd_pool(&si6, &pool));
}

TEST_F(Service_ipv6TestFixture, EdgeCaseGetPdPool_InvalidPrefixLength) {
    pd_pool_t pool;
    serv_ipv6 si6;

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_subprefix-start"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("2001:db8::", sizeof("2001:db8::")),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_subprefix-end"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("2001:db8::ffff", sizeof("2001:db8::ffff")),
            ::testing::Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));


    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix-length"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("invalid", sizeof("invalid")),
            ::testing::Return(0)
        ));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_pd-length"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>("", sizeof("")),
            ::testing::Return(0)
        ));


    EXPECT_EQ(-1, get_pd_pool(&si6, &pool));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_Failure)
{
        struct serv_ipv6 si6;
        memset(&si6, 0, sizeof(si6));
        si6.sefd = 1; // Mock file descriptor
        si6.setok = 1; // Mock token

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll( ::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("service_ipv6-status"), StrEq("error"), _))
                        .WillOnce(::testing::DoAll( ::testing::Return(0)
                        ));


        EXPECT_EQ(-1, lan_addr6_set(&si6));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_NoActiveLanInterface)
{
         struct serv_ipv6 si6;
	char buf[128]="brlan0",buf1[128]="\0";
	char active_insts[32]="1";
    char active_insts_buf1[32]= "0";
	char iface_prefix[46]="2601:647:4b00:c9d0::";
    char buffer[16]="brlan0",buffer1[16]="brlan0";
    char val_buffer[64]="ready";
    memset(&si6, 0, sizeof(si6));
    si6.sefd = 1; // Mock file descriptor
    si6.setok = 1; // Mock token
		       //
    strcpy(si6.mso_prefix,"2601:647:4b00:c9d0::/64");

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll(::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
                        .Times(2)
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<2>(buf, sizeof(buf)),
                                        ::testing::Return(0)
                        ))
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<2>(buf1, sizeof(buf1)),
                                        ::testing::Return(0)
                        ));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
                        .Times(1)
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(active_insts, sizeof(active_insts)),
                                        ::testing::Return(0)
                        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
		.Times(2)
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)))
			.WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));
	  EXPECT_CALL(*g_safecLibMock,_strcat_s_chk(_, _, _, _))
                        .Times(1)
                        .WillOnce(::testing::Return(0)
                        );

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_brlan0-prefix"),StrEq(iface_prefix), _))
                        .Times(1);

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-start"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-end"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-length"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_pd-length"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"),StrEq("ready"), _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_get( _, _, StrEq("ipv6_prefix-divided"), _, _))
                .Times(1)
	        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(val_buffer, sizeof(val_buffer)),
                                        ::testing::Return(0)));

        EXPECT_EQ(-1, lan_addr6_set(&si6));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_DividePrefixError)
{
        struct serv_ipv6 si6;
	char buf[128]="brlan0",buf1[128];
	char active_insts[32]="1";
    char active_insts_buf1[32];
	char iface_prefix[46]="2601:647:4b00:c9d0::";
    char buffer[16]="brlan0",buffer1[16]="brlan0";
        memset(&si6, 0, sizeof(si6));
        si6.sefd = 1; // Mock file descriptor
        si6.setok = 1; // Mock token
		       //
        strcpy(si6.mso_prefix,"2601:647:4b00:c9d0::/64");

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll(::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<2>(buf, sizeof(buf)),
                                        ::testing::Return(0)
                        ));
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(active_insts, sizeof(active_insts)),
                                        ::testing::Return(0)
                        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
		.Times(2)
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)))
			.WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));
	 EXPECT_CALL(*g_safecLibMock,_strcat_s_chk(_, _, _, _))
                        .Times(1)
                        .WillOnce(::testing::Return(0)
                        );

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_brlan0-prefix"),StrEq(iface_prefix), _))
                        .Times(1);

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-start"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-end"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-length"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_pd-length"), _, _))
                        .Times(1);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"),StrEq("ready"), _))
                        .Times(1);

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .Times(1)
                        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>("error", sizeof("error")),
                                        ::testing::Return(0)));

        EXPECT_EQ(-1, lan_addr6_set(&si6));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_PrefixNotDivided)
{
        struct serv_ipv6 si6;
        memset(&si6, 0, sizeof(si6));
        si6.sefd = 1; // Mock file descriptor
        si6.setok = 1; // Mock token

	 EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll(::testing::Return(0)
                        ));

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("service_ipv6-status"), StrEq("error"), _))
                        .Times(1);

        EXPECT_EQ(-1, lan_addr6_set(&si6));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_NoActiveLanInterface_corenetlib)
{
    struct serv_ipv6 si6;
    memset(&si6, 0, sizeof(si6));
    si6.sefd = 1; 
    si6.setok = 1; 
	char buf[128]="brlan0";
	char active_insts[32]="1";
    char active_insts_buf1[32]= "0";
	char iface_prefix[46]="2601:647:4b00:c9d0::";
    char mockBuffer[] = "2601:647:4b00:c9d0::/64";
    char mockKey1[] = "ipv6_brlan0-addr";
    char mockKey2[] = "zebra-restart";
    char mockValue1[] = "2601:647:4b00:c9d0";
    char buffer[16]="brlan0",buffer1[16]="brlan0";
    char val_buffer[64]="ready";

    strcpy(si6.mso_prefix,"2601:647:4b00:c9d0::/64");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll(::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<2>(buf, sizeof(buf)),
                                        ::testing::Return(0)
                        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<3>(active_insts, sizeof(active_insts)),
                                        ::testing::Return(0)
                        ));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_brlan0-prefix"),StrEq(iface_prefix), _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-start"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-end"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-length"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_pd-length"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"),StrEq("ready"), _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_get( _, _, StrEq("ipv6_prefix-divided"), _, _))
                .Times(1)
	        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(val_buffer, sizeof(val_buffer)),
                                        ::testing::Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-prefix"), _, _))
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_linklocal"), StrEq("up"), _))
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_libnetMock, interface_up(testing::_))
                                        .Times(testing::AtLeast(1))
                                        .WillOnce(::testing::Return(CNL_STATUS_FAILURE));

    EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, StrEq("brlan0"), StrEq("1")))
                                        .Times(AnyNumber())
                                        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, StrEq("brlan0"), StrEq("0")))
                                        .Times(AnyNumber())
                                        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
                                        .WillOnce(testing::DoAll(
                                                  testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
                                                  Return(EOK)
                                        ));

    EXPECT_CALL(*g_utopiaMock, iface_get_hwaddr(testing::_, testing::_, testing::_))
                                        .Times(1)
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcat_s_chk(_, _, _, _))
                                    .Times(AnyNumber())
                                    .WillRepeatedly(Return(EOK));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(mockKey1), StrEq(mockValue1), _))
                    .WillOnce(Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(mockKey2), nullptr, _))
                    .WillOnce(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_add(testing::_))
                    .Times(testing::AtLeast(1))
                    .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_EQ(0, lan_addr6_set(&si6));
}

TEST_F(Service_ipv6TestFixture, TestLanAddr6Set_NoActiveLanInterface_corenetlib_failure)
{
    struct serv_ipv6 si6;
	char buf[128]="brlan0",buf1[128]="\0";
	char active_insts[32]="1";
    char active_insts_buf1[32]= "0";
	char iface_prefix[46]="2601:647:4b00:c9d0::";
    char mockBuffer[] = "2601:647:4b00:c9d0::/64";
    char mockKey1[] = "ipv6_brlan0-addr";
    char mockValue1[] = "2601:647:4b00:c9d0";
    char buffer[16]="brlan0",buffer1[16]="brlan0";
    char val_buffer[64]="ready";
    memset(&si6, 0, sizeof(si6));
    si6.sefd = 1;
    si6.setok = 1;
    strcpy(si6.mso_prefix,"2601:647:4b00:c9d0::/64");

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"), _, _))
                        .WillOnce(::testing::DoAll(::testing::Return(0)
                        ));
	EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<2>(buf, sizeof(buf)),
                                        ::testing::Return(0)
                        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<3>(active_insts, sizeof(active_insts)),
                                        ::testing::Return(0)
                        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
                        .WillRepeatedly(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_brlan0-prefix"),StrEq(iface_prefix), _))
                        .Times(1);

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-start"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_subprefix-end"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-length"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_pd-length"), _, _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_prefix-divided"),StrEq("ready"), _))
                        .Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_get( _, _, StrEq("ipv6_prefix-divided"), _, _))
                .Times(1)
	        .WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(val_buffer, sizeof(val_buffer)),
                                        ::testing::Return(0)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-prefix"), _, _))
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_linklocal"), StrEq("up"), _))
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_libnetMock, interface_up(testing::_))
                                        .Times(testing::AtLeast(1))
                                        .WillOnce(::testing::Return(CNL_STATUS_SUCCESS));

    EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, StrEq("brlan0"), StrEq("1")))
                                        .Times(AnyNumber())
                                        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, StrEq("brlan0"), StrEq("0")))
                                        .Times(AnyNumber())
                                        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1)
                                        .WillOnce(testing::DoAll(
                                                  testing::SetArrayArgument<0>(mockBuffer, mockBuffer + strlen(mockBuffer) + 1),
                                                  Return(EOK)
                                        ));

    EXPECT_CALL(*g_utopiaMock, iface_get_hwaddr(testing::_, testing::_, testing::_))
                                        .Times(1)
                                        .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcat_s_chk(_, _, _, _))
            .Times(AnyNumber())
            .WillRepeatedly(Return(EOK));

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(mockKey1), StrEq(mockValue1), _))
       .WillOnce(Return(0));

    EXPECT_CALL(*g_libnetMock, addr_add(testing::_))
       .Times(testing::AtLeast(1))
       .WillOnce(Return(CNL_STATUS_FAILURE));

    EXPECT_EQ(-1, lan_addr6_set(&si6));
}


TEST_F(Service_ipv6TestFixture, PositiveCaseLanAddr6Unset) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;

    unsigned int l2_insts[MAX_LAN_IF_NUM] = {1, 2};
    char if_name[128] = "brlan0";
    char buffer[16]="brlan0";
    char iface_prefix[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::/64";
    char iface_addr[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::1";
    char evt_name[64] = "ipv6_brlan0-prefix";
    int prefix_len = 64;
    char active_instances[64] = "1";


    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
		.Times(1)
        .WillOnce(::testing::DoAll(SetArgNPointeeTo<2>(if_name, sizeof(if_name)),
		    ::testing::Return(0)));
EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
        .Times(1)
		.WillOnce(::testing::DoAll(SetArgNPointeeTo<3>(active_instances, sizeof(active_instances)),
				            ::testing::Return(0)));


EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
		.Times(2)
                 .WillOnce(::testing::DoAll(
                 			SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)))
		.WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-prefix"), _, _))
        .Times(1)
        .WillOnce(testing::DoAll(SetArgNPointeeTo<3>(iface_prefix,sizeof(iface_prefix)),
                                ::testing::Return(0)));


    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-addr"), _, _))
        .Times(1)
        .WillOnce(testing::DoAll(SetArgNPointeeTo<3>(iface_addr,sizeof(iface_addr)),
				::testing:: Return(0)));

     EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, _ , _))
		.Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_linklocal"), StrEq("down"), _))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_libnetMock, addr_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_SUCCESS));

    EXPECT_EQ(0, lan_addr6_unset(&si6));

}

TEST_F(Service_ipv6TestFixture, PositiveCaseLanAddr6Unset_addr_delete_failure) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;

    unsigned int l2_insts[MAX_LAN_IF_NUM] = {1, 2};
    char if_name[128] = "brlan0";
    char buffer[16]="brlan0";
    char iface_prefix[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::/64";
    char iface_addr[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::1";
    char evt_name[64] = "ipv6_brlan0-prefix";
    int prefix_len = 64;
    char active_instances[64] = "1";


    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
		.Times(1)
        .WillOnce(::testing::DoAll(SetArgNPointeeTo<2>(if_name, sizeof(if_name)),
		    ::testing::Return(0)));
EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
        .Times(1)
		.WillOnce(::testing::DoAll(SetArgNPointeeTo<3>(active_instances, sizeof(active_instances)),
				            ::testing::Return(0)));


EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_1-name"), _, _))
		.Times(2)
                 .WillOnce(::testing::DoAll(
                 			SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)))
		.WillOnce(::testing::DoAll(
                                        SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-prefix"), _, _))
        .Times(1)
        .WillOnce(testing::DoAll(SetArgNPointeeTo<3>(iface_prefix,sizeof(iface_prefix)),
                                ::testing::Return(0)));


    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_brlan0-addr"), _, _))
        .Times(1)
        .WillOnce(testing::DoAll(SetArgNPointeeTo<3>(iface_addr,sizeof(iface_addr)),
				::testing:: Return(0)));

     EXPECT_CALL(*g_utopiaMock, sysctl_iface_set(_, _ , _))
		.Times(1);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("ipv6_linklocal"), StrEq("down"), _))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_libnetMock, addr_delete(testing::_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(CNL_STATUS_FAILURE));

    EXPECT_EQ(0, lan_addr6_unset(&si6));

}

TEST_F(Service_ipv6TestFixture, NegativeCaseLanAddr6Unset) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;

    unsigned int l2_insts[MAX_LAN_IF_NUM] = {1, 2};
    char if_name[128]={0};
    char iface_prefix[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::/64";
    char iface_addr[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::1";
    char evt_name[64] = "ipv6_brlan0-prefix";
    int prefix_len = 64;



    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
		.Times(1)
        .WillOnce(::testing::DoAll(SetArgNPointeeTo<2>(if_name, sizeof(if_name)),
		    ::testing::Return(0)));

    EXPECT_EQ(-1, lan_addr6_unset(&si6));

}

TEST_F(Service_ipv6TestFixture, EmptyActiveInstances) {
    struct serv_ipv6 si6;
    char if_name[128]="brlan0";
    char buffer[32]="eth0";
    char active_instances[32]="0";
    si6.sefd = 1;
    si6.setok = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
		.Times(1)
        .WillOnce(::testing::DoAll(SetArgNPointeeTo<2>(if_name, sizeof(if_name)),
		    ::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet-instances"), _, _))
        .Times(1)
		.WillOnce(::testing::DoAll(SetArgNPointeeTo<3>(active_instances, sizeof(active_instances)),
				            ::testing::Return(0)));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("multinet_0-name"), _, _))
		.Times(1)
                 .WillOnce(::testing::DoAll(
                 			SetArgNPointeeTo<3>(buffer, sizeof(buffer)),
					::testing::Return(0)));

    EXPECT_EQ(-1, lan_addr6_unset(&si6));
}


#ifdef _HUB4_PRODUCT_REQ_
TEST_F(Service_ipv6TestFixture, PositiveCaseGetLanUlaInfo) {
        int ula_enable;
        char* pUla_enable = strdup("TRUE");

        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, StrEq("eRT."), StrEq("dmsb.lanmanagemententry.lanulaenable"), _, _))
                .Times(1)
		.WillOnce(testing::DoAll(SetArgNPointeeTo<3>(pUla_enable,sizeof(pUla_enable)),
                                ::testing:: Return(CCSP_SUCCESS)));


        EXPECT_EQ(0, getLanUlaInfo(&ula_enable));
        EXPECT_EQ(TRUE, ula_enable);

        free(pUla_enable);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseGetLanUlaInfo) {
        int ula_enable;
        char* pUla_enable = strdup("FALSE");

        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, StrEq("eRT."), StrEq("dmsb.lanmanagemententry.lanulaenable"), _, _))
                .Times(1)
		.WillOnce(testing::DoAll(SetArgNPointeeTo<3>(pUla_enable,sizeof(pUla_enable)),
                                ::testing:: Return(CCSP_SUCCESS)));

        EXPECT_EQ(0, getLanUlaInfo(&ula_enable));
        EXPECT_EQ(FALSE, ula_enable);

        free(pUla_enable);
}

TEST_F(Service_ipv6TestFixture, FailCaseGetLanUlaInfo) {
        int ula_enable;

        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, StrEq("eRT."), StrEq("dmsb.lanmanagemententry.lanulaenable"), _, _))
                .Times(1)
                .WillOnce(Return(CCSP_FAILURE));

        EXPECT_EQ(-1, getLanUlaInfo(&ula_enable));
}
#endif
TEST_F(Service_ipv6TestFixture, PositiveCaseFormatDibblerOption) {
    char option[] = "2001:558:feed::1 2001:558:feed::2";
    EXPECT_EQ(0, format_dibbler_option(option));
    EXPECT_STREQ("2001:558:feed::1,2001:558:feed::2", option);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseFormatDibblerOption) {
    char *option = NULL;
    EXPECT_EQ(-1, format_dibbler_option(option));
}

TEST_F(Service_ipv6TestFixture, NoSpacesFormatDibblerOption) {
    char option[] = "2001:558:feed::1";
    EXPECT_EQ(0, format_dibbler_option(option));
    EXPECT_STREQ("2001:558:feed::1", option);
}

TEST_F(Service_ipv6TestFixture, MultipleSpacesFormatDibblerOption) {
    char option[] = "2001:558:feed::1 2001:558:feed::2 2001:558:feed::3";
    EXPECT_EQ(0, format_dibbler_option(option));
    EXPECT_STREQ("2001:558:feed::1,2001:558:feed::2,2001:558:feed::3", option);
}

TEST_F(Service_ipv6TestFixture, EmptyStringFormatDibblerOption) {
    char option[] = "";
    EXPECT_EQ(0, format_dibbler_option(option));
    EXPECT_STREQ("", option);
}

TEST_F(Service_ipv6TestFixture, OnlySpacesFormatDibblerOption) {
    char option[] = "     ";
    EXPECT_EQ(0, format_dibbler_option(option));
    EXPECT_STREQ(",,,,,", option);
}

TEST_F(Service_ipv6TestFixture, PositiveCaseDhcpv6sStop) {
        struct serv_ipv6 si6;
        EXPECT_EQ(0, dhcpv6s_stop(&si6));
}

TEST_F(Service_ipv6TestFixture, NegativeCaseDhcpv6sRestart) {
        serv_ipv6 si6;
        char evt_val[64]="error";
     EXPECT_CALL(*g_syseventMock, sysevent_get(si6.sefd, si6.setok, StrEq("ipv6_prefix-divided"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(evt_val), sizeof(evt_val)),
            ::testing::Return(0)
        ));
        EXPECT_CALL(*g_syseventMock, sysevent_set(si6.sefd, si6.setok, StrEq("ipv6_prefix-divided"), _, _))
        .Times(1);

         EXPECT_CALL(*g_utopiaMock,pid_of(_,_))
                        .Times(1)
                        .WillOnce(::testing::DoAll( ::testing::Return(567)))
                        .WillOnce(::testing::DoAll( ::testing::Return(567)));
        EXPECT_CALL(*g_syseventMock, sysevent_set(si6.sefd, si6.setok, StrEq("service_ipv6-status"), StrEq("error"), _))
        .Times(1);
        EXPECT_EQ(-1, dhcpv6s_restart(&si6));
}



TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6Start_WanNotReady) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;
    si6.wan_ready = false;
    char rtmod[16] = "0";

    EXPECT_CALL(*g_utopiaMock, serv_can_start(si6.sefd, si6.setok, StrEq("service_ipv6")))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
	.WillOnce(testing::DoAll(SetArgNPointeeTo<2>(rtmod,sizeof(rtmod)),
                                ::testing:: Return(0)));

    EXPECT_EQ(-1, serv_ipv6_start(&si6));
}


TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6Start_ServCanStartError) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;
    si6.wan_ready = true;

    EXPECT_CALL(*g_utopiaMock, serv_can_start(si6.sefd, si6.setok, StrEq("service_ipv6")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(-1, serv_ipv6_start(&si6));
}

TEST_F(Service_ipv6TestFixture, ServIpv6Start_Ipv4OnlyMode) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;
    si6.wan_ready = true;
    char rtmod[16] = "1";

    EXPECT_CALL(*g_utopiaMock, serv_can_start(si6.sefd, si6.setok, StrEq("service_ipv6")))
        .Times(1)
        .WillOnce(Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
	.WillOnce(testing::DoAll(SetArgNPointeeTo<2>(rtmod,sizeof(rtmod)),
                                ::testing:: Return(0)));

    EXPECT_EQ(0, serv_ipv6_start(&si6));
}




TEST_F(Service_ipv6TestFixture, PositiveCaseServIpv6Stop) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;
    char buf[128]="eth0";
    char tpmod[32]="0";
    char if_name[16]="eth0";
    char if_name1[16]="eth0";
    char prefix[46]="2601:647:4b00:c9d0::/64";
     char iface_prefix[INET6_ADDRSTRLEN] = "2601:647:4b00:c9d0::/64";
    EXPECT_CALL(*g_utopiaMock, serv_can_stop(1, 1, StrEq("service_ipv6")))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*g_syseventMock, sysevent_set(1, 1, StrEq("service_ipv6-status"), StrEq("stopping"), 0))
        .Times(1)
        .WillOnce(Return(0));
#if !defined(_CBR_PRODUCT_REQ_) && !defined(_BWG_PRODUCT_REQ_)
 EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("lan_pd_interfaces"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

 EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(if_name), sizeof(if_name)),
            ::testing::Return(0)
        ));
EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_eth0-prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));

EXPECT_CALL(*g_syseventMock, sysevent_get(_, _,StrEq("ipv6_eth0-addr") , _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(iface_prefix), sizeof(iface_prefix)),
            ::testing::Return(0)
        ));
EXPECT_CALL(*g_utilMock, sysctl_iface_set(_, _ , _))
        .Times(1);


EXPECT_CALL(*g_syseventMock, sysevent_set(_, _,StrEq("ipv6_linklocal") , StrEq("down"), _))
        .Times(1)
        .WillOnce(Return(0)
        );



#endif

    EXPECT_CALL(*g_syseventMock, sysevent_set(1, 1, StrEq("service_ipv6-status"), StrEq("stopped"), 0))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(0, serv_ipv6_stop(&si6));
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6Stop) {
    struct serv_ipv6 si6;
    si6.sefd = 1;
    si6.setok = 1;

    EXPECT_CALL(*g_utopiaMock, serv_can_stop(1, 1, StrEq("service_ipv6")))
        .Times(1)
        .WillOnce(Return(false));

    EXPECT_EQ(-1, serv_ipv6_stop(&si6));
}

/*
class ServiceIPv6Test : public ::testing::Test {
protected:
    serv_ipv6 si6;
};
*/
TEST_F(Service_ipv6TestFixture, RestartStartFail)
{
    struct serv_ipv6 si6;
    EXPECT_EQ(-1, serv_ipv6_restart(&si6));
}

TEST_F(Service_ipv6TestFixture, RestartBothFail)
{
   struct serv_ipv6 si6;
   EXPECT_EQ(-1, serv_ipv6_restart(&si6));
}

TEST_F(Service_ipv6TestFixture, PositiveCaseServIpv6Init) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled
    char buff[16] = "2";
    char prefix[64] = "2601:647:4b00:c9d0::/64";

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));
#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)
    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1)

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1)

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1)

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("erouter_topology-mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(buff), sizeof(buff)),
            ::testing::Return(0)
        ));


    EXPECT_EQ(0, serv_ipv6_init(&si6));
    EXPECT_TRUE(si6.wan_ready);
    EXPECT_EQ(FAVOR_WIDTH, si6.tpmod);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitIPv6NotEnabled) {
    struct serv_ipv6 si6;
    char buf[16] = "1"; // Assuming 1 means IPv6 is not enabled

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));

#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)

    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1);

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));


    EXPECT_EQ(-1, serv_ipv6_init(&si6));
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitNoPrefix) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled
    char prefix[64] = "";

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));
#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)
    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1);

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));



    EXPECT_EQ(-1, serv_ipv6_init(&si6));
    EXPECT_FALSE(si6.wan_ready);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitUnknownTopologyMode) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled
    char prefix[64] = "2601:647:4b00:c9d0::/64";
    char tpmod[16] = "3"; // Unknown topology mode

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));
#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)
    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1);

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("erouter_topology-mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(tpmod), sizeof(tpmod)),
            ::testing::Return(0)
        ));



    EXPECT_EQ(0, serv_ipv6_init(&si6));
    EXPECT_EQ(TPMOD_UNKNOWN, si6.tpmod);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitSyseventOpenFail) {
    struct serv_ipv6 si6;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(-1));

    EXPECT_EQ(-1, serv_ipv6_init(&si6));
}



TEST_F(Service_ipv6TestFixture, PositiveCaseServIpv6InitFavorDepth) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled
    char prefix[64] = "2601:647:4b00:c9d0::/64";
    char tpmod[16] = "1"; // Favor depth

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));
#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)
    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1);

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("erouter_topology-mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(tpmod), sizeof(tpmod)),
            ::testing::Return(0)
        ));



    EXPECT_EQ(0, serv_ipv6_init(&si6));
    EXPECT_EQ(FAVOR_DEPTH, si6.tpmod);
}

TEST_F(Service_ipv6TestFixture, PositiveCaseServIpv6InitFavorWidth) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled
    char prefix[64] = "2601:647:4b00:c9d0::/64";
    char tpmod[16] = "2"; // Favor width

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));
#if defined(MULTILAN_FEATURE) || defined(_HUB4_PRODUCT_REQ_)
    EXPECT_CALL(*g_anscMemoryMock,Ansc_AllocateMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,Ansc_FreeMemory_Callback( _))
    .Times(1);

    EXPECT_CALL(*g_anscMemoryMock,AnscFreeMemoryOrig( _))
    .Times(1);

    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(0));
#endif
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(prefix), sizeof(prefix)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("erouter_topology-mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(tpmod), sizeof(tpmod)),
            ::testing::Return(0)
        ));



    EXPECT_EQ(0, serv_ipv6_init(&si6));
    EXPECT_EQ(FAVOR_WIDTH, si6.tpmod);
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitSyscfgGetFail) {
    struct serv_ipv6 si6;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::Return(-1));

    EXPECT_EQ(-1, serv_ipv6_init(&si6));
}

TEST_F(Service_ipv6TestFixture, NegativeCaseServIpv6InitSyseventGetFail) {
    struct serv_ipv6 si6;
    char buf[16] = "2"; // Assuming 2 means IPv6 is enabled

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("last_erouter_mode"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<2>(std::begin(buf), sizeof(buf)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("ipv6_prefix"), _, _))
        .Times(1)
        .WillOnce(::testing::Return(-1));

    EXPECT_EQ(-1, serv_ipv6_init(&si6));
}
