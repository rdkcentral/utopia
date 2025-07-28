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

#include "apply_system_defaults_test.h"

class apply_system_defaults_test : public ::testing::Test
{
protected:
    SyscfgMock mockedsyscfg;
    SecureWrapperMock mockedSecureWrapper;
    SafecLibMock mockedSafecLib;
    utopiaMock mockedUtopia;
    SyseventMock mockedSysevent;
    PsmMock mockedPsm;
    cjsonMock mockedcJSON;
    telemetryMock mockedTelemetry;
    AnscMemoryMock mockedAnscMemoryMock;
    MessageBusMock mockedMessagebusMock;
    apply_system_defaults_test() 
    {
        g_syscfgMock = &mockedsyscfg;
        g_securewrapperMock = &mockedSecureWrapper;
        g_safecLibMock = &mockedSafecLib;
        g_utopiaMock = &mockedUtopia;
        g_syseventMock = &mockedSysevent;
        g_psmMock = &mockedPsm;
        g_cjsonMock = &mockedcJSON;
        g_telemetryMock = &mockedTelemetry;
        g_anscMemoryMock = &mockedAnscMemoryMock;
        g_messagebusMock = &mockedMessagebusMock;
    }
    virtual ~apply_system_defaults_test()
    {
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_safecLibMock = nullptr;
        g_utopiaMock = nullptr;
        g_syseventMock = nullptr;
        g_psmMock = nullptr;
        g_cjsonMock = nullptr;
        g_telemetryMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_messagebusMock = nullptr;
    }
};

TEST_F(apply_system_defaults_test, addInSysCfgdDB) {
    char key[] = "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support";
    char value[] = "false";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _)).WillRepeatedly(Return(0));  
    addInSysCfgdDB(key, value);
}

TEST_F(apply_system_defaults_test, updateSysCfgdDB) {
    char key[] = "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support";
    char value[] = "false";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _)).WillRepeatedly(Return(0));    
    updateSysCfgdDB(key, value);
}

TEST_F(apply_system_defaults_test, compare_partner_json_param_FALSE) {
    char partner_nvram_bs_obj[] = "{\"WiFiPersonalization\":{\"Support\":\"false\"}}";
    char partner_etc_obj[] = "{\"WiFiPersonalization\":{\"Support\":\"true\"}}";
    char partnerID[] = "comcast";

    cJSON *emptyJSON = NULL;

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_)).WillRepeatedly(Return(emptyJSON));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_,_)).WillRepeatedly(Return(emptyJSON));
    EXPECT_CALL(*g_cjsonMock, cJSON_CreateObject()).WillRepeatedly(Return(emptyJSON));
    EXPECT_CALL(*g_cjsonMock, cJSON_AddItemToObject(_,_,_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*g_cjsonMock, cJSON_AddItemReferenceToObject(_,_,_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_)).WillRepeatedly(Return());

    int res = compare_partner_json_param(partner_nvram_bs_obj, partner_etc_obj, partnerID);
    EXPECT_EQ(res, -1);
}

TEST_F(apply_system_defaults_test, compare_partner_json_param_WifiPerSupport) {
    const char *json_string = "{\
    \"properties\": {\
        \"comments\": \"MANDATORY: !!! Please increment below version value for any new parameter added in this partners_defaults.json !!!\",\
        \"version\": \"8.29\"\
    },\
    \"comcast\": {\
        \"Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.Footer.PartnerLink\": \"http://www.xfinity.com\",\
        \"Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support\": \"false\"\
    },\
    \"extra_key\": \"extra_value\"\
    }";
    const char *etc_json_string = "{\
    \"comcast\": {\
        \"Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.Footer.PartnerLink\": \"http://www.xfinity.com\",\
        \"Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support\": \"false\"\
    },\
    \"extra_key\": \"extra_value\"\
    }";

    char *partner_nvram_bs_obj = strdup(json_string);
    char *partner_etc_obj = strdup(etc_json_string);
    char PartnerID[] = "comcast";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _)).WillRepeatedly(Return(0));

    int res = compare_partner_json_param(partner_nvram_bs_obj, partner_etc_obj, PartnerID);
    EXPECT_EQ(res, 0);
}