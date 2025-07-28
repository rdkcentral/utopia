/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include "utapi.h"
#include "utapi_util.h"
#include "utapi_wlan.h"
#include "DM_TR181.h"
#include <arpa/inet.h>
#include "safec_lib_common.h"

int Utopia_Get_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle)
{
    char tokenBuf[64];
    char tokenVal[64];
    errno_t rc = -1;

    if(!str_handle){
        ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: Invalid Input Parameter", __FUNCTION__);
        return ERR_INVALID_ARGS;
    }

    Obj_Device_DNS_Relay *deviceDnsRelay = (Obj_Device_DNS_Relay*)str_handle;

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_enable_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    tokenVal[0] = 0;
    Utopia_RawGet(pCtx, NULL, tokenBuf, tokenVal, sizeof(tokenVal));
    deviceDnsRelay->Enable = (strcasecmp(tokenVal, "false") == 0) ? FALSE : TRUE;
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: Get Enable key & val = %s, %u", __FUNCTION__, tokenBuf, deviceDnsRelay->Enable);

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_server_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    tokenVal[0] = 0;
    Utopia_RawGet(pCtx, NULL, tokenBuf, tokenVal, sizeof(tokenVal));
    deviceDnsRelay->DNSServer.Value = inet_addr(tokenVal);

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_interface_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    deviceDnsRelay->Interface[0] = 0;
    Utopia_RawGet(pCtx, NULL, tokenBuf, deviceDnsRelay->Interface, sizeof(deviceDnsRelay->Interface));

    return UT_SUCCESS;
}

int Utopia_Set_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle)
{
    char tokenBuf[64];
    char tokenVal[64];
    errno_t rc = -1;

    if (!pCtx || !str_handle) {
        ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: Invalid Input Parameter", __FUNCTION__);
        return ERR_INVALID_ARGS;
    }

    Obj_Device_DNS_Relay *deviceDnsRelay = (Obj_Device_DNS_Relay*)str_handle;

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_enable_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: Set Enable key & val = %s, %u", __FUNCTION__, tokenBuf, deviceDnsRelay->Enable);
    Utopia_RawSet(pCtx, NULL, tokenBuf, (deviceDnsRelay->Enable == FALSE) ? "false" : "true");

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_server_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    rc = sprintf_s(tokenVal, sizeof(tokenVal), "%d.%d.%d.%d", 
                      (int)(deviceDnsRelay->DNSServer.Value) & 0xFF,
                      (int)(deviceDnsRelay->DNSServer.Value >> 8)  & 0xFF,
                      (int)(deviceDnsRelay->DNSServer.Value >> 16) & 0xFF,
                      (int)(deviceDnsRelay->DNSServer.Value >> 24) & 0xFF );
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    Utopia_RawSet(pCtx, NULL, tokenBuf, tokenVal);

    rc = sprintf_s(tokenBuf, sizeof(tokenBuf), "tr_dns_relay_forwarding_interface_%d", index);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    Utopia_RawSet(pCtx, NULL, tokenBuf, deviceDnsRelay->Interface);

    return UT_SUCCESS;
}
