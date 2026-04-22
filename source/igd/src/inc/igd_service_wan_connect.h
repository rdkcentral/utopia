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

/*
 *    FileName:    igd_service_wan_connect.h
 *      Author:    Andy Liu(zhihliu@cisco.com)
 *                     Tao Hong(tahong@cisco.com)
 *        Date:    2009-05-03
 * Description:    WAN IP/PPP connection service header file of UPnP IGD project
 *****************************************************************************/
/*$Id: igd_service_wan_connect.h,v 1.2 2009/05/22 05:38:06 zlipin Exp $
 *
 *$Log: igd_service_wan_connect.h,v $
 *Revision 1.2  2009/05/22 05:38:06  zlipin
 *Adjust the PII "PortMapping" module interface
 *
 *Revision 1.1  2009/05/13 08:57:48  tahong
 *create orignal version
 *
 *
 **/

#ifndef WAN_CONNECTION_SERVICE_H
#define WAN_CONNECTION_SERVICE_H

#include <stdio.h>

#include "pal_upnp_device.h"
#include "pal_def.h"

#define WAN_CONNECTION_DEVICE_LOG_NAME "wan_con"

#define WAN_PPP_CONNECTION_SERVICE_TYPE "urn:schemas-upnp-org:service:WANPPPConnection:1"
#define WAN_IP_CONNECTION_SERVICE_TYPE  "urn:schemas-upnp-org:service:WANIPConnection:1"

enum wan_connection_service_state_variables_index
{
    ConnectionType_index=0,
    PossibleConnectionTypes_index,
    ConnectionStatus_index,
    Uptime_index,
    LastConnectionError_index,
    ExternalIPAddress_index,
    RSIPAvailable_index,
    NATEnabled_index,
    PortMappingNumberOfEntries_index,
    PortMappingEnabled_index,
    PortMappingLeaseDuration_index,
    RemoteHost_index,
    ExternalPort_index,
    InternalPort_index,
    PortMappingProtocol_index,
    InternalClient_index,
    PortMappingDescription_index,
    UpstreamMaxBitRate_index,
    DownstreamMaxBitRate_index
};

// be aligned with wan_connection_service_event_variables_name
enum wan_connection_service_event_variables_index
{
    PossibleConnectionTypes_event_index=0,
    ConnectionStatus_event_index,
    ExternalIPAddress_event_index,
    PortMappingNumberOfEntries_event_index
};

typedef struct{
    INT32 code;
    CHAR *desc;
} error_pair;

/**
* @brief Initialize WAN IP connection service instance.
*
* Creates and initializes a WANIPConnection service instance for the UPnP IGD device.
* \n Called by IGD_wan_connection_device_init() to initialize a wan ip connection service instance.
*
* @param[in] input_index_struct - Pointer to device_and_service_index structure containing:
*                                 \n WAN device index, WAN connection device index, and WAN connection service index.
* @param[in,out] wan_desc_file - File pointer to device description file for writing service XML entry.
*                                \n Service description will be appended to this file.
*
* @return Pointer to initialized upnp_service structure.
* @retval struct upnp_service* - Pointer to initialized WAN IP connection service if successful.
* @retval NULL if initialization fails (memory allocation error or invalid parameters).
*
*/
extern struct upnp_service * IGD_wan_ip_connection_service_init (IN VOID* input_index_struct, INOUT FILE *wan_desc_file);
/**
* @brief Initialize WAN PPP connection service instance.
*
* Creates and initializes a WANPPPConnection service instance for the UPnP IGD device.
* \n Called by IGD_wan_connection_device_init() to initialize a wan ppp connection service instance.
*
* @param[in] input_index_struct - Pointer to device_and_service_index structure containing:
*                                 \n WAN device index, WAN connection device index, and WAN connection service index.
* @param[in,out] wan_desc_file - File pointer to device description file for writing service XML entry.
*                                \n Service description will be appended to this file.
*
* @return Pointer to initialized upnp_service structure.
* @retval struct upnp_service* - Pointer to initialized WAN PPP connection service if successful.
* @retval NULL if initialization fails (memory allocation error or invalid parameters).
*
*/
extern struct upnp_service * IGD_wan_ppp_connection_service_init (IN VOID* input_index_struct, INOUT FILE *wan_desc_file);

#endif /* WAN_CONNECTION_SERVICE_H */
