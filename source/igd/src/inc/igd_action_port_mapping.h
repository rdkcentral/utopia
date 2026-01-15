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
 *    FileName:    igd_action_port_mapping.h
 *      Author:    Lipin Zhou(zlipin@cisco.com)
 *        Date:    2009-04-30
 * Description:    IGD port map implementation of UPnP IGD project
 *****************************************************************************/
/*$Id: igd_action_port_mapping.h,v 1.4 2009/05/22 05:36:58 zlipin Exp $
 *
 *$Log: igd_action_port_mapping.h,v $
 *Revision 1.4  2009/05/22 05:36:58  zlipin
 *Adjust the PII "PortMapping" module interface
 *
 *Revision 1.3  2009/05/15 08:00:21  bowan
 *1st Integration
 *
 *Revision 1.2  2009/05/14 05:56:05  zlipin
 *update the included file name
 *
 *Revision 1.1  2009/05/14 01:58:26  zlipin
 *First version
 *
 *
 **/

#ifndef _IGD_ACTION_PORT_MAPPING_
#define _IGD_ACTION_PORT_MAPPING_

/***************************including***************************/
#include "igd_platform_independent_inf.h"
#include "pal_upnp_device.h"
#include "pal_xml2s.h"
#include "pal_def.h"
/***************************including end***********************/


/***************************data structure***********************/

#define IGD_GENERAL_ERROR           -1

typedef struct _genPortMapIndex{
    PAL_XML2S_FDMSK fieldMask;

    #define MASK_OF_PORTMAP_INDEX    0x00000001

    UINT16 portMapIndex;
}genPortMapIndex;

typedef struct _PORT_MAP_INDEX{
    PAL_XML2S_FDMSK fieldMask;

    #define MASK_OF_INDEX_REMOTE_HOST       0x00000001
    #define MASK_OF_INDEX_EXTERNAL_PORT    0x00000002
    #define MASK_OF_INDEX_PROTOCOL              0x00000004

    CHAR    *remoteHost;
    UINT16  externalPort;
    CHAR    *pmProtocol;
}PORT_MAP_INDEX, *PPORT_MAP_INDEX;

typedef struct _PORT_MAP_ENTRY{
    PAL_XML2S_FDMSK fieldMask;

    #define MASK_OF_ENTRY_REMOTE_HOST       0x00000001
    #define MASK_OF_ENTRY_EXTERNAL_PORT    0x00000002
    #define MASK_OF_ENTRY_PROTOCOL              0x00000004
    #define MASK_OF_ENTRY_INTERNAL_PORT    0x00000008
    #define MASK_OF_ENTRY_INTERNAL_CLIENT 0x00000010
    #define MASK_OF_ENTRY_ENABLED                0x00000020
    #define MASK_OF_ENTRY_DESCRIPTION         0x00000040
    #define MASK_OF_ENTRY_LEASE_TIME           0x00000080

    CHAR    *remoteHost;
    UINT16  externalPort;
    CHAR    *pmProtocol;
    UINT16  internalPort;
    CHAR    *internalClient;
    BOOL     pmEnabled;
    CHAR    *pmDescription;
    UINT32  pmLeaseTime;
}PORT_MAP_ENTRY, *PPORT_MAP_ENTRY;

/***************************data structure end********************/


/***************************interface function***************************/

/**
* @brief Get NAT and RSIP status.
*
* Retrieves the NAT (Network Address Translation) and RSIP (Realm-Specific IP) status
* \n for the WAN connection device and returns the values in UPnP action response.
*
* @param[in,out] event - Pointer to action_event structure containing UPnP action request.
*                        \n The event structure includes service information, request parameters,
*                        \n and will be populated with response data or error codes.
*
* @return The status of the operation.
* @retval PAL_UPNP_E_SUCCESS if successful.
* @retval IGD_GENERAL_ERROR if input parameter is NULL.
* @retval PAL_UPNP_SOAP_E_ACTION_FAILED if service private data is NULL or PII function fails.
*
*/
INT32 IGD_get_NATRSIP_status(INOUT struct action_event *event);

/**
* @brief Get generic port mapping entry by index.
*
* Retrieves port mapping entry information by index number.
* \n Returns all port mapping fields including remote host, external/internal ports,
* \n protocol, internal client, enabled status, description, and lease duration.
* \n Input parameter NewPortMappingIndex specifies the entry to retrieve.
*
* @param[in,out] event - Pointer to action_event structure containing UPnP action request.
*                        \n Input: NewPortMappingIndex (UINT16) - Index of port mapping entry to retrieve.
*                        \n Output: All port mapping entry fields in action response.
*
* @return The status of the operation.
* @retval PAL_UPNP_E_SUCCESS if successful.
* @retval IGD_GENERAL_ERROR if input parameter is NULL.
* @retval PAL_UPNP_SOAP_E_ACTION_FAILED if service private data is NULL.
* @retval PAL_UPNP_SOAP_E_INVALID_ARGS if XML parsing fails.
* @retval ARRAY_INDEX_INVALID if port mapping index is out of range.
*
*/
INT32 IGD_get_GenericPortMapping_entry(INOUT struct action_event *event);

/**
* @brief Get specific port mapping entry by key fields.
*
* Retrieves port mapping entry information by specifying remote host, external port, and protocol.
* \n Returns internal port, internal client, enabled status, description, and lease duration.
*
* @param[in,out] event - Pointer to action_event structure containing UPnP action request.
*                        \n Input: NewRemoteHost (string), NewExternalPort (UINT16), NewProtocol (string).
*                        \n Output: Internal port, internal client, enabled, description, lease duration.
*
* @return The status of the operation.
* @retval PAL_UPNP_E_SUCCESS if successful.
* @retval IGD_GENERAL_ERROR if input parameter is NULL.
* @retval PAL_UPNP_SOAP_E_ACTION_FAILED if service private data is NULL.
* @retval PAL_UPNP_SOAP_E_INVALID_ARGS if XML parsing fails or remote host format is invalid (must be x.x.x.x).
*
*/
INT32 IGD_get_SpecificPortMapping_entry(INOUT struct action_event *event);

/**
* @brief Add a port mapping entry.
*
* Creates a new port mapping entry with specified parameters.
* \n Validates remote host and internal client IP address formats (x.x.x.x).
* \n Verifies internal client matches control point address and is within valid subnet.
* \n Checks for conflicts with SpeedBoost port ranges if SPEED_BOOST_SUPPORTED is enabled.
* \n Sets lease time to 86400 seconds (24 hours) for the port mapping rule.
*
* @param[in,out] event - Pointer to action_event structure containing UPnP action request.
*                        \n Input: All port mapping fields for the new entry.
*                        \n Output: Empty response on success, error code on failure.
*
* @return The status of the operation.
* @retval PAL_UPNP_E_SUCCESS if successful.
* @retval IGD_GENERAL_ERROR if input parameter is NULL.
* @retval PAL_UPNP_SOAP_E_ACTION_FAILED if service private data is NULL.
* @retval PAL_UPNP_SOAP_E_INVALID_ARGS if XML parsing fails, IP format invalid, or client validation fails.
* @retval Conflict_In_MappingEntry if port conflicts with SpeedBoost port ranges.
*
*/
INT32 IGD_add_PortMapping(INOUT struct action_event *event);

/**
* @brief Delete a port mapping entry.
*
* Removes an existing port mapping entry identified by remote host, external port, and protocol.
* \n Validates remote host IP address format if provided (must be x.x.x.x).
*
* @param[in,out] event - Pointer to action_event structure containing UPnP action request.
*                        \n Input: NewRemoteHost (string), NewExternalPort (UINT16), NewProtocol (string).
*                        \n Output: Empty response on success, error code on failure.
*
* @return The status of the operation.
* @retval PAL_UPNP_E_SUCCESS if successful.
* @retval IGD_GENERAL_ERROR if input parameter is NULL.
* @retval PAL_UPNP_SOAP_E_ACTION_FAILED if service private data is NULL.
* @retval PAL_UPNP_SOAP_E_INVALID_ARGS if XML parsing fails or remote host format is invalid.
*
*/
INT32 IGD_delete_PortMapping(INOUT struct action_event *event);

#if defined (SPEED_BOOST_SUPPORTED)

/**
* @brief Check if port overlaps with SpeedBoost port ranges.
*
* Validates that external and internal UPnP port mapping ports do not overlap
* \n with reserved SpeedBoost port ranges (IPv4 and IPv6).
*
* @param[in] ExternalPort - External port number for UPnP port mapping.
* @param[in] InternalPort - Internal port number for UPnP port mapping.
*
* @return The status of port overlap check.
* @retval TRUE if external or internal port overlaps with SpeedBoost port ranges.
* @retval FALSE if no overlap detected or SpeedBoost is disabled.
*
*/
INT32 IGD_checkport_SpeedboostPort(UINT16 ExternalPort, UINT16 InternalPort);
#endif

/***************************interface function end***********************/

#endif  //_IGD_ACTION_PORT_MAPPING_

