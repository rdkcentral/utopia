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
 *    FileName:    igd_platform_independent_inf.h
 *      Author:    Andy Liu(zhihliu@cisco.com) Tao Hong(tahong@cisco.com)
 *                 Jianrong(jianxiao@cisco.com)Lipin Zhou(zlipin@cisco.com)
 *        Date:    2009-05-03
 * Description:    Header file including all Product-related macro and functions
 *****************************************************************************/
/*$Id: igd_platform_independent_inf.h,v 1.10 2009/05/26 09:58:28 zhangli Exp $
 *
 *$Log: igd_platform_independent_inf.h,v $
 *Revision 1.10  2009/05/26 09:58:28  zhangli
 *Completed the cleanup activity
 *
 *Revision 1.9  2009/05/22 05:37:34  zlipin
 *Adjust the PII "PortMapping" module interface
 *
 *Revision 1.8  2009/05/21 07:58:13  zhihliu
 *update PII interface
 *
 *Revision 1.7  2009/05/21 06:25:35  jianxiao
 *Modified some define of MACRO and add IGD_pii_get_wan_device_number/IGD_pii_get_wan_connection_device_number interface
 *
 *Revision 1.6  2009/05/15 09:25:11  tahong
 *use MACRO to construct description file of wan connection file
 *
 *Revision 1.5  2009/05/15 05:40:45  jianxiao
 *Update for integration
 *
 *Revision 1.4  2009/05/14 02:36:19  jianxiao
 *Add the wan_connect
 *
 *Revision 1.3  2009/05/14 02:05:18  jianxiao
 *Add the function IGD_pii_get_uuid
 *
 *Revision 1.2  2009/05/14 01:47:12  jianxiao
 *Add some macro for description file
 *
 *Revision 1.1  2009/05/13 08:57:38  tahong
 *create orignal version
 *
 *
 **/

#ifndef IGD_PLATFORM_INDEPENDENT_INF_H
#define IGD_PLATFORM_INDEPENDENT_INF_H

#include "pal_def.h"
#include "igd_platform_dependent_inf.h"
#include "autoconf.h"
#include <utapi/utapi.h>

#if defined (FEATURE_SUPPORT_RDKLOG)
#include "rdk_debug.h"
#endif //FEATURE_SUPPORT_RDKLOG

/***********************************************************************
* (1) Product-related macro
*     Notes: All the below macro should be modified based on your needs
*     when you port IGD to your products
************************************************************************/

// The name of the lan interface that the IGD will be run on
//#define IGD_UPNP_INTERFACE "lan0"
//Now pulled from syscfg

// The plarform-related info that will be used in the the description file of IGD device

#define WANDEVICE_FRIENDLY_NAME 	        "WANDevice:1"
#define WAN_CONNECTION_DEVICE_FRIENDLY_NAME 	"WANConnectionDevice:1"
#define LANDEVICE_FRIENDLY_NAME 	        "LANDevice:1"

#ifndef INTEL_PUMA7
#define ROOT_FRIENDLY_NAME 			CONFIG_VENDOR_MODEL
#undef MODULE_DESCRIPTION
#define MODULE_DESCRIPTION 		        CONFIG_VENDOR_MODEL
#undef MODULE_NAME
#define MODULE_NAME 				CONFIG_VENDOR_MODEL
#undef MODULE_NUMBER
#define MODULE_NUMBER 				CONFIG_VENDOR_MODEL
#undef UPC
#define UPC 					CONFIG_VENDOR_MODEL
#endif
/***********************************************************************
* (2) Product-related functions
*     Notes: All the below functions should be implemented based on your
*     products when you port IGD to them
************************************************************************/
/**
* @brief Get the serial number of the product.
*
* Retrieves the serial number from the product database.
* \n The serial number is used in the UPnP IGD device description file.
*
* @return Pointer to static buffer containing serial number string.
* @retval CHAR* pointer to serial number of IGD if successful.
* @retval NULL if failure or serial number not available.
*
*/
extern CHAR* IGD_pii_get_serial_number(VOID);

#define UPNP_UUID_LEN_BY_VENDER 42

/**
* @brief Get UUID for a new UPnP device.
*
* Generates a unique UUID for each UPnP device instance.
* \n According to UPnP specification, each device MUST have a different UUID.
* \n Our IGD stack will call this function to get one new UUID when
* \n create one new device. That means, this function MUST return the different
* \n UUID when it is called every time. And one method to create UUID is provided
* \n in the "igd_platform_independent_inf.c".
*
* @param[out] uuid - Buffer to store the generated UUID string.
*                    \n Must be allocated with minimum size of UPNP_UUID_LEN_BY_VENDER (42 bytes).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if uuid parameter is NULL or MAC address retrieval fails.
*
*/
extern INT32 IGD_pii_get_uuid(OUT CHAR *uuid);

/**
* @brief Get the instance number of WANDevice in IGD device.
*
* Returns the number of WANDevice instances supported by the IGD device.
*
* @return The instance number of WAN devices.
* @retval Instance number of the WAN device on success
* @retval -1 if failure.
*
*/
extern INT32 IGD_pii_get_wan_device_number(VOID);

/**
* @brief Get the instance number of WANConnectionDevice.
*
* Returns the number of WANConnectionDevice instances in in one WANDevice specified by the input device index.
*
* @param[in] wan_device_index - Index of WANDevice, range: 1 to Number of WANDevices.
*
* @return The instance number of WANConnectionDevice.
* @retval Instance number of the WAN connection device on success.
* @retval -1 if failure.
*
*/
extern INT32 IGD_pii_get_wan_connection_device_number(IN INT32 wan_device_index);

/**
* @brief Get the instance number of WANPPPConnectionService.
*
* Returns the number of WANPPPConnectionService instances in one WANConnectionDevice
* specified by the input device index.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
*
* @return The instance number of WANPPPConnectionService.
* @retval Instance number of the WAN PPP connection service on success.
* @retval 0 No PPP connection service (not supported)
* @retval -1 if failure.
*
*/
extern INT32 IGD_pii_get_wan_ppp_service_number(IN INT32 WanDeviceIndex,
                                                                            IN INT32 WanConnectionDeviceIndex);

/**
* @brief Get the instance number of WANIPConnectionService.
*
* Returns the number of WANIPConnectionService instances in one WANConnectionDevice
* specified by the input device index.
* \n Related UPnP Device/Service: WANIPConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
*
* @return The instance number of WANIPConnectionService.
* @retval Instance number of WANIPConnectionService on success
* @retval -1 if failure.
*
*/
extern INT32 IGD_pii_get_wan_ip_service_number(IN INT32 WanDeviceIndex,
                                                                            IN INT32 WanConnectionDeviceIndex);

// The valid value of the input parameter,"ServiceType"
#define SERVICETYPE_IP     (1)
#define SERVICETYPE_PPP    (2)

// The valid value of the output parameter,"ConnectionTypesList"
// possible IP connection types
#define IPCONNTYPE_UNCONFIGURED "Unconfigured"
#define IPCONNTYPE_IP_ROUTED        "IP_Routed"
#define IPCONNTYPE_IP_BRIDGED       "IP_Bridged"
// possible PPP connection types
#define PPPCONNTYPE_UNCONFIGURED  "Unconfigured"
#define PPPCONNTYPE_IP_ROUTED         "IP_Routed"
#define PPPCONNTYPE_DHCP_SPOOFED  "DHCP_Spoofed"
#define PPPCONNTYPE_PPPOE_BRIDGED "PPPoE_Bridged"
#define PPPCONNTYPE_PPTP_RELAY        "PPTP_Relay"
#define PPPCONNTYPE_L2TP_RELAY        "L2TP_Relay"
#define PPPCONNTYPE_PPPOE_RELAY     "PPPoE_Relay"

/**
* @brief Get list of possible connection types.
*
* Retrieves the list of possible connection types for the specified WAN connection service
* specified by the input device index and service type.
* \n Returns a comma-separated string of connection types.
* \n For IP connections: "Unconfigured,IP_Routed,IP_Bridged".
* \n For PPP connections: "Unconfigured,IP_Routed,DHCP_Spoofed,PPPoE_Bridged,PPTP_Relay,L2TP_Relay,PPPoE_Relay".
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] ConnectionTypesList - Buffer to store comma-separated list of possible connection types.
*                                   \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_get_possible_connection_types(IN INT32 WanDeviceIndex,
                                                                                        IN INT32 WanConnectionDeviceIndex,
                                                                                        IN INT32 WanConnectionServiceIndex,
                                                                                        IN INT32 ServiceType,
                                                                                        OUT CHAR *ConnectionTypesList);


// The valid value of the output parameter,"ConnectionStatus"
// possible connection status, for both IP and PPP
#define CONNSTATUS_UNCONFIGURED "Unconfigured"
#define CONNSTATUS_CONNECTED        "Connected"
#define CONNSTATUS_DISCONNECTED  "Disconnected"

/**
* @brief Get current connection status.
*
* Retrieves the current connection status of the specified WAN connection service
* specified by the input device index and service type.
* \n Reads WAN connection status from Utopia context.
* \n Possible values: "Connected", "Connecting", "Disconnecting", "Disconnected", "Unconfigured".
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] ConnectionStatus - Buffer to store current connection status string.
*                                \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
*                                \n Values: CONNSTATUS_UNCONFIGURED, CONNSTATUS_CONNECTED, CONNSTATUS_DISCONNECTED.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN connection status from Utopia.
*
*/
extern INT32 IGD_pii_get_connection_status(IN INT32 WanDeviceIndex,
                                                                        IN INT32 WanConnectionDeviceIndex,
                                                                        IN INT32 WanConnectionServiceIndex,
                                                                        IN INT32 ServiceType,
                                                                        OUT CHAR *ConnectionStatus);


/**
* @brief Get current connection type.
*
* Retrieves the current connection type of the specified WAN connection service
* specified by the input device index and service type.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] ConnectionType - Buffer to store current connection type string.
*                              \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
*                              \n Valid values same as ConnectionTypesList from IGD_pii_get_possible_connection_types().
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_get_connection_type(IN INT32 WanDeviceIndex,
                                                                    IN INT32 WanConnectionDeviceIndex,
                                                                    IN INT32 WanConnectionServiceIndex,
                                                                    IN INT32 ServiceType,
                                                                    OUT CHAR *ConnectionType);

/**
* @brief Set connection type.
*
* Sets the connection type for the specified WAN connection service
* specified by the input device index and service type.
* \n Stores the connection type value in internal static buffer.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[in] ConnectionType - Connection type string to set.
*                             \n Valid values same as ConnectionTypesList from IGD_pii_get_possible_connection_types().
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_set_connection_type(IN INT32 WanDeviceIndex,
                                                                    IN INT32 WanConnectionDeviceIndex,
                                                                    IN INT32 WanConnectionServiceIndex,
                                                                    IN INT32 ServiceType,
                                                                    IN CHAR *ConnectionType);


// The valid value of the input parameter,"ConnectionType"
// Same as the output parameter,"ConnectionTypesList", of IGD_pii_get_possible_connection_types()

/**
* @brief Request to initiate WAN connection.
*
* Initiates the connection for the specified WAN connection service
* specified by the input device index and service type.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_request_connection(IN INT32 WanDeviceIndex,
                                                                IN INT32 WanConnectionDeviceIndex,
                                                                IN INT32 WanConnectionServiceIndex,
                                                                IN INT32 ServiceType);

/**
* @brief Force terminate WAN connection.
*
* Forces termination of the connection for the specified WAN connection service
* specified by the input device index and service type.
* \n Checks if IGD internet disable is allowed. If allowed, terminate the connection.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if termination not allowed or WAN connection termination fails.
*
*/
extern INT32 IGD_pii_force_termination(IN INT32 WanDeviceIndex,
                                                            IN INT32 WanConnectionDeviceIndex,
                                                            IN INT32 WanConnectionServiceIndex,
                                                            IN INT32 ServiceType);

/**
* @brief Get external IP address.
*
* Retrieves the current external IP address used by NAT for the WAN connection
* specified by the input device index and service type.
* \n Reads WAN connection status from Utopia context and returns the IP address.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] ExternalIp - Buffer to store external IP address in string format (x.x.x.x).
*                          \n Buffer should be allocated with at least IPV4_ADDR_LEN bytes.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN connection status from Utopia.
*
*/
extern INT32 IGD_pii_get_external_ip(IN INT32 WanDeviceIndex,
                                                        IN INT32 WanConnectionDeviceIndex,
                                                        IN INT32 WanConnectionServiceIndex,
                                                        IN INT32 ServiceType,
                                                        OUT CHAR *ExternalIp);

/**
* @brief Get link layer maximum bitrates.
*
* Retrieves the maximum upstream and downstream bitrates for the WAN connection
* specified by the input device index and service type.
* \n These values are static once a connection is established.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] UpRate - Buffer to store maximum upstream bitrate in bits per second.
*                      \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
* @param[out] DownRate - Buffer to store maximum downstream bitrate in bits per second.
*                        \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_get_link_layer_max_bitrate(IN INT32 WanDeviceIndex,
                                                                            IN INT32 WanConnectionDeviceIndex,
                                                                            IN INT32 WanConnectionServiceIndex,
                                                                            IN INT32 ServiceType,
                                                                            OUT CHAR *UpRate,
                                                                            OUT CHAR *DownRate);

/**
* @brief Get WAN connection uptime.
*
* Retrieves the time in seconds that the WAN connection has stayed up.
* \n Reads WAN connection status from Utopia context and returns the uptime value.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] UpTime - Buffer to store connection uptime in seconds.
*                      \n Buffer should be allocated with sufficient size (recommend UPNP_LINE_SIZE).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN connection status from Utopia.
*
*/
extern INT32 IGD_pii_get_up_time(IN INT32 WanDeviceIndex,
                                                    IN INT32 WanConnectionDeviceIndex,
                                                    IN INT32 WanConnectionServiceIndex,
                                                    IN INT32 ServiceType,
                                                    OUT CHAR *UpTime);


/**
* @brief Get NAT and RSIP status.
*
* Retrieves the current state of NAT (Network Address Translation) and RSIP (Realm Specific IP)
* specified by the input device index and service type.
* \n Reads NAT enable status and RSIP status from Utopia context.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] NATEnable - Pointer to BOOL variable to store NAT enable status.
*                         \n Value: BOOL_TRUE (1) if NAT is enabled, BOOL_FALSE (0) if disabled.
* @param[out] RSIPAvailable - Pointer to BOOL variable to store RSIP availability.
*                             \n Value: BOOL_TRUE (1) if RSIP supported, BOOL_FALSE (0) if not supported.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_get_NAT_RSIP_status( IN INT32 WanDeviceIndex,
                            IN INT32 WanConnectionDeviceIndex,
                            IN INT32 WanConnectionServiceIndex,
                            IN INT32 ServiceType,
                            OUT BOOL *NATEnable,
                            OUT BOOL *RSIPAvailable );



//Structure definition for the output parameter,"PortmappingEntry"
#define PORT_MAP_PROTOCOL_LEN         4

// To avoid string truncation compiler warnings:
//   sizeof IGD_PortMapping_Entry.description    == sizeof portMapDyn_t.name
//   sizeof IGD_PortMapping_Entry.internalClient == sizeof portMapDyn_t.internal_host

typedef struct IGD_PortMapping_Entry{
    CHAR        remoteHost[IPADDR_SZ];            //"RemoteHost"
    UINT16      externalPort;                     //"ExternalPort"
    CHAR        protocol[PORT_MAP_PROTOCOL_LEN];  //"PortMappingProtocol"
    UINT16      internalPort;                     //"InternalPort"
    CHAR        internalClient[IPADDR_SZ];        //"InternalClient"
    BOOL        enabled;                          //"PortMappingEnabled"
    CHAR        description[NAME_SZ];             //"PortMappingDescription"
    UINT32      leaseTime;                        //"PortMappingLeaseDuration"
}IGD_PortMapping_Entry, *PIGD_PortMapping_Entry;

//Error code
#define ERROR_PORTMAPPING_ADD_FAILED         -501
#define ERROR_WILDCARD_NOTPERMIT_FOR_SRC_IP        -715 //The source IP address cannot be wild-carded(i.e. empty string)
#define ERROR_WILDCARD_NOTPERMIT_FOR_EXTERNAL_PORT -716 //The external port cannot be wild-carded(i.e. 0)
#define ERROR_CONFLICT_FOR_MAPPING_ENTRY           -718 //The port mapping entry specified conflicts with a mapping assigned previously to another client
#define ERROR_SAME_PORT_VALUE_REQUIRED             -724 //Internal and External port values must be the same
#define ERROR_ONLY_PERMANENT_LEASETIME_SUPPORTED   -725 //The NAT implementation only supports permanent lease times on port mappings
#define ERROR_REMOST_HOST_ONLY_SUPPORT_WILDCARD    -726 //RemoteHost must be a wildcard and cannot be a specific IP address or DNS name
#define ERROR_EXTERNAL_PORT_ONLY_SUPPORT_WILDCARD  -727 //ExternalPort must be a wildcard and cannot be a specific port value

/**
* @brief Add a new port mapping entry.
*
* Creates a new port mapping entry or updates an existing mapping with the same internal client.
* \n Check if entry exists and If entry exists for same internal client, updates lease time and description.
* \n If entry exists for different internal client, returns ERROR_CONFLICT_FOR_MAPPING_ENTRY.
* \n For new entries, add to configuration.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[in] PortmappingEntry - Pointer to IGD_PortMapping_Entry structure containing port mapping details.
*                               \n Required fields: remoteHost, externalPort, protocol, internalPort,
*                               \n internalClient, enabled, description, leaseTime.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if IGD configuration disabled or addition fails.
* @retval ERROR_CONFLICT_FOR_MAPPING_ENTRY if entry conflicts with existing mapping for different client.
*
*/
extern INT32 IGD_pii_add_portmapping_entry( IN INT32 WanDeviceIndex,
                                	IN INT32 WanConnectionDeviceIndex,
                                	IN INT32 WanConnectionServiceIndex,
                                	IN INT32 ServiceType,
                                	IN PIGD_PortMapping_Entry PortmappingEntry);

/**
* @brief Delete a port mapping entry.
*
* Removes a previously instantiated port mapping identified by RemoteHost, ExternalPort, and Protocol from configuration.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[in] RemoteHost - Remote host IP address string.
* @param[in] ExternalPort - External port number.
* @param[in] Protocol - Protocol string ("TCP" or "UDP").
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if deletion fails or entry not found.
*
*/
extern INT32 IGD_pii_del_portmapping_entry( IN INT32 WanDeviceIndex,
                        	IN INT32 WanConnectionDeviceIndex,
                        	IN INT32 WanConnectionServiceIndex,
                        	IN INT32 ServiceType,
                        	IN CHAR  *RemoteHost,
                        	IN UINT16  ExternalPort,
                        	IN CHAR  *Protocol);

/**
* @brief Get total number of port mapping entries.
*
* Retrieves the total count of configured port mapping entries.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[out] PortmappingEntryNum - Pointer to INT32 variable to store the total number of port mapping entries.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
extern INT32 IGD_pii_get_portmapping_entry_num(IN INT32 WanDeviceIndex,
                                        IN INT32 WanConnectionDeviceIndex,
                                        IN INT32 WanConnectionServiceIndex,
                                        IN INT32 ServiceType,
                                        OUT INT32 *PortmappingEntryNum);


// Error code
#define ERROR_SPECIFIED_INDEX_INVALID -713 //The Specified index is out of bounds

/**
* @brief Get port mapping entry by index.
*
* Retrieves a specific port mapping entry by its index number.
* \n Index range: 0 to PortmappingEntryNum-1 (IGD uses 0-based indexing).
* \n Populates all fields of the PortmappingEntry structure.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[in] PortmappingIndex - Index of the port mapping entry to retrieve.
*                               \n Valid range: 0 to PortmappingEntryNum-1.
* @param[out] PortmappingEntry - Pointer to IGD_PortMapping_Entry structure to store the retrieved entry.
*                                \n All fields will be populated on success.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if index out of range or retrieval fails.
*
*/
extern INT32 IGD_pii_get_portmapping_entry_generic( IN INT32 WanDeviceIndex,
                                IN INT32 WanConnectionDeviceIndex,
                                IN INT32 WanConnectionServiceIndex,
                                IN INT32 ServiceType,
                                IN INT32 PortmappingIndex,
                                OUT PIGD_PortMapping_Entry PortmappingEntry);


/*Special notes for the INOUT parameter,PortmappingEntry
typedef struct IGD_PortMapping_Entry{
    CHAR        remoteHost[IPV4_ADDR_LEN];        //IN
    UINT16      externalPort;                     //IN
    CHAR        protocol[PORT_MAP_PROTOCOL_LEN];  //IN

    UINT16      internalPort;                    //OUT
    CHAR        internalClient[IPV4_ADDR_LEN];   //OUT
    BOOL        enabled;                         //OUT
    CHAR        description[NAME_SZ];            //OUT
    UINT32      leaseTime;                       //OUT
}IGD_PortMapping_Entry, *PIGD_PortMapping_Entry; */

//Error code
#define ERROR_NO_SUCH_ENTRY -714 // The specified value doesn't exist

/**
* @brief Get port mapping entry by unique tuple.
*
* Retrieves a specific port mapping entry by its unique tuple of RemoteHost, ExternalPort, and Protocol.
* \n Input: remoteHost, externalPort, protocol fields of PortmappingEntry parameter.
* \n Output: internalPort, internalClient, enabled, description, leaseTime fields.
* \n Related UPnP Device/Service: WAN(IP/PPP)ConnectionService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[in] WanConnectionServiceIndex - Index of WAN(IP/PPP)ConnectionService, range: 1 to Number of services.
* @param[in] ServiceType - Type of WAN connection service.
*                          \n Valid values: SERVICETYPE_IP (1) or SERVICETYPE_PPP (2).
* @param[in,out] PortmappingEntry - Pointer to IGD_PortMapping_Entry structure.
*                                   \n INPUT fields: remoteHost, externalPort, protocol.
*                                   \n OUTPUT fields: internalPort, internalClient, enabled, description, leaseTime.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if entry not found.
*
*/
extern INT32 IGD_pii_get_portmapping_entry_specific( IN INT32 WanDeviceIndex,
                                IN INT32 WanConnectionDeviceIndex,
                                IN INT32 WanConnectionServiceIndex,
                                IN INT32 ServiceType,
                                INOUT PIGD_PortMapping_Entry PortmappingEntry);


// The valid value of the output parameter,"status"
#define ETHERNETLINKSTATUS_UP			"Up"
#define ETHERNETLINKSTATUS_DOWN			"Down"
#define ETHERNETLINKSTATUS_UNAVAILABLE	"Unavailable"

/**
* @brief Get Ethernet link status.
*
* Retrieves the link status of the WAN Ethernet connection.
* \n Reads WAN connection status from Utopia contex and returns "Up" if phylink_up is non-zero, "Down" otherwise.
* \n Related UPnP Device/Service: WANEthernetLinkConfigService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] WanConnectionDeviceIndex - Index of WANConnectionDevice, range: 1 to Number of WANConnectionDevices.
* @param[out] EthernetLinkStatus - Buffer to store Ethernet link status string.
*                                  \n Buffer should be allocated with at least 16 bytes.
*                                  \n Values: ETHERNETLINKSTATUS_UP, ETHERNETLINKSTATUS_DOWN, ETHERNETLINKSTATUS_UNAVAILABLE.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN connection status from Utopia.
*
*/
extern INT32 IGD_pii_get_ethernet_link_status(IN INT32 WanDeviceIndex,
													IN INT32 WanConnectionDeviceIndex,
													OUT CHAR *EthernetLinkStatus);

// The valid value of the output parameter,"WanAccessType"
#define WANACCESSTYPE_DSL 		"DSL"
#define WANACCESSTYPE_POTS 		"POTS"
#define WANACCESSTYPE_CABLE 	"Cable"
#define WANACCESSTYPE_ETHERNET 	"Ethernet"

// The valid value of the output parameter,"PhyscialLinkStatus"
#define LINKSTATUS_UP 	"Up"
#define LINKSTATUS_DOWN "Down"

/**
* @brief Get common link properties of WAN device.
*
* Retrieves common link properties including WAN access type, maximum bitrates, and physical link status
* specified by the input device index.
* \n Related UPnP Device/Service: WANCommonInterfaceConfigService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[out] WanAccessType - Buffer to store WAN access type string.
*                             \n Buffer should be allocated with at least 16 bytes.
*                             \n Values: WANACCESSTYPE_DSL, WANACCESSTYPE_POTS, WANACCESSTYPE_CABLE, WANACCESSTYPE_ETHERNET.
* @param[out] Layer1UpstreamMaxBitRate - Buffer to store maximum upstream bitrate in bits per second.
*                                        \n Buffer should be allocated with at least 16 bytes.
* @param[out] Layer1DownstreamMaxBitRate - Buffer to store maximum downstream bitrate in bits per second.
*                                          \n Buffer should be allocated with at least 16 bytes.
* @param[out] PhyscialLinkStatus - Buffer to store physical link status string.
*                                  \n Buffer should be allocated with at least 16 bytes.
*                                  \n Values: LINKSTATUS_UP or LINKSTATUS_DOWN.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN connection status from Utopia.
*
*/
extern INT32 IGD_pii_get_common_link_properties(IN INT32 WanDeviceIndex,
														OUT CHAR *WanAccessType,
														OUT CHAR *Layer1UpstreamMaxBitRate,
														OUT CHAR *Layer1DownstreamMaxBitRate,
														OUT CHAR *PhyscialLinkStatus);


/**
* @brief Get WAN device traffic statistics.
*
* Retrieves traffic statistics including total bytes and packets sent/received on the WAN device
* specified by the input device index.
* \n Related UPnP Device/Service: WANCommonInterfaceConfigService.
*
* @param[in] WanDeviceIndex - Index of WANDevice, range: 1 to Number of WANDevices.
* @param[in] bufsz - Size of output buffers for all four output parameters (all buffers must be same size).
* @param[out] TotalBytesSent - Buffer to store total bytes sent on WAN device.
*                              \n Buffer should be allocated with size specified by bufsz parameter.
* @param[out] TotalBytesReceived - Buffer to store total bytes received on WAN device.
*                                  \n Buffer should be allocated with size specified by bufsz parameter.
* @param[out] TotalPacketsSent - Buffer to store total packets sent on WAN device.
*                                \n Buffer should be allocated with size specified by bufsz parameter.
* @param[out] TotalPacketsReceived - Buffer to store total packets received on WAN device.
*                                    \n Buffer should be allocated with size specified by bufsz parameter.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving WAN traffic statistics.
*
*/
INT32 IGD_pii_get_traffic_stats(IN INT32 WanDeviceIndex,
				IN INT32 bufsz,
				OUT CHAR *TotalBytesSent,
				OUT CHAR *TotalBytesReceived,
				OUT CHAR *TotalPacketsSent,
				OUT CHAR *TotalPacketsReceived);

/**
* @brief Get LAN DHCP server configurability status.
*
* Returns whether the DHCP server is configurable via UPnP IGD.
* \n It is security violation to allow DHCP Server to be configurable using UPnP IGD currently
* there is no authentication to protect DHCP server set methods hence return NOT configurable
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[out] status - Buffer to store configurability status.
*                     \n Buffer should be allocated with at least 16 bytes.
*                     \n Always returns "0" (not configurable).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
INT32 IGD_pii_get_lan_dhcpserver_configurable(IN INT32 LanDeviceIndex, OUT CHAR *status);

/**
* @brief Get LAN DHCP relay status.
*
* Checks if the device is in bridge mode (DHCP relay) or router mode.
* \n Checks if bridge mode, then return 1 and if router mode, then return 0
* \n To be enhanced as part of LAN Auto-Bridging feature.
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[out] status - Buffer to store DHCP relay status.
*                     \n Buffer should be allocated with at least 16 bytes.
*                     \n Returns "1" if bridge mode (DHCP relay), "0" if router mode.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero error code if failure.
*
*/
INT32 IGD_pii_get_lan_dhcp_relay_status(IN INT32 LanDeviceIndex, OUT CHAR *status);

/**
* @brief Get LAN device information.
*
* Retrieves LAN device settings including IP address, subnet mask, and domain name.
* \n Reads LAN settings from Utopia context .
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[in] bufsz - Size of output buffers for all three output parameters (all buffers must be same size).
* @param[out] ipaddr - Buffer to store LAN IP address
*                     \n Buffer should be allocated with size specified by bufsz parameter.
* @param[out] subnet_mask - Buffer to store subnet mask address.
*                          \n Buffer should be allocated with size specified by bufsz parameter.
* @param[out] domain_name - Buffer to store domain name of the device.
*                          \n Buffer should be allocated with size specified by bufsz parameter.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving LAN settings from Utopia.
*
*/
INT32 IGD_pii_get_lan_info(IN INT32 LanDeviceIndex, IN INT32 bufsz, OUT CHAR *ipaddr, OUT CHAR *subnet_mask, OUT CHAR *domain_name);

/**
* @brief Get LAN DNS servers.
*
* Retrieves the list of DNS servers for the LAN device.
* \n Currently system uses router's DNS proxy as the LAN's DNS server,
* \n so returns LAN default gateway address (router IP) as the DNS server address.
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[out] dns_servers - Buffer to store comma-separated list of DNS server addresses.
*                          \n Buffer should be allocated with size specified by max_list_sz parameter.
* @param[in] max_list_sz - Maximum size of dns_servers buffer.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving LAN settings from Utopia.
*
*/
INT32 IGD_pii_get_lan_dns_servers(IN INT32 LanDeviceIndex, OUT CHAR *dns_servers, IN INT32 max_list_sz);

/**
* @brief Get LAN DHCP address range.
*
* Retrieves the DHCP address range (minimum and maximum addresses) for the LAN DHCP server.
* \n Reads DHCP server settings and LAN settings from Utopia context.
* \n Calculates range using LAN IP subnet and DHCP server's DHCPIPAddressStart and DHCPMaxUsers.
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[in] buf_sz - Size of output buffers for both output parameters (both buffers must be same size).
* @param[out] min_address - Buffer to store start address of DHCP range.
*                          \n Buffer should be allocated with size specified by buf_sz parameter.
* @param[out] max_address - Buffer to store end address of DHCP range.
*                          \n Buffer should be allocated with size specified by buf_sz parameter.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving DHCP server or LAN settings from Utopia.
*
*/
INT32 IGD_pii_get_lan_addr_range(IN INT32 LanDeviceIndex, IN INT32 buf_sz, OUT CHAR *min_address, OUT CHAR *max_address);

/**
* @brief Get LAN reserved DHCP address list.
*
* Retrieves the list of reserved DHCP addresses (static host mappings) configured on the LAN DHCP server.
* \n Reads LAN settings and DHCP static hosts from Utopia context.
* \n Returns comma-separated list of IP addresses that have static DHCP reservations.
*
* @param[in] LanDeviceIndex - Index of LANDevice, range: 1 to Number of LANDevices.
* @param[out] reserved_list - Buffer to store comma-separated list of reserved DHCP IP addresses.
*                            \n Buffer should be allocated with size specified by max_list_sz parameter.
* @param[in] max_list_sz - Maximum size of reserved_list buffer.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error retrieving LAN settings or DHCP static hosts from Utopia.
*
*/
INT32 IGD_pii_get_lan_reserved_addr_list(IN INT32 LanDeviceIndex, OUT CHAR *reserved_list, IN INT32 max_list_sz);

#endif /*IGD_PLATFORM_INDEPENDENT_INF_H*/