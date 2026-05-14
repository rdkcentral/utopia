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
   Copyright [2015] [Cisco Systems, Inc.]

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
#ifndef MNET_LIB_H
 #define MNET_LIB_H

 #include "service_multinet_base.h"
#include <stdbool.h>


 #define MAX_MEMBERS 32

#if defined (INTEL_PUMA7) || defined(MULTILAN_FEATURE)
//Intel Proposed RDKB Bug Fix
#define MAX_BUF_SIZE 256
#define MAX_IFNAME_SIZE 32
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_NOK
#define STATUS_NOK 1
#endif
#endif //defined (INTEL_PUMA7)

 extern unsigned char isDaemon;
 extern char* executableName;

 extern bool ethWanEnableState;
/**
* @brief Bring up a Layer 2 network bridge.
*
* This function load the stored configuration and initialize the bridge network.
*
* @param[in] network - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] bFirewallRestart - Flag indicating whether to restart the firewall.
*                             \n Non-zero value triggers firewall restart.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_bridgeUp(PL2Net network, int bFirewallRestart);

 /**
* @brief Bring up a Layer 2 network bridge by instance identifier.
*
* This function uses the network instance ID to load the stored configuration and initialize the bridge network.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
* @param[in] bFirewallRestart - Flag indicating whether to restart the firewall.
*                             \n Non-zero value triggers firewall restart.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_bridgeUpInst(int l2netInst, int bFirewallRestart);

/**
* @brief Bring down a Layer 2 network bridge.
*
* @param[in] network - Pointer to the L2Net structure representing the Layer 2 network.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_bridgeDown(PL2Net network);

 /**
* @brief Bring down a Layer 2 network bridge by instance identifier.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_bridgeDownInst(int l2netInst);

/**
* @brief Synchronize a Layer 2 network with specified member interfaces.
*
* @param[in] network - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to synchronize.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_Sync(PL2Net network, PMember members, int numMembers);

 /**
* @brief Synchronize a Layer 2 network by instance identifier.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_SyncInst(int l2netInst);

/**
* @brief Synchronize all Layer 2 network bridges in the system.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_bridgesSync();

/**
* @brief Update the interface status for a member in a Layer 2 network.
*
* @param[in] network - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] interface - Pointer to the Member structure representing the interface.
* @param[in] status - The interface status to set.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_ifStatusUpdate(PL2Net network, PMember interface, IF_STATUS status);

 /**
* @brief Update the interface status using identifier strings.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
* @param[in] ifname - Pointer to the interface name string.
* @param[in] ifType - Pointer to the interface type string.
* @param[in] status - Pointer to the status string.
* @param[in] tagging - Pointer to the VLAN tagging configuration string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_ifStatusUpdate_ids(int l2netInst, char* ifname, char* ifType, char* status, char* tagging);

/**
* @brief Initialize the multinet library.
*
* @param[in] daemon - Flag indicating whether running as a daemon (TRUE) or not (FALSE).
* @param[in] exeName - Pointer to the executable name string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_lib_init(BOOL daemon, char* exeName);

#if defined (INTEL_PUMA7) || defined(MULTILAN_FEATURE)
//Intel Proposed RDKB Bug Fix
/**
* @brief Get the interface name from the port name.
*
* Get the interface name from the port name. ifName would be the real interface name
* if it's not switch port. Otherwise, ifName would be same as port name.

* @param[out] ifName - Pointer to the buffer to store the interface name string.
* @param[in] portName - Pointer to the port name string.
*
* @return The status of the operation.
* @retval STATUS_OK on success.
* @retval STATUS_NOK on failure.
*
*/
 int getIfName(char *ifName, char* portName);

#endif

#if defined(MULTILAN_FEATURE)
/**
* @brief Assign a CIDR block to a bridge for a Layer 2 network instance.
*
* This function assign an address in CIDR format to a bridge instance.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
* @param[in] CIDR - Pointer to the CIDR notation string.
* @param[in] IPVersion - IP version type.
*                     \n Value 4 for IPv4 or 6 for IPv6.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int multinet_assignBridgeCIDR(int l2netInst, char *CIDR, int IPVersion);

 #endif

#if defined(MESH_ETH_BHAUL)
/**
* @brief Toggle Ethernet backhaul ports on or off.
*
* @param[in] onOff - Boolean flag to enable (TRUE) or disable (FALSE) Ethernet backhaul ports.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
 int toggle_ethbhaul_ports(BOOL onOff);

#endif

 #endif