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
#ifndef MNET_NV_H
#define MNET_NV_H

#define MNET_NV_PRIMARY_L2_INST_KEY "dmsb.MultiLAN.PrimaryLAN_l2net"
#define MNET_NV_PRIMARY_L2_INST_FORMAT "%3d"

#include "service_multinet_base.h"


/**
* @brief Get member interfaces from non-volatile storage for a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[out] memberList - Pointer to the array of Member structures to store retrieved members.
* @param[in] numMembers - Maximum number of members that can be stored in the memberList array.
*
* @return The actual number of members retrieved.
* @retval number of members on success
* @retval 0 on failure
*
*/
int nv_get_members(PL2Net net, PMember memberList, int numMembers);
/**
* @brief Get bridge configuration from non-volatile storage for a Layer 2 network instance.
*
* @param[in] l2netInst - The Layer 2 network instance identifier.
* @param[out] net - Pointer to the L2Net structure to store the bridge configuration.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int nv_get_bridge(int l2netInst, PL2Net net);
/**
* @brief Get the primary Layer 2 network instance identifier from non-volatile storage.
*
* @return The primary Layer 2 network instance identifier.
*
*/
int nv_get_primary_l2_inst(void);
#if defined(MESH_ETH_BHAUL)
/**
* @brief Toggle Ethernet backhaul ports on or off.
*
* @param[in] onOff - Boolean flag to enable (TRUE) or disable (FALSE) Ethernet backhaul ports.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on failure.
*
*/
int nv_toggle_ethbhaul_ports(BOOL onOff);
#endif

#endif
