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
#ifndef MNET_EP_H
#define MNET_EP_H

#include "service_multinet_base.h"

#define MNET_EP_ALLMEMBERS_KEY_FORMAT(x) "multinet_%d-allMembers", x
#define MNET_EP_MEMBER_FORMAT(ifname, iftype, ready) "%[^:]:%[^,],%hhu", iftype, ifname, ready
#define MNET_EP_MEMBER_SET_FORMAT(ifname, iftype, ready) "%s:%s,%hhu" , iftype, ifname, ready
#define MNET_EP_BRIDGE_VID_FORMAT(instance) "multinet_%d-vid", instance
#define MNET_EP_BRIDGE_NAME_FORMAT(instance) "multinet_%d-name", instance
#define MNET_EP_BRIDGE_MODE_KEY "bridge_mode"

//int ep_set_memberStatus(PL2Net net, PMember member);

/**
* @brief Get all member interfaces of a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[out] live_members - Pointer to the array of Member structures to store retrieved members.
* @param[in] numMembers - Maximum number of members that can be stored in the live_members array.
*
* @return The actual number of members retrieved.
*
*/
int ep_get_allMembers(PL2Net net, PMember live_members, int numMembers);

/**
* @brief Set all member interfaces for a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to be set.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_set_allMembers(PL2Net net, PMember members, int numMembers);

/**
* @brief Clear all members and configuration for a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network to clear.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_clear(PL2Net net); // TODO


/**
* @brief Add a Layer 2 network to the active networks list.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network to add.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_add_active_net(PL2Net net); // TODO deferred

/**
* @brief Remove a Layer 2 network from the active networks list.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network to remove.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_rem_active_net(PL2Net net); // TODO deferred

/**
* @brief Check if a Layer 2 network instance is started.
*
* @param[in] netInst - The Layer 2 network instance identifier.
*
* @return The network started status.
* @retval Non-zero if the network is started.
* @retval 0 if the network is not started.
*
*/
int ep_netIsStarted(int netInst); // TODO

/**
* @brief Get bridge configuration for a Layer 2 network instance.
*
* @param[in] l2netinst - The Layer 2 network instance identifier.
* @param[out] net - Pointer to the L2Net structure to store the bridge configuration.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_get_bridge(int l2netinst, PL2Net net);

/**
* @brief Set bridge configuration for a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure containing the bridge configuration to set.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_set_bridge(PL2Net net);

/**
* @brief Get the current bridge mode setting.
*
* @return The bridge mode value.
*
*/
int ep_get_bridge_mode(void);

//-- Raw

/**
* @brief Set a raw string value for a specified key.
*
* @param[in] key - Pointer to the key string.
* @param[in] value - Pointer to the value string to set.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_set_rawString(char* key, char* value);

/**
* @brief Get a raw string value for a specified key.
*
* @param[in] key - Pointer to the key string.
* @param[out] value - Pointer to the buffer to store the retrieved value string.
* @param[in] valueSize - Size of the value buffer in bytes.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ep_get_rawString(char* key, char* value, int valueSize);


#endif