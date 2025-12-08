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
#ifndef MNET_SWFAB_EP_H
#define MNET_SWFAB_EP_H

#include "service_multinet_swfab_deps.h"

#define SWFAB_ENTITY_PORTMEMBER_KEY_FORMAT(vlan,entID) "vid_%d_entity_%d_members", vlan, entID
#define SWFAB_PORT_PATHREF_KEY_FORMAT(vlan,portID) "vid_%d_port_%s_paths", vlan, portID
#define SWFAB_VID_ENTITYMEMBER_KEY_FORMAT(vlan) "vid_%d_entities", vlan
#define SWFAB_VID_TRUNKMEMBER_KEY_FORMAT(vlan) "vid_%d_trunkports", vlan

/**
 * @brief Sets the member port names for a specific entity within a VLAN.
 *
 * This function stores the list of member port names associated with an entity in the specified VLAN
 * to persistent storage using sysevent. The key format is "vid_<vlan>_entity_<entID>_members".
 *
 * @param[in] vid - VLAN ID.
 * @param[in] entity - Entity ID.
 * @param[in] memberPortNames - Array of port name strings to set as members.
 * @param[in] numPorts - Number of ports in the memberPortNames array.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_set_entity_vid_portMembers(int vid, int entity, char* memberPortNames[], int numPorts);

/**
 * @brief Sets the list of entity IDs that are members of a VLAN.
 *
 * This function stores the list of entity IDs associated with a VLAN to persistent storage
 * using sysevent. The key format is "vid_<vlan>_entities".
 *
 * @param[in] vid - VLAN ID.
 * @param[in] entities - Array of entity IDs to set as VLAN members.
 * @param[in] numEntities - Number of entities in the entities array.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_set_entity_vidMembers(int vid, int entities[], int numEntities);

/**
 * @brief Sets the entity path dependencies for a trunk port in a VLAN.
 *
 * This function stores the list of entity path dependencies (A,B pairs) for a trunk port
 * in the specified VLAN to persistent storage using sysevent. The key format is
 * "vid_<vlan>_port_<portID>_paths". Each path is stored as "A,B" format.
 *
 * @param[in] vid - VLAN ID.
 * @param[in] portName - Name of the trunk port.
 * @param[in] paths - Array of EntityPath structures containing A and B entity endpoints.
 * @param[in] numPaths - Number of paths in the paths array.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_set_trunkPort_vid_paths(int vid, char* portName, PEntityPath paths, int numPaths);

/**
 * @brief Sets the list of trunk port names for a VLAN.
 *
 * This function stores the list of trunk port names associated with a VLAN to persistent storage
 * using sysevent. The key format is "vid_<vlan>_trunkports".
 *
 * @param[in] vid - VLAN ID.
 * @param[in] portNames - Array of trunk port name strings.
 * @param[in] numPorts - Number of ports in the portNames array.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_set_trunkPort_vidMembers(int vid, char* portNames[], int numPorts);

/**
 * @brief Retrieves the member port names for a specific entity within a VLAN.
 *
 * This function retrieves the list of member port names associated with an entity in the specified VLAN
 * from persistent storage using sysevent. Port names are tokenized from space-separated storage format.
 * The function respects MAX_ADD_PORTS limit.
 *
 * @param[in] vid - VLAN ID.
 * @param[in] entity - Entity ID.
 * @param[out] memberPortNames - Array of pointers to receive port name strings from buf.
 * @param[in,out] numPorts - Pointer to number of ports retrieved.
 * @param[out] buf - Buffer to store port name strings.
 * @param[in] bufSize - Size of the buf buffer in bytes.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_get_entity_vid_portMembers(int vid, int entity, char* memberPortNames[], int* numPorts, char buf[], int bufSize );

/**
 * @brief Retrieves the list of entity IDs that are members of a VLAN.
 *
 * This function retrieves the list of entity IDs associated with a VLAN from persistent storage
 * using sysevent. Entity IDs are tokenized from space-separated storage format.
 *
 * @param[in] vid - VLAN ID.
 * @param[out] entities - Array to receive entity IDs.
 * @param[in,out] numEntities - Pointer to number of entities retrieved.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_get_entity_vidMembers(int vid, int entities[], int* numEntities);

/**
 * @brief Retrieves the entity path dependencies for a trunk port in a VLAN.
 *
 * This function retrieves the list of entity path dependencies (A,B pairs) for a trunk port
 * in the specified VLAN from persistent storage using sysevent. Each path is parsed from
 * "A,B" comma-separated format.
 *
 * @param[in] vid - VLAN ID.
 * @param[in] portName - Name of the trunk port.
 * @param[out] paths - Array of EntityPath structures to receive path dependencies.
 * @param[in,out] numPaths - Pointer to number of paths retrieved.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_get_trunkPort_vid_paths(int vid, char* portName, PEntityPath paths, int* numPaths);

/**
 * @brief Retrieves the list of trunk port names for a VLAN.
 *
 * This function retrieves the list of trunk port names associated with a VLAN from persistent storage
 * using sysevent. Port names are tokenized from space-separated storage format.
 * The function respects MAX_ADD_PORTS limit.
 *
 * @param[in] vid - VLAN ID.
 * @param[out] portNames - Array of pointers to receive port name strings from buf.
 * @param[in,out] numPorts - Pointer to number of ports retrieved.
 * @param[out] buf - Buffer to store port name strings.
 * @param[in] bufSize - Size of the buf buffer in bytes.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int ep_get_trunkPort_vidMembers(int vid, char* portNames[], int* numPorts, char buf[], int bufSize);

#endif
