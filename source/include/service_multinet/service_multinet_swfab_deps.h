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
#ifndef MNET_DEPS_H
#define MNET_DEPS_H

#include "service_multinet_base.h"
#include "service_multinet_swfab.h"
#include "service_multinet_util.h"

typedef struct vlanDepState {
    int vid;
    List trunkPorts;
    List memberEntities;
    BOOL trunksDirty;
    BOOL entitiesDirty;
} VlanTrunkState, *PVlanTrunkState;

typedef struct trunkPort {
    PPlatformPort port;
    List pathList;
    BOOL dirty;
} TrunkPort, *PTrunkPort;

typedef struct entityPortlist {
    int entity;
    List memberPorts;
    BOOL dirty;
} EntityPortList, *PEntityPortList;

typedef struct entityPath {
    int A;
    int B;
} EntityPath, *PEntityPath;

typedef struct entityPathDeps {
    EntityPath path;
    int numPorts;
    PPlatformPort* trunkPorts;

} EntityPathDeps, *PEntityPathDeps;


//---- Public

/**
 * @brief Adds a new port to a VLAN entity and retrieves trunk ports that need configuration.
 *
 * This function adds a new platform port to its associated entity within the VLAN state.
 * If the entity does not exist, it creates the entity and calculates path dependencies to other entities,
 * then populates the list with trunk ports that require configuration. Fills listToAppend with new trunk
 * ports that should be configured (PPlatformPort).
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] newPort - Pointer to the platform port to be added.
 * @param[out] listToAppend - Pointer to list where new trunk ports requiring configuration will be appended.
 *
 * @return The number of trunk ports that were changed/added.
 */
int addAndGetTrunkPorts(PVlanTrunkState vidState, PPlatformPort newPort, PList listToAppend);

/**
 * @brief Removes a port from a VLAN entity and retrieves trunk ports that need cleanup.
 *
 * This function removes a platform port from its entity and dereferences all trunk ports
 * that were dependent on paths involving this entity. Trunk ports with no remaining path dependencies
 * are added to the output list for removal/cleanup.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] oldPort - Pointer to the platform port to be removed.
 * @param[out] listToAppend - Pointer to list where trunk ports requiring cleanup will be appended.
 *
 * @return The number of trunk ports that were changed/removed.
 */
int removeAndGetTrunkPorts(PVlanTrunkState vidState, PPlatformPort oldPort, PList listToAppend);

/**
 * @brief Retrieves or creates the VLAN state structure for a specified VLAN ID.
 *
 * This function searches for an existing VLAN state matching the given VLAN ID.
 * If found, it returns the existing state. If not found, it allocates a new VLAN state structure,
 * loads its configuration from persistent storage, and returns it.
 *
 * @param[out] vidState - Pointer to receive the VLAN trunk state structure pointer.
 * @param[in] vid - VLAN ID to search for or create.
 *
 * @return Status indicating if state was found or created.
 * @retval 1 if an existing VLAN state was found.
 * @retval 0 if a new VLAN state was allocated and loaded.
 */
int getVlanState(PVlanTrunkState* vidState, int vid);

//---- Private

/**
 * @brief Searches for an entity within the specified VLAN state.
 *
 * This function iterates through the member entities list of the VLAN state to find
 * a matching entity by entity ID.
 *
 * @param[in] vidState - Pointer to the VLAN trunk state structure to search.
 * @param[in] entity - Entity ID to search for.
 *
 * @return Pointer to the EntityPortList structure if found.
 * @retval Non-NULL pointer if entity is a VLAN member.
 * @retval NULL if entity is not a VLAN member.
 */
PEntityPortList getEntity(PVlanTrunkState vidState, int entity);

/**
 * @brief Adds a new entity to the VLAN state.
 *
 * This function allocates and initializes a new entity port list structure and adds it to the
 * member entities list of the VLAN state. The entities dirty flag is set to indicate changes.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] entity - Entity ID to add.
 *
 * @return Pointer to the newly created EntityPortList structure.
 */
PEntityPortList addEntity(PVlanTrunkState vidState, int entity);

/**
 * @brief Adds a new trunk port to the VLAN state.
 *
 * This function allocates and initializes a new trunk port structure with the specified platform port
 * and adds it to the trunk ports list of the VLAN state. The trunks dirty flag is set to indicate changes.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] platport - Pointer to the platform port to be added as a trunk.
 *
 * @return Pointer to the newly created TrunkPort structure.
 */
PTrunkPort addTrunkPort(PVlanTrunkState vidState, PPlatformPort platport);

/**
 * @brief Adds an entity path dependency to a trunk port.
 *
 * This function allocates and adds a new entity path to the trunk port's path list,
 * indicating a dependency relationship. The trunk port's dirty flag is set to indicate changes.
 *
 * @param[in,out] port - Pointer to the trunk port structure.
 * @param[in] path - Pointer to the entity path structure to be added.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int addPathToTrunkPort(PTrunkPort port, PEntityPath path);

/**
 * @brief Adds a path reference to a trunk port, or adds the port if not previously referenced.
 *
 * This function searches for an existing trunk port matching the specified platform port.
 * If found, it adds the path dependency to the existing port. If not found, it creates a new
 * trunk port and adds it to the VLAN state with the specified path dependency.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] port - Pointer to the platform port to reference.
 * @param[in] path - Pointer to the entity path dependency to add.
 *
 * @return Status indicating if a new port was added.
 * @retval 1 if a new port was added to the VLAN.
 * @retval 0 if only a path reference was added to an existing port.
 */
int refTrunkPort(PVlanTrunkState vidState, PPlatformPort port, PEntityPath path);

/**
 * @brief Searches for and removes path references matching the specified entity.
 *
 * This function iterates through the trunk port's path list and removes all paths
 * where either endpoint (A or B) matches the specified entity ID. The port's dirty flag
 * is set if any paths are removed.
 *
 * @param[in,out] port - Pointer to the trunk port structure.
 * @param[in] entity - Entity ID to match and remove from path dependencies.
 *
 * @return Status indicating if all paths were removed.
 * @retval 1 if no paths remain for this trunk port.
 * @retval 0 if paths still exist for this trunk port.
 */
int deRefTrunkPort(PTrunkPort port, int entity);

/**
 * @brief Removes a member port from an entity, and removes the entity if it becomes empty.
 *
 * This function searches for the specified entity in the VLAN state, removes the given port
 * from its member port list, and if the entity has no remaining member ports, removes the entity
 * from the VLAN state and clears its persistent storage configuration.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure.
 * @param[in] entity - Entity ID from which to remove the port.
 * @param[in] port - Pointer to the platform port to remove.
 *
 * @return Status indicating if the entity was emptied.
 * @retval 1 if the entity was emptied and removed.
 * @retval 0 if the entity still has remaining member ports.
 */
int deRefEntity(PVlanTrunkState vidState, int entity, PPlatformPort port);

/**
 * @brief Adds a member port to an entity's port list.
 *
 * This function adds a platform port to the entity's member port list if it is not already present.
 * It checks for duplicate ports by comparing HAL IDs and using the HAL's equality check.
 * The entity's dirty flag is set to indicate changes.
 *
 * @param[in,out] entity - Pointer to the entity port list structure.
 * @param[in] port - Pointer to the platform port to add.
 *
 * @return Status of the operation.
 * @retval 0 if the port was added successfully or already exists.
 * @retval -1 if the port pointer is NULL.
 */
int addMemberPort(PEntityPortList entity, PPlatformPort port);

/**
 * @brief Removes a member port from an entity's port list.
 *
 * This function searches for a platform port in the entity's member port list by comparing
 * HAL IDs and using the HAL's equality check. If found, it removes the port and sets
 * the entity's dirty flag.
 *
 * @param[in,out] entity - Pointer to the entity port list structure.
 * @param[in] port - Pointer to the platform port to remove.
 *
 * @return Status of the operation.
 * @retval 1 if the port was found and removed.
 * @retval 0 if the port was not found in the list.
 */
int remMemberPort(PEntityPortList entity, PPlatformPort port);

/**
 * @brief Saves the VLAN state to persistent storage.
 *
 * This function persists the current VLAN state including member entities, their port memberships,
 * trunk ports, and path dependencies to endpoint storage. It processes dirty flags to determine
 * which elements need to be saved.
 *
 * @param[in] vidState - Pointer to the VLAN trunk state structure to save.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int saveVlanState(PVlanTrunkState vidState);

/**
 * @brief Loads the VLAN state from persistent storage.
 *
 * This function retrieves VLAN configuration from endpoint storage including entity memberships,
 * member ports for each entity, trunk ports, and their path dependencies. It populates the VLAN
 * state structure and clears all dirty flags after loading.
 *
 * @param[in,out] vidState - Pointer to the VLAN trunk state structure to populate.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int loadVlanState(PVlanTrunkState vidState);

#endif
