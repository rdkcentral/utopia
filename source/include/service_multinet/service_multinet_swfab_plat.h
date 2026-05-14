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
#ifndef MNET_SWFAB_PLAT_H
#define MNET_SWFAB_PLAT_H

#include "service_multinet_base.h"
#include "service_multinet_swfab_deps.h"

/**
 * @brief Maps a network interface to its corresponding platform port.
 *
 * This is a platform-specific mapping between DM (Data Model) ports and physical ports.
 * The function fills in the "map" member of the interface structure with a PPlatformPort pointer
 * to a complete platform port, including HAL references. Integrators may utilize any approach
 * to expedite mapping, such as port naming conventions. The pointers returned from this function
 * are internally managed by the mapping code and will not be freed by the framework.
 *
 * @param[in,out] iface - Pointer to network interface structure.
 *                        \n iface->type->name contains the interface type (WiFi, SW, Gre, Eth, Moca, virt).
 *                        \n iface->name contains the interface name for parsing.
 *                        \n iface->map will be populated with the platform port mapping.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int mapToPlat(PNetInterface iface);

/**
 * @brief Returns entity path dependency information for connecting two entities.
 *
 * This function returns a pointer to an EntityPathDeps structure that defines a list of trunk ports
 * requiring configuration to connect the two specified entities. It is expected that this information
 * can be provided for any combination of entity IDs. This mapping must remain static - the framework
 * does not support re-mapping of trunk ports for existing paths.
 *
 * @param[in] entityLow - Lower entity ID. Must be less than entityHigh.
 * @param[in] entityHigh - Higher entity ID. Must be greater than entityLow.
 *
 * @return Pointer to EntityPathDeps structure containing trunk port configuration requirements.
 */
PEntityPathDeps getPathDeps(int entityLow, int entityHigh);

/**
 * @brief Returns the platform port represented by its string ID.
 *
 * This function maps a string-based port identifier to its corresponding platform port structure.
 * The string ID is retrieved via the HAL's stringID function. This is primarily used when loading
 * from non-volatile storage or string-based runtime data stores.
 *
 * @param[in] portIdString - String identifier of the port to map.
 *
 * @return Pointer to the platform port structure.
 * @retval Non-NULL pointer if mapping is found.
 * @retval NULL if no mapping is found for the given string.
 */
PPlatformPort plat_mapFromString(char* portIdString);


#endif
