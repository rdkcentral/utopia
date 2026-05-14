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

#ifndef MNET_HANDLER_H
#define MNET_HANDLER_H

#include "service_multinet_base.h"
#ifdef MULTINET_IFHANDLER_PLUGIN
#include "service_multinet_ifplugin_defs.h"
#endif
enum defaultHandlers {
	IFTYPE_SWFAB = 0,
	NUM_DEFAULT_IFTYPES
};

typedef struct memberControl {
    PMember member;
    int* handled;
    int numMembers;
    //int remaining;
}MemberControl, *PMemberControl;

typedef int (*memberHandlerFunc)(PL2Net net, PMemberControl members);

typedef struct memberHandler {
    memberHandlerFunc create;
    memberHandlerFunc add_vlan_for_members;
    memberHandlerFunc remove_vlan_for_members;
    memberHandlerFunc ensure_mapping;
}MemberHandler, *PMemberHandler;

struct allIfHandlers {
#ifdef MULTINET_IFHANDLER_PLUGIN
    MemberHandler pluginHandlers[NUM_PLUGIN_IFTYPES];
#endif

    MemberHandler defaultHandlers[NUM_DEFAULT_IFTYPES];

};

extern PMemberHandler handlerList;
extern int numHandlers;
/**
* @brief Initialize the interface handler system.
*
* This function initializes the global handler list by registering default handlers.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int handlerInit();

/**
* @brief Create and register interfaces for a Layer 2 network.
*
* This function performs interface creation and registration for all applicable handlers
* and registers dynamic interfaces for status events.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to create and register.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int create_and_register_if(PL2Net net, PMember members, int numMembers);
/**
* @brief Unregister interfaces from a Layer 2 network.
*
* This function performs cleanup of mappings and unregisters dynamic interfaces from the event system.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to unregister.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int unregister_if(PL2Net net, PMember members, int numMembers);

/**
* @brief Add VLAN tagging for member interfaces.
*
* This function adds VLAN tagging to member interfaces by invoking the appropriate handler-specific implementation.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to add VLAN for.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int add_vlan_for_members(PL2Net net, PMember members, int numMembers);
/**
* @brief Remove VLAN tagging from member interfaces.
*
* This function removes VLAN tagging from member interfaces by invoking the appropriate handler-specific implementation.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] members - Pointer to the array of Member structures to remove VLAN from.
* @param[in] numMembers - Number of members in the members array.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int remove_vlan_for_members(PL2Net net, PMember members, int numMembers);


#endif