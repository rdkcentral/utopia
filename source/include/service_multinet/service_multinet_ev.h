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
#ifndef MNET_EV_H
#define MNET_EV_H

#include "service_multinet_base.h"
#include "sysevent/sysevent.h"

#define MNET_STATUS_FORMAT(x) "multinet_%d-status", x
#define MNET_IFSTATUS_FORMAT(x) "if_%s-status", x
#define MNET_IFSTATUS_ASYNCID_FORMAT(x) "ifstatus_%s_async", x
#define MNET_IFSTATUS_ASYNCVAL_FORMAT(x) "%d %d", (x).action_id, (x).trigger_id
#define MNET_NAME_FORMAT(x) "multinet_%d-name", x


extern token_t sysevent_token_interactive;
extern int sysevent_fd_interactive;
/**
* @brief Register the current running process for the given interface event name.
*
* This function must register in the appropriate way based on execution style of the process.
* If a status value name and bool pointer are provided, the current status will be polled after
* registration and filled into the bool variable to handle any registration / initialization race conditions.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] member - Pointer to the Member structure representing the network member.
* @param[in] ifStatusEventName - Pointer to the interface status event name string.
* @param[in] ifStatusValueName - Pointer to the interface status value name string (optional).
* @param[out] readyFlag - Pointer to the BOOL variable to store the current status after registration.
*                      \n If provided, the current status will be polled after registration to handle any registration/initialization race conditions.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_register_ifstatus(PL2Net net, PMember member,  char* ifStatusEventName, char* ifStatusValueName, BOOL* readyFlag);

/**
* @brief Unregister the current running process for the given interface event name.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] ifStatusEventName - Pointer to the interface status event name string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_unregister_ifstatus(PL2Net net, char* ifStatusEventName);


/**
* @brief Announce to the system the status of a given Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
* @param[in] status - The service status to set.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_set_netStatus(PL2Net net, enum service_status status);

/**
* @brief Initialize the event system.
*
* This function initialize the event system. isDaemon should be initialized before this is called.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on error.
*
*/
int ev_init(void);

/**
* @brief Convert a status string to SERVICE_STATUS enumeration.
*
* @param[in] stringStatus - Pointer to the status string to convert.
* @param[out] status - Pointer to store the converted SERVICE_STATUS value.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_string_to_status(char* stringStatus, SERVICE_STATUS* status);

/**
* @brief Trigger a firewall restart event.
*
* this function used for ev firewall restart Triggering.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_firewall_restart(void);

/**
* @brief Set the name event for a Layer 2 network.
*
* @param[in] net - Pointer to the L2Net structure representing the Layer 2 network.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int ev_set_name(PL2Net net);

//Private----------

/** This function registers the current handler for the specified event. Function must register
 * appropriately based on the calling style of the handler and capabilities of the underlying eventing
 * system. Calling style should be indicated during lib init.
 */
//int ev_register_event(char* eventName);

#endif