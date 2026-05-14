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
#ifndef MNET_SWFAB_LINIF_H
#define MNET_SWFAB_LINIF_H

#include "service_multinet_swfab.h"

/**
 * @brief Configures VLAN settings for Linux network interfaces.
 *
 * This function adds or removes Linux network interfaces from bridge devices and configures
 * VLAN tagging as needed. When bringing interfaces up, it creates VLAN interfaces using vconfig
 * if tagging is enabled, adds interfaces to bridges using brctl, and brings interfaces up.
 * When bringing interfaces down, it removes VLAN interfaces or removes interfaces from bridges.
 *
 * @param[in] args - Array of SWFabHALArg structures containing interface configuration.
 *                   \n args[i].portID contains the interface name.
 *                   \n args[i].vidParams.vid contains the VLAN ID.
 *                   \n args[i].vidParams.tagging indicates if VLAN tagging is enabled.
 *                   \n args[i].hints.network->name contains the bridge name.
 * @param[in] numArgs - Number of arguments in the args array.
 * @param[in] up - Boolean flag indicating operation mode.
 *                 \n TRUE to bring interfaces up and add to bridge.
 *                 \n FALSE to bring interfaces down and remove from bridge.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int linuxIfConfigVlan(PSWFabHALArg args, int numArgs, BOOL up);

/**
 * @brief Initializes Linux network interfaces.
 *
 * This function is to initialize the Linux network interfaces
 *
 * @param[in] args - Array of SWFabHALArg structures containing interface configuration.
 * @param[in] numArgs - Number of arguments in the args array.
 * @param[in] up - Boolean flag indicating whether to bring the interface up (TRUE) or down (FALSE).
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int linuxIfInit(PSWFabHALArg args, int numArgs, BOOL up);

#endif
