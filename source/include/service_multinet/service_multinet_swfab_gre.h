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
#ifndef MNET_SWFAB_GRE_H
#define MNET_SWFAB_GRE_H

#include "service_multinet_swfab.h"

/**
 * @brief Initializes a GRE (Generic Routing Encapsulation) interface for a network instance.
 *
 * This function creates and configures a GRE interface by invoking the handle_gre.sh script
 * with the network instance ID and port ID. Platform-specific implementations handle standard
 * GRE interfaces (like gretap0) and Intel GRE hotspot configurations differently.
 *
 * @param[in] args - Array of SWFabHALArg structures containing port ID and network hints.\n
 *                   args[0].portID contains the GRE interface name.\n
 *                   args[0].hints.network->inst contains the network instance ID.
 * @param[in] numArgs - Number of arguments in the args array.
 * @param[in] up - Boolean flag indicating whether to bring the interface up (TRUE) or down (FALSE).
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int greIfInit(PSWFabHALArg args, int numArgs, BOOL up) ;

#endif
