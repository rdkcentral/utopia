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
#ifndef P6_PLAT_SW_H
#define P6_PLAT_SW_H

#include "service_multinet_swfab.h"

#define SW_PORT_VENABLE_FORMAT(x) "sw_%s_venable", x->stringID
#define SW_PORT_UTVID_FORMAT(x) "sw_%s_ut_vid", x->stringID
#define SW_PORT_TVIDS_FORMAT(x) "sw_%s_t_vids", x->stringID
#define SW_PORT_TVIDS_DELIM ";"

typedef struct switchPortIDAndState {
    int portID;
    char* stringID;

    BOOL vidsLoaded;
    List taggingVids; // List of vids (ints)
    unsigned short untaggedVid;
    unsigned char bVlanEnabled;
} SwPortState, *PSwPortState;

/**
* @brief Configure VLAN on external switch ports for Puma6 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing port and VLAN configuration.
*                    \n Each structure includes portID, network instance, VLAN ID, and tagging mode.
*                    \n The function processes external switch ports and formats them for VLAN operations.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many ports need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add VLAN configuration, FALSE to delete VLAN configuration.
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
*
*/
int configVlan_ESW(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Configure VLAN on internal switch ports for Puma6 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing port and VLAN configuration.
*                    \n Each structure includes portID, network instance, VLAN ID, and tagging mode.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many internal ports need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add VLAN configuration , FALSE to delete VLAN configuration .
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
*
*/
int configVlan_ISW(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Configure VLAN for WiFi interfaces on Puma6 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing WiFi interface and VLAN configuration.
*                    \n Each structure includes portID, network instance, VLAN ID, and tagging mode.
*                    \n The function concatenates all WiFi interface names and applies VLAN configuration via handle_gre.sh script.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many WiFi interfaces need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add VLAN configuration , FALSE to delete VLAN configuration .
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
*
*/
int configVlan_WiFi(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Get the string identifier for an internal switch port.
*
* @param[in] portID  - Pointer to a SwPortState structure representing the internal switch port.
*                    \n The function extracts the stringID field from the SwPortState structure.
* @param[out] stringbuf  - Pointer to a buffer where the string identifier will be stored.
*                    \n The buffer will contain the port's string identifier.
* @param[in] bufSize  - The size of the stringbuf buffer.
*                    \n Specifies the maximum number of characters that can be written to stringbuf.
*
* @return The number of bytes required for the string identifier .
* @retval >0 Number of bytes needed for the complete string identifier.
* @retval 0 If operation failed.
*
*/
int stringIDIntSw (void* portID, char* stringbuf, int bufSize) ;

/**
* @brief Get the string identifier for an external switch port.
*
* @param[in] portID  - Pointer to a SwPortState structure representing the external switch port.
*                    \n The function extracts the stringID field from the SwPortState structure.
* @param[out] stringbuf  - Pointer to a buffer where the string identifier will be stored.
*                    \n The buffer will contain the port's string identifier.
* @param[in] bufSize  - The size of the stringbuf buffer.
*                    \n Specifies the maximum number of characters that can be written to stringbuf.
*
* @return The number of bytes required for the string identifier .
* @retval >0 Number of bytes needed for the complete string identifier .
* @retval 0 If operation failed.
*
*/
int stringIDExtSw (void* portID, char* stringbuf, int bufSize) ;

/**
* @brief Generate a sysevent name for a switch port.
*
* @param[in] portID  - Pointer to a SwPortState structure representing the switch port.
*                    \n The function extracts the stringID field and generates a sysevent name from it.
* @param[out] stringbuf  - Pointer to a buffer where the generated sysevent name will be stored.
*                    \n The buffer will contain the sysevent name in the format "if_<stringID>-status".
* @param[in] bufSize  - The size of the stringbuf buffer.
*                    \n Specifies the maximum number of characters that can be written to stringbuf.
*
* @return The number of bytes required for the sysevent name.
* @retval >0 Number of bytes needed for the complete sysevent name string.
* @retval 0 If the operation failed.
*
*/
int eventIDSw (void* portID, char* stringbuf, int bufSize);

#endif
