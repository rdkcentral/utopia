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
#ifndef MNET_PLAT_H
#define MNET_PLAT_H

#include "service_multinet_base.h"
#include "service_multinet_handler.h"
//#include "service_multinet_ifplugin.h"
#include "service_multinet_util.h"


#define TRUE 1
#define FALSE 0
#define HAL_MAX_PORTS 32
#define MAX_ADD_PORTS HAL_MAX_PORTS*2
#define MAX_ENTITIES 32
#define MAX_PATHS 128

typedef struct vidParams {
    int vid;
    int tagging;
    int pvid;
} VLANParams, *PVLANParams;

typedef struct portConfig {
    struct platport* platPort;
    VLANParams vidParams;
} PortConfig, *PPortConfig;

typedef struct pcControl {
    PortConfig config;
    int handled;
} PortConfigControl, *PPortConfigControl;

typedef struct halhints {
    PL2Net network;
    PNetInterface iface;
} HalHints, *PHalHints;

typedef struct halArg {
    void* portID;
    VLANParams vidParams;
    BOOL ready;
     HalHints hints;
} SWFabHALArg, *PSWFabHALArg;

typedef struct argMemberMap {
    PSWFabHALArg args;
    PMember* members;
    PL2Net network;
} HALArgMemberMap, *PHALArgMemberMap;

typedef int (*IFHandlerFunc)(PSWFabHALArg args, int numArgs, BOOL up);
typedef int (*IsEqualFunc)(void* portIDa, void* portIDb);
typedef int (*IDToStringFunc)(void* portID, char* stringbuf, int bufsize);
//typedef int (*EventStringFunc)(void* portID, char* stringbuf, int bufsize);

typedef struct swfabhal {
    // Used to match. Should be unique for each instance, or initIF and configVlan should be
    // identical across instances.
    int id;

    //Should fill the 'ready' field of each member
    IFHandlerFunc initIF;

    IFHandlerFunc configVlan;

    //Check if two ports are equal. Do not assume all arguements are of the local HALs portID type.
    IsEqualFunc isEqual;

    /**Return the number of characters written including null terminator.
     */
    IDToStringFunc stringID;
    IDToStringFunc eventString;
}SWFabHAL, *PSWFabHAL;

typedef struct platport {
    void* portID;
    int entity;
    PSWFabHAL hal;
    /**Dynamic means the availability of this interface may change
     * during the course of runtime, and should be taken into consideration
     * by the bridging framework. A false value here will save some overhead.
     */
    int isDynamic;

    /** Shared means this port may be a trunking port for multiple other platform ports in
     * some configuration. If it can be a shared pathway, mark this true.
     *
     * The framework will force this port to tagging mode if this port is a dependency
     * and this flag is set. Otherwise the port will be assigned the tagging mode specified
     * on the member port.
     */
    //int isShared;
} PlatformPort, *PPlatformPort;





// typedef struct ifTypeHandler {
//
// } IFTypeHandler, *PIFTypeHandler;

/**
 * @brief Adds VLAN configuration to a Layer 2 network.
 *
 * This function adds VLAN configuration for the specified network and its member interfaces.
 * It maps interfaces to platform ports, retrieves VLAN state, and configures trunk ports
 * with proper VLAN tagging. This is a wrapper that calls swfab_configVlan with add flag set to 1.
 *
 * @param[in] net - Pointer to Layer 2 network structure containing network instance and VLAN ID.
 * @param[in] members - Pointer to member control structure containing member interfaces and their states.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int swfab_addVlan(PL2Net net, PMemberControl members);

/**
 * @brief Removes VLAN configuration from a Layer 2 network.
 *
 * This function removes VLAN configuration for the specified network and its member interfaces.
 * It removes interfaces from bridges, removes VLAN tags, and cleans up trunk port configurations.
 * This is a wrapper that calls swfab_configVlan with add flag set to 0.
 *
 * @param[in] net - Pointer to Layer 2 network structure containing network instance and VLAN ID.
 * @param[in] members - Pointer to member control structure containing member interfaces and their states.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int swfab_removeVlan(PL2Net net, PMemberControl members);

/**
 * @brief Creates and initializes a Layer 2 network with its member interfaces.
 *
 * This function performs initial creation of a Layer 2 network by mapping interfaces to platform ports
 * and calling each HAL's initIF function to initialize interfaces. It groups interfaces by HAL type,
 * calls the initialization function for each HAL only once, and propagates the ready flag from HAL
 * responses back to member structures.
 *
 * @param[in] net - Pointer to Layer 2 network structure containing network instance information.
 * @param[in,out] members - Pointer to member control structure.
 *                          \n Input: Contains member interfaces to initialize.
 *                          \n Output: Updates handled flags and bReady status for each member.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int swfab_create(PL2Net net, PMemberControl members);

/**
 * @brief Maps network interfaces to platform ports and marks them as handled.
 *
 * This function iterates through member interfaces and maps each unmapped interface to its
 * corresponding platform port using mapToPlat. It also populates dynamic interface properties
 * and event names, then marks interfaces as handled.
 *
 * @param[in] net - Pointer to Layer 2 network structure.
 * @param[in,out] members - Pointer to member control structure.
 *                          \n Input: Contains member interfaces to map.
 *                          \n Output: Updates interface map pointers, dynamic flags, event names, and handled flags.
 *
 * @return Status of the operation.
 * @retval 0 on success.
 */
int swfab_domap(PL2Net net, PMemberControl members);

//-------------
//int isPortEqual(PPlatformPort portA, PPlatformPort portB);

/**
 * @brief Prints platform port information for debugging.
 *
 * This function retrieves the string identifier of a platform port using its HAL's stringID
 * function and prints it for debugging purposes. It handles NULL port and missing HAL cases.
 *
 * @param[in] port - Pointer to platform port structure to print.
 *
 * @return None.
 */
void printPlatport(PPlatformPort port);


#endif
