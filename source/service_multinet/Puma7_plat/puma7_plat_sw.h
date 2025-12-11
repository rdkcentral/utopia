/****************************************************************************
  Copyright 2017 Intel Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************************************************************************/

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
#ifndef P7_PLAT_SW_H
#define P7_PLAT_SW_H

#include "service_multinet_swfab.h"

#define SW_PORT_VENABLE_FORMAT(x) "sw_%s_venable", x->stringID
#define SW_PORT_UTVID_FORMAT(x) "sw_%s_ut_vid", x->stringID
#define SW_PORT_TVIDS_FORMAT(x) "sw_%s_t_vids", x->stringID
#define SW_PORT_TVIDS_DELIM ";"

typedef struct {
    char     device_name[16];
    int      qos_virtual_scheme_idx;
}pp_dev_ioctl_param_t;

typedef struct switchPortIDAndState {
    int portID;
    char* stringID;

    BOOL vidsLoaded;
    List taggingVids; // List of vids (ints)
    unsigned short untaggedVid;
    unsigned char bVlanEnabled;
} SwPortState, *PSwPortState;

/**
* @brief Configure VLAN on external switch ports for Puma7 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing port and VLAN configuration.
*                    \n Each structure includes portID , network instance, bridge name, VLAN ID, and tagging mode.
*                    \n The function processes external switch ports using portHelper to connect/disconnect ports to/from the bridge.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many external switch ports need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add port to bridge, FALSE to remove port from bridge.
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
* @retval Non-zero If operation failed.
*
*/
int configVlan_ESW(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Configure VLAN for GRE tunnel interfaces on Puma7 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing GRE interface and VLAN configuration.
*                    \n Each structure includes portID (GRE interface name), bridge name, VLAN ID, and tagging mode.
*                    \n The function connects GRE interfaces to the bridge and configures TCP MSS clamping iptables rules.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many GRE interfaces need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add GRE interface to bridge with MSS clamping, FALSE to remove interface and rules.
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
* @retval Non-zero If operation failed.
*
*/
int configVlan_GRE(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Configure VLAN for generic network interfaces on Puma7 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing interface and VLAN configuration.
*                    \n Each structure includes portID (interface name), bridge name, VLAN ID, and tagging mode.
*                    \n The function provides generic interface handling using portHelper to connect/disconnect ports to/from the bridge.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many interfaces need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add interface to bridge, FALSE to remove interface from bridge.
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
* @retval Non-zero If operation failed.
*
*/
int configVlan_puma7(PSWFabHALArg args, int numArgs, BOOL up);

/**
* @brief Configure VLAN for WiFi interfaces on Puma7 platform.
*
* @param[in] args  - Pointer to an array of SWFabHALArg structures containing WiFi interface and VLAN configuration.
*                    \n Each structure includes portID, bridge name, VLAN ID, and tagging mode.
* @param[in] numArgs  - The number of arguments in the args array.
*                    \n Specifies how many WiFi interfaces need to be configured with the VLAN.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to add WiFi interface to bridge, FALSE to remove interface from bridge.
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
* @retval Non-zero If failed.
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
* @return The number of bytes required for the string identifier.
* @retval >0 Number of bytes needed for the complete string identifier.
* @retval 0 If  operation failed.
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
* @return The number of bytes required for the string identifier.
* @retval >0 Number of bytes needed for the complete string identifier.
* @retval 0 If operation failed.
*
*/
int stringIDExtSw (void* portID, char* stringbuf, int bufSize) ;

/**
* @brief Generate a sysevent name for an external switch port.
*
* @param[in] portID  - Pointer to a SwPortState structure representing the external switch port.
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

#if defined (MULTILAN_FEATURE)
/**
* @brief Helper function to connect or disconnect ports to or from a bridge.
*
* @param[in] bridge  - Pointer to a string containing the bridge name.
*                    \n Specifies the target bridge for the port operation.
* @param[in] port  - Pointer to a string containing the port name.
*                    \n The port can be a switch port (sw_x) or any network interface name.
*                    \n If port is sw_x, getIfName is called to get the real interface name.
* @param[in] tagging  - Integer flag indicating whether VLAN tagging is enabled.
*                    \n Non-zero value creates a VLAN interface using vconfig before adding to bridge.
*                    \n Zero value adds the interface directly without VLAN tagging.
* @param[in] vid  - The VLAN ID to be used when tagging is enabled.
*                    \n This parameter is used with vconfig to create a tagged VLAN interface.
* @param[in] up  - Boolean flag indicating the operation type.
*                    \n TRUE to connect port to bridge (creates VLAN interface if tagging, configures VPID, brings interface up, adds to bridge).
*                    \n FALSE to disconnect port from bridge (removes from bridge, removes VPID, brings interface down, deletes VLAN interface if tagging).
*
* @return The status of the operation.
* @retval 0 Operation completed successfully.
* @retval Non-zero If operation failed.
*
*/
int portHelper(char *bridge, char *port, int tagging, int vid, BOOL up);

/**
* @brief Check if a network interface is really connected to a specific bridge.
*
* @param[in] net  - Pointer to an L2Net structure representing the bridge network.
*                    \n The structure contains the bridge name and VLAN ID used for verification.
* @param[in] ifname  - Pointer to a string containing the interface name to check.
*                    \n The interface name can have a "-t" suffix for tagged interfaces, which is stripped during processing.
*                    \n If ifname is a switch port (sw_x), getIfName is called to resolve the real interface name.
*                    \n For tagged interfaces, the function appends ".<vlanid>" suffix to the real interface name.
*
* @return The bridge connectivity status.
* @retval 1 The interface is NOT connected to the bridge.
* @retval 0 The interface IS connected to the bridge.
*
*/
int ep_check_if_really_bridged(PL2Net net, char *ifname);
#endif

#endif