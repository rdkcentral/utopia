/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

const char TYPE[]="SW";

#define TAGGING_MODE 2
#define UNTAGGED_MODE 1
#define NATIVE_MODE 0

#define ADD     1
#define DELETE  0

const char SW_ALL_PORTS[]="sw_1 sw_2 sw_3 sw_4 sw_5 atom arm I2E E2I";
const char PORTMAP_sw_1[]="-c 0 -p 0";
const char PORTMAP_sw_2[]="-c 0 -p 1";
const char PORTMAP_sw_3[]="-c 0 -p 2";
const char PORTMAP_sw_4[]="-c 0 -p 3";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
const char PORTMAP_sw_5[]="-c 16 -p 3";  //moca
#endif
const char PORTMAP_atom[]="-c 16 -p 0";
const char PORTMAP_arm[]="-c 16 -p 7";
const char PORTMAP_I2E[]="-c 16 -p 2";
const char PORTMAP_E2I[]="-c 0 -p 5";

const char PORTMAP_DEF_sw_1[]="-c 34 -p 0";
const char PORTMAP_DEF_sw_2[]="-c 34 -p 1";
const char PORTMAP_DEF_sw_3[]="-c 34 -p 2";
const char PORTMAP_DEF_sw_4[]="-c 34 -p 3";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
const char PORTMAP_DEF_sw_5[]="-c 16 -p 3 -m 0 -q 1"; //moca
#endif
const char PORTMAP_DEF_atom[]="-c 16 -p 0 -m 0 -q 1";
const char PORTMAP_DEF_arm[]="-c 16 -p 7 -m 0 -q 1";
const char PORTMAP_DEF_I2E[]="-c 16 -p 2 -m 0 -q 1";
const char PORTMAP_DEF_E2I[]="-c 34 -p 5";

const char PORTMAP_REM_sw_1[]="-c 1 -p 0";
const char PORTMAP_REM_sw_2[]="-c 1 -p 1";
const char PORTMAP_REM_sw_3[]="-c 1 -p 2";
const char PORTMAP_REM_sw_4[]="-c 1 -p 3";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
const char PORTMAP_REM_sw_5[]="-c 17 -p 3";  //moca
#endif
const char PORTMAP_REM_atom[]="-c 17 -p 0";
const char PORTMAP_REM_arm[]="-c 17 -p 7";
const char PORTMAP_REM_I2E[]="-c 17 -p 2";
const char PORTMAP_REM_E2I[]="-c 1 -p 5";

const char PORTMAP_VENABLE_sw_1[]="-c 4 -p 0";
const char PORTMAP_VENABLE_sw_2[]="-c 4 -p 1";
const char PORTMAP_VENABLE_sw_3[]="-c 4 -p 2";
const char PORTMAP_VENABLE_sw_4[]="-c 4 -p 3";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
const char PORTMAP_VENABLE_sw_5[]="-c 20 -p 3";  //moca
const char PORTMAP_VDISABLE_sw_5[]="-c 21 -p 3"; //moca
#endif
const char PORTMAP_VENABLE_atom[]="-c 20 -p 0";
const char PORTMAP_VENABLE_arm[]="-c 20 -p 7";
const char PORTMAP_VENABLE_I2E[]="-c 20 -p 2";
const char PORTMAP_VENABLE_E2I[]="-c 4 -p 5";

const char EXT_DEP[]="I2E-t E2I-a";
const char ATOM_DEP[]="atom-t";

//const char MGMT_PORT_LINUX_IFNAME[]="l2sm0";

/**
 * @brief Add a VLAN to the switch for specified network and ports.
 *
 * Configures a VLAN on the Puma6 platform switch by enabling VLAN tagging on specified ports, creating
 * VLAN interfaces, and managing port memberships. The function retrieves existing port configurations from
 * sysevent, enables VLAN on ARM/ATOM/I2E/E2I ports as needed, adds the specified ports to the VLAN using
 * swctl commands with appropriate tagging modes (TAGGING_MODE, UNTAGGED_MODE, or NATIVE_MODE), and updates
 * sysevent variables to track VLAN port memberships. It handles both internal switch ports (sw_1 through sw_5)
 * and external dependency ports (atom, I2E, E2I).
 *
 * @param[in] net_id - The network instance ID (L2 network identifier)
 * @param[in] vlan_id - The VLAN ID to configure (1-4094)
 * @param[in] ports_add - Space-separated string of port names to add to the VLAN.
 *
 * @return None
 */
void addVlan(int, int, char*);

/**
 * @brief Set multicast MAC address filtering on switch ports.
 *
 * Configures multicast MAC address filtering on specific switch ports (I2E port 2, MoCA port 3, and ARM port 7)
 * by setting the multicast MAC address 01:00:5E:7F:FF:FA using swctl command with code 23. This enables proper
 * multicast traffic handling on the Puma6 platform switch for IGMP snooping and multicast routing scenarios.
 *
 * @return None
 */
void setMulticastMac();

/**
 * @brief Add IPC (Inter-Process Communication) VLAN to the switch.
 *
 * Creates and configures the IPC VLAN on the switch by calling addVlan with network ID 0, IPC_VLAN ID, and
 * port "sw_6". The IPC VLAN is used for internal communication between different subsystems on the Puma6
 * platform, enabling isolated data plane traffic for system management and control operations.
 *
 * @return None
 */
void addIpcVlan();

/**
 * @brief Add RADIUS VLAN to the switch for authentication traffic.
 *
 * Creates and configures the RADIUS VLAN on the switch by calling addVlan with network ID 0, RADIUS_VLAN ID,
 * and port "sw_6". The RADIUS VLAN provides a dedicated path for RADIUS authentication, authorization, and
 * accounting (AAA) traffic, isolating security-sensitive authentication flows from regular data traffic on
 * the Puma6 platform.
 *
 * @return None
 */
void addRadiusVlan();

/**
 * @brief Create mesh networking VLANs for WiFi mesh backhaul communication.
 *
 * Creates two mesh VLANs (VLAN 112 and VLAN 113) on the Puma6 platform switch to support WiFi mesh backhaul
 * communication. For each VLAN, it configures VLAN tagging on ATOM port 0 and ARM port 7 using swctl with
 * TAGGING_MODE, creates the VLAN interface on l2sd0 using vconfig, and assigns link-local IP addresses
 * (169.254.0.254/24 for VLAN 112 and 169.254.1.254/24 for VLAN 113) to facilitate mesh node communication
 * without external DHCP dependency.
 *
 * @return None
 */
void createMeshVlan();

/**
 * @brief Add mesh backhaul VLAN to the switch for WiFi mesh traffic.
 *
 * Creates and configures the mesh backhaul VLAN on the switch by calling addVlan with network ID 0,
 * MESHBHAUL_VLAN ID, and port "sw_6". This VLAN is dedicated to carrying WiFi mesh backhaul traffic,
 * providing a separate path for mesh node inter-communication and enabling mesh network topology on the
 * Puma6 platform.
 *
 * @return None
 */
void addMeshBhaulVlan(); // RDKB-15951
