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

#include "ccsp_custom.h"
#include "ccsp_psm_helper.h"
#include "ccsp_base_api.h"
#include "ccsp_memory.h"

extern void* g_vBus_handle;

#define CCSP_SUBSYS     "eRT."
#define PSM_VALUE_GET_STRING(name, str) PSM_Get_Record_Value2(g_vBus_handle, CCSP_SUBSYS, name, NULL, &(str))
#define PSM_VALUE_SET_STRING(name, str) PSM_Set_Record_Value2(g_vBus_handle, CCSP_SUBSYS, name, ccsp_string, str)
#define PSM_VALUE_GET_INS(name, pIns, ppInsArry) PsmGetNextLevelInstances(g_vBus_handle, CCSP_SUBSYS, name, pIns, ppInsArry)

/**
 * @brief Initialize and bring up the LAN interface.
 *
 * Initializes the primary LAN interface by retrieving configuration from PSM (Persistent Storage Manager),
 * setting up L2 and L3 network instances, configuring bridge ports, and establishing the LAN network.
 * The function handles home security network setup, manages async event handlers, and triggers the
 * necessary system events to bring the LAN interface operational. It also handles multi-LAN feature
 * enablement and logs boot-up timing information.
 *
 * @return None
 */
void bring_lan_up();

/**
 * @brief Update the IPv4 status for a specified L3 instance.
 *
 * Handles the IPv4 status changes (up/down) for a given L3 network instance. When status is "up",
 * it configures the interface with IPv4 and IPv6 addresses, enables DHCP server, sets up firewall rules,
 * and manages various network services. When status is "down", it tears down the network configuration.
 * The function also handles erouter mode changes, DS-Lite configuration, IPv6 prefix delegation, and
 * bridge mode transitions.
 *
 * @param[in] l3_inst - The L3 network instance number
 * @param[in] status - The IPv4 status string ("up" or "down")
 *
 * @return None
 */
void ipv4_status(int l3_inst, char *status);

/**
 * @brief Restart the LAN interface with updated configuration.
 *
 * Restarts the LAN interface by comparing current syscfg values with PSM stored values for IP address
 * and subnet mask. If changes are detected, it updates the PSM, flushes IPv6 addresses, reconfigures
 * the interface, and restarts dependent services including DHCP server and dibbler. The function handles
 * both IPv4 and IPv6 configurations and manages ULA (Unique Local Address) setup in WAN failover or
 * extender modes.
 *
 * @return None
 */
void lan_restart();

/**
 * @brief Stop the LAN interface and disable network services.
 *
 * Stops the LAN interface by triggering ipv4-down event, disabling IPv6 on the interface, flushing
 * all IPv6 addresses, and stopping the dibbler-server. This function is typically called during
 * system shutdown, bridge mode transition, or when the LAN needs to be taken down for configuration
 * changes.
 *
 * @return None
 */
void lan_stop();

/**
 * @brief Teardown and remove a specific L3 network instance.
 *
 * Tears down a specific L3 network instance by removing its async callbacks, clearing its configuration,
 * and removing it from the list of active IPv4 instances. This function unregisters the L2 async event
 * handler, calls remove_config to clean up the network configuration, and updates the ipv4-instances
 * sysevent variable to reflect the removal.
 *
 * @param[in] l3_inst - The L3 network instance number to teardown
 *
 * @return None
 */
void teardown_instance(int l3_inst);

/**
 * @brief Resynchronize and bring up a specific L3 network instance.
 *
 * Brings up a specific L3 network instance by retrieving its configuration from PSM, validating the
 * ethernet link association, and triggering the network setup. The function reads L3 instance parameters
 * including IP address, subnet mask, and enable status, then initiates the network configuration process.
 * In bridge mode, it avoids resyncing the primary LAN instance. This function is typically called when
 * adding new network instances or recovering from configuration changes.
 *
 * @param[in] l3_inst - The L3 network instance number to resynchronize
 *
 * @return None
 */
void resync_instance (int l3_inst);

/**
 * @brief Handle erouter mode update events.
 *
 * Responds to changes in erouter mode by checking the current bridge mode and IPv4 status configuration.
 * When transitioning between routing and bridge modes, it triggers appropriate network reconfiguration.
 * The function retrieves the last erouter mode from syscfg and compares it with the current state to
 * determine if network services need to be restarted or reconfigured.
 *
 * @return None
 */
void erouter_mode_updated();

/**
 * @brief Resynchronize IPv4 configuration for a LAN instance.
 *
 * Resynchronizes the IPv4 configuration for the specified LAN instance by retrieving IP address and
 * subnet mask from PSM and applying them to syscfg. This function is typically called when the primary
 * LAN instance needs to update its IPv4 configuration after changes in the data model or during recovery
 * from configuration inconsistencies. It only processes if the provided instance matches the primary LAN
 * L3 network instance.
 *
 * @param[in] lan_inst - The LAN instance identifier string
 *
 * @return None
 */
void ipv4_resync(char *lan_inst);
