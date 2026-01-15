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

/**
 * @brief Bring up an IPv4 L3 network instance.
 *
 * Brings up the specified IPv4 L3 network instance by checking if a lower L2 instance is associated.
 * If no lower L2 instance exists, it calls resync_instance to configure and bring up the network.
 * If a lower L2 instance exists, it retrieves the multinet status and calls handle_l2_status to
 * process the network state accordingly.
 *
 * @param[in] l3_inst - String containing the L3 network instance number
 *
 * @return None
 */
void ipv4_up(char *l3_inst);
/**
 * @brief Handle L2 network status changes for an L3 instance.
 *
 * Processes L2 network status changes and takes appropriate action for the associated L3 instance.
 * When the L2 network status is "partial" or "ready" and localready flag is set, it prepares the IPv4
 * configuration by setting the interface name and loading static L3 configuration. When the L2 network
 * is down or stopped, it sets the IPv4 status to "pending" and triggers a multinet-up event if needed
 * to improve XHome and WAN uptime.
 *
 * @param[in] l3_inst - The L3 network instance number
 * @param[in] l2_inst - The L2 network instance number
 * @param[in] net_status - String indicating the network status.
 * @param[in] input - Flag indicating if multinet-up event should be triggered when network is down
 *
 * @return None
 */
void handle_l2_status (int l3_inst, int l2_inst, char *net_status, int input);
/**
 * @brief Remove True Static IP (TSIP) configuration from the system.
 *
 * Removes the True Static IP configuration by retrieving TSIP settings from PSM (IP address, subnet, gateway),
 * flushing the interface addresses, deleting routes, and updating system events to reflect the removal.
 * The function handles both enabled and disabled TSIP states and cleans up all associated network configuration.
 *
 * @return None
 */
void remove_tsip_config();
/**
 * @brief Remove True Static IP Additional Subnet (TSIP ASN) configurations.
 *
 * Removes all True Static IP Additional Subnet configurations by iterating through all TSIP ASN instances
 * stored in PSM. For each enabled instance (up to MAX_TS_ASN_COUNT), it retrieves the IP address and subnet,
 * flushes the interface addresses, deletes associated routes, and cleans up the configuration. The function
 * handles multiple subnet instances for advanced static IP routing scenarios.
 *
 * @return None
 */
void remove_tsip_asn_config();
/**
 * @brief Synchronize True Static IP (TSIP) configuration to the system.
 *
 * Synchronizes the True Static IP configuration from PSM to the active system configuration. The function
 * retrieves TSIP settings including enable status, IP address, subnet mask, and gateway from PSM storage,
 * calculates network parameters, assigns the IP address to the interface, and adds the necessary routes.
 * This is typically called during system initialization or when TSIP configuration changes are detected.
 *
 * @return None
 */
void sync_tsip ();
/**
 * @brief Resynchronize True Static IP (TSIP) configuration based on enable state.
 *
 * Resynchronizes the TSIP configuration by first removing existing TSIP configuration and then applying
 * new configuration if TSIP is enabled. The function retrieves TSIP parameters from PSM, removes old settings
 * and if tsip_enable parameter is set, it reconfigures the interface with the updated IP address, subnet, and
 * gateway settings including route additions.
 *
 * @param[in] tsip_enable - Flag indicating if TSIP should be enabled (non-zero) or disabled (0)
 *
 * @return None
 */
void resync_tsip(int tsip_enable);
/**
 * @brief Synchronize True Static IP Additional Subnet (TSIP ASN) configurations to the system.
 *
 * Synchronizes all TSIP Additional Subnet configurations from PSM to the active system. The function
 * retrieves all TSIP ASN instances from PSM (up to MAX_TS_ASN_COUNT), and for each enabled instance,
 * it retrieves the IP address and subnet, calculates network parameters, assigns the additional IP to
 * the interface, and adds the necessary routes. This allows multiple static IP subnets to be configured
 * on the same interface for advanced networking scenarios.
 *
 * @return None
 */
void sync_tsip_asn ();
/**
 * @brief Resynchronize all True Static IP Additional Subnet (TSIP ASN) configurations.
 *
 * Resynchronizes all TSIP ASN configurations by first removing existing configurations and then reapplying
 * them from PSM storage. The function iterates through all TSIP ASN instances, retrieves their enable status,
 * IP addresses, and subnet masks, removes old interface addresses and routes, and reconfigures them if enabled.
 * This is typically called when TSIP ASN configuration changes are detected or during system recovery.
 *
 * @return None
 */
void resync_tsip_asn();
/**
 * @brief Resynchronize a specific True Static IP Additional Subnet instance.
 *
 * Resynchronizes a specific TSIP ASN instance identified by the instance number. The function retrieves
 * the enable status, IP address, and subnet mask for the specified instance from PSM, validates the parameters,
 * calculates network parameters and if enabled, assigns the IP address to the interface
 * and adds the necessary route. This provides granular control for updating individual TSIP ASN instances
 * without affecting others.
 *
 * @param[in] instance - The TSIP ASN instance number to resynchronize (must be greater than 0)
 *
 * @return None
 */
void resync_tsip_asn_instance(int instance);
/**
 * @brief Apply IPv4 configuration to a specific L3 network instance.
 *
 * Applies IPv4 configuration to the specified L3 instance by setting the IP address and subnet mask on
 * the interface, configuring ARP settings, adding routes to routing tables, and updating system events.
 * The function retrieves or uses provided static IPv4 address and subnet, validates them, calculates network
 * parameters, assigns the IP to the interface, sets up ARP ignore flags, adds routes for the subnet and
 * default gateway, and synchronizes TSIP/TSIP ASN configurations if enabled. In extender mode, it handles
 * special IP assignment logic.
 *
 * @param[in] l3_inst - The L3 network instance number
 * @param[in] staticIpv4Addr - Static IPv4 address to apply (NULL to retrieve from sysevent)
 * @param[in] staticIpv4Subnet - Static IPv4 subnet mask to apply (NULL to retrieve from sysevent)
 *
 * @return Configuration status
 * @retval TRUE - Configuration applied successfully
 * @retval FALSE - Configuration failed (invalid parameters or error during application)
 */
BOOL apply_config(int l3_inst, char *staticIpv4Addr, char *staticIpv4Subnet);
/**
 * @brief Resynchronize all L3 network instances between active and non-volatile storage.
 *
 * Resynchronizes all L3 network instances by comparing active instances
 * with non-volatile instances . The function identifies instances that need to be
 * removed and instances that need to be added . It then calls teardown_instance for
 * instances to remove and resync_instance for instances to add, ensuring the active
 * network configuration matches the persistent configuration. This is typically called during
 * system startup or configuration recovery.
 *
 * @return None
 */
void resync_all_instance();


