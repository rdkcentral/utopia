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

#ifdef RDKB_EXTENDER_ENABLED
typedef enum {
    ROUTER =0,
    EXTENDER_MODE,
} Dev_Mode;

/**
 * @brief Get the current device operating mode.
 *
 * Retrieves the device mode from syscfg configuration to determine if the device is operating
 * as a router or in extender mode. The function reads the "Device_Mode" parameter and converts
 * it to the appropriate Dev_Mode enumeration value.
 *
 * @return The current device operating mode
 * @retval ROUTER (0) - Device is operating in router mode
 * @retval EXTENDER_MODE (1) - Device is operating in extender mode
 */
unsigned int Get_Device_Mode();
#endif

/**
 * @brief Stop the DHCP server and related services.
 *
 * Stops the DHCP server by waiting for it to reach end state, then terminates the dnsmasq process.
 * The function checks the current dhcp_server-status and only proceeds if the server is not already stopped.
 * In extender mode, it verifies mesh WAN link status before stopping. It kills the dnsmasq process using
 * its PID, removes configuration files, and updates the dhcp_server-status sysevent to "stopped".
 *
 * @return None
 */
void dhcp_server_stop();

/**
 * @brief Start the DHCP server with the specified configuration.
 *
 * Starts the DHCP server by initializing the service, preparing configuration files (hostname, dhcp.conf,
 * dnsmasq.conf), and launching the dnsmasq process. The function checks if DHCP server is enabled in syscfg,
 * validates the LAN status, handles bridge mode scenarios, and manages the transition from stopped to started state.
 * In extender mode, it verifies mesh WAN link is up before proceeding. It handles process restart logic by
 * comparing current and previous configurations, and sets up the dhcp_server-status sysevent accordingly.
 *
 * @param[in] input - Input parameter string
 *
 * @return The status of the operation
 * @retval 0 - DHCP server started successfully or is disabled
 * @retval 1 - Failed to start (prerequisites not met)
 */
int dhcp_server_start (char *input);

/**
 * @brief Initialize DHCP service parameters and slow start configuration.
 *
 * Initializes the DHCP service by retrieving and setting various configuration parameters including
 * WAN nameserver propagation, domain propagation, BYOI (Bring Your Own Internet) settings, and slow start
 * feature configuration. The function determines if DHCP slow start is needed based on WAN IP address state,
 * HSD mode, and temporary IP prefix settings. It sets up slow start quanta and lease time parameters,
 * and retrieves device properties for DHCP operation.
 *
 * @return The status of the operation
 * @retval SUCCESS (0) - Initialization completed successfully
 */
int service_dhcp_init();

/**
 * @brief Handle LAN status change events.
 *
 * Responds to LAN status change events by checking the current lan-status and taking appropriate action.
 * If DHCP server is disabled, it starts only the DNS forwarder service by preparing hostname and DNS-only
 * configuration. If DHCP server is enabled, it either starts or restarts the DHCP server with full configuration.
 * In extender mode, it validates that mesh WAN link is up before proceeding. The function updates dns-status
 * and dhcp_server-status sysevent variables accordingly.
 *
 * @param[in] input - Input parameter string containing LAN status information
 *
 * @return None
 */
void lan_status_change(char *input);

/**
 * @brief Handle syslog restart request and update DHCP configuration.
 *
 * Processes syslog restart requests by regenerating DHCP and DNS configuration files based on current
 * dhcp_server_enabled setting. The function waits for DNS and DHCP server to reach end state, backs up
 * the current dnsmasq.conf, prepares new hostname and DHCP configuration (DNS-only if DHCP server is disabled,
 * full configuration otherwise), compares with previous configuration, and restarts the dnsmasq process if
 * changes are detected. It only proceeds if dhcp_server-status is "started".
 *
 * @return The status of the operation
 * @retval 0 - Request processed successfully or dhcp_server-status not started
 * @retval Non-zero - Error occurred during processing
 */
int syslog_restart_request();

/**
 * @brief Resynchronize DHCP pool configuration to non-volatile storage.
 *
 * Synchronizes DHCP server pool configurations between current runtime state and PSM (Persistent Storage Manager)
 * non-volatile storage. The function compares current DHCP pools with PSM instances, identifies pools to remove
 * and pools to load, and updates the configuration accordingly. It handles up to 15 DHCP pools and manages pool
 * parameters including Enable, IPInterface, MinAddress, MaxAddress, SubnetMask, and LeaseTime. The function sets
 * up async callbacks for pool status monitoring and updates the dhcp_server_current_pools sysevent variable.
 *
 * @param[in] RemPools - String containing pool instances to remove (NULL to auto-detect from system state)
 *
 * @return None
 */
void resync_to_nonvol(char *RemPools);
