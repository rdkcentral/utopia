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
#define ERROR	-1
#define SUCCESS	0
extern void* g_vBus_handle;

/**
 * @brief Start the DHCPv6 client service.
 *
 * Starts the DHCPv6 client service by validating prerequisites including erouter mode (IPv6 modes 2 or 3),
 * WAN link status, WAN interface configuration, bridge mode, and WAN status. If the PID file exists but the
 * process is not running, it triggers a service stop first. If all prerequisites are met, it prepares the
 * dibbler client configuration file, creates necessary directories, and starts the dibbler-client process.
 *
 * @return None
 */
void dhcpv6_client_service_start ();

/**
 * @brief Stop the DHCPv6 client service.
 *
 * Stops the DHCPv6 client service by checking if dibbler client is enabled and terminating the running
 * dibbler-client process. The function retrieves the process PID from the PID file, sends appropriate
 * signals to terminate the process, waits for process termination,
 * and removes the PID file. Platform-specific handling is provided for different hardware configurations.
 *
 * @return None
 */
void dhcpv6_client_service_stop ();

/**
 * @brief Update the DHCPv6 client service state based on enabled flag.
 *
 * Updates the DHCPv6 client service by checking the dhcpv6c_enabled sysevent flag. If enabled,
 * it starts the DHCPv6 client service by calling dhcpv6_client_service_start(). If disabled,
 * it stops the service by calling dhcpv6_client_service_stop(). This function is typically called when
 * configuration changes require the service state to be synchronized.
 *
 * @return None
 */
void dhcpv6_client_service_update ();

/**
 * @brief Register a sysevent handler for DHCPv6 client service.
 *
 * Registers a sysevent notification handler for the specified event. The function sets up event options
 * if the flag parameter is provided, creates a notification callback, stores the async ID in the appropriate
 * global array slot based on event type, and saves the async ID to sysevent for later retrieval. This enables the DHCPv6 client
 * service to respond to system events that affect its operation.
 *
 * @param[in] service_name - The name of the service registering the handler
 * @param[in] event_name - The sysevent name to monitor
 * @param[in] handler - The handler script or binary to execute when event triggers
 * @param[in] flag - Optional flag to set event options (pass non-NULL to enable TUPLE_FLAG_EVENT)
 *
 * @return None
 */
void register_sysevent_handler(char *service_name, char *event_name, char *handler, char *flag);

/**
 * @brief Unregister a sysevent handler for DHCPv6 client service.
 *
 * Unregisters a previously registered sysevent notification handler for the specified event. The function
 * retrieves the stored async ID from sysevent based on the event type, removes the notification callback using sysevent_rmnotification, and
 * clears the stored async ID from sysevent. This is called during service shutdown or when event monitoring
 * needs to be disabled.
 *
 * @param[in] service_name - The name of the service unregistering the handler
 * @param[in] event_name - The sysevent name to stop monitoring
 *
 * @return None
 */
void unregister_sysevent_handler(char *service_name, char *event_name);

/**
 * @brief Register all sysevent handlers required by DHCPv6 client service.
 *
 * Registers all sysevent handlers needed by the DHCPv6 client service to monitor system state changes.
 * The function registers handlers for erouter_mode-updated, phylink_wan_state, current_wan_ifname, and
 * bridge_mode events. It also creates a registration marker file to track that
 * handlers have been registered. This is typically called during service enablement.
 *
 * @return None
 */
void register_dhcpv6_client_handler();

/**
 * @brief Unregister all sysevent handlers for DHCPv6 client service.
 *
 * Unregisters all sysevent handlers previously registered by the DHCPv6 client service. The function
 * unregisters handlers for erouter_mode-updated, phylink_wan_state, current_wan_ifname, and bridge_mode
 * events, and removes the registration marker file. This is typically called during
 * service disablement to clean up event monitoring resources.
 *
 * @return None
 */
void unregister_dhcpv6_client_handler();

/**
 * @brief Enable the DHCPv6 client service.
 *
 * Enables the DHCPv6 client service by checking if it's already enabled via dhcpv6c_enabled sysevent.
 * If already enabled, it verifies that event handlers are registered and registers them if missing.
 * If not enabled, it starts the DHCPv6 client service, sets the dhcpv6c_enabled flag to "1", and
 * registers all necessary sysevent handlers to monitor system state changes. This is the primary entry
 * point for enabling DHCPv6 client functionality.
 *
 * @return None
 */
void dhcpv6_client_service_enable ();

/**
 * @brief Disable the DHCPv6 client service.
 *
 * Disables the DHCPv6 client service by checking if it's currently enabled via dhcpv6c_enabled sysevent.
 * If not enabled, it returns immediately. If enabled, it sets the dhcpv6c_enabled flag to "0" and
 * unregisters all sysevent handlers to stop monitoring system state changes. This effectively disables
 * DHCPv6 client functionality without stopping the currently running dibbler-client process.
 *
 * @return None
 */
void dhcpv6_client_service_disable ();
