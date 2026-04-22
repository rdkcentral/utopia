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

#ifndef  _DHCP_SERVER_FUNCTIONS_H
#define  _DHCP_SERVER_FUNCTIONS_H

/**
* @brief Prepare hostname configuration.
*
* Sets the system hostname from syscfg and creates /etc/hosts and /etc/hostname files.
* \n Writes hostname, localhost entries, and IPv6 entries to hosts file.
* \n Handles SecureWebUI LocalFqdn configuration if enabled.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero if error.
*/
int prepare_hostname();

/**
* @brief Calculate and write DHCP range configuration.
*
* Calculates DHCP IP address range based on LAN IP address and netmask.
* \n Writes dhcp-range configuration to the dnsmasq configuration file.
* \n Includes lease time and DHCP start/end addresses.
*
* @param[in] local_dhcpconf_file - File pointer to dnsmasq configuration file.
* @param[in] prefix - Prefix string for DHCP configuration (typically interface name).
*
* @return None
*/
void calculate_dhcp_range (FILE *local_dhcpconf_file, char *prefix);

/**
* @brief Prepare DHCP static hosts configuration.
*
* Reads static host entries from syscfg and writes them to /etc/dhcp_static_hosts
* \n file with MAC address, IP address, and lease time.
*
* @return None
*/
void prepare_dhcp_conf_static_hosts();

/**
* @brief Prepare DHCP options for WAN DNS propagation.
*
* Writes DNS server options to /etc/dhcp_options file if dhcp_server_propagate_wan_nameserver is enabled.
* \n Retrieves WAN DHCP DNS servers from sysevent and formats them as dnsmasq options.
*
* @return None
*/
void prepare_dhcp_options_wan_dns();

/**
* @brief Prepare whitelist URLs for captive portal mode.
*
* Adds address and server entries to dnsmasq configuration for whitelisted URLs
* \n used in captive portal mode, including redirect URLs and cloud personal URLs.
* \n Resolves URLs to IP addresses using erouter0 interface.
*
* @param[in] fp_local_dhcp_conf - File pointer to dnsmasq configuration file.
*
* @return None
*/
void prepare_whitelist_urls(FILE *);

/**
* @brief Configure extra DHCP pools.
*
* Iterates through configured DHCP pools and adds dhcp-range entries to dnsmasq configuration.
* \n Handles pool-specific options including DNS nameservers and lease times.
* \n Supports multiple network interfaces and pool configurations.
*
* @param[in] local_dhcpconf_file - File pointer to dnsmasq configuration file.
* @param[in] prefix - Prefix string for DHCP configuration.
* @param[in] bDhcpNs_Enabled - Flag indicating if DHCP nameserver is enabled.
* @param[in] pWan_Dhcp_Dns - WAN DHCP DNS server string.
*
* @return None
*/
void do_extra_pools (FILE *local_dhcpconf_file, char *prefix, unsigned char bDhcpNs_Enabled, char *pWan_Dhcp_Dns);

/**
* @brief Prepare complete DHCP server configuration.
*
* Main function that generates the dnsmasq configuration file /var/dnsmasq.conf.
* \n Configures DHCP ranges, static hosts, DNS options, extra pools, and interface bindings.
* \n Handles captive portal mode, IoT network, and various platform-specific configurations.
* \n Creates necessary directories and copies configuration files to appropriate locations.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero if error.
*/
int prepare_dhcp_conf();

/**
* @brief Check and retrieve WAN DHCP DNS servers.
*
* Retrieves wan_dhcp_dns from sysevent and converts space-separated DNS addresses
* \n to comma-separated format for dnsmasq configuration.
* \n The buffer pointed by pl_cWan_Dhcp_Dns should be allocated with at least 256 bytes.
*
* @param[out] pl_cWan_Dhcp_Dns - Buffer to store comma-separated WAN DHCP DNS addresses.
*
* @return None
*/
void check_and_get_wan_dhcp_dns( char *pl_cWan_Dhcp_Dns );

/**
* @brief Get DHCP options for brlan0 interface.
*
* Constructs dhcp-option string for brlan0 with DNS nameservers from syscfg.
* \n Includes dhcp_nameserver_1, dhcp_nameserver_2, dhcp_nameserver_3, and WAN DNS if SecureWebUI is enabled.
* \n The buffer pointed by pDhcpNs_OptionString should be allocated with at least 1024 bytes.
*
* @param[out] pDhcpNs_OptionString - Buffer to store formatted DHCP option string.
*
* @return None
*/
void get_dhcp_option_for_brlan0( char *pDhcpNs_OptionString );

/**
* @brief Prepare static DNS URL entries.
*
* Reads static DNS URLs from /etc/dns_static_urls file and adds server entries
* \n to dnsmasq configuration for blocking or redirecting specific domains.
*
* @param[in] fp_local_dhcp_conf - File pointer to dnsmasq configuration file.
*
* @return None
*/
void prepare_static_dns_urls(FILE *fp_local_dhcp_conf);

/**
* @brief Update DHCP configuration based on sysevent change.
*
* Monitors dhcp_conf_change sysevent and updates internal configuration list.
* \n Handles interface additions, updates with different ranges, and removals.
* \n Maintains dynamic DHCP configuration for multiple interfaces.
*
* @return None
*/
void UpdateDhcpConfChangeBasedOnEvent();
#endif /* _DHCP_SERVER_FUNCTIONS_H */