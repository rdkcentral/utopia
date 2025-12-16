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
   Copyright [2014] [Cisco Systems, Inc.]

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

#ifndef __SERV_UTIL__
#define __SERV_UTIL__
#include <sysevent/sysevent.h>

#define SE_SERV         "127.0.0.1"

#ifndef NELEMS
#define NELEMS(arr)     (sizeof(arr) / sizeof((arr)[0]))
#endif

#if defined (WIFI_MANAGE_SUPPORTED)
#define MANAGE_WIFI_PSM_STR "dmsb.MultiLAN.ManageWiFi_l3net"
#define MANAGE_WIFI_BRIDGE_NAME "dmsb.l2net.%s.Name"
#define MANAGE_WIFI_V4_ADDR "dmsb.l3net.%s.V4Addr"

/**
* @brief Update DHCP pool configuration data to dnsmasq configuration file.
*
* This function retrieves DHCP pool settings from PSM and writes them to the dnsmasq configuration file.
*
* @param[in] bus_handle - Pointer to the message bus handle for PSM communication.
* @param[in] pIndex     - Pointer to string containing the DHCP pool index.
* @param[in,out] pFile  - Pointer to FILE handle for the dnsmasq configuration file.
*
* @return None.
*
*/
void updateDhcpPoolData(void * bus_handle, char * pIndex, FILE * pFile);
#endif /* WIFI_MANAGE_SUPPORTED*/

/**
* @brief Retrieve a parameter value from PSM (Persistent Storage Manager).
*
* This function retrieves a parameter value from PSM using the CCSP message bus.
*
* @param[in] bus_handle  - Pointer to the CCSP message bus handle.
* @param[in] pParamName  - Pointer to the PSM parameter name string.
* @param[out] pParamValue - Pointer to buffer where the parameter value will be stored.
* @param[in] len         - Size of the pParamValue buffer in bytes.
*
* @return None.
*
*/
void psmGet(void *bus_handle, char *pParamName, char *pParamValue, size_t len);

/**
* @brief Execute a shell command with printf-style formatting.
*
* This function constructs a shell command from a format string and variable arguments, then executes it using system().
*
* @param[in] fmt - Format string for the command (printf-style).
* @param[in] ... - Variable arguments corresponding to format specifiers in fmt.
*
* @return Status of the command execution.
* @retval Exit status returned by system() on successful command execution.
* @retval -1 if fails
*
*/
int vsystem(const char *fmt, ...);

/**
* @brief Set a sysctl parameter for a network interface.
*
* This function writes a value to a sysctl file, optionally formatting the path with an interface name.
*
* @param[in] path    - Path to the sysctl file, optionally containing a %s format specifier for ifname.
* @param[in] ifname  - Interface name to substitute into path (can be NULL).
* @param[in] content - Content string to write to the sysctl file.
*
* @return Status of the operation.
* @retval 0 if the sysctl parameter was successfully written.
* @retval -1 if opening or writing to the file fails.
*
*/
int sysctl_iface_set(const char *path, const char *ifname, const char *content);

/**
* @brief Get the hardware (MAC) address of a network interface.
*
* This function retrieves the MAC address of the specified network interface.
*
* @param[in] ifname - Name of the network interface (e.g., "eth0", "wlan0").
* @param[out] mac   - Pointer to buffer where the MAC address string will be stored.
* @param[in] size   - Size of the mac buffer in bytes.
*
* @return Status of the operation.
* @retval 0 if the MAC address was successfully retrieved and stored.
* @retval -1 if parameters are invalid, socket creation fails, interface is not present, or ioctl fails.
*
*/
int iface_get_hwaddr(const char *ifname, char *mac, size_t size);

/**
* @brief Get the IPv4 address of a network interface.
*
* This function retrieves the IPv4 address of the specified network interface.
*
* @param[in] ifname    - Name of the network interface.
* @param[out] ipv4Addr - Pointer to buffer where the IPv4 address string will be stored.

* @param[in] size      - Size of the ipv4Addr buffer in bytes.
*
* @return Status of the operation.
* @retval 0 if the IPv4 address was successfully retrieved and stored.
* @retval -1 if parameters are invalid, socket creation fails, interface is not present, or ioctl fails.
*
*/
int iface_get_ipv4addr(const char *ifname, char *ipv4Addr, size_t size);

/**
* @brief Check if a network interface is present in the system.
*
* This function checks whether the specified network interface exists.
*
* @param[in] ifname - Name of the network interface to check.
*
* @return Interface presence status.
* @retval 1 if the interface is present and operational.
* @retval 0 if the interface is not present, parameters are invalid, or any error occurs.
*
*/
int is_iface_present(const char *ifname);

/**
* @brief Check if a service can be started based on its current status.
*
* This function queries the service status from sysevent and determines if the service can be started.
*
* @param[in] sefd     - Sysevent file descriptor for communication with sysevent daemon.
* @param[in] tok      - Sysevent token for authentication.
* @param[in] servname - Name of the service to check.
*
* @return Service start capability status.
* @retval 1 if the service can be started.
* @retval 0 if the service is already starting, started, or stopping.
*
*/
int serv_can_start(int sefd, token_t tok, const char *servname);

/**
* @brief Check if a service can be stopped based on its current status.
*
* This function queries the service status from sysevent and determines if the service can be stopped.

*
* @param[in] sefd     - Sysevent file descriptor for communication with sysevent daemon.
* @param[in] tok      - Sysevent token for authentication.
* @param[in] servname - Name of the service to check.
*
* @return Service stop capability status.
* @retval 1 if the service can be stopped.
* @retval 0 if the service is already stopping, stopped, or starting.
*
*/
int serv_can_stop(int sefd, token_t tok, const char *servname);

/**
* @brief Find the process ID (PID) of a running process by name and optional keyword.
*
* This function searches /proc filesystem to find a process matching the specified name.
*
* @param[in] name    - Name of the process to search for.
* @param[in] keyword - Optional keyword to search for in the command line (can be NULL).
*
* @return Process ID of the matching process.
* @retval Positive PID value if a matching process is found.
* @retval -1 if no matching process is found or /proc directory cannot be opened.
*
*/
int pid_of(const char *name, const char *keyword);
#endif /* __SERV_UTIL__ */
