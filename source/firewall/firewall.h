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

#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <string.h>   // strcasestr needs __USE_GNU

#include <errno.h>

#include "syscfg/syscfg.h"
#include "sysevent/sysevent.h"

#include "ccsp_psm_helper.h"
#include <ccsp_base_api.h>
#include "ccsp_memory.h"
#include "firewall_custom.h"
#include "secure_wrapper.h"
#include "safec_lib_common.h"

/**
* @brief Apply logging rules to the filter table.
*
* This function adds iptables/ip6tables rules for logging dropped or rejected packets
* based on the configured firewall level and logging settings.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_logs(FILE *fp);

/**
* @brief Apply WAN to self attack protection rules.
*
* Adds protection against common WAN-side attacks targeting the router itself.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] wan_ip - Pointer to the WAN IP address string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_wan2self_attack(FILE *fp,char* wan_ip);

/**
* @brief Prepare IPv4 firewall rules and write to file.
*
* This function opens the specified file and writes all required iptables rules for IPv4 according to
* current configuration, features and security policies.
*
* @param[in] fw_file - Pointer to the firewall file path string.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on bad input parameters.
* @retval -2 when could not open firewall file.
*
*/
int prepare_ipv4_firewall(const char *fw_file);

/**
* @brief Prepare IPv6 firewall rules and write to file.
*
* This function opens the specified file and writes all required iptables rules for IPv6 according to
* current configuration, features and security policies.
*
* @param[in] fw_file - Pointer to the firewall file path string.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on Bad input parameters.
* @retval -2 when could not open firewall file.
*
*/
int prepare_ipv6_firewall(const char *fw_file);
#define CCSP_SUBSYS "eRT."

#define IF_IPV6ADDR_MAX 16

#define IPV6_ADDR_SCOPE_MASK    0x00f0U
#define IPV6_ADDR_SCOPE_GLOBAL  0
#define IPV6_ADDR_SCOPE_LINKLOCAL     0x0020U
#define _PROCNET_IFINET6  "/proc/net/if_inet6"
#define MAX_INET6_PROC_CHARS 200

#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_)
#define CM_SNMP_AGENT             "172.31.255.45"
#define kOID_cmRemoteIpAddress    "1.3.6.1.4.1.4413.2.2.2.1.2.12161.1.2.2.0"
#define kOID_cmRemoteIpv6Address  "1.3.6.1.4.1.4413.2.2.2.1.2.12161.1.3.2.0"
#endif

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#define ETH_MESH_BRIDGE "br403"
extern BOOL isMAPTReady;

#if defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#define NAT46_INTERFACE "map0"
#define NAT46_CLAMP_MSS  1440
#endif // NAT46_KERNEL_SUPPORT
#endif

/* HUB4 application specific defines. */
#ifdef _HUB4_PRODUCT_REQ_
#ifdef HUB4_BFD_FEATURE_ENABLED
#define IPOE_HEALTHCHECK "ipoe_healthcheck"
#endif //HUB4_BFD_FEATURE_ENABLED

#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
#define SELFHEAL "SELFHEAL"
#define HTTP_HIJACK_DIVERT "HTTP_HIJACK_DIVERT"
#endif //HUB4_SELFHEAL_FEATURE_ENABLED
#elif defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (IHC_FEATURE_ENABLED)
#define IPOE_HEALTHCHECK "ipoe_healthcheck"
#endif //IHC_FEATURE_ENABLED
#endif //_HUB4_PRODUCT_REQ_

#define PORT_SCAN_CHECK_CHAIN "PORT_SCAN_CHK"
#define PORT_SCAN_DROP_CHAIN  "PORT_SCAN_DROP"

extern void* bus_handle ;
extern int sysevent_fd;
extern char sysevent_ip[19];
extern unsigned short sysevent_port;

/**
* @brief Check if the HOTSPOT interface is currently active.
*
* This function queries the WAN Manager to determine if the HOTSPOT interface is active.
* It retrieves the interface active status parameter which contains a pipe-delimited list
* of WAN interfaces and their statuses in the format: "INTERFACE_NAME,STATUS|INTERFACE_NAME,STATUS|...".
* The function parses this string to check if HOTSPOT is present and has an active status (value = 1).
* Example response: "HOTSPOT,1|WANOE,0|DSL,0" would return true since HOTSPOT has status 1.
*
* @return The status of the HOTSPOT interface.
* @retval true if the HOTSPOT interface is active (status = 1).
* @retval false if the HOTSPOT interface is not active, not present, or if the query fails.
*
*/
#define PSM_VALUE_GET_STRING(name, str) PSM_Get_Record_Value2(bus_handle, CCSP_SUBSYS, name, NULL, &(str)) 
#define PSM_HOTSPOT_WAN_IFNAME "dmsb.wanmanager.if.3.Name"

/**
* @brief Get IPv6 addresses for a given interface.
*
* @param[in] ifname - Pointer to the interface name string.
* @param[out] ipArry - Array to store the retrieved IPv6 addresses.
* @param[in,out] p_num - Pointer to the number of addresses.
*                     \n On input, maximum number of addresses to retrieve.
*                     \n On output, actual number of addresses retrieved.
* @param[in] scope_in - Scope filter for IPv6 addresses.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on failure.
*
*/
int get_ip6address (char * ifname, char ipArry[][40], int * p_num, unsigned int scope_in);

// Constants used by both files
#define MAX_NO_IPV6_INF 10
#define MAX_LEN_IPV6_INF 32
#endif


// Raw table functions
/**
* @brief Apply raw table rules for Puma7 platform.
*
* @param[in] fp - Pointer to the FILE stream for writing raw table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_raw_table_puma7(FILE *fp);

// IPv6 specific functions
/**
* @brief Apply IPv6 source/destination filter rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return None.
*
*/
void do_ipv6_sn_filter(FILE *fp);

/**
* @brief Apply IPv6 NAT table rules.
*
* @param[in] fp - Pointer to the FILE stream for writing NAT table rules.
*
* @return None.
*
*/
void do_ipv6_nat_table(FILE *fp);

/**
* @brief Apply IPv6 filter table rules.
*
* Core IPv6 filter table policy enforcement.
*
* @param[in] fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_ipv6_filter_table(FILE *fp);

/**
* @brief Apply IPv6 UI over WAN filter rules.
*
* Controlled by the "UI over WAN" feature flag.
*
* @param[in] fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_ipv6_UIoverWAN_filter(FILE* fp);


// Access rules
/**
* @brief Apply Ethernet WAN MSO GUI access rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return None.
*
*/
void ethwan_mso_gui_acess_rules(FILE *filter_fp, FILE *mangle_fp);

// Block and protection functions
/**
* @brief Block WPAD (Web Proxy Auto-Discovery) and ISATAP IPv6 traffic.
*
* Prevents known attack vectors related to WPAD spoofing and ISATAP tunneling.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_wpad_isatap_blockv6(FILE *fp);

/**
* @brief Block fragmented IPv6 packets.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_blockfragippktsv6(FILE *fp);

/**
* @brief Apply IPv6 port scan protection rules.
*
* Function to add IP Table rules against Ports scanning.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_portscanprotectv6(FILE *fp);

/**
* @brief Apply IPv6 IP flood detection rules.
*
* Function to add IP Table rules against IPV6 Flooding.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_ipflooddetectv6(FILE *fp);

/**
* @brief Block WPAD (Web Proxy Auto-Discovery) and ISATAP IPv4 traffic.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_wpad_isatap_blockv4 (FILE *fp);

/**
* @brief Block fragmented IPv4 packets.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_blockfragippktsv4(FILE *fp);

/**
* @brief Apply IPv4 port scan protection rules.
*
* Function to add IP Table rules against Ports scanning.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_portscanprotectv4(FILE *fp);

/**
* @brief Apply IPv4 IP flood detection rules.
*
* Function to add IP Table rules against IPV4 Flooding.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_ipflooddetectv4(FILE *fp);

/**
* @brief Apply web UI attack filter rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_webui_attack_filter(FILE *filter_fp);

/**
* @brief Apply WAN/LAN web UI attack protection rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] interface - Pointer to the interface name string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int wan_lan_webui_attack(FILE *fp, const char *interface);

// Rule preparation functions
/**
* @brief Prepare RABID rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] ver - IP version type.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_rabid_rules(FILE *filter_fp, FILE *mangle_fp, ip_ver_t ver);

/**
* @brief Prepare RABID rules version 2020Q3B.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] ver - IP version type.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_rabid_rules_v2020Q3B(FILE *filter_fp, FILE *mangle_fp, ip_ver_t ver);

/**
* @brief Prepare RABID rules for MAP-T (Mapping of Address and Port with Translation).
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] ver - IP version type.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_rabid_rules_for_mapt(FILE *filter_fp, ip_ver_t ver);

/**
* @brief Apply parental control firewall rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] iptype - IP type.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_parental_control(FILE *fp, FILE *nat_fp, int iptype);

/**
* @brief Prepare LNF internet access rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] iptype - IP type.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on failure.
*
*/
int prepare_lnf_internet_rules(FILE *mangle_fp, int iptype);

/**
* @brief Allow container traffic through firewall.
*
* @param[in] pFilter - Pointer to the FILE stream for writing filter table rules.
* @param[in] pMangle - Pointer to the FILE stream for writing mangle table rules.
* @param[in] pNat - Pointer to the FILE stream for writing NAT table rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void do_container_allow(FILE *pFilter, FILE *pMangle, FILE *pNat, int family);

// MAPT related functions
/**
* @brief Apply MAP-T IPv6 filter rules.
*
* The function apply IPv6 Rules for HUB4 MAPT feature.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_mapt_rules_v6(FILE *filter_fp);

// HUB4 specific functions
#ifdef _HUB4_PRODUCT_REQ_
/**
* @brief Apply HUB4 voice service IPv6 firewall rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_voice_rules_v6(FILE *filter_fp, FILE *mangle_fp);

/**
* @brief Apply HUB4 DNS routing IPv6 mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_dns_rule_v6(FILE *mangle_fp);

#ifdef HUB4_BFD_FEATURE_ENABLED
/**
* @brief Apply HUB4 BFD (Bidirectional Forwarding Detection) IPv6 rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_bfd_rules_v6(FILE *filter_fp, FILE *mangle_fp);

#endif
#ifdef HUB4_QOS_MARK_ENABLED
/**
* @brief Apply QoS (Quality of Service) output marking IPv6 mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_qos_output_marking_v6(FILE *mangle_fp);

#endif
#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
/**
* @brief Apply self-heal IPv6 mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_self_heal_rules_v6(FILE *mangle_fp);

#endif
#endif

// MultiNet related functions
#ifdef INTEL_PUMA7
/**
* @brief Prepare MultiNet IPv6 mangle table rules for Puma7 platform.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return None.
*
*/
void prepare_multinet_mangle_v6(FILE *mangle_fp);

#endif
#ifdef MULTILAN_FEATURE
/**
* @brief Prepare MultiNet IPv6 filter forward chain rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_multinet_filter_forward_v6(FILE *fp);

/**
* @brief Prepare MultiNet IPv6 filter output chain rules.
*
* This function prepare the iptables-restore file that establishes all ipv6 firewall rules pertaining to traffic
* which will be either forwarded or received locally.
*
* @param[in] fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_multinet_filter_output_v6(FILE *fp);

#endif

// IPv6 rule mode functions
#ifdef RDKB_EXTENDER_ENABLED
/**
* @brief Prepare IPv6 firewall rules for extender mode.
*
* @param[in] raw_fp - Pointer to the FILE stream for writing raw table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_ipv6_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);
#endif
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && !defined(_CBR_PRODUCT_REQ_)
/**
* @brief Prepare IPv6 MultiNet rules with DHCPv6 prefix delegation support.
*
* @param[in] fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on failure.
*
*/
int prepare_ipv6_multinet(FILE *fp);

#endif

// Access control functions
/**
* @brief Apply LAN telnet and SSH access rules.
*
* This function enable / disable telnet and ssh from lan side.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] family - IP address family.
*                  \n Possible values are AF_INET for IPv4 or AF_INET6 for IPv6.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int lan_telnet_ssh(FILE *fp, int family);

/**
* @brief Apply SSH IP access table whitelist rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] port - Pointer to the SSH port number string.
* @param[in] family - IP address family.
*                  \n Possible values are AF_INET for IPv4 or AF_INET6 for IPv6.
* @param[in] interface - Pointer to the interface name string.
*
* @return None.
*
*/
void do_ssh_IpAccessTable(FILE *fp, const char *port, int family, const char *interface);

/**
* @brief Apply SNMP IP access table whitelist rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void do_snmp_IpAccessTable(FILE *fp, int family);

/**
* @brief Apply TR-069 ACS (Auto Configuration Server) whitelist rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void do_tr69_whitelistTable(FILE *fp, int family);

/**
* @brief Apply remote access control rules.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] family - IP address family.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_remote_access_control(FILE *nat_fp, FILE *filter_fp, int family);

// Port functions
/**
* @brief Apply blocked ports rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_block_ports(FILE *filter_fp);

/**
* @brief Apply web UI rate limiting rules to prevent brute force attacks.
*
* This function create chain to ratelimit remote management GUI packets over erouter interface.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_webui_rate_limit(FILE *filter_fp);

/**
* @brief Set LAN access protocol rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
* @param[in] port - Pointer to the port number string.
* @param[in] interface - Pointer to the interface name string.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int lan_access_set_proto(FILE *fp, const char *port, const char *interface);

/**
* @brief Apply single port forwarding rules.
*
* This function prepare the iptables-restore statements for single port forwarding.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] iptype - IP type.
* @param[in] filter_fp_v6 - Pointer to the FILE stream for writing IPv6 filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on bad input parameter.
*
*/
int do_single_port_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6);

/**
* @brief Apply port range forwarding rules.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] iptype - IP type.
* @param[in] filter_fp_v6 - Pointer to the FILE stream for writing IPv6 filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on bad input parameter.
*
*/
int do_port_range_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6);

/**
* @brief Open special ports from WAN to self or LAN.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return None.
*
*/
void do_openPorts(FILE *fp);

/**
* @brief Forward special ports from WAN to self or LAN.
*
* @param[in] fp - Pointer to the FILE stream for writing NAT table rules.
*
* @return None.
*
*/
void do_forwardPorts(FILE *fp);

// Utility functions
/**
* @brief Validate IPv6 address format.
*
* @param[in] ip_addr_string - Pointer to the IPv6 address string to validate.
*
* @return The validation status.
* @retval 1 if the IPv6 address is valid.
* @retval 0 if the IPv6 address is invalid.
*
*/
int IsValidIPv6Addr(char* ip_addr_string);
<<<<<<< HEAD

/**
* @brief Check if ULA (Unique Local Address) is enabled.
*
*This function check if ULA is enabled, If ULA is enabled we will broadcast ULA prefix.
*
* @return The ULA enabled status.
* @retval 0 if ULA is enabled.
* @retval -1 if ULA is disabled.
*
*/
int checkIfULAEnabled(void);

/**
* @brief Get parameter values from the RDK bus.
*
* This function retrieves a parameter value from the specified component on the RDK bus
* using the CcspBaseIf_getParameterValues interface. The returned value is copied to the
* provided buffer with proper null-termination and truncation handling.
*
* @param[in]  pComponent     - Pointer to the component name string.
* @param[in]  pBus           - Pointer to the D-Bus path string .
* @param[in]  pParamName     - Pointer to the parameter name to query.
* @param[out] pReturnVal     - Pointer to a buffer where the parameter value will be returned.
*                              The buffer must be pre-allocated by the caller with sufficient size.
* @param[in]  returnValSize  - Size of the pReturnVal buffer in bytes. Must be greater than 0.
*                              The returned string will be null-terminated and truncated if necessary
*                              to fit within this size.
*
* @return The status of the operation.
* @retval ANSC_STATUS_SUCCESS if the parameter value is successfully retrieved and copied.
* @retval ANSC_STATUS_FAILURE if pReturnVal is NULL, returnValSize is 0, or the RDK bus query fails.
*
*/

/**
* @brief Get list of IPv6 interfaces.
*
* This function used to get the list of IPv6 interfaces.
*
* @param[out] Interface - Array to store IPv6 interface names.
* @param[in,out] len - Pointer to the number of interfaces.
*                   \n On input, maximum number of interfaces to retrieve.
*                   \n On output, actual number of interfaces retrieved.
*
* @return None.
*
*/
#ifdef WAN_FAILOVER_SUPPORTED
int checkIfULAEnabled(void);
#endif
void getIpv6Interfaces(char Interface[MAX_NO_IPV6_INF][MAX_LEN_IPV6_INF], int *len);

/**
* @brief Prepare hotspot GRE (Generic Routing Encapsulation) IPv6 rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void prepare_hotspot_gre_ipv6_rule(FILE *filter_fp);

/**
* @brief Apply LAN to self rules based on WAN IPv6 address.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_lan2self_by_wanip6(FILE *filter_fp);

/**
* @brief Open video analytics port in firewall rules.
*
* @param[in] fp - Pointer to the FILE stream for writing filter rules.
*
* @return None.
*
*/
void do_OpenVideoAnalyticsPort(FILE *fp);

/**
* @brief Check if firewall service is needed.
*
* @return The service needed status.
* @retval true if service is needed.
* @retval false if service is not needed.
*
*/
bool isServiceNeeded(void);

// DNS functions
#ifdef XDNS_ENABLE
/**
* @brief Apply DNS routing rules for XDNS (Extended DNS).
*
* This function route DNS requests from LAN through dnsmasq.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] iptype - IP type.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_dns_route(FILE *nat_fp, int iptype);

#endif

// Speedboost functions
#if defined(SPEED_BOOST_SUPPORTED) && defined(SPEED_BOOST_SUPPORTED_V6)
/**
* @brief Apply speed boost port marking and redirection rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] iptype - IP type.
*                  \n Value 4 for IPv4 or 6 for IPv6.
*
* @return None.
*
*/
void do_speedboost_port_rules(FILE *mangle_fp, FILE *nat_fp, int iptype);

#endif

// String manipulation utilities
/**
* @brief Perform string substitutions in firewall rule strings.
*
* This function change well-known symbols in a string to the running/configured values.
*
* @param[in] in_str - Pointer to the input string.
* @param[out] out_str - Pointer to the output string buffer.
* @param[in] size - Size of the output buffer in bytes.
*
* @return Pointer to the output string.
* @retval  A pointer to the output string on success.
* @retval NULL on failure.
*
*/
char *make_substitutions(char *in_str, char *out_str, const int size);

// Global variables used in both files
extern char current_wan_ifname[50];
extern char wan6_ifname[50];
extern char ecm_wan_ifname[20];
extern char lan_ifname[50];
extern char cmdiag_ifname[20];
extern char emta_wan_ifname[20];
extern token_t sysevent_token;
extern char *sysevent_name;
extern int syslog_level;
extern char firewall_levelv6[20];
extern int isWanPingDisableV6;
extern int isHttpBlockedV6;
extern int isP2pBlockedV6;
extern int isIdentBlockedV6;
extern int isMulticastBlockedV6;
extern int isFirewallEnabled;
extern int isBridgeMode;
extern int isWanServiceReady;
extern int isDevelopmentOverride;
extern int isRawTableUsed;
extern int isContainerEnabled;
extern int isComcastImage;
extern bool bEthWANEnable;
extern int isCmDiagEnabled;
extern char iot_ifName[50];       // IOT interface
extern int isDmzEnabled;
extern int isPingBlockedV6;
#if defined (INTEL_PUMA7)
extern bool erouterSSHEnable;
#else
extern bool erouterSSHEnable;
#endif
extern int ecm_wan_ipv6_num;
extern char ecm_wan_ipv6[IF_IPV6ADDR_MAX][40];
#ifdef WAN_FAILOVER_SUPPORTED
extern char mesh_wan_ifname[32];
#endif
extern int isNatReady;
extern bool bAmenityEnabled;

#if defined(SPEED_BOOST_SUPPORTED)
extern char speedboostports[32];
extern BOOL isPvDEnable;
#if defined(SPEED_BOOST_SUPPORTED_V6)
extern char speedboostportsv6[32];
#endif
#endif

#define MAX_QUERY 256
#define MAX_SYSCFG_ENTRIES 128
#define XHS_IF_NAME    "brlan1"
#define LNF_IF_NAME    "br106"
#define MAX_NO_IPV6_INF 10
#define MAX_LEN_IPV6_INF 32
#define MAX_BUFF_LEN 350

#ifdef WAN_FAILOVER_SUPPORTED
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
/**
* @brief Redirect DNS queries to extender interface in WAN failover mode.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void  redirect_dns_to_extender(FILE *nat_fp,int family);

#endif //_PLATFORM_RASPBERRYPI_ && _PLATFORM_BANANAPI_R4_

typedef enum {
    ROUTER =0,
    EXTENDER_MODE,
} Dev_Mode;


/**
* @brief Get the device operating mode.
*
* This function used to get device mode.
*
* @return The device mode.
* @retval ROUTER if device is in router mode.
* @retval EXTENDER_MODE if device is in extender mode.
*
*/
unsigned int Get_Device_Mode() ;

/**
* @brief Get the IP address of a specified interface.
*
* @param[in] iface_name - Pointer to the interface name string.
*
* @return The status of the operation or pointer to the IP address string.
* @retval Pointer to the IP address string on success.
* @retval NULL on failure.
*
*/
char* get_iface_ipaddr(const char* iface_name);


#endif

#ifdef WAN_FAILOVER_SUPPORTED
#define WAN_FAILOVER_SUPPORT_CHECK if (isServiceNeeded()) \
     {

#define WAN_FAILOVER_SUPPORT_CHECk_END }

#else
#define WAN_FAILOVER_SUPPORT_CHECK
#define WAN_FAILOVER_SUPPORT_CHECk_END
#endif
#ifdef RDKB_EXTENDER_ENABLED

/**
* @brief Add interface MSS (Maximum Segment Size) clamping rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void add_if_mss_clamping(FILE *mangle_fp,int family);

/**
* @brief Start firewall service in extender mode.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval <0 on error code.
*
*/
int service_start_ext_mode () ;

/**
* @brief Prepare IPv4 firewall rules for extender mode.
*
* @param[in] raw_fp - Pointer to the FILE stream for writing raw table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_ipv4_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);

/**
* @brief Prepare IPv6 firewall rules for extender mode.
*
* @param[in] raw_fp - Pointer to the FILE stream for writing raw table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_ipv6_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);

/**
* @brief Check if the device is running in extender profile.
*
* @return The extender profile status.
* @retval 0 if device is in extender profile.
* @retval -1 if device is not in extender profile.
*
*/
int isExtProfile();

#endif
#if defined (WIFI_MANAGE_SUPPORTED)
/**
* @brief Update managed WiFi firewall rules.
*
* @param[in] busHandle - Pointer to the bus handle.
* @param[in] pCurWanInterface - Pointer to the current WAN interface name string.
* @param[in] filterFp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void updateManageWiFiRules(void * busHandle, char * pCurWanInterface, FILE * filterFp);

/**
* @brief Check if managed WiFi is enabled.
*
* @return The managed WiFi enabled status.
* @retval true if managed WiFi is enabled.
* @retval false if managed WiFi is disabled.
*
*/
bool isManageWiFiEnabled(void);

#endif/*WIFI_MANAGE_SUPPORTED*/

#if defined (AMENITIES_NETWORK_ENABLED)
#define AMENITY_WIFI_BRIDGE_NAME "dmsb.l2net.%s.Name"
#define VAP_NAME_2G_INDEX "dmsb.MultiLAN.AmenityNetwork_2g_l3net"
#define VAP_NAME_5G_INDEX "dmsb.MultiLAN.AmenityNetwork_5g_l3net"
#define VAP_NAME_6G_INDEX "dmsb.MultiLAN.AmenityNetwork_6g_l3net"
/**
* @brief Update amenity network firewall rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] iptype - IP type.
*
* @return None.
*
*/
void updateAmenityNetworkRules(FILE *filter_fp , FILE *mangle_fp,int iptype);

#endif /*AMENITIES_NETWORK_ENABLED*/


#ifdef WAN_FAILOVER_SUPPORTED

#define PSM_MESH_WAN_IFNAME "dmsb.Mesh.WAN.Interface.Name"
extern int mesh_wan_ipv6_num;
extern char mesh_wan_ipv6addr[IF_IPV6ADDR_MAX][40];
extern char dev_type[20];
extern char mesh_wan_ifname[32];
/**
* @brief Apply hotspot post-routing NAT rules for source address translation.
*
* This function writes iptables post-routing rules to enable Source NAT (SNAT) for hotspot WAN traffic.
* It configures SNAT rules to translate outgoing traffic on the hotspot WAN interface to use the WAN IP address.
*
* @param[in] fp       - Pointer to an open file stream where the iptables rules will be written.
* @param[in] isIpv4   - Boolean flag indicating the IP version.
*                       \n true: Apply IPv4 post-routing rules.
*                       \n false: Apply IPv6 post-routing rules.
*
* @return None.
*
*/
#endif

void applyHotspotPostRoutingRules(FILE *fp, bool isIpv4);
extern char hotspot_wan_ifname[50];
extern int current_wan_ipv6_num;
extern char default_wan_ifname[50]; // name of the regular wan interface
extern char current_wan_ipv6[IF_IPV6ADDR_MAX][40];
extern char current_wan_ip6_addr[128];
extern char lan_local_ipv6[IF_IPV6ADDR_MAX][40];
extern int lan_local_ipv6_num;
extern bool isDefHttpPortUsed;
extern bool isDefHttpsPortUsed;
extern char devicePartnerId[255];
extern int rfstatus;

//Hardcoded support for cm and erouter should be generalized.
#if defined(_HUB4_PRODUCT_REQ_) || defined(_TELCO_PRODUCT_REQ_)
extern char * ifnames[];
#else
extern char * ifnames[];
#endif /* * _HUB4_PRODUCT_REQ_ */
extern int numifs;
/*----*/

#if defined(_WNXL11BWL_PRODUCT_REQ_)
/**
* @brief Apply DNS proxy rules.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void  proxy_dns(FILE *nat_fp,int family);

/**
* @brief Get ULA (Unique Local Address) IPv6 address of an interface.
*
* @param[in] ifname - Pointer to the interface name string.
* @param[out] ipaddr - Pointer to the buffer to store the IPv6 address.
* @param[in] max_ip_size - Maximum size of the IP address buffer in bytes.
*
* @return None.
*
*/
void get_iface_ipaddr_ula(const char* ifname,char* ipaddr, int max_ip_size);
#endif
