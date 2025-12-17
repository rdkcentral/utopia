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

#ifndef __FIREWALL_CUSTOM_H__
#define __FIREWALL_CUSTOM_H__


#include <stdio.h>
#include<stdlib.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include "ccsp_custom.h"
extern FILE *firewallfp;
#define FW_DEBUG 1

/**
* @brief Append device-based packet processing disabled rule.
*
* @param[in] fp - Pointer to the FILE stream for writing firewall rules.
* @param[in] ins_num - Pointer to the instance number string.
* @param[in] lan_ifname - Pointer to the LAN interface name string.
* @param[in] query - Pointer to the MAC address query string.
*
* @return None.
*
*/
void do_device_based_pp_disabled_appendrule(FILE *fp, const char *ins_num, const char *lan_ifname, const char *query);

/**
* @brief Append device-based packet processing disabled IP rule.
*
* @param[in] fp - Pointer to the FILE stream for writing firewall rules.
* @param[in] ins_num - Pointer to the instance number string.
* @param[in] ipAddr - Pointer to the IP address string.
*
* @return None.
*
*/
void do_device_based_pp_disabled_ip_appendrule(FILE *fp, const char *ins_num, const char *ipAddr);

/**
* @brief Append parental control management LAN to WAN PC site rule.
*
* @param[in] fp - Pointer to the FILE stream for writing firewall rules.
*
* @return The number of rules appended.
*
*/
int do_parcon_mgmt_lan2wan_pc_site_appendrule(FILE *fp);

/**
* @brief Insert parental control management LAN to WAN PC site rule at specified index.
*
* @param[in] fp - Pointer to the FILE stream for writing firewall rules.
* @param[in] index - Index position where the rule should be inserted.
* @param[in] nstdPort - Pointer to the non-standard port string.
*
* @return None.
*
*/
void do_parcon_mgmt_lan2wan_pc_site_insertrule(FILE *fp, int index, char *nstdPort);

/**
* @brief Log firewall messages with variable arguments.
*
* This function logs a message to the firewall log file with a timestamp prefix.
*
* @param[in] fmt - Pointer to the format string for the log message.
* @param[in] ... - Variable arguments for the format string.
*
* @return None.
*
*/
void firewall_log( char* fmt, ...);

/**
* @brief Update RABID (Router Advertisement Basic Interface Discovery) features status.
*
* @return None.
*
*/
void update_rabid_features_status();

/**
* @brief Apply port forwarding rules to the filter table.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_forwardPorts(FILE *filter_fp);

/**
* @brief Apply SNMP IP access table rules.
*
* @param[in] filt_fp - Pointer to the FILE stream for writing filter rules.
* @param[in] family - IP address family.
*
* @return None.
*
*/
void do_snmp_IpAccessTable(FILE *filt_fp, int family);

/**
* @brief Apply SSH IP access table rules.
*
* @param[in] filt_fp - Pointer to the FILE stream for writing filter rules.
* @param[in] port - Pointer to the SSH port string.
* @param[in] family - IP address family.
* @param[in] interface - Pointer to the interface name string.
*
* @return None.
*
*/
void do_ssh_IpAccessTable(FILE *filt_fp, const char *port, int family, const char *interface);

/**
* @brief Apply TR-069 whitelist table rules.
*
* @param[in] filt_fp - Pointer to the FILE stream for writing filter rules.
* @param[in] family - IP address family.
*                  \n Possible values are AF_INET for IPv4 or AF_INET6 for IPv6.
*
* @return None.
*
*/
void do_tr69_whitelistTable(FILE *filt_fp, int family);

/**
* @brief Apply port mapping filter rules.
*
* This function enable portmap traffic only on loopback and PEER IP.
*
* @param[in] filt_fp - Pointer to the FILE stream for writing filter rules.
*
* @return None.
*
*/
void filterPortMap(FILE *filt_fp);

/**
* @brief Apply open ports firewall rules.
*
* This function open special ports from wan to self/lan.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_openPorts(FILE *filter_fp);

/**
* @brief Prepare XCONF (external configuration) mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_xconf_rules(FILE *mangle_fp);

/**
* @brief Apply IPv6 self-heal mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_self_heal_rules_v6(FILE *mangle_fp);

/**
* @brief Apply IPv6 QoS output marking mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_qos_output_marking_v6(FILE *mangle_fp);

/**
* @brief Apply HUB4 MAP-T IPv6 filter rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_mapt_rules_v6(FILE *filter_fp);

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

/**
* @brief Apply HUB4 DNS IPv6 mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_dns_rule_v6(FILE* mangle_fp);

/**
* @brief Apply HUB4 voice IPv6 rules.
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
* @brief Apply IPv4 self-heal mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_self_heal_rules_v4(FILE *mangle_fp);

/**
* @brief Apply IPv4 QoS output marking mangle rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_qos_output_marking_v4(FILE *mangle_fp);

/**
* @brief Apply HUB4 MAP-T IPv4 rules.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_mapt_rules_v4(FILE *nat_fp, FILE *filter_fp);

/**
* @brief Apply HUB4 BFD (Bidirectional Forwarding Detection) IPv4 rules.
*
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_bfd_rules_v4(FILE *nat_fp, FILE *filter_fp, FILE *mangle_fp);

/**
* @brief Apply HUB4 voice IPv4 filter rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int do_hub4_voice_rules_v4(FILE *filter_fp);

/**
* @brief Check if the system is in self-heal mode.
*
* @return The self-heal mode status.
* @retval 1 if in self-heal mode.
* @retval 0 if not in self-heal mode.
*
*/
int isInSelfHealMode ();

/**
* @brief Get the LAN IP address.
*
* @return Pointer to the LAN IP address string.
* @retval LAN IP address on success.
* @retval NULL on failure.
*
*/
char *get_lan_ipaddr();

/**
* @brief Get the current WAN interface name.
*
* @return Pointer to the current WAN interface name string.
* @retval WAN interface name on success.
* @retval NULL on failure.
*
*/
char *get_current_wan_ifname();

/**
* @brief Apply Ethernet WAN MSO GUI access rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return None.
*
*/
void ethwan_mso_gui_acess_rules(FILE *filter_fp,FILE *mangle_fp);

/**
* @brief Open video analytics port in firewall rules.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_OpenVideoAnalyticsPort (FILE *filter_fp);

/**
* @brief Apply web UI rate limiting rules.
*
* This function create chain to ratelimit remote management GUI packets over erouter interface.
*
* @param[in] filter_fp - Pointer to the FILE stream for writing filter table rules.
*
* @return None.
*
*/
void do_webui_rate_limit (FILE *filter_fp);

/**
* @brief Prepare DSCP (Differentiated Services Code Point) rules for prioritized clients.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_dscp_rules_to_prioritized_clnt(FILE* mangle_fp);

/**
* @brief Prepare LLD (Link Layer Discovery) DSCP rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return The status of the operation.
* @retval 0 on success.
*
*/
int prepare_lld_dscp_rules(FILE *mangle_fp);

/**
* @brief Prepare DSCP rule for host management traffic.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
*
* @return None.
*
*/
void prepare_dscp_rule_for_host_mngt_traffic(FILE *mangle_fp);

#if defined(SPEED_BOOST_SUPPORTED)
/**
* @brief Apply speed boost port rules.
*
* @param[in] mangle_fp - Pointer to the FILE stream for writing mangle table rules.
* @param[in] nat_fp - Pointer to the FILE stream for writing NAT table rules.
* @param[in] iptype - IP type.
*
* @return None.
*
*/
void do_speedboost_port_rules(FILE *mangle_fp, FILE *nat_fp , int iptype);

/**
* @brief Check if a port overlaps with speed boost port range.
*
* @param[in] ExternalPort - External port number.
* @param[in] ExternalPortEndRange - External port end range number.
* @param[in] InternalPort - Internal port number.
* @param[in] InternalPortend - Internal port end range number.
*
* @return The overlap status.
* @retval 1 if there is overlap.
* @retval 0 if there is no overlap.
*
*/
int IsPortOverlapWithSpeedboostPortRange(int ExternalPort, int ExternalPortEndRange, int InternalPort , int InternalPortend);
#endif

#ifdef FW_DEBUG
#define COMMA ,
#define FIREWALL_DEBUG(x) firewall_log(x);
#else
#define FIREWALL_DEBUG(x)
#endif

#define SHM_MUTEX "FirewallMutex"

typedef enum {
    IP_V4 = 0,
    IP_V6,
}ip_ver_t;

typedef struct fw_shm_mutex {
  pthread_mutex_t *ptr;
  int fw_shm_create;
  int fw_shm_fd;
  char fw_mutex[32];

} fw_shm_mutex;


/**
* @brief Initialize a firewall shared memory mutex.
*
* @param[in] name - Pointer to the mutex name string.
*
* @return The initialized firewall shared memory mutex structure.
*
*/
fw_shm_mutex fw_shm_mutex_init(char *name);

/**
* @brief Close a firewall shared memory mutex.
*
* @param[in] mutex - The firewall shared memory mutex structure to close.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on failure.
*
*/
int fw_shm_mutex_close(fw_shm_mutex mutex);

/*
 *  rdkb_arm is same as 3939/3941
 *
#define CONFIG_CCSP_LAN_HTTP_ACCESS
#define CONFIG_CCSP_VPN_PASSTHROUGH
 */
#if defined (INTEL_PUMA7) || (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_)) || defined(_COSA_QCA_ARM_)
#define CONFIG_CCSP_VPN_PASSTHROUGH
#endif

#if defined (INTEL_PUMA7)
#define CONFIG_KERNEL_NETFILTER_XT_TARGET_CT
#endif
#define CONFIG_CCSP_WAN_MGMT
#define CONFIG_CCSP_WAN_MGMT_PORT
//#define CONFIG_CCSP_WAN_MGMT_ACCESS //defined in ccsp_custom.h
#ifndef _HUB4_PRODUCT_REQ_
#define CONFIG_CCSP_CM_IP_WEBACCESS
#endif /* * !_HUB4_PRODUCT_REQ_ */

#endif
