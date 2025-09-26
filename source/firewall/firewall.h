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

int do_logs(FILE *fp);
int do_wan2self_attack(FILE *fp,char* wan_ip);
int prepare_ipv4_firewall(const char *fw_file);
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
#define PSM_VALUE_GET_STRING(name, str) PSM_Get_Record_Value2(bus_handle, CCSP_SUBSYS, name, NULL, &(str)) 
#define PSM_HOTSPOT_WAN_IFNAME "dmsb.wanmanager.if.3.Name"

int get_ip6address (char * ifname, char ipArry[][40], int * p_num, unsigned int scope_in);

// Constants used by both files
#define MAX_NO_IPV6_INF 10
#define MAX_LEN_IPV6_INF 32
#endif

// Raw table functions
int do_raw_table_puma7(FILE *fp);

// IPv6 specific functions
void do_ipv6_sn_filter(FILE *fp);
void do_ipv6_nat_table(FILE *fp);
void do_ipv6_filter_table(FILE *fp);
void do_ipv6_UIoverWAN_filter(FILE* fp);
void do_ipv6_filter_table(FILE *fp);

// Access rules
void ethwan_mso_gui_acess_rules(FILE *filter_fp, FILE *mangle_fp);

// Block and protection functions
int do_wpad_isatap_blockv6(FILE *fp);
int do_blockfragippktsv6(FILE *fp);
int do_portscanprotectv6(FILE *fp);
int do_ipflooddetectv6(FILE *fp);
int do_wpad_isatap_blockv4 (FILE *fp);
int do_blockfragippktsv4(FILE *fp);
int do_portscanprotectv4(FILE *fp);
int do_ipflooddetectv4(FILE *fp);


// Rule preparation functions
int prepare_rabid_rules(FILE *filter_fp, FILE *mangle_fp, ip_ver_t ver);
int prepare_rabid_rules_v2020Q3B(FILE *filter_fp, FILE *mangle_fp, ip_ver_t ver);
int prepare_rabid_rules_for_mapt(FILE *filter_fp, ip_ver_t ver);
int do_parental_control(FILE *fp, FILE *nat_fp, int iptype);
int prepare_lnf_internet_rules(FILE *mangle_fp, int iptype);
void do_container_allow(FILE *pFilter, FILE *pMangle, FILE *pNat, int family);

// MAPT related functions
int do_mapt_rules_v6(FILE *filter_fp);

// HUB4 specific functions
#ifdef _HUB4_PRODUCT_REQ_
int do_hub4_voice_rules_v6(FILE *filter_fp, FILE *mangle_fp);
int do_hub4_dns_rule_v6(FILE *mangle_fp);
#ifdef HUB4_BFD_FEATURE_ENABLED
int do_hub4_bfd_rules_v6(FILE *filter_fp, FILE *mangle_fp);
#endif
#ifdef HUB4_QOS_MARK_ENABLED
int do_qos_output_marking_v6(FILE *mangle_fp);
#endif
#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
int do_self_heal_rules_v6(FILE *mangle_fp);
#endif
#endif

// MultiNet related functions
#ifdef INTEL_PUMA7
void prepare_multinet_mangle_v6(FILE *mangle_fp);
#endif
#ifdef MULTILAN_FEATURE
int prepare_multinet_filter_forward_v6(FILE *fp);
int prepare_multinet_filter_output_v6(FILE *fp);
#endif

// IPv6 rule mode functions
#ifdef RDKB_EXTENDER_ENABLED
int prepare_ipv6_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);
#endif
#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && !defined(_CBR_PRODUCT_REQ_)
int prepare_ipv6_multinet(FILE *fp);
#endif

// Access control functions
int lan_telnet_ssh(FILE *fp, int family);
void do_ssh_IpAccessTable(FILE *fp, const char *port, int family, const char *interface);
void do_snmp_IpAccessTable(FILE *fp, int family);
void do_tr69_whitelistTable(FILE *fp, int family);
int do_remote_access_control(FILE *nat_fp, FILE *filter_fp, int family);

// Port functions
int do_block_ports(FILE *filter_fp);
void do_webui_rate_limit(FILE *filter_fp);
int lan_access_set_proto(FILE *fp, const char *port, const char *interface);
int do_single_port_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6);
int do_port_range_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6);
void do_openPorts(FILE *fp);
void do_forwardPorts(FILE *fp);

// Utility functions
int IsValidIPv6Addr(char* ip_addr_string);
#ifdef WAN_FAILOVER_SUPPORTED
int checkIfULAEnabled(void);
#endif
void getIpv6Interfaces(char Interface[MAX_NO_IPV6_INF][MAX_LEN_IPV6_INF], int *len);
void prepare_hotspot_gre_ipv6_rule(FILE *filter_fp);
int do_lan2self_by_wanip6(FILE *filter_fp);
void do_OpenVideoAnalyticsPort(FILE *fp);
bool isServiceNeeded(void);
// DNS functions
#ifdef XDNS_ENABLE
int do_dns_route(FILE *nat_fp, int iptype);
#endif

// Speedboost functions
#if defined(SPEED_BOOST_SUPPORTED) && defined(SPEED_BOOST_SUPPORTED_V6)
void do_speedboost_port_rules(FILE *mangle_fp, FILE *nat_fp, int iptype);
#endif

// String manipulation utilities
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
void  redirect_dns_to_extender(FILE *nat_fp,int family);
#endif //_PLATFORM_RASPBERRYPI_ && _PLATFORM_BANANAPI_R4_

typedef enum {
    ROUTER =0,
    EXTENDER_MODE,
} Dev_Mode;


unsigned int Get_Device_Mode() ;

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

void add_if_mss_clamping(FILE *mangle_fp,int family);
int service_start_ext_mode () ;

int prepare_ipv4_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);
int prepare_ipv6_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp);
int isExtProfile();
#endif
#if defined (WIFI_MANAGE_SUPPORTED)
void updateManageWiFiRules(void * busHandle, char * pCurWanInterface, FILE * filterFp);
bool isManageWiFiEnabled(void);
#endif/*WIFI_MANAGE_SUPPORTED*/

#if defined (AMENITIES_NETWORK_ENABLED)
#define AMENITY_WIFI_BRIDGE_NAME "dmsb.l2net.%s.Name"
#define VAP_NAME_2G_INDEX "dmsb.MultiLAN.AmenityNetwork_2g_l3net"
#define VAP_NAME_5G_INDEX "dmsb.MultiLAN.AmenityNetwork_5g_l3net"
#define VAP_NAME_6G_INDEX "dmsb.MultiLAN.AmenityNetwork_6g_l3net"
void updateAmenityNetworkRules(FILE *filter_fp , FILE *mangle_fp,int iptype);
#endif /*AMENITIES_NETWORK_ENABLED*/


#ifdef WAN_FAILOVER_SUPPORTED

#define PSM_MESH_WAN_IFNAME "dmsb.Mesh.WAN.Interface.Name"
extern int mesh_wan_ipv6_num;
extern char mesh_wan_ipv6addr[IF_IPV6ADDR_MAX][40];
extern char dev_type[20];
extern char mesh_wan_ifname[32];
#endif

void applyHotspotPostRoutingRules(FILE *fp, bool isIpv4);
extern char hotspot_wan_ifname[32];
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
void  proxy_dns(FILE *nat_fp,int family);

void get_iface_ipaddr_ula(const char* ifname,char* ipaddr, int max_ip_size);
#endif

