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

/*
 ============================================================================

 Introduction to IPv4 Firewall
 -------------------------------
 
 The firewall is based on iptables. It uses the mangle, nat, and filters tables,
 and for each of these, it add several subtables.

 The reason for using subtables is that a subtable represents a block of rules
 which can be erased (using -F), and reconstituted using syscfg and sysevent, 
 without affecting the rest of the firewall. That makes its easier to organize
 a complex firewall into smaller functional groups. 

 The main tables, INPUT OUTPUT, and FORWARD, contain jumps to subtables that better represent
 a Utopia firewall: wan2self, lan2self, lan2wan, wan2wan. Each of these subtables
 further specifies the order of rules and jumps to further subtables. 
 
 As mentioned earlier, the firewall is iptables based. There are two ways to use iptables:
 iptables-restore using an input file, or issuing a series of iptables commands. Using iptables-restore
 disrupts netfilters connection tracking which causes established connections to appear to be invalid.
 Using iptables is slower, and it requires that Utopia firewall table structure already exists. This means
 that it cannot be used to initially structure the firewall. 

 The behavior of firewall.c is to check whether the iptables file (/tmp/.ipt)
 exists. If it doesn't exist, then a new one is created and instantiated via iptables-restore.
 On the other hand if .ipt already exists, then all subtables are flushed and reconstituted
 using iptables rules. 

 Here is a list of subtables and how each subtable is populated:
 Note that some syscfg/sysevent tuples are used to populate more than one subtable

 raw
 ---
   prerouting_ephemeral:
   output_ephemeral:
      Rules are made from:
         -sysevent RawFirewallRule

   prerouting_raw:
   output_raw:
      Rules are made from:
         - syscfg set RawTableFirewallRule

   prerouting_nowan:
   output_nowan:
      Rules are made when current_wan_ipaddr is 0.0.0.0

 mangle
 -----
   prerouting_trigger:
      Rules are made from:
           - syscfg PortRangeTrigger_x

   prerouting_qos:
   postrouting_qos:
     Rules are made from:
      - syscfg QoSPolicy_x
      - syscfg QoSUserDefinedPolicy_x
      - syscfg QoSDefinedPolicy_x
      - syscfg QoSMacAddr_x
      - syscfg QoSVoiceDevice_x
  
   postrouting_lan2lan
      Rules are made from:
         - syscfg block_nat_redirection

 nat
 ---
   prerouting_fromwan:
        - syscfg SinglePortForward_x
        - syscfg PortRangeFoward_x
        - syscfg WellKnownPortForward_x
        - sysevent portmap_dyn_pool

   prerouting_mgmt_override:
        - syscfg mgmt_httpaccess
        - syscfg mgmt_httpsaccess
        - syscfg http_admin_port

   prerouting_plugins:
      Root of subtables used by plugins such as parental control which use a local logic
      to provision its subtables

   prerouting_fromwan_todmz:
        - syscfg dmz_enabled

   prerouting_fromlan:
   postrouting_tolan:
     Rules are made from:
        - syscfg SinglePortForward_x
        - syscfg PortRangeFoward_x
        - syscfg WellKnownPortForward_x
        - sysevent portmap_dyn_pool

   postrouting_towan:
     Rules are made from:
       - syscfg nat_enabled

   prerouting_ephemeral:
   postrouting_ephemeral:
     powerful rules that are run early on the PREROUTING|POSTROUTING chain
     Rules are made from:
        - sysevent NatFirewallRule

   xlog_drop_lanattack:
      attacks from lan

   postrouting_plugins:
      Root of subtables used by plugins such as parental control which use a local logic
      to provision its subtables


 filter
 ------
   The filter table splits traffic into chains based on the incoming interface and the destination.
   Traffic specific chains are:
      lan2wan 
      wan2lan
      lan2self
      wan2self 
   Each chain further classifies traffic, and acts upon the traffic that fits the rule's criterea


   general_input:
   general_output:
   general_forward:
      powerful rules that are run early on the INPUT/OUTPUT/FORWARD chains 
      Rules are made from:
         - syscfg GeneralPurposeFirewallRule_x
         - sysevent GeneralPurposeFirewallRule
         - a DNAT trigger (via GeneralPurposeFirewallRule) 

   lan2wan:
     used to jump to other sub tables that are interested in traffic from lan to wan
      lan2wan_disable:
        Rules ase made from:
            - If nat is disable all lan to wan traffic dorped

      lan2wan_misc:
         Rules are made from:
            - sysevent get current_wan_ipaddr. If the current_wan_ipaddr is 0.0.0.0 then 
              there is no lan to wan traffic allowed
            - sysevent ppp_clamp_mtu

      lan2wan_triggers:
        Rules are made from:
           - syscfg PortRangeTrigger_x

      lan2wan_webfilters:
        Rules are made from:
           - syscfg block_webproxy
           - syscfg block_java
           - syscfg block_activex
           - syscfg block_cookies

      lan2wan_iap :
        Rules are made from:
           - syscfg InternetAccessPolicy_x
           This subtable is used to hold Internet Access Policy subtables
               * namespace_classification
               * namespace_rules

      lan2wan_plugins :
         Root of subtables used by plugins such as parental control which use a local logic
         to provision its subtables

   wan2lan:
     used to jump to other tables that are interested in traffic from wan to lan

      wan2lan_disabled:
         Rules are made from:
            - sysevent get current_wan_ipaddr. If the current_wan_ipaddr is 0.0.0.0 then 
              there is no wan to lan traffic allowed

      wan2lan_forwarding_accept:
        Rules are made from:
           - syscfg SinglePortForward_x
           - syscfg PortRangeFoward_x
           - syscfg WellKnownPortForward_x
           - sysevent portmap_dyn_pool
           - syscfg StaticRoute_x

      wan2lan_misc:
        Rules are made from:
           - syscfg W2LFirewallRule_x
           - syscfg W2LWellKnownFirewallRule_x
           - sysevent ppp_clamp_mtu

      wan2lan_accept:
         Rules are accept multicast

      wan2lan_nonat:
        When nat is disabled then firewall doesn't block forwarding to lan hosts
        Rules are made from:
           - syscfg nat_enabled (if not enabled)

      wan2lan_plugins:
         Root of subtables used by plugins such as parental control which use a local logic
         to provision its subtables

      wan2lan_dmz:
        Rules are made from:
           - syscfg dmz_enabled
     

   lan2self:
     used to jump to other tables that are interested in traffic from lan to utopia
     These tables are:
        lan2self_mgmt
        lan2self_attack
        host_detect

      lan2self_mgmt:
        Rules are made from:
           - syscfg mgmt_wifi_access

      lanattack:
        Rules are made from well known rules to protect from attacks on our trusted interface

      host_detect:
          Rules are made dynamically as lan host are discovered

      lan2self_plugins:
         Root of subtables used by plugins such as parental control which use a local logic
         to provision its subtables

   self2lan:
      used to jump to other tables that are interested in traffic from utopia to the lan
      These tables are:
         self2lan_plugins

      self2lan_plugins:
         Root of subtables used by plugins such as parental control which use a local logic
         to provision its subtables

   wan2self:
     used to jump to other tables that are interested in traffic from wan to utopia
     These tables are:
        wan2self_ports
        wan2self_mgmt
        wan2self_attack

      wan2self_mgmt:
         Rules are made from:
            - syscfg mgmt_wan_access

      wan2self_ports:
         powerful port control for packets from wan to our untrusted interface. They are examined early
         and allow accept/deny priviledges for ports/protocols etc. 
         Rules are made from:
            syscfg rip_enabled
            syscfg firewall_development_override
            syscfg block_ping
            syscfg block_multicast
            syscfg block_ident

      wanattack:
        Rules are made from well known rules to protect from attacks on our untrusted interface

   terminal rules:
      Many rules end with a jump to the appropriate log. In these rules, if logging is turned on, then a 
      log will be emitted. Otherwise no log is emitted, but the packet will be either accepted or dropped.

      xlog_accept_lan2wan:
      xlog_accept_wan2lan:
      xlog_accept_wan2self:
      xlog_drop_wan2lan:
      xlog_drop_lan2wan:
      xlog_drop_wan2self:
      xlog_drop_wanattack:
      xlog_drop_lanattack:
      xlogdrop:
      xlogreject:
        Rules are to log and drop/accept/reject

NOTES:
1) Port Range Triggering requires the userspace process "trigger" to be included in the image


Author: enright@cisco.com

Defines used to control conditional compilation 
-----------------------------------------------
CONFIG_BUILD_TRIGGER:
   Port Range Triggering built in. This requires the userspace process "trigger" to 
   be built into the image

OBSOLETE:
NOT_DEF:
   Not used code, but not yet removed

 ============================================================================
*/
#include "autoconf.h"
//zqiu: ARRISXB3-893
#ifdef CONFIG_INTEL_NF_TRIGGER_SUPPORT
#define CONFIG_KERNEL_NF_TRIGGER_SUPPORT CONFIG_INTEL_NF_TRIGGER_SUPPORT
#endif


#include"firewall.h"

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <ctype.h>
#include <ulog/ulog.h>


#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/mman.h>
#include "secure_wrapper.h"
#include "util.h"


#if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#endif

#ifdef FEATURE_464XLAT
#define XLAT_IF "xlat"
#define XLAT_IP "192.0.0.1"
#endif


#if defined(RDKB_EXTENDER_ENABLED)
char cellular_ifname[32];
#endif 
#if defined (_PROPOSED_BUG_FIX_)
#include <linux/version.h>
#endif

#define PORTMAPPING_2WAY_PASSTHROUGH
#define MAX_URL_LEN 1024 

#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
#define PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK "18080" // the same as the port in lighttpd.conf
#define PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK "10443" // the same as the port in lighttpd.conf
//#define DNS_QUERY_QUEUE_NUM 5

#define DNS_RES_QUEUE_NUM_START 6 //should be the same range as system_defaults-xxx
#define DNS_RES_QUEUE_NUM_END 8

#define DNSV6_RES_QUEUE_NUM_START 9 //should be the same range as system_defaults-xxx
#define DNSV6_RES_QUEUE_NUM_END 10

#define HTTP_GET_QUEUE_NUM_START 11 
#define HTTP_GET_QUEUE_NUM_END 12

#define HTTPV6_GET_QUEUE_NUM_START 13 
#define HTTPV6_GET_QUEUE_NUM_END 14


#if (HTTP_GET_QUEUE_NUM_END == HTTP_GET_QUEUE_NUM_START)
#define __IPT_GET_QUEUE_CONFIG__(x) "--queue-num " #x
#define _IPT_GET_QUEUE_CONFIG_(x) __IPT_GET_QUEUE_CONFIG__(x)
#define HTTP_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(DNS_RES_QUEUE_NUM_START)
#define DNSR_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(HTTP_GET_QUEUE_NUM_START)
#define HTTPV6_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(DNSV6_RES_QUEUE_NUM_START)
#define DNSV6R_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(HTTPV6_GET_QUEUE_NUM_START)
#else
#define __IPT_GET_QUEUE_CONFIG__(s,e) "--queue-balance " #s ":" #e 
#define _IPT_GET_QUEUE_CONFIG_(s,e) __IPT_GET_QUEUE_CONFIG__(s,e)
#define HTTP_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(HTTP_GET_QUEUE_NUM_START, HTTP_GET_QUEUE_NUM_END) 
#define DNSR_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(DNS_RES_QUEUE_NUM_START, DNS_RES_QUEUE_NUM_END) 
#define HTTPV6_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(HTTPV6_GET_QUEUE_NUM_START, HTTPV6_GET_QUEUE_NUM_END) 
#define DNSV6R_GET_QUEUE_CONFIG _IPT_GET_QUEUE_CONFIG_(DNSV6_RES_QUEUE_NUM_START, DNSV6_RES_QUEUE_NUM_END) 
#endif

#endif

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
#define PARCON_ALLOW_LIST "/var/.parcon_allow_list"
#define PARCON_IP_URL "/var/parcon"

#define PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK "18080" // the same as the port in lighttpd.conf
#define PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK "10443" // the same as the port in lighttpd.conf
#define PARCON_WALLED_GARDEN_HTTP_PORT_TIMEBLK "38080" // the same as the port in lighttpd.conf
#define PARCON_WALLED_GARDEN_HTTPS_PORT_TIMEBLK "30443" // the same as the port in lighttpd.conf

#define DNS_QUERY_QUEUE_NUM 5

#define DNS_RES_QUEUE_NUM_START 6 //should be the same range as system_defaults-xxx
#define DNS_RES_QUEUE_NUM_END 8

#define HTTP_GET_QUEUE_NUM_START 11 
#define HTTP_GET_QUEUE_NUM_END 12
#endif
#define FW_DEBUG 1

#ifdef _COSA_FOR_BCI_
#define BRIDGE_MODE_IP_ADDRESS "10.1.10.1"
#else
#define BRIDGE_MODE_IP_ADDRESS "10.0.0.1"
#endif

#if defined(_LG_OFW_)
#define BLOCK_WPAD_ISATAP
#endif

#define IS_EMPTY_STRING(s) ((s == NULL) || (*s == '\0'))

#define BUFLEN_8 8
#define BUFLEN_32 32
#define BUFLEN_64 64
#define RET_OK 0
#define RET_ERR -1
#define SET "set"
#define RESET "reset"
#define UP "up"

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#define SYSEVENT_MAPT_IP_ADDRESS "mapt_ip_address"
#define MAPT_NAT_IPV4_POST_ROUTING_TABLE "postrouting_towan"
#define SYSEVENT_MAPT_RATIO "mapt_ratio"
#define SYSEVENT_MAPT_IPV6_ADDRESS "mapt_ipv6_address"
#define SYSEVENT_MAPT_PSID_OFFSET "mapt_psid_offset"
#define SYSEVENT_MAPT_PSID_VALUE "mapt_psid_value"
#define SYSEVENT_MAPT_PSID_LENGTH "mapt_psid_length"

BOOL isMAPTSet(void);
static int do_wan_nat_lan_clients_mapt(FILE *fp);
static char mapt_ip_address[BUFLEN_32];

#ifdef FEATURE_MAPT_DEBUG
void logPrintMain(char* filename, int line, char *fmt,...);
#define LOG_PRINT_MAIN(...) logPrintMain(__FILE__, __LINE__, __VA_ARGS__ )
#endif

#endif //FEATURE_MAPT

#ifdef FEATURE_SUPPORT_MAPT_NAT46
#define XHS_BRIDGE  "brlan1"
#define LNF_BRIDGE  "br106"
#endif

#define V4_BLOCKFRAGIPPKT   "v4_BlockFragIPPkts"
#define V4_PORTSCANPROTECT  "v4_PortScanProtect"
#define V4_IPFLOODDETECT    "v4_IPFloodDetect"

#define XHS_GRE_CLAMP_MSS   1400
#define XHS_EB_MARK         4703

//core net lib
#include <stdint.h>
#ifdef CORE_NET_LIB
#include <libnet.h>
#endif

char *sysevent_name = "firewall";

int firewall_lib_init(void *bus_handle, int sysevent_fd, token_t sysevent_token);
#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
static int do_lan2wan_helpers(FILE *raw_fp);
#endif
FILE *firewallfp = NULL;

//#define CONFIG_BUILD_TRIGGER 1
/*
 * Service template declarations & definitions
 */
static char *service_name = "firewall";

//void* bus_handle = NULL;
const char* const firewall_component_id = "ccsp.firewall";
//pthread_mutex_t firewall_check;
fw_shm_mutex fwmutex;
#define SERVICE_EV_COUNT 4
enum{
    NAT_DISABLE = 0,
    NAT_DHCP,
    NAT_STATICIP,
    NAT_DISABLE_STATICIP,
};
#define PCMD_LIST "/tmp/.pcmd"

typedef struct _decMacs_
{
char mac[19];
}devMacSt;

#ifdef CISCO_CONFIG_TRUE_STATIC_IP 
#define MAX_TS_ASN_COUNT 64
typedef struct{
    char ip[20];
    char mask[20];
}staticip_subnet_t;

static char wan_staticip_status[20];       // wan_service-status

static char current_wan_static_ipaddr[20];//ipv4 static ip address 
static char current_wan_static_mask[20];//ipv4 static ip mask 
static char firewall_true_static_ip_enable[20];
//static char firewall_true_static_ip_enablev6[20];
static int isWanStaticIPReady;
static int isFWTS_enable = 0;
static int StaticIPSubnetNum = 0;
staticip_subnet_t StaticIPSubnet[MAX_TS_ASN_COUNT]; 


#define MAX_IP4_SIZE 20
char PfRangeIP[MAX_TS_ASN_COUNT][MAX_IP4_SIZE];

static int PfRangeCount = 0;

#if defined(_BWG_PRODUCT_REQ_)
staticip_subnet_t StaticClientIP[MAX_TS_ASN_COUNT];
static int StaticNatCount = 0;
#endif

#endif
typedef enum {
    SERVICE_EV_UNKNOWN,
    SERVICE_EV_START,
    SERVICE_EV_STOP,
    SERVICE_EV_RESTART,
    // add custom events here
    SERVICE_EV_SYSLOG_STATUS,
} service_ev_t;

/* iptables module name
 * Note: when get priorty from sysevent failed, it will use the default priority order
 * the default priority is IPT_PRI_XXXXX.
 * 1 is the highest priorty
 */ 
enum{
   IPT_PRI_NONEED = 0,
#ifdef CISCO_CONFIG_TRUE_STATIC_IP   
   IPT_PRI_STATIC_IP,
#endif
   IPT_PRI_PORTMAPPING,
   IPT_PRI_PORTTRIGGERING,
   IPT_PRI_FIREWALL,
   IPT_PRI_DMZ,   
   IPT_PRI_MAX = IPT_PRI_DMZ,
};

#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
static void wanmgr_get_wan_interface(char *wanInterface);
#endif

/*
 * Service event mapping table
 */
struct {
    service_ev_t ev;
    char         *ev_string;
} service_ev_map[SERVICE_EV_COUNT] = 
    {
        { SERVICE_EV_START,   "firewall-start" },
        { SERVICE_EV_STOP,    "firewall-stop" },
        { SERVICE_EV_RESTART, "firewall-restart" },
        // add entries for custom events here
        { SERVICE_EV_SYSLOG_STATUS, "syslog-status" },
    } ;


static char eth_wan_enabled[20];
static char wan_service_status[20];       // wan_service-status

static char current_wan_ipaddr[20]; // ipv4 address of the wan interface, whether ppp or regular
static char lan_ipaddr[20];       // ipv4 address of the lan interface
static char lan_netmask[20];      // ipv4 netmask of the lan interface
static char lan_3_octets[20];     // first 3 octets of the lan ipv4 address
static char iot_primaryAddress[50]; //IOT primary IP address
#if defined(_COSA_BCM_MIPS_)
static char lan0_ipaddr[20];       // ipv4 address of the lan0 interface used to access web ui in bridge mode
#endif
static char rip_enabled[20];      // is rip enabled
static char rip_interface_wan[20];  // if rip is enabled, then is it enabled on the wan interface
static char nat_enabled[20];      // is nat enabled
static char dmz_enabled[20];      // is dmz enabled
static char firewall_enabled[20]; // is the firewall enabled
static char container_enabled[20]; // is the container enabled
static char bridge_mode[20];      // is system in bridging mode
static char log_level[5];         // if logging is enabled then this is the log level
static int  log_leveli;           // an integer version of the above
static char reserved_mgmt_port[10];  // mgmt port of utopia
static char transparent_cache_state[10]; // state of the transparent http cache
static char byoi_bridge_mode[10]; // whether or not byoi is in bridge mode
static char cmdiag_enabled[20];   // If eCM diagnostic Interface Enabled
static char firewall_level[20];   // None, Low, Medium, High, or Custom
static char natip4[20];
static char captivePortalEnabled[50]; //to ccheck captive portal is enabled or not

#if defined (_XB6_PRODUCT_REQ_)
static char rfCaptivePortalEnabled[50]; //to check RF captive portal is enabled or not
#endif
static char redirectionFlag[50]; //Captive portal mode flag

static char iptables_pri_level[IPT_PRI_MAX];
static char lxcBridgeName[20];
//static int  portmapping_pri;        
//static int  porttriggering_pri;
//static int  firewall_pri;
//static int  dmz_pri;

static int isHairpin;
static int isWanReady;

static int isRFC1918Blocked;
static int allowOpenPorts;
static int isRipEnabled;
static int isRipWanEnabled;
static int isNatEnabled;

static int isLogEnabled;
static int isLogSecurityEnabled;
static int isLogIncomingEnabled;
static int isLogOutgoingEnabled;
static int isCronRestartNeeded;
static int isPingBlocked;
static int isIdentBlocked;
static int isMulticastBlocked;
static int isNatRedirectionBlocked;
static int isPortscanDetectionEnabled;
static int isWanPingDisable;
static int isNtpFinished                 = 0;
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
static int isTriggerMonitorRestartNeeded = 0;
#endif
static int isLanHostTracking             = 0;
static int isDMZbyMAC                    = 0;   // DMZ is known by MAC address
static int isCacheActive                 = 0;
static int isHttpBlocked;                       // Block incoming HTTP/HTTPS traffic
static int isP2pBlocked;                        // Block incoming P2P traffic

static int flush = 0;

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int isGuestNetworkEnabled;
static char guest_network_ipaddr[20];
static char guest_network_mask[20];
#endif

static int ppFlushNeeded = 0;
#ifdef _HUB4_PRODUCT_REQ_
static int isProdImage = 0;
#endif

#if defined(_ENABLE_EPON_SUPPORT_)
static BOOL isEponEnable = TRUE;
#else
static BOOL isEponEnable = FALSE;
#endif
int lan_local_ipv6_num = 0;
char current_wan_ip6_addr[128];
bool isDefHttpsPortUsed = FALSE ;
int current_wan_ipv6_num = 0;
char default_wan_ifname[50]; // name of the regular wan interface
int rfstatus;
/*
 * For timed internet access rules we use cron 
 */
#define crontab_dir  "/var/spool/cron/crontabs/"
#define crontab_filename  "firewall"
#define cron_everyminute_dir "/etc/cron/cron.everyminute"
/*
 * For tracking lan hosts
 */
#define lan_hosts_dir "/tmp/lanhosts"
#define hosts_filename "lanhosts"
/*
 * various files that we use to make well known name to rule mappings
 * This allows User Interface and Firewall to refer to the rules by name.
 */
#define qos_classification_file_dir "/etc/"
#define qos_classification_file "qos_classification_rules"
#define wellknown_ports_file_dir "/etc/"
#define wellknown_ports_file "services"
#define otherservices_dir "/etc/"
#define otherservices_file "otherservices"

/*
 * triggers use this well known namespace within iptables LOGs.
 * keep this in sync with trigger_monitor.sh 
 */
#define LOG_TRIGGER_PREFIX "UTOPIA.TRIGGER"

/*
 * For simplicity purposes we cap the number of syscfg entries within a
 * specific namespace. This cap is controlled by MAX_SYSCFG_ENTRIES
 */
#define MAX_PORT 65535

#define MAX_NAMESPACE 64

#define MAX_SRC_IP_TABLE_ROW    10   /*RDKB-7145, CID-33123, defining max size for src_ip[MAX_SRC_IP_TABLE_ENTRY][]*/
#define MAX_SRC_IP_ENTRY_LEN    25   /*RDKB-7145, CID-33123, defining max size for src_ip[][MAX_SRC_IP_ENTRY_LEN]*/


/*
 * For URL blocking,
 * The string lengths of "http://" and "https://"
 */
#define STRLEN_HTTP_URL_PREFIX  (7)
#define STRLEN_HTTPS_URL_PREFIX (8)


#ifdef WAN_FAILOVER_SUPPORTED
   #define REMOTEWAN_ROUTER_IP "remotewan_router_ip"
   #define REMOTEWAN_ROUTER_IPv6 "MeshWANInterface_UlaAddr"
#endif
/*
 * local date and time
 */
static struct tm local_now;

/*
 * iptables priority level 
 */

static inline void SET_IPT_PRI_DEFAULT(void){
  iptables_pri_level[IPT_PRI_PORTMAPPING -1 ]= IPT_PRI_PORTMAPPING; 
  iptables_pri_level[IPT_PRI_PORTTRIGGERING -1]= IPT_PRI_PORTTRIGGERING; 
  iptables_pri_level[IPT_PRI_DMZ-1]= IPT_PRI_DMZ; 
  iptables_pri_level[IPT_PRI_FIREWALL -1]= IPT_PRI_FIREWALL; 
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
  iptables_pri_level[IPT_PRI_STATIC_IP -1]= IPT_PRI_STATIC_IP; 
#endif
}


static inline int SET_IPT_PRI_MODULD(char *s){
    if(strcmp(s, "portmapping") == 0)
       return IPT_PRI_PORTMAPPING;
    else if(strcmp(s, "porttriggering") == 0)
       return IPT_PRI_PORTTRIGGERING;
    else if(strcmp(s, "dmz") == 0)
       return IPT_PRI_DMZ;
    else if(strcmp(s, "firewall") == 0)
       return IPT_PRI_FIREWALL;
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
    else if(strcmp(s, "staticip") == 0)
       return IPT_PRI_STATIC_IP;
#endif
   else
       return 0; 
} 

/* 
 * Get PSM value 
 */
 #ifdef CISCO_CONFIG_TRUE_STATIC_IP
#define PSM_NAME_TRUE_STATIC_IP_ADDRESS "dmsb.truestaticip.Ipaddress"
#define PSM_NAME_TRUE_STATIC_IP_NETMASK "dmsb.truestaticip.Subnetmask"
#define PSM_NAME_TRUE_STATIC_IP_ENABLE  "dmsb.truestaticip.Enable"
#define PSM_NAME_TRUE_STATIC_ASN        "dmsb.truestaticip.Asn."
#define PSM_NAME_TRUE_STATIC_ASN_IP     "Ipaddress"
#define PSM_NAME_TRUE_STATIC_ASN_MASK   "Subnetmask"
#define PSM_NAME_TRUE_STATIC_ASN_ENABLE "Enable"
#endif

#define PSM_VALUE_GET_INS(name, pIns, ppInsArry) PsmGetNextLevelInstances(bus_handle, CCSP_SUBSYS, name, pIns, ppInsArry)

#define PSM_NAME_SPEEDTEST_SERVER_CAPABILITY "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Server.Capability"

#if defined(FEATURE_SUPPORT_RADIUSGREYLIST) && (defined(_COSA_INTEL_XB3_ARM_) || defined(_XB6_PRODUCT_REQ_) || defined (_XB8_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_))
#define PSM_NAME_RADIUS_GREY_LIST_ENABLED "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RadiusGreyList.Enable"
#endif
/* 
 */
#define REMOTE_ACCESS_IP_RANGE_MAX_RULE 20

/* DSCP val for gre*/
#define PSM_NAME_GRE_DSCP_VALUE "dmsb.hotspot.tunnel.1.DSCPMarkPolicy"
int greDscp = 44; // Default initialized to 44

/* Configure WiFi flag for captive Portal*/
#define PSM_NAME_CP_NOTIFY_VALUE "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges"

#define PSM_IDM_INTERFACE_NAME      "dmsb.interdevicemanager.BroadcastInterface"

#if defined(FEATURE_RDKB_INTER_DEVICE_MANAGER)
    char idmInterface[32] = {0};
#endif

/*
 =================================================================
                     utilities
 =================================================================
 */
static int isInRFCaptivePortal();

#define LOG_BUFF_SIZE 512
void firewall_log( char* fmt, ...)
{
    time_t now_time;
    struct tm *lc_time;
    char buff[LOG_BUFF_SIZE] = "";
    va_list args;
    int time_size;

    if(firewallfp == NULL)
        return;
    va_start(args, fmt);
    time(&now_time);
    lc_time=localtime(&now_time);
    time_size = strftime(buff, LOG_BUFF_SIZE,"%y%m%d-%X ", lc_time);
    strncat(buff,fmt, (LOG_BUFF_SIZE - time_size -1));
    vfprintf(firewallfp, buff, args);
    va_end(args);
    return;
}

#ifdef WAN_FAILOVER_SUPPORTED
unsigned int Get_Device_Mode()
{
	FIREWALL_DEBUG("Inside Get_Device_Mode\n");
        syscfg_get(NULL, "Device_Mode", dev_type, sizeof(dev_type));
        unsigned int dev_mode = atoi(dev_type);
        Dev_Mode mode;
        if(dev_mode==1)
        {
          mode =EXTENDER_MODE;
        }
        else
          mode = ROUTER;

        return mode;

}
#endif

#ifdef WAN_FAILOVER_SUPPORTED

int create_socket() 
{
   int sockfd = 0;
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if(sockfd == -1){
         fprintf(stderr, "Could not get socket.\n");
         return -1;
         }
         return sockfd;
}

char* get_iface_ipaddr(const char* iface_name)
{
   if(!iface_name )
         return NULL;
      struct ifreq ifr;
      memset(&ifr,0,sizeof(struct ifreq));
      int skfd = 0;
      if ((skfd = create_socket() ) < 0) {
         printf("socket error %s\n", strerror(errno));
         return NULL;
      }
         
      ifr.ifr_addr.sa_family = AF_INET   ;
      strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
      if ( ioctl(skfd, SIOCGIFADDR, &ifr)  < 0 )
      {
         printf("Failed to get %s IP Address\n",iface_name);
         close(skfd);
         return NULL;   
      }
      close(skfd);

      return (inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

bool isServiceNeeded()
{
        FIREWALL_DEBUG("Inside isServiceNeeded\n");
        if (Get_Device_Mode()==EXTENDER_MODE)
        {
		FIREWALL_DEBUG("Service Not Needed\n");
            return FALSE;
        }
        else
        {
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
        if(strcmp(current_wan_ifname, mesh_wan_ifname ) == 0)
#else
        if(strcmp(current_wan_ifname,default_wan_ifname ) != 0)
#endif
		{
			FIREWALL_DEBUG("current Wam interface Name is not equal to default wan ifname\n");
                        return FALSE;
		}
        }

      FIREWALL_DEBUG("returning true\n");
    return TRUE;
}
#endif


int IsValidIPv6Addr(char* ip_addr_string)
{
    struct in6_addr addr;
	
    if(ip_addr_string == NULL)
        return 0;
	
    if(!inet_pton(AF_INET6, ip_addr_string, &addr))
    {
        return 0;
    }

    /* Here non valid IPv6 address are
     * 1) 0:0:0:0:0:0:0:0 
     * 2) ::
     */
    if( (0 == strcmp("0:0:0:0:0:0:0:0", ip_addr_string)) ||
        (0 == strcmp("::", ip_addr_string)))
    {
        return 0;
    }
	return 1;
}


#ifdef FEATURE_464XLAT
void do_xlat_rule(FILE *nat_fp)
{
       char status[16] = {0};

       syscfg_get(NULL, "xlat_status", status, sizeof(status));
       
       if(strcmp(status,"up") == 0)
       {
	       fprintf(nat_fp, "-I POSTROUTING -o %s -j SNAT --to-source  %s\n",XLAT_IF,XLAT_IP);
       }
}
#endif


#ifdef DSLITE_FEATURE_SUPPORT
static void add_dslite_mss_clamping(FILE *fp);
#endif

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
static int IsValidIPv4Addr(char* ip_addr_string)
{
    int ret = 1;
    struct in_addr ip_value;

    if(!inet_pton(AF_INET, ip_addr_string, &(ip_value.s_addr)))
    {
        return 0;
    }

    /* Here non valid IPv4 address are
     * 1) 0.0.0.0
     * 2) 255.255.255.255
     * 3) multicast addresses
     */
    if( (0 == strcmp("0.0.0.0", ip_addr_string)) ||
        (0 == strcmp("255.255.255.255", ip_addr_string)) ||
        (IN_MULTICAST(ntohl(inet_addr(ip_addr_string) ))))
    {
        ret = 0;
    }

    return ret;
}

/*
 ==========================================================================
                     HUB4 MAPT Feature
 ==========================================================================
 */
/*
 *  Procedure     : do_mapt_rules_v6
 *  Purpose       : IPv6 Rules for HUB4 MAPT feature.
 *  Parameters    :
 *     filter_fp  : An open file that will be used for iptables filter rules set.
 *  Return Values :
 *     0          : done
 */
int do_mapt_rules_v6(FILE *filter_fp)
{
    int ret = RET_OK;
    char ipV6address_str[BUFLEN_64] = {0};
    char mapt_config_value[BUFLEN_8] = {0};

    /* Check sysevent fd availabe at this point. */
    if (sysevent_fd < 0)
    {
        FIREWALL_DEBUG("ERROR: Sysevent FD is not available \n");
        ret = RET_ERR;
        goto END;
    }

    /* Check MAPT config
     * Add rules only if it set.*/
    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, mapt_config_value, sizeof(mapt_config_value)) != 0)
    {
        FIREWALL_DEBUG("ERROR: Failed to get MAPT configuration value from sysevent \n");
        ret = RET_ERR;
        goto END;
    }

    /*  Check mapt config flag is set/reset, Rules will add only if it is SET.*/
    if (strncmp(mapt_config_value,SET, 3) != 0)
    {
        FIREWALL_DEBUG("DEBUG: mapt_config_value not set. So no need to add v4 map-t rules. \n");
        ret = RET_ERR;
        goto END;
    }

    /* Get Ipaddress. */
    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_IPV6_ADDRESS, ipV6address_str, sizeof(ipV6address_str)) != 0)
    {
        FIREWALL_DEBUG("ERROR: Failed to get IP address from sysevent, not setting rule \n");
        ret = RET_ERR;
        goto END;
    }
    /*  Check IP address string is empty. */
    if (IS_EMPTY_STRING(ipV6address_str))
    {
        FIREWALL_DEBUG("ERROR: Empty IP V6 address string received from the sysevent, no rules addes \n");
        ret = RET_ERR;
        goto END;
    }

    /* Add POSTROUTING rule. */
#if (IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT) || (FEATURE_SUPPORT_MAPT_NAT46)
    /* bypass IPv6 firewall, let IPv4 firewall handle MAP-T packets */
    fprintf(filter_fp, "-I wan2lan -d %s -j ACCEPT\n", ipV6address_str);

    //SKYH4-5461 - ip6tables lan2wan accept for map-t translated packets because it has already been validated in IPv4 tables.
    fprintf(filter_fp, "-I lan2wan -s %s -j ACCEPT\n", ipV6address_str);

#endif // (IVI_KERNEL_SUPPORT) || (NAT46_KERNEL_SUPPORT) || (FEATURE_SUPPORT_MAPT_NAT46)
END:
    return ret;
}

/*
 ==========================================================================
                     HUB4 MAPT Feature
 ==========================================================================
 */
/*
 *  Procedure     : do_mapt_rules_v4
 *  Purpose       : IPv4 Rules for HUB4 MAPT feature.
 *  Parameters    :
 *     nat_fp     : An open file that will be used for iptables nat rules set.
 *     filter_fp  : An open file that will be used for iptables filter rules set.
 *     mangle_fp  : An open file that will be used for iptables mangle rules set.
 *  Return Values :
 *     0               : done
 */
int do_mapt_rules_v4(FILE *nat_fp, FILE *filter_fp, FILE *mangle_fp)
{
    int ret = RET_OK;
    unsigned int mapt_config_ratio = 0;
    char ipaddress_str[BUFLEN_32] = {0};
    char mapt_config_ratio_str[BUFLEN_64] = {0};
    char mapt_config_value[BUFLEN_8] = {0};
    unsigned int contigous_port = 0;
    int ratio = 0;
    int port = 0;
    unsigned int i =0;
    unsigned int j = 0;
    unsigned int a = 0;
    unsigned int m = 0;
    unsigned initialPortValue=0;
    unsigned finalPortValue=0;
    unsigned int offset = 0;
    unsigned int psidLen = 0;
    unsigned int psid = 0;
    char sysevent_val[BUFLEN_64] = {0};

    /* Check sysevent fd availabe at this point. */
    if (sysevent_fd < 0)
    {
        FIREWALL_DEBUG("ERROR: Sysevent FD is not available \n");
        ret = RET_ERR;
        goto END;
    }

    /* Check MAPT config
     * Add rules only if it set.*/
    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, mapt_config_value, sizeof(mapt_config_value)) != 0)
    {
        FIREWALL_DEBUG("ERROR: Failed to get MAPT configuration value from sysevent \n");
        ret = RET_ERR;
        goto END;
    }

    /*  Check mapt config flag is set/reset, Rules will add only if it is SET.*/
    if (strncmp(mapt_config_value,SET, 3) != 0)
    {
        FIREWALL_DEBUG("DEBUG: mapt_config_value not set. So no need to add v4 map-t rules. \n");
        ret = RET_ERR;
        goto END;
    }

    /*  SET Rules. */
    /* Check MAPT configuration ratio value. */
    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_RATIO, mapt_config_ratio_str, sizeof(mapt_config_ratio_str)) != 0)
    {
        FIREWALL_DEBUG("ERROR: Failed to get MAPT ratio value from sysevent \n");
        ret = RET_ERR;
        goto END;
    }
    mapt_config_ratio = atoi(mapt_config_ratio_str);

    /* Get Ipaddress. */
    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_IP_ADDRESS, ipaddress_str, sizeof(ipaddress_str)) != 0)
    {
        FIREWALL_DEBUG("ERROR: Failed to get IP address from sysevent, not setting rule \n");
        ret = RET_ERR;
        goto END;
    }
    /*  Check IP address string is empty. */
    if (IS_EMPTY_STRING(ipaddress_str))
    {
        FIREWALL_DEBUG("ERROR: Empty IP address string received from the sysevent, no rules addes \n");
        ret = RET_ERR;
        goto END;
    }

    /* Add PREROUTING rule. */
#if defined(NAT46_KERNEL_SUPPORT)
    if (strcmp ( devicePartnerId, "sky-uk") == 0) 
    {
        fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d\n", NAT46_INTERFACE, NAT46_CLAMP_MSS);
    }
#endif

    /* Add POSTROUTING rule. */
#if defined(IVI_KERNEL_SUPPORT)
    fprintf(nat_fp, "-A POSTROUTING -o %s -j %s\n",get_current_wan_ifname(),MAPT_NAT_IPV4_POST_ROUTING_TABLE);
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
    fprintf(nat_fp, "-A POSTROUTING -o %s -j %s\n", NAT46_INTERFACE, MAPT_NAT_IPV4_POST_ROUTING_TABLE);
#endif

#if defined(NAT46_KERNEL_SUPPORT)
/* UK MAPT Not connected MQTT broker. */
    if (strcmp ( devicePartnerId, "sky-uk") == 0) {
        fprintf(mangle_fp, "-A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o %s -j TCPMSS --set-mss %d"
                       "\n", NAT46_INTERFACE, NAT46_CLAMP_MSS);
    }else {
        // TCP MSS RULE - SKYH4-5123 - To improve IPv4 Downstream traffic performance
        fprintf(mangle_fp, "-A FORWARD -p tcp --tcp-flags SYN,RST SYN -o %s -j TCPMSS --set-mss %d\n", NAT46_INTERFACE, NAT46_CLAMP_MSS);
    }
#elif defined (FEATURE_SUPPORT_MAPT_NAT46)
    // RDKB-40515 - [MAP-T] Gw to NOC connectivity failure
    fprintf(mangle_fp, "-A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o %s -j TCPMSS --set-mss %d"
                       "\n", NAT46_INTERFACE, NAT46_CLAMP_MSS);
#endif
    if (mapt_config_ratio == 1) //config all
    {
        /* Set rule. */
        fprintf(nat_fp, "-A %s -j SNAT --to-source %s\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, ipaddress_str);
    }
    else
    {
        /*  Generate MAPT port numbers and add rules.
         *  This code has been ported from Hub4 wanmanager application
         *  to setup the IP rules for the MAPT feature. */


        /* Find offset, psid value, length from sysevent. */
        if(sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_OFFSET, sysevent_val, sizeof(sysevent_val)) != 0)
        {
            FIREWALL_DEBUG("ERROR: Failed to get PSID offset \n");
            ret = RET_ERR;
            goto END;
        }
        if (IS_EMPTY_STRING(sysevent_val))
        {
            FIREWALL_DEBUG("ERROR: Empty string \n");
            ret = RET_ERR;
            goto END;
        }

        offset = atoi (sysevent_val);

        if(sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_VALUE, sysevent_val, sizeof(sysevent_val)) != 0)
        {
            FIREWALL_DEBUG("ERROR: Failed to get PSID value \n");
            ret = RET_ERR;
            goto END;
        }
        if (IS_EMPTY_STRING(sysevent_val))
        {
            FIREWALL_DEBUG("ERROR: Empty string \n");
            ret = RET_ERR;
            goto END;
        }

        psid = atoi(sysevent_val);

        if(sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_PSID_LENGTH, sysevent_val, sizeof(sysevent_val)) != 0)
        {
            FIREWALL_DEBUG("ERROR: Failed to get PSID length \n");
            ret = RET_ERR;
            goto END;
        }

        if (IS_EMPTY_STRING(sysevent_val))
        {
            FIREWALL_DEBUG("ERROR: Empty string \n");
            ret = RET_ERR;
            goto END;
        }

        psidLen = atoi(sysevent_val);

        if (offset == 0)
            offset = 6;

        a = (1 << offset);
        m = 16 - (psidLen + offset);
        contigous_port = (1 << m);
        ratio = 16 - offset;

        /* Start of port range parameters. */
        /* create rules */
        for(i=1; i< (a); i++)
        {
            for(j=0; j<(contigous_port); j++)
            {
                port = (i<<ratio) + (psid <<(m)) + j;

                if(j == 0)
                    initialPortValue = port;
                if( j == contigous_port - 1 )
                    finalPortValue = port;
            }
#if defined(IVI_KERNEL_SUPPORT)
            fprintf(nat_fp, "-A %s -o %s -p tcp --sport %d:%d -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, get_current_wan_ifname(), initialPortValue, finalPortValue, ipaddress_str,
                    initialPortValue, finalPortValue);
            fprintf(nat_fp, "-A %s -o %s -p udp --sport %d:%d -j SNAT --to-source %s:%d-%d\n",MAPT_NAT_IPV4_POST_ROUTING_TABLE, get_current_wan_ifname(), initialPortValue, finalPortValue, ipaddress_str,
                    initialPortValue, finalPortValue);
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined(_HUB4_PRODUCT_REQ_NO_DPORT_)
            fprintf(nat_fp, "-A %s -p tcp -m connlimit --connlimit-upto %d --connlimit-daddr -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
            fprintf(nat_fp, "-A %s -p udp -m connlimit --connlimit-upto %d --connlimit-daddr -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
            fprintf(nat_fp, "-A %s -p icmp -m connlimit --connlimit-upto %d --connlimit-daddr -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
#else
            fprintf(nat_fp, "-A %s -p tcp -m connlimit --connlimit-upto %d --connlimit-daddr-dport -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
            fprintf(nat_fp, "-A %s -p udp -m connlimit --connlimit-upto %d --connlimit-daddr-dport -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
            fprintf(nat_fp, "-A %s -p icmp -m connlimit --connlimit-upto %d --connlimit-daddr-dport -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, finalPortValue - initialPortValue + 1, ipaddress_str, initialPortValue,finalPortValue);
#endif //_HUB4_PRODUCT_REQ_NO_DPORT_
#endif //IVI_KERNEL_SUPPORT
        }
#ifdef IVI_KERNEL_SUPPORT
        fprintf(nat_fp, "-A %s -o %s -p icmp -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, get_current_wan_ifname(), ipaddress_str,initialPortValue, finalPortValue);
        fprintf(nat_fp, "-A %s -o %s -p tcp -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, get_current_wan_ifname(), ipaddress_str, initialPortValue, finalPortValue);
        fprintf(nat_fp, "-A %s -o %s -p udp -j SNAT --to-source %s:%d-%d\n", MAPT_NAT_IPV4_POST_ROUTING_TABLE, get_current_wan_ifname(), ipaddress_str, initialPortValue,finalPortValue);
#endif //IVI_KERNEL_SUPPORT
    }

END:
    return ret;
}

#ifdef FEATURE_MAPT_DEBUG
void logPrintMain(char* filename, int line, char *fmt,...)
{
    static FILE *fpIviLogFile;
    static char strIviLogFileName[32] = "/tmp/ivirule_add.txt";
    va_list         list;
    char            *p, *r;
    time_t ctime;
    int     e;
    struct tm *info;

    fpIviLogFile = fopen(strIviLogFileName,"a");

    time(&ctime); /* Get current time */
    info = localtime(&ctime);

    fprintf(fpIviLogFile,"[%02d:%02d:%02d][line:%d] ",
        info->tm_hour,info->tm_min,info->tm_sec,line);

    va_start( list, fmt );

    for ( p = fmt ; *p ; ++p )
    {
        if ( *p != '%' )
        {
            fputc( *p, fpIviLogFile);
        }
        else
        {
            switch ( *++p )
            {

            case 's':
            {
                r = va_arg( list, char * );

                fprintf(fpIviLogFile,"%s", r);
                continue;
            }

            case 'd':
            {
                e = va_arg( list, int );

                fprintf(fpIviLogFile,"%d", e);
                continue;
            }

            default:
                fputc( *p, fpIviLogFile );
            }
        }
    }
    va_end( list );
    fputc( '\n', fpIviLogFile );
    fclose(fpIviLogFile);
}
#endif
BOOL isMAPTSet(void)
{
    char mapt_config_value[BUFLEN_8] = {0};
    BOOL isMAPTEnabled = FALSE;

    /* Check sysevent fd availabe at this point. */
    if (sysevent_fd < 0)
    {
#ifdef FEATURE_MAPT_DEBUG
        LOG_PRINT_MAIN("ERROR: Sysevent FD is not available \n");
#endif        
        return RET_ERR;
    }

    if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, mapt_config_value, sizeof(mapt_config_value)) != 0)
    {
#ifdef FEATURE_MAPT_DEBUG
        LOG_PRINT_MAIN("ERROR: Failed to get MAPT configuration value from sysevent \n");
#endif        
        return RET_ERR;
    }

#ifdef FEATURE_MAPT_DEBUG
    LOG_PRINT_MAIN("mapt_config_value:%s",mapt_config_value);
#endif        
    /*  Check mapt config flag is SET*/
    if (strncmp(mapt_config_value,SET, 3) == 0)
    {
        /*Get the MAP-T Address*/
        if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_IP_ADDRESS, mapt_ip_address, sizeof(mapt_ip_address)) != 0)
        {
#ifdef FEATURE_MAPT_DEBUG
            LOG_PRINT_MAIN("ERROR: Failed to get MAPT IP Address from sysevent \n");
#endif        
            return RET_ERR;
        }
#ifdef FEATURE_MAPT_DEBUG
        LOG_PRINT_MAIN("mapt_ip_address:%s",mapt_ip_address);
#endif        
        isMAPTEnabled = TRUE;
    }
    return isMAPTEnabled;
}

/*
 *  Procedure     : do_wan_nat_lan_clients_mapt
 *  Purpose       : prepare the iptables-restore statements for natting the outgoing packets from lan
 *                  to the filter table 
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_wan_nat_lan_clients_mapt(FILE *fp)
{
    unsigned int mapt_config_ratio = 0;
    char mapt_config_ratio_str[64];

#ifdef FEATURE_MAPT_DEBUG
    LOG_PRINT_MAIN("Entering do_wan_nat_lan_clients_mapt\n");
#endif
    /*  Check mapt config flag is SET*/
    if (isMAPTReady == TRUE)
    {
        if(!IS_EMPTY_STRING(mapt_ip_address))
        {
            mapt_config_ratio_str[0] = 0;
            if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_RATIO, mapt_config_ratio_str, sizeof(mapt_config_ratio_str)) != 0)
            {
#ifdef FEATURE_MAPT_DEBUG
                LOG_PRINT_MAIN("ERROR: Failed to get MAPT ratio value from sysevent \n");
#endif
            }
            else
            {
                mapt_config_ratio = atoi(mapt_config_ratio_str);
#ifdef FEATURE_MAPT_DEBUG
                LOG_PRINT_MAIN("mapt_config_ratio :%d \n",mapt_config_ratio);
#endif
                if (mapt_config_ratio == 1)
                {
		    fprintf(fp, "-A postrouting_towan -s 10.0.0.0/8  -j SNAT --to-source %s\n", mapt_ip_address);
		    fprintf(fp, "-A postrouting_towan -s 192.168.0.0/16  -j SNAT --to-source %s\n", mapt_ip_address);
                    fprintf(fp, "-A postrouting_towan -s 172.16.0.0/12  -j SNAT --to-source %s\n", mapt_ip_address);
                }
            }
        }
    }

#ifdef FEATURE_MAPT_DEBUG
    LOG_PRINT_MAIN("Exiting do_wan_nat_lan_clients_mapt\n");
#endif
    return 0;
}
#endif //FEATURE_MAPT
void do_webui_attack_filter(FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_webui_attack_filter\n");
   fprintf(filter_fp, ":%s - [0:0]\n", "UPLOAD_ATTACK_FILTER");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", "<?php");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -m string --algo bm --string \"%s\" -j DROP \n", "filename=" , ".php");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -m string --algo bm --string \"%s\" -j DROP \n", "filename=", ".phtml");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".jsp");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".asp");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", "<%@");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".cgi");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".pi");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".sh");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", ".py");
   fprintf(filter_fp, "-A UPLOAD_ATTACK_FILTER -m string --algo bm --string \"%s\" -j DROP \n", "multipart/form-data");
   FIREWALL_DEBUG("Exiting do_webui_attack_filter\n");
}
/*
 *  Procedure     : do_webui_rate_limit
 *  Purpose       : Create chain to ratelimit remote management GUI packets over erouter interface
 *  Parameters    :
 *    fp             : An open file to write webui_ratelimit Rule
 * Return Values  :
 *    0              : Success
 */
void do_webui_rate_limit (FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_webui_rate_limit\n");
   fprintf(filter_fp, ":%s - [0:0]\n", "webui_limit");
   fprintf(filter_fp, "-I webui_limit -m state --state ESTABLISHED,RELATED -j ACCEPT\n");
#if defined(_HUB4_PRODUCT_REQ_)
   fprintf(filter_fp, "-A webui_limit -p tcp -m tcp  --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 4/sec --limit-burst 10 -j ACCEPT\n");
#else
   fprintf(filter_fp, "-A webui_limit -p tcp -m tcp  --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec --limit-burst 20 -j ACCEPT\n");
#endif
   fprintf(filter_fp, "-A webui_limit -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix \"WebUI Rate Limited: \" --log-level 6\n");
   fprintf(filter_fp, "-A webui_limit -j DROP\n"); 
   FIREWALL_DEBUG("Exiting do_webui_rate_limit\n");
}

/*
 * Check whether an l2 instance belongs to a MultiLAN bridge
 */
static inline BOOL isMultiLANL2Instance(int instance){
  char query[MAX_QUERY];
  char *pStr = NULL;
  int rc = 0;

   FIREWALL_DEBUG("Entering isMultiLANL2Instance\n");         
  /* Fetch alias from l2net instance */
  snprintf(query, MAX_QUERY, "dmsb.l2net.%d.Alias", instance);

   FIREWALL_DEBUG("Getting %s value from psm\n" COMMA query);         
  rc = PSM_VALUE_GET_STRING(query, pStr);
  if(rc != CCSP_SUCCESS || pStr == NULL)
    return FALSE;

   FIREWALL_DEBUG("value is %s\n" COMMA pStr);         
  /* Look for the word "multiLAN" in the alias */
  if(NULL == strcasestr(pStr, "multiLAN"))
    return FALSE;

  FIREWALL_DEBUG("Exiting isMultiLANL2Instance\n");         
  /* Found l2net alias and it contained "multiLAN", return TRUE */
  return TRUE;
}

/*
 * Check whether an IP instance belongs to a MultiLAN bridge
 */
static inline BOOL isMultiLANL3Instance(int instance){
  char query[MAX_QUERY];
  char *pStr = NULL;
  int pVal = 0;
  int rc = 0;

   FIREWALL_DEBUG("Entering isMultiLANL3Instance\n");         
  /* Ignore invalid instance number so we don't have to validate it in the caller */
  if(instance <= 0)
    return FALSE;

  /* Fetch EthLink from IP instance */
  snprintf(query, MAX_QUERY, "dmsb.l3net.%d.EthLink", instance);

  FIREWALL_DEBUG("Getting %s value from psm\n" COMMA query);         
  rc = PSM_VALUE_GET_STRING(query, pStr);
  if(rc != CCSP_SUCCESS || pStr == NULL)
    return FALSE;
  pVal = atoi(pStr);
  if(pStr){
    AnscFreeMemory(pStr);
    pStr = NULL;
  }

   FIREWALL_DEBUG("value is %d\n" COMMA pVal);         
  if(pVal <= 0)
    return FALSE;

  /* Fetch l2net from EthLink instance */
  snprintf(query, MAX_QUERY, "dmsb.EthLink.%d.l2net", pVal);

  FIREWALL_DEBUG("Getting %s value from psm\n" COMMA query);         
  rc = PSM_VALUE_GET_STRING(query, pStr);
  if(rc != CCSP_SUCCESS || pStr == NULL)
    return FALSE;
  pVal = atoi(pStr);
  if(pStr){
    AnscFreeMemory(pStr);
    pStr = NULL;
  }

   FIREWALL_DEBUG("value is %d\n" COMMA pVal);         
  if(pVal <= 0)
    return FALSE;

  /* Check if l2 instance is a MultiLAN instance */
  if(!isMultiLANL2Instance(pVal))
    return FALSE;

  /* Found l2net alias and it contained "multiLAN", return TRUE */

   FIREWALL_DEBUG("Entering isMultiLANL3Instance\n");         
  return TRUE;
}

static int privateIpCheck(char *ip_to_check)
{
#ifndef MULTILAN_FEATURE

    struct in_addr l_sIpValue, l_sDhcpStart, l_sDhcpEnd;
    long int l_iIpValue, l_iDhcpStart, l_iDhcpEnd;
	char l_cDhcpStart[16] = {0}, l_cDhcpEnd[16] = {0};
	int l_iRes;

	if (NULL == ip_to_check || 0 == ip_to_check[0])
	{
		FIREWALL_DEBUG("Invalied IP Address to check\n");
		return 1;
	}

	syscfg_get(NULL, "dhcp_start", l_cDhcpStart, sizeof(l_cDhcpStart));
	syscfg_get(NULL, "dhcp_end", l_cDhcpEnd, sizeof(l_cDhcpEnd));

    l_iRes = inet_pton(AF_INET, ip_to_check, &l_sIpValue);
    l_iRes &= inet_pton(AF_INET, l_cDhcpStart, &l_sDhcpStart);
    l_iRes &= inet_pton(AF_INET, l_cDhcpEnd, &l_sDhcpEnd);

    l_iIpValue = ntohl(l_sIpValue.s_addr);
    l_iDhcpStart = ntohl(l_sDhcpStart.s_addr);
    l_iDhcpEnd = ntohl(l_sDhcpEnd.s_addr);

	switch(l_iRes) 
	{
    	case 1:
        	if (l_iIpValue <= l_iDhcpEnd && l_iIpValue >= l_iDhcpStart)
		  	{	
                FIREWALL_DEBUG("IP Address:%s is in private address range\n" COMMA ip_to_check);
				return 1;
			}
          	else
			{
                FIREWALL_DEBUG("IP Address:%s is not in private address range\n" COMMA ip_to_check);
          		return 0;
			}
       case 0:
          FIREWALL_DEBUG("invalid input / dhcp start / dhcp end values\n");
          return 1;
       default:
          FIREWALL_DEBUG("inet_pton conversion error:%d\n" COMMA errno);
          return 1;
    }
#else
   return 1;
#endif
}

/*
 * Procedure     : trim
 * Purpose       : trims a string
 * Parameters    :
 *    in         : A string to trim
 * Return Value  : The trimmed string
 * Note          : This procedure will change the input sting in situ
 */
static char *trim(char *in)
{
  //               FIREWALL_DEBUG("Entering *trim\n");         
   // trim the front of the string
   if (NULL == in) {
      return(NULL);
   }
   char *start = in;
   while(isspace(*start)) {
      start++;
   }
   // trim the end of the string

   char *end = start+strlen(start);
   end--;
   while(isspace(*end)) {
      *end = '\0';
      end--;
   }
    //             FIREWALL_DEBUG("Exiting *trim\n");         
   return(start);
}


/*
 * Procedure     : token_get
 * Purpose       : given the start of a string 
 *                 containing a delimiter,
 *                 return the end of the string
 * Parameters    :
 *    in         : The start of the string containing a token
 *    delim      : A character used as delimiter
 *
 * Return Value  : The start of the next possible token
 *                 NULL if end
 * Note          : This procedure will change the input sting in situ by breaking
 *                 it up into substrings at the delimiter.
 */
static char *token_get(char *in, char delim)
{
      //           FIREWALL_DEBUG("Entering *token_get\n");         
   char *end = strchr(in, delim);
   if (NULL != end) {
      *end = '\0';
      end++;
   }
        //         FIREWALL_DEBUG("Exiting *token_get\n");         
   return(end);   
}

/*
 *  Procedure     : time_delta
 *  Purpose       : how much time between two times in different formats
 *  Parameters    :
 *    time1          : time in struct tm format
 *    time2          : time in hh:mm format (24 hour time)
 *    hours          : hours between time1 and time2
 *    mins           : mins between time1 and time2
 *  Return Value:
 *     0       : if time2 was greater than time1
 *    -1       : if time 1 was greater than time2
 *  Note        :
 *   If return value is -1 then hours and mins will be 0
 */
static int time_delta(struct tm *time1, const char *time2, int *hours, int *mins)
{
   int t2h;
   int t2m;
   sscanf(time2,"%d:%d", &t2h, &t2m);
  // FIREWALL_DEBUG("Entering time_delta\n");         
  if (time1->tm_hour > t2h) {
      *hours = *mins = 0;
      return(-1);
   } else if (time1->tm_hour == t2h && time1->tm_min >= t2m) { 
      *hours = *mins = 0;
      return(-1);
   } else {
      *hours = t2h-time1->tm_hour;
      if (time1->tm_min <= t2m) {
         *mins = t2m -time1->tm_min;
      } else {
         *hours -= 1;
         *mins = (60 - (time1->tm_min-t2m));
      }
      return(0);
   }
  // FIREWALL_DEBUG("Exiting time_delta\n");         
}
 
/*
 *  Procedure     : substitute
 *  Purpose       : Change all occurances of a token to another token 
 *  Paramenters   :
 *    in_str         : A string that might contain the from token
 *    out_str        : Memory to place the string with from string replaced by to token
 *    size           : The size of out_str
 *    from           : The token to look for
 *    to             : The token to replace to
 * Return Values  :
 *    The number of substitutions
 *    -1   : ERROR
 */
static int substitute(char *in_str, char *out_str, const int size, char *from, char *to)
{
    char *in_str_p    = in_str;
    char *out_str_p   = out_str;
    char *in_str_end  = in_str + strlen(in_str);
    char *out_str_end = out_str + size;
    int   num_subst   = 0;
   // FIREWALL_DEBUG("Entering substitute\n");         
    while (in_str_p < in_str_end && out_str_p < out_str_end) {
       char *from_p;
       from_p = strstr(in_str_p, from);
       if (NULL != from_p) {
          /*
           * we found an instance of the token to replace.
           * First copy the bytes upto the token
           */
          int num_bytes = from_p-in_str_p;
          if (out_str_p + num_bytes < out_str_end) {
             memmove(out_str_p, in_str_p, num_bytes);
             out_str_p += num_bytes;
          } else {
            out_str[size-1] = '\0';
            return(-1);
          }
          /*
           * now substitute the token
           */
          if (out_str_p + strlen(to) < out_str_end) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", to);
             in_str_p = from_p + strlen(from);
             num_subst++;
          } else {
             out_str[size-1] = '\0';
             return(-1);
          }
       } else {
          /*
           * no more instances of the token are found
           * so copy in the rest of the input string and return
           */
          int num_bytes = strlen(in_str_p) + 1;
          if (out_str_p + num_bytes < out_str_end) {
             memmove(out_str_p, in_str_p, num_bytes);
             out_str_p += num_bytes;
             out_str[size-1] = '\0';
             return(num_subst);
          } else {
            out_str[size-1] = '\0';
            return(-1);
          }
       }
    }

    out_str[size-1] = '\0';
   // FIREWALL_DEBUG("Exiting substitute\n");         
    return(num_subst);
}

/*
 *  Procedure     : make_substitutions
 *  Purpose       : Change any well-known symbols in a string to the running/configured values
 *  Paramenters   :
 *    in_str         : A string that might contain well-known symbols
 *    out_str        : Memory to place the string with symbols converted to values
 *    size           : The size of out_str
 * Return Values  :
 *    A pointer to out_str on success
 *    Otherwise NULL
 * Notes:
 *   Currently we handle $WAN_IPADDR, $WAN_IFNAME, $LAN_IFNAME, $LAN_IPADDR, $LAN_NETMASK
 *                       $ACCEPT $DROP $REJECT and 
 *   QoS classes $HIGH, $MEDIUM, $NORMAL, $LOW
 */
char *make_substitutions(char *in_str, char *out_str, const int size)
{
    char *in_str_p = in_str;
    char *out_str_p = out_str;
    char *in_str_end = in_str + strlen(in_str);
    char *out_str_end = out_str + size;
   // FIREWALL_DEBUG("Entering *make_substitutions\n");         
    while (in_str_p < in_str_end && out_str_p < out_str_end) {
       char token[50];
       if ('$' == *in_str_p) {
          sscanf(in_str_p, "%50s", token); 
          in_str_p += strlen(token);
          if (0 == strcmp(token, "$WAN_IPADDR")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", current_wan_ipaddr);
          } else if (0 == strcmp(token, "$WAN_IFNAME")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", current_wan_ifname);
          } else if (0 == strcmp(token, "$LAN_IFNAME")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", lan_ifname);
          } else if (0 == strcmp(token, "$LAN_IPADDR")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", lan_ipaddr);
          } else if (0 == strcmp(token, "$LAN_NETMASK")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", lan_netmask);
          } else if (0 == strcmp(token, "$ACCEPT")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "ACCEPT");
          } else if (0 == strcmp(token, "$DROP")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "DROP");
          } else if (0 == strcmp(token, "$REJECT")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "REJECT --reject-with tcp-reset");
         } else if (0 == strcmp(token, "$HIGH")) {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "EF");
         } else  if (0 == strcmp(token, "$MEDIUM")) { 
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "AF11");
         } else  if (0 == strcmp(token, "$NORMAL")) { 
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "AF22");
         } else  if (0 == strcmp(token, "$LOW")) { 
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", "BE");
         } else {
             out_str_p += snprintf(out_str_p, out_str_end-out_str_p, "%s", token);
         }
       } else {
          *out_str_p = *in_str_p;
          out_str_p++;
          in_str_p++;
       }
       if ('\0' == *in_str_p) {
          *out_str_p = *in_str_p;
          break;
       } 
   }

    out_str[size-1] = '\0';
   // FIREWALL_DEBUG("Exiting *make_substitutions\n");         
    return(out_str);
}
 
/*
 *  Procedure     : match_keyword
 *  Purpose       : given an open file with format 
 *                  keyword [delim] .......
 *                  return the first line matching that keyword
 *  Parameters    :
 *     fp              : An open file to search
 *     keyword         : The keyword to search for in the first field
 *     delim           : The delimiter 
 *     line            : A string in which to place the found line
 *     size            : the size of line
 * Return Values  : 
 *    A pointer to the start of the rest of the line after the delimiter
 *    NULL if keyword is not found
 * 
 */
static char *match_keyword(FILE *fp, char *keyword, char delim, char *line, int size)
{
  // FIREWALL_DEBUG("Entering *match_keyword\n");         
   while (NULL != fgets(line, size, fp) ) {
      char *keyword_candidate = NULL;
      char *next;
      /*
       * handle space differently
       */
      if (' ' == delim) {
         char local_name[50];
         local_name[0] = '\0';
         sscanf(line, "%50s ", local_name); 
         next = line + strlen(local_name);
         if (next-line > size) {
              continue;
         } else {
            *next = '\0';
            next++;
            keyword_candidate = trim(line);
         }
      } else {
         keyword_candidate = line;
         if (NULL != keyword_candidate) {
            next = token_get(keyword_candidate, delim); /*RDKB-7145, CID-33413, use after null check*/
            keyword_candidate = trim(keyword_candidate);
         } else {
            continue;
         }
      }

      if (keyword_candidate && (0 == strcasecmp(keyword, keyword_candidate))) { /*RDKB-7145, CID-33413, use after null check*/
         return(next);
      } 
   }
  // FIREWALL_DEBUG("Exiting *match_keyword\n");         
   return(NULL);
}


/*
 *  Procedure     : to_syslog_level
 *  Purpose       : convert syscfg log_level to syslog level
 */
static int to_syslog_level (int log_leveli)
{
   switch (log_leveli) {
   case 0:
      return LOG_WARNING;
   case 2:
      return LOG_INFO;
   case 3:
      return LOG_DEBUG;
   case 1:
   default:
      return LOG_NOTICE;
   }
}

typedef struct v6sample {
           unsigned int bitsToMask;
           char intrName[20];
           unsigned char ipv6_addr[40];
           char address6[40];
           unsigned int devIndex;
           unsigned int flags;
           unsigned int scopeofipv6;
           char prefix_v6[40];
}ifv6Details;

int parseProcfileParams(char* lineToParse,ifv6Details *detailsToParse,char* interface)
{
    struct sockaddr_in6 sAddr6;
    char splitv6[8][5];
    ulogf(ULOG_FIREWALL, UL_INFO,"%s, Parse the line read from file\n",__FUNCTION__);

    if (lineToParse == NULL)
           return 0;

    memset((void*)&sAddr6, 0, sizeof(struct sockaddr_in6));
    memset((void*)detailsToParse, 0, sizeof(ifv6Details)); // must zero out to clear this structure since it gets repopulated every time

    if(sscanf(lineToParse, "%s %x %x %x %x %s", detailsToParse->ipv6_addr,&detailsToParse->devIndex,
              &detailsToParse->bitsToMask,&detailsToParse->scopeofipv6,&detailsToParse->flags,detailsToParse->intrName) == 6)
    {
       ulogf(ULOG_FIREWALL, UL_INFO,"%s, Check if interface matches\n",__FUNCTION__);
       if (!strcmp(interface, detailsToParse->intrName))
       {
           ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface matched\n",__FUNCTION__);
           //Convert the raw interface ip to IPv6 format
           int position,placeholder=0;
           for (position=0; position<strlen(detailsToParse->ipv6_addr); position++)
           {
               detailsToParse->address6[placeholder] = detailsToParse->ipv6_addr[position];
               placeholder++;
               // Positions at which ":" should be put.
               if((position==3)||(position==7)||(position==11)||(position==15)||
                   (position==19)||(position==23)||(position==27))
               {
                   detailsToParse->address6[placeholder] = ':';
                   placeholder++;
               }
           }
           detailsToParse->address6[placeholder] = '\0';
           ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface IPv6 address calculation\n",__FUNCTION__);
           // Perform IPv6 Address Normlization
           int rtn = inet_pton(AF_INET6, detailsToParse->address6,(struct sockaddr *) &sAddr6.sin6_addr);
           if (rtn <= 0)
           {
              ulogf(ULOG_FIREWALL, UL_INFO, "%s Interface IPv6 address text to binary conversion error. Return Code %d\n", __FUNCTION__, rtn);
              return 0;
           }
           sAddr6.sin6_family = AF_INET6;
           if (inet_ntop(AF_INET6, (struct sockaddr *) &sAddr6.sin6_addr, detailsToParse->address6, sizeof(detailsToParse->address6)) == NULL)
           {
              ulogf(ULOG_FIREWALL, UL_INFO, "%s Interface IPv6 address binary to text conversion error.\n", __FUNCTION__);
              return 0;
           }
           ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface IPv6 address is: %s\n",__FUNCTION__,detailsToParse->address6);

           if(sscanf(lineToParse, "%4s%4s%4s%4s%4s%4s%4s%4s", splitv6[0], splitv6[1], splitv6[2],
                                                              splitv6[3], splitv6[4],splitv6[5], splitv6[6], splitv6[7])==8)
           {
               memset(detailsToParse->prefix_v6,0,sizeof(detailsToParse->prefix_v6));
               int iCount =0;
               for (iCount=0; (iCount< ( detailsToParse->bitsToMask%16 ? (detailsToParse->bitsToMask/16+1):detailsToParse->bitsToMask/16)) && iCount<8; iCount++)
               {
                   sprintf(detailsToParse->prefix_v6+strlen(detailsToParse->prefix_v6), "%s:",splitv6[iCount]);
               }
               ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface IPv6 prefix calculation done\n",__FUNCTION__);
            }
            return 1;
      }
      else
      {
         return 0;
      }
    }
    else
    {
      ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface line read failed\n",__FUNCTION__);
      return 0;
    }
}
int get_ip6address (char * ifname, char ipArry[][40], int * p_num, unsigned int scope_in)
{
    FILE * fp = NULL;
	//char addr6p[8][5];
	//int plen, scope, dad_status, if_idx;    
	//char addr6[40], devname[20];
    char procLine[MAX_INET6_PROC_CHARS];
    ifv6Details v6Details = { 0 };
    int parsingResult;

    int    i = 0;
    //FIREWALL_DEBUG("Entering get_ip6address\n");
    /* CID 124927 and 74863 : Dereference after null check */
    if (!ifname || !ipArry || !p_num)
        return -1;
    fp = fopen(_PROCNET_IFINET6, "r");
    if (!fp)
        return -1;
   
    while(fgets(procLine, MAX_INET6_PROC_CHARS, fp))
    {
      memset(&v6Details, 0, sizeof(ifv6Details));
      parsingResult=parseProcfileParams(procLine, &v6Details,ifname);
      if (parsingResult == 1)
      {
            ulogf(ULOG_FIREWALL, UL_INFO,"%s parsing the value of %s\n",__FUNCTION__,v6Details.intrName);
            /* Global address */ 
            if(scope_in == (v6Details.scopeofipv6 & IPV6_ADDR_SCOPE_MASK)){
		/*CID 185694: BUFFER_SIZE */
                strncpy(ipArry[i], v6Details.address6, sizeof(ipArry[i])-1);
		ipArry[i][sizeof(ipArry[i])-1] = '\0';
                i++;
                if(i == IF_IPV6ADDR_MAX)
                    break;
			}
        } 
    }
    if(i == 0) {
      ulogf(ULOG_FIREWALL, UL_INFO,"%s,Interface %s not found in %s\n",__FUNCTION__,ifname,_PROCNET_IFINET6);
    }

    *p_num = i;

    fclose(fp);
    //FIREWALL_DEBUG("Exiting get_ip6address\n");
    return 0;
}

#define DEVICE_PROPERTIES    "/etc/device.properties"

 /*
  *  RDKB-7836	adding protocol verify the build prod or not.
  *  Procedure	   : bIsProductionImage
  *  Purpose	   : return True for production image.
  *  Parameters    :
  *  Return Values :
  *  1             : 1 for prod images
  *  2             : 0 for other images
  */

#ifdef _HUB4_PRODUCT_REQ_

 static int bIsProductionImage( void)
 {
    char fileContent[255] = {'\0'};
    FILE *deviceFilePtr;
    char *pBldTypeStr = NULL;
    int offsetValue = 0;
    deviceFilePtr = fopen( DEVICE_PROPERTIES, "r" );

    if (deviceFilePtr) {
        while ( fscanf(deviceFilePtr , "%s", fileContent) != EOF ) {
            if ( (pBldTypeStr = strstr(fileContent, "BUILD_TYPE")) != NULL) {
                offsetValue = strlen("BUILD_TYPE=");
                pBldTypeStr = pBldTypeStr + offsetValue ;
                break;
            }
        }
        fclose(deviceFilePtr);
        if(pBldTypeStr)
        {
            if(0 == strncmp(pBldTypeStr,"prod",5))
            {
                return 1;
            }
        }
    }
    return 0;
 }

#endif

 /*
  *  RDKB-12305  Adding method to check whether comcast device or not
  *  Procedure     : bIsComcastImage
  *  Purpose       : return True for Comcast build.
  *  Parameters    :
  *  Return Values :
  *  1             : 1 for comcast images
  *  2             : 0 for other images
  */
 static int bIsComcastImage( void)
 {
    char PartnerId[255] = {'\0'};
    int isComcastImg = 1;
    
    getPartnerId ( PartnerId ) ;
    
    if ( 0 != strcmp ( PartnerId, "comcast") ) {
   	 isComcastImg = 0;
    }

    return isComcastImg;
 }


static int bIsContainerEnabled( void)
 {
    char *pContainerSupport = NULL, *pLxcBridge = NULL;
    int isContainerEnabled = 0, offsetValue = 0;
    char fileContent[255] = {'\0'};
    FILE *deviceFilePtr;
    errno_t   safec_rc     = -1;

    FIREWALL_DEBUG("Entering bIsContainerEnabled\n");
    deviceFilePtr = fopen( DEVICE_PROPERTIES, "r" );

    if (deviceFilePtr) {
        while (fscanf(deviceFilePtr , "%s", fileContent) != EOF ) {
            if ((pContainerSupport = strstr(fileContent, "CONTAINER_SUPPORT")) != NULL) {
                offsetValue = strlen("CONTAINER_SUPPORT=");
                pContainerSupport = pContainerSupport + offsetValue;
                if (0 == strncmp(pContainerSupport, "1", 1)) {
                   isContainerEnabled = 1;
                }
            } else if ((pLxcBridge = strstr(fileContent, "LXC_BRIDGE_NAME")) != NULL) {
                offsetValue = strlen("LXC_BRIDGE_NAME=");
                pLxcBridge = pLxcBridge + offsetValue ;
                safec_rc = strcpy_s(lxcBridgeName, sizeof(lxcBridgeName),pLxcBridge);
                ERR_CHK(safec_rc);
            } else {
                continue;
            }
        }
        fclose(deviceFilePtr);
    }
 
    FIREWALL_DEBUG("Exiting bIsContainerEnabled\n");
    return isContainerEnabled;
 }

#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
/*
 *  Procedure     : prepare_multinet_prerouting_raw
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be evaluated by raw table before routing
 *  Parameters    :
 *    raw_fp      : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_prerouting_raw (FILE *raw_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    FIREWALL_DEBUG("Entering prepare_multinet_prerouting_raw\n");         

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip if not multiLAN L3 instance
        if (!isMultiLANL3Instance(atoi(tok)))
          continue;

        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(raw_fp, "-A prerouting_raw -i %s -j lan2wan_helpers\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    FIREWALL_DEBUG("Exiting prepare_multinet_prerouting_raw\n");         

    return 0;
}
#endif

/*
 *  Procedure     : prepare_globals_from_configuration
 *  Purpose       : use syscfg and sysevent to prepare information such as
 *                  wan interface name, wan ip address, etc
 */
static int prepare_globals_from_configuration(void)
{
   int rc;
   char tmp[100];
   char *pStr = NULL;
   int i;
   errno_t  safec_rc  = -1;
   FIREWALL_DEBUG("Entering prepare_globals_from_configuration\n");       
   tmp[0] = '\0';
   // use wan protocol determined wan interface name if possible, else use default (the name used by the OS)
   default_wan_ifname[0] = '\0';
   current_wan_ifname[0] = '\0';
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   current_wan_static_ipaddr[0] = '\0';
   current_wan_static_mask[0] = '\0';
   wan_staticip_status[0] = '\0';
#endif
   lan_ipaddr[0] = '\0';
   transparent_cache_state[0] = '\0';
   wan_service_status[0] = '\0';
#if defined(_COSA_BCM_MIPS_)
   lan0_ipaddr[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "lan0_ipaddr", lan0_ipaddr, sizeof(lan0_ipaddr));
#endif

#ifdef _HUB4_PRODUCT_REQ_
   isProdImage = bIsProductionImage(); 
#endif
   getPartnerId ( devicePartnerId ) ;
   isComcastImage = bIsComcastImage();
   sysevent_get(sysevent_fd, sysevent_token, "wan_ifname", default_wan_ifname, sizeof(default_wan_ifname));
   sysevent_get(sysevent_fd, sysevent_token, "current_wan_ifname", current_wan_ifname, sizeof(current_wan_ifname));
   if ('\0' == current_wan_ifname[0]) {
      if ('\0' == default_wan_ifname[0]) {
         snprintf(current_wan_ifname, sizeof(current_wan_ifname), "%s", "erouter0");
      }
      else {
         snprintf(current_wan_ifname, sizeof(current_wan_ifname), "%s", default_wan_ifname);
      }
   }

   sysevent_get(sysevent_fd, sysevent_token, "current_wan_ipaddr", current_wan_ipaddr, sizeof(current_wan_ipaddr));

   sysevent_get(sysevent_fd, sysevent_token, "current_lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
   
#if defined(CONFIG_CISCO_FEATURE_CISCOCONNECT) || defined(CONFIG_CISCO_PARCON_WALLED_GARDEN) 
   FILE *gwIpFp = fopen("/var/.gwip", "w");
   fprintf(gwIpFp, "%s", lan_ipaddr);
   fclose(gwIpFp);
#endif

   sysevent_get(sysevent_fd, sysevent_token, "transparent_cache_state", transparent_cache_state, sizeof(transparent_cache_state));
   sysevent_get(sysevent_fd, sysevent_token, "byoi_bridge_mode", byoi_bridge_mode, sizeof(byoi_bridge_mode));
   sysevent_get(sysevent_fd, sysevent_token, "wan_service-status", wan_service_status, sizeof(wan_service_status));
   isWanServiceReady = (0 == strcmp("started", wan_service_status)) ? 1 : 0;

   char pri_level_name[20];
   memset(iptables_pri_level, 0, sizeof(iptables_pri_level));
   for(i = 0; i < IPT_PRI_MAX; i++)
   {
      safec_rc = sprintf_s(pri_level_name, sizeof(pri_level_name),"ipt_pri_level_%d", i+1);
      if(safec_rc < EOK)
      {
         ERR_CHK(safec_rc);
      }
      tmp[0] = '\0';
      rc =  sysevent_get(sysevent_fd, sysevent_token, pri_level_name, tmp, sizeof(tmp));
      if(rc != 0 || tmp[0] == '\0')
      {
          SET_IPT_PRI_DEFAULT();
          break;
      }
      iptables_pri_level[i] = SET_IPT_PRI_MODULD(tmp);
      if(iptables_pri_level[i] == 0){
          SET_IPT_PRI_DEFAULT();
          break;
      }
   }

   memset(lan_ifname, 0, sizeof(lan_ifname));
   memset(cmdiag_ifname, 0, sizeof(cmdiag_ifname));
//   memset(lan_ipaddr, 0, sizeof(lan_ipaddr));
   memset(lan_netmask, 0, sizeof(lan_netmask));
   memset(lan_3_octets, 0, sizeof(lan_3_octets));
   memset(rip_enabled, 0, sizeof(rip_enabled));
   memset(rip_interface_wan, 0, sizeof(rip_interface_wan));
   memset(nat_enabled, 0, sizeof(nat_enabled));
   memset(dmz_enabled, 0, sizeof(dmz_enabled));
   memset(firewall_enabled, 0, sizeof(firewall_enabled));
   memset(container_enabled, 0, sizeof(container_enabled));
   memset(bridge_mode, 0, sizeof(bridge_mode));
   memset(log_level, 0, sizeof(log_level));
   memset(lan_local_ipv6,0,sizeof(lan_local_ipv6));

   syscfg_get(NULL, "lan_ifname", lan_ifname, sizeof(lan_ifname));
   if ('\0' == lan_ipaddr[0]) {
        syscfg_get(NULL, "lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
        sysevent_set(sysevent_fd, sysevent_token, "current_lan_ipaddr", lan_ipaddr, 0);
   }
   //syscfg_get(NULL, "lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
   syscfg_get(NULL, "lan_netmask", lan_netmask, sizeof(lan_netmask)); 
   syscfg_get(NULL, "rip_enabled", rip_enabled, sizeof(rip_enabled)); 
   syscfg_get(NULL, "rip_interface_wan", rip_interface_wan, sizeof(rip_interface_wan)); 
   syscfg_get(NULL, "nat_enabled", nat_enabled, sizeof(nat_enabled)); 
   syscfg_get(NULL, "dmz_enabled", dmz_enabled, sizeof(dmz_enabled)); 
   syscfg_get(NULL, "firewall_enabled", firewall_enabled, sizeof(firewall_enabled)); 
   syscfg_get(NULL, "containersupport", container_enabled, sizeof(container_enabled)); 
   //mipieper - change for pseudo bridge
   //syscfg_get(NULL, "bridge_mode", bridge_mode, sizeof(bridge_mode)); 
   sysevent_get(sysevent_fd, sysevent_token, "bridge_mode", bridge_mode, sizeof(bridge_mode));
   syscfg_get(NULL, "log_level", log_level, sizeof(log_level)); 
   if (! log_level[0]) {
        log_level[0] = '1';
        log_level[1] = '\0';
   }
   log_leveli = atoi(log_level);
   syslog_level = to_syslog_level(log_leveli);

   // the first 3 octets of the lan ip address
   snprintf(lan_3_octets, sizeof(lan_3_octets), "%s", lan_ipaddr);
   char *p;
   for (p=lan_3_octets+strlen(lan_3_octets); p >= lan_3_octets; p--) {
      if (*p == '.') {
         *p = '\0';
         break;
      } else {
         *p = '\0';
      }
   }

   syscfg_get(NULL, "cmdiag_ifname", cmdiag_ifname, sizeof(cmdiag_ifname));
   syscfg_get(NULL, "cmdiag_enabled", cmdiag_enabled, sizeof(cmdiag_enabled));

   syscfg_get(NULL, "firewall_level", firewall_level, sizeof(firewall_level));
   syscfg_get(NULL, "firewall_levelv6", firewall_levelv6, sizeof(firewall_levelv6));

   syscfg_get(NULL, "ecm_wan_ifname", ecm_wan_ifname, sizeof(ecm_wan_ifname));
   syscfg_get(NULL, "emta_wan_ifname", emta_wan_ifname, sizeof(emta_wan_ifname));
   syscfg_get(NULL, "eth_wan_enabled", eth_wan_enabled, sizeof(eth_wan_enabled));
   if (0 == strcmp("true", eth_wan_enabled))
      bEthWANEnable = TRUE;

#if defined (AMENITIES_NETWORK_ENABLED)
   char cAmenityReceived [BUFLEN_8] = {0};
   syscfg_get( NULL, "Is_Amenity_Received", cAmenityReceived, BUFLEN_8);
   if(0 == strncmp(cAmenityReceived, "true",4))
       bAmenityEnabled = TRUE;
#endif
   memset(current_wan_ip6_addr, 0, sizeof(current_wan_ip6_addr)); 
   sysevent_get(sysevent_fd, sysevent_token, "tr_erouter0_dhcpv6_client_v6addr", current_wan_ip6_addr, sizeof(current_wan_ip6_addr));

   if ( ('\0' == current_wan_ip6_addr[0] ) && ( 0 == strlen(current_wan_ip6_addr) ) ) {
#ifndef CORE_NET_LIB
        FILE *ipAddrFp = NULL;
#endif
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
	char wanInterface[BUFLEN_64] = {'\0'};
	wanmgr_get_wan_interface(wanInterface);
#ifdef CORE_NET_LIB
        libnet_status ret;
        ret = get_ipv6_address(wanInterface, current_wan_ip6_addr, sizeof(current_wan_ip6_addr));
        if (ret == CNL_STATUS_SUCCESS) {
            FIREWALL_DEBUG("Successfully retrived global IPv6 address for %s\n" COMMA wanInterface);
	    current_wan_ip6_addr[sizeof(current_wan_ip6_addr) - 1] = '\0';
	}
       	else {
            FIREWALL_DEBUG("Failed to retrieve global IPv6 address for %s\n" COMMA wanInterface);
	    current_wan_ip6_addr[0] = '\0';
	}
#else
	ipAddrFp = v_secure_popen("r","ifconfig %s | grep Global |  awk '/inet6/{print $3}' | cut -d '/' -f1", wanInterface);
#endif
#else
#ifdef CORE_NET_LIB
	char interface_ipv6[BUFLEN_64] = "erouter0";
        libnet_status stat;
      	stat = get_ipv6_address(interface_ipv6, current_wan_ip6_addr, sizeof(current_wan_ip6_addr));
        if (stat == CNL_STATUS_SUCCESS) {
            FIREWALL_DEBUG("Successfully retrived IPv6 address for erouter0\n");
	    current_wan_ip6_addr[sizeof(current_wan_ip6_addr) - 1] = '\0';
        }
        else {
            FIREWALL_DEBUG("Failed to retrieve global IPv6 address for erouter0\n");
	    current_wan_ip6_addr[0] = '\0';
        }
#else
        ipAddrFp = v_secure_popen("r","ifconfig erouter0 | grep Global |  awk '/inet6/{print $3}' | cut -d '/' -f1");
#endif
#endif
#ifndef CORE_NET_LIB
	if (ipAddrFp != NULL )
        {
            if(fgets(current_wan_ip6_addr, sizeof(current_wan_ip6_addr), ipAddrFp)!=NULL)
            {
                  int ipAddr_len = 0;
                  ipAddr_len = strlen(current_wan_ip6_addr);
                  if ( current_wan_ip6_addr[ipAddr_len-1] == '\n' )
                  {
                      current_wan_ip6_addr[ipAddr_len - 1] = '\0';
                  }
            }
            v_secure_pclose(ipAddrFp);
            ipAddrFp = NULL;
          }
#endif
    } 

   get_ip6address(ecm_wan_ifname, ecm_wan_ipv6, &ecm_wan_ipv6_num,IPV6_ADDR_SCOPE_GLOBAL);
   get_ip6address(lan_ifname, lan_local_ipv6, &lan_local_ipv6_num,IPV6_ADDR_SCOPE_LINKLOCAL);
   get_ip6address(current_wan_ifname, current_wan_ipv6, &current_wan_ipv6_num,IPV6_ADDR_SCOPE_GLOBAL);

   #if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)

   if(bus_handle != NULL)
   {
         memset(mesh_wan_ifname,0,sizeof(mesh_wan_ifname));

         rc = PSM_VALUE_GET_STRING(PSM_MESH_WAN_IFNAME,pStr);
         if(rc == CCSP_SUCCESS && pStr != NULL){
               safec_rc = strcpy_s(mesh_wan_ifname, sizeof(mesh_wan_ifname),pStr);
               ERR_CHK(safec_rc);
               Ansc_FreeMemory_Callback(pStr);
               pStr = NULL;
         }      
   }
   memset(mesh_wan_ipv6addr,0,sizeof(mesh_wan_ipv6addr));
   get_ip6address(mesh_wan_ifname, mesh_wan_ipv6addr, &mesh_wan_ipv6_num,IPV6_ADDR_SCOPE_GLOBAL);
   #endif 

   if (0 == strcmp("true", container_enabled)) {
      isContainerEnabled = bIsContainerEnabled();
   }
   rfstatus =  isInRFCaptivePortal();
   isCacheActive     = (0 == strcmp("started", transparent_cache_state)) ? 1 : 0;
   isFirewallEnabled = (0 == strcmp("0", firewall_enabled)) ? 0 : 1; 

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   isMAPTReady = isMAPTSet();

   if(!isMAPTReady) //Dual Stack Line
      isWanReady        = IsValidIPv4Addr(current_wan_ipaddr);
#if defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   else { //MAPT Line
      isWanReady        = IsValidIPv4Addr(mapt_ip_address);
      safec_rc = strcpy_s(current_wan_ipaddr, sizeof(current_wan_ipaddr),mapt_ip_address);
      ERR_CHK(safec_rc);
   }
// Check isWanReady flag for IVI Kernel Module. If required, include this changes under IVI_KERNEL_SUPPORT Build flag
#else // IVI
   isWanReady        = IsValidIPv4Addr(current_wan_ipaddr);
#endif //NAT46_KERNEL_SUPPORT
#endif //FEATURE_MAPT

#ifdef _HUB4_PRODUCT_REQ_
#ifndef FEATURE_MAPT
   isWanReady        = (0 == strcmp("0.0.0.0", current_wan_ipaddr)) ? 0 : 1;
#endif //FEATURE_MAPT
#else //_HUB4_PRODUCT_REQ_ ENDS
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      isWanReady        = (0 == strcmp("0.0.0.0", current_wan_ipaddr)) ? 0 : 1;
   }
#endif // NON _HUB4_PRODUCT_REQ_
   //isBridgeMode        = (0 == strcmp("1", bridge_mode)) ? 1 : (0 == strcmp("1", byoi_bridge_mode)) ? 1 : 0;
   isBridgeMode        = (0 == strcmp("0", bridge_mode)) ? 0 : 1;
   isRipEnabled      = (0 == (strcmp("1", rip_enabled))) ? 1 : 0;
   isRipWanEnabled   = ((isRipEnabled) && (0 == (strcmp("1", rip_interface_wan)))) ? 1 : 0;
   isDmzEnabled      = (0 == strcmp("1", dmz_enabled)) ? 1 : 0;
   /* nat_enabled(0): disable  (1) DHCP (2)StaticIP (others) disable */
   isNatEnabled      = atoi(nat_enabled);
   #ifdef CISCO_CONFIG_TRUE_STATIC_IP
   isNatEnabled      = (isNatEnabled > NAT_STATICIP ? NAT_DISABLE : isNatEnabled);
   #else
   isNatEnabled      = (isNatEnabled == NAT_DISABLE ? NAT_DISABLE : NAT_DHCP);
   #endif
   isLogEnabled      = (log_leveli > 1) ? 1 : 0;
   isLogSecurityEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;
#if 0
   isLogIncomingEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;
   isLogOutgoingEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;
#endif
   //todo add syscfg to config log flag 
   isLogIncomingEnabled = 0;
   isLogOutgoingEnabled = 0;
   isCmDiagEnabled   = (0 == strcmp("1", cmdiag_enabled)) ? 1 : 0;

#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   /* get true static IP info */   
   sysevent_get(sysevent_fd, sysevent_token, "wan_staticip-status", wan_staticip_status, sizeof(wan_staticip_status));
   isWanStaticIPReady = (0 == strcmp("started", wan_staticip_status)) ? 1 : 0; 
   /* Get Ture Static IP Enable/Disable */
   if(bus_handle != NULL && isWanStaticIPReady){
       isWanStaticIPReady = 0;
       if(isBridgeMode == 0)
       {
       rc = PSM_VALUE_GET_STRING(PSM_NAME_TRUE_STATIC_IP_ENABLE, pStr);
       if(rc == CCSP_SUCCESS && pStr != NULL){
          if((strcmp("TRUE", pStr) == 0) || (strcmp("1", pStr) == 0)){
              isWanStaticIPReady = 1;
          }
          Ansc_FreeMemory_Callback(pStr);
       }
       }   
   }

   /* get value from PSM */
   if(bus_handle != NULL && isWanStaticIPReady)
   {
      /* Get True static Ip information */ 
      rc = PSM_VALUE_GET_STRING(PSM_NAME_TRUE_STATIC_IP_ADDRESS,pStr);
      if(rc == CCSP_SUCCESS && pStr != NULL){
         safec_rc = strcpy_s(current_wan_static_ipaddr, sizeof(current_wan_static_ipaddr),pStr);
         ERR_CHK(safec_rc);
         Ansc_FreeMemory_Callback(pStr);
         pStr = NULL;
      }
      
      rc = PSM_VALUE_GET_STRING(PSM_NAME_TRUE_STATIC_IP_NETMASK ,pStr);
      if(rc == CCSP_SUCCESS && pStr != NULL){
         safec_rc = strcpy_s(current_wan_static_mask, sizeof(current_wan_static_mask),pStr);
         ERR_CHK(safec_rc);
         Ansc_FreeMemory_Callback(pStr);
         pStr = NULL;
      }
      
      strncpy(StaticIPSubnet[0].ip, current_wan_static_ipaddr, sizeof(StaticIPSubnet[0].ip));
      strncpy(StaticIPSubnet[0].mask, current_wan_static_mask, sizeof(StaticIPSubnet[0].mask));
      StaticIPSubnetNum = 1;

      unsigned int ts_asn_count = 0;
      unsigned int *ts_asn_ins = NULL;
      rc = PSM_VALUE_GET_INS(PSM_NAME_TRUE_STATIC_ASN, &ts_asn_count, &ts_asn_ins);
      if(rc == CCSP_SUCCESS && ts_asn_count != 0){
          if(MAX_TS_ASN_COUNT -1  < ts_asn_count){
             fprintf(stderr, "[Firewall] ERROR too many Ture static subnet\n");
             ts_asn_count = MAX_TS_ASN_COUNT -1;
          }
          for(i = 0; i < (int)ts_asn_count ; i++){
             safec_rc = sprintf_s(tmp, sizeof(tmp),"%s%d.%s", PSM_NAME_TRUE_STATIC_ASN, ts_asn_ins[i], PSM_NAME_TRUE_STATIC_ASN_ENABLE);
             if(safec_rc < EOK){
               ERR_CHK(safec_rc);
             }
             rc = PSM_VALUE_GET_STRING(tmp, pStr) - CCSP_SUCCESS;
             if(rc == 0 && pStr != NULL){
                if(atoi(pStr) != 1){
                    Ansc_FreeMemory_Callback(pStr);
                    pStr = NULL;
                    continue;
                }
                Ansc_FreeMemory_Callback(pStr);
                pStr = NULL;
             }
 
             safec_rc = sprintf_s(tmp, sizeof(tmp),"%s%d.%s", PSM_NAME_TRUE_STATIC_ASN, ts_asn_ins[i], PSM_NAME_TRUE_STATIC_ASN_IP);
             if(safec_rc < EOK){
               ERR_CHK(safec_rc);
             }
             rc |= PSM_VALUE_GET_STRING(tmp, pStr) - CCSP_SUCCESS;
             if(rc == 0 && pStr != NULL){
                strncpy(StaticIPSubnet[StaticIPSubnetNum].ip, pStr, sizeof(StaticIPSubnet[StaticIPSubnetNum].ip));
                Ansc_FreeMemory_Callback(pStr);
                pStr = NULL;
             }
 
             safec_rc = sprintf_s(tmp, sizeof(tmp),"%s%d.%s", PSM_NAME_TRUE_STATIC_ASN, ts_asn_ins[i], PSM_NAME_TRUE_STATIC_ASN_MASK);
             if(safec_rc < EOK){
               ERR_CHK(safec_rc);
             }
             rc |= PSM_VALUE_GET_STRING(tmp, pStr) - CCSP_SUCCESS;
             if(rc == 0 && pStr != NULL){
                strncpy(StaticIPSubnet[StaticIPSubnetNum].mask, pStr, sizeof(StaticIPSubnet[StaticIPSubnetNum].mask));
                Ansc_FreeMemory_Callback(pStr);
                pStr = NULL;
             }

             if(rc == 0){
                printf("%d : ip %s mask %s \n", StaticIPSubnetNum, StaticIPSubnet[StaticIPSubnetNum].ip, StaticIPSubnet[StaticIPSubnetNum].mask);
                StaticIPSubnetNum++;
             }  
          }
          Ansc_FreeMemory_Callback(ts_asn_ins);
      }else{
        FIREWALL_DEBUG("%d GET INSTERR\n" COMMA __LINE__);
      }
   }

   if(isWanReady && isNatEnabled == 1){
       isNatReady = 1;
       safec_rc = strcpy_s(natip4, sizeof(natip4),current_wan_ipaddr);
       ERR_CHK(safec_rc);
   }else if(isWanReady && isNatEnabled == 2 && isWanStaticIPReady ){
       isNatReady = 1;
       safec_rc = strcpy_s(natip4, sizeof(natip4),current_wan_static_ipaddr);
       ERR_CHK(safec_rc);
   }else if(isWanReady && isNatEnabled == 2 && isWanStaticIPReady == 0 ){
       /* RDKB-34155 When True static IP configured device moved to bridge mode */
       safec_rc = strcpy_s(natip4, sizeof(natip4),current_wan_ipaddr);
       ERR_CHK(safec_rc);
       isNatReady = 1;  
   }else 
       isNatReady = 0;

   memset(firewall_true_static_ip_enable, 0, sizeof(firewall_true_static_ip_enable));
   syscfg_get(NULL, "firewall_true_static_ip_enable", firewall_true_static_ip_enable,sizeof(firewall_true_static_ip_enable));
   isFWTS_enable = (0 == strcmp("1", firewall_true_static_ip_enable) ? 1 : 0);
	   
#else
    safec_rc = strcpy_s(natip4, sizeof(natip4),current_wan_ipaddr);
    ERR_CHK(safec_rc);
    isNatReady = isWanReady; 
#endif


   char temp[20];

   temp[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "pp_flush", temp, sizeof(temp));
   if ('\0' == temp[0]) {
       ppFlushNeeded = 0;
   } else if (0 == strcmp("0", temp)) {
       ppFlushNeeded  = 0;
   } else {
       ppFlushNeeded  = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_ping", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isPingBlocked = 1;
   } else if (0 == strcmp("0", temp)) {
      isPingBlocked = 0;
   } else {
     isPingBlocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_pingv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isPingBlockedV6 = 1;
   } else if (0 == strcmp("0", temp)) {
      isPingBlockedV6 = 0;
   } else {
     isPingBlockedV6 = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_multicast", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isMulticastBlocked = 0;
   } else if (0 == strcmp("0", temp)) {
      isMulticastBlocked = 0;
   } else {
     isMulticastBlocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_multicastv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isMulticastBlockedV6 = 0;
   } else if (0 == strcmp("0", temp)) {
      isMulticastBlockedV6 = 0;
   } else {
     isMulticastBlockedV6 = 1;
   }

   temp[0] = '\0';
   isNatRedirectionBlocked = 0;
   rc = syscfg_get(NULL, "block_nat_redirection", temp, sizeof(temp));
   if (0 == rc && '\0' != temp[0]) {
      if (0 == strcmp("1", temp)){
         isNatRedirectionBlocked = 1;
      }
   }

   temp[0] = '\0';
   isHairpin = 0;
   rc = syscfg_get(NULL, "nat_hairping_enable", temp, sizeof(temp));
   if(0 == rc || '\0' != temp[0]){
       if(!strcmp("1", temp))
          isHairpin = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_ident", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isIdentBlocked = 1;
   } else if (0 == strcmp("0", temp)) {
      isIdentBlocked = 0;
   } else {
     isIdentBlocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_identv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isIdentBlockedV6 = 1;
   } else if (0 == strcmp("0", temp)) {
      isIdentBlockedV6 = 0;
   } else {
     isIdentBlockedV6 = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_rfc1918", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isRFC1918Blocked = 0;
   } else if (0 == strcmp("0", temp)) {
      isRFC1918Blocked = 0;
   } else {
     isRFC1918Blocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "RFCAllowOpenPorts", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      allowOpenPorts = 0;
   } else if (0 == strcmp("true", temp)) {
      allowOpenPorts = 1;
   } else {
     allowOpenPorts = 0;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_http", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isHttpBlocked = 0;
   } else if (0 == strcmp("0", temp)) {
      isHttpBlocked = 0;
   } else {
     isHttpBlocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_httpv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isHttpBlockedV6 = 0;
   } else if (0 == strcmp("0", temp)) {
      isHttpBlockedV6 = 0;
   } else {
     isHttpBlockedV6 = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_p2p", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isP2pBlocked = 0;
   } else if (0 == strcmp("0", temp)) {
      isP2pBlocked = 0;
   } else {
     isP2pBlocked = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "block_p2pv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isP2pBlockedV6 = 0;
   } else if (0 == strcmp("0", temp)) {
      isP2pBlockedV6 = 0;
   } else {
     isP2pBlockedV6 = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "firewall_development_override", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isDevelopmentOverride = 0;
   } else if (0 == strcmp("0", temp)) {
      isDevelopmentOverride = 0;
   } else {
     isDevelopmentOverride = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "portscan_enabled", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isPortscanDetectionEnabled = 1;
   } else if (0 == strcmp("0", temp)) {
      isPortscanDetectionEnabled = 0;
   } else {
     isPortscanDetectionEnabled = 1;
   }

   temp[0] = '\0';
   rc = syscfg_get(NULL, "firewall_disable_wan_ping", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isWanPingDisable = 0;
   } else if (0 == strcmp("0", temp)) {
      isWanPingDisable = 0;
   } else {
     isWanPingDisable = 1;
   }


   temp[0] = '\0';
   rc = syscfg_get(NULL, "firewall_disable_wan_pingv6", temp, sizeof(temp));
   if (0 != rc || '\0' == temp[0]) {
      isWanPingDisableV6 = 0;
   } else if (0 == strcmp("0", temp)) {
      isWanPingDisableV6 = 0;
   } else {
     isWanPingDisableV6 = 1;
   }



#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   temp[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "ciscoconnect_guest_enable", temp, sizeof(temp));
   if ('\0' == temp[0]) {
      isGuestNetworkEnabled = 0;
   } else if (0 == strcmp("0", temp)) {
       isGuestNetworkEnabled  = 0;
   } else {
       isGuestNetworkEnabled  = 1;
   }

   char guest_network_ins[8];
   char guestnet_ip_name[32];
   char guestnet_mask_name[32];

   sysevent_get(sysevent_fd, sysevent_token, "ciscoconnect_guest_l3net", guest_network_ins, sizeof(guest_network_ins));

   snprintf(guestnet_ip_name, sizeof(guestnet_ip_name), "ipv4_%s-ipv4addr", guest_network_ins);
   sysevent_get(sysevent_fd, sysevent_token, guestnet_ip_name, guest_network_ipaddr, sizeof(guest_network_ipaddr));

   FILE *f = fopen("/var/.guestnetip", "w");
   fprintf(f, "%s", guest_network_ipaddr);
   fclose(f);

   snprintf(guestnet_mask_name, sizeof(guestnet_mask_name), "ipv4_%s-ipv4subnet", guest_network_ins);
   sysevent_get(sysevent_fd, sysevent_token, guestnet_mask_name, guest_network_mask, sizeof(guest_network_mask));
#endif

   /*
    * for development we all ping and rfc 1918 addresses on wan
    */
   if (isDevelopmentOverride) {
      isRFC1918Blocked = 0;
      isPingBlocked = 0;
   }

   /*
    * Is the system clock trustable
    */
   temp[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "ntpclient-status", temp, sizeof(temp));
   if ( '\0' != temp[0] && 0 == strcmp("started", temp)) {      
      isNtpFinished=1;
   }

   if (isFirewallEnabled) {
      /*
       * Are we tracking bandwidth usage on a per host basis
       */
      temp[0] = '\0';
      rc = syscfg_get(NULL, "lanhost_tracking_enabled", temp, sizeof(temp));
      if (0 == rc && '\0' != temp[0]) {
         if (0 != strcmp("0", temp)) {
            isLanHostTracking              = 1;
         }
      } else {
         temp[0] = '\0';
         sysevent_get(sysevent_fd, sysevent_token, "lanhost_tracking_enabled", temp, sizeof(temp));
         if ( '\0' != temp[0] && 0 != strcmp("0", temp)) {      
            isLanHostTracking              = 1;
         }
      }

      /*
       * Are we using DMZ based on mac address
       */
      temp[0] = '\0';
      if (isDmzEnabled) {
         rc = syscfg_get(NULL, "dmz_dst_ip_addr", temp, sizeof(temp));
         if (0 != rc || '\0' == temp[0]) {
            temp[0] = '\0';
            rc = syscfg_get(NULL, "dmz_dst_mac_addr", temp, sizeof(temp));
            if (0 == rc && '\0' != temp[0]) {
               isDMZbyMAC  = 1;
            }
         }
      }
   }

   reserved_mgmt_port[0] = '\0';
   rc = syscfg_get(NULL, "http_admin_port", reserved_mgmt_port, sizeof(reserved_mgmt_port));
   if (0 != rc || '\0' == reserved_mgmt_port[0]) {
      snprintf(reserved_mgmt_port, sizeof(reserved_mgmt_port), "80");
   } 
   
   /* Get DSCP value for gre */
   if(bus_handle != NULL){
       rc = PSM_VALUE_GET_STRING(PSM_NAME_GRE_DSCP_VALUE, pStr);
       if(rc == CCSP_SUCCESS && pStr != NULL){
          greDscp = atoi(pStr);
          Ansc_FreeMemory_Callback(pStr);
          pStr = NULL;
       }   
   }
#ifdef RDKB_EXTENDER_ENABLED
   memset(cellular_ifname,0,sizeof(cellular_ifname));
   sysevent_get(sysevent_fd, sysevent_token, "cellular_ifname", cellular_ifname, sizeof(cellular_ifname));
#endif
   

#if defined(FEATURE_RDKB_INTER_DEVICE_MANAGER)
   memset(idmInterface,0,sizeof(idmInterface));
   pStr = NULL;
   if(bus_handle != NULL){ // CID 330280: Dereference after null check (FORWARD_NULL)
       rc = PSM_VALUE_GET_STRING(PSM_IDM_INTERFACE_NAME,pStr);
       if(rc == CCSP_SUCCESS && pStr != NULL){
           safec_rc = strcpy_s(idmInterface, sizeof(idmInterface),pStr);
           FIREWALL_DEBUG("PSM_IDM_INTERFACE_NAME is %s\n" COMMA idmInterface);       
           ERR_CHK(safec_rc);
           Ansc_FreeMemory_Callback(pStr);
           pStr = NULL;
        }
    }
#endif

   #if defined(SPEED_BOOST_SUPPORTED)
   {
      char sb_port_start[10] , sb_port_end[10] , pvd_enable[8];
      speedboostports[0]='\0';
      sb_port_start[0]='\0';
      sb_port_end[0]='\0';
      pvd_enable[0]='\0';
      int rc_sb = syscfg_get(NULL, "SpeedBoost_Port_StartV4" , sb_port_start, sizeof(sb_port_start));
      rc_sb |= syscfg_get(NULL, "SpeedBoost_Port_EndV4" , sb_port_end, sizeof(sb_port_end));
      if (rc_sb == 0 && atoi(sb_port_start) && atoi(sb_port_end) ) {
         snprintf(speedboostports , sizeof(speedboostports), "%s:%s", sb_port_start, sb_port_end);
      }
      #if defined(SPEED_BOOST_SUPPORTED_V6)
      speedboostportsv6[0]='\0';
      rc_sb = syscfg_get(NULL, "SpeedBoost_Port_StartV6" , sb_port_start, sizeof(sb_port_start));
      rc_sb |= syscfg_get(NULL, "SpeedBoost_Port_EndV6" , sb_port_end, sizeof(sb_port_end));
      if (rc_sb == 0 && atoi(sb_port_start) && atoi(sb_port_end) ) {
         snprintf(speedboostportsv6 , sizeof(speedboostportsv6), "%s:%s", sb_port_start, sb_port_end);
      }
      #endif
      rc_sb = syscfg_get(NULL, "Advertisement_pvd_enable" , pvd_enable, sizeof(pvd_enable));
      if (rc_sb == 0 && (0 == strcmp("1", pvd_enable) || 0 == strcasecmp("true", pvd_enable))) {
         isPvDEnable=TRUE;
      }
      else {
         isPvDEnable=FALSE;
      }
   }
   #endif

    FIREWALL_DEBUG("Exiting prepare_globals_from_configuration\n");       
   return(0);
}

/*
 ****************************************************************
 *               IPv4 Firewall                                  *
 ****************************************************************
 */

/*
 =================================================================
             Logging
 =================================================================
 */

/*
 *  Procedure     : do_raw_logs
 *  Purpose       : prepare the iptables-restore statements with statements for logging
 *                  the raw table
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *                  protocol.
 *  Return Values :
 *     0               : done
 */
 int do_raw_logs(FILE *fp)
{
  // FIREWALL_DEBUG("Entering do_raw_logs\n");       
 if (isLogEnabled) {
      if (isLogSecurityEnabled) {
         fprintf(fp, "-A xlog_drop_lanattack -j LOG --log-prefix \"UTOPIA: FW.LANATTACK DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
      }
   }
   fprintf(fp, "-A xlog_drop_lanattack -j DROP\n");
  // FIREWALL_DEBUG("Exiting do_raw_logs\n");       
   return(0);
}

/*
 *  Procedure     : do_logs
 *  Purpose       : prepare the iptables-restore statements with statements for logging
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *                  protocol.
 *  Return Values :
 *     0               : done
 */
 int do_logs(FILE *fp)
{
  // FIREWALL_DEBUG("Entering do_logs\n");       
   /*
    * Aside from the general idea that logging is enabled,
    * we can turn on/off certain logs according to whether
    * they are security related, incoming, or outgoing
    */
   if (isLogEnabled) {
      if (isLogOutgoingEnabled) {
            fprintf(fp, "-A xlog_accept_lan2wan -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.LAN2WAN ACCEPT \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
      }

      if (isLogIncomingEnabled) {
         fprintf(fp, "-A xlog_accept_wan2lan -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.WAN2LAN ACCEPT \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlog_accept_wan2self -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.WAN2SELF ACCEPT \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlog_drop_wan2lan -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.WAN2LAN DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlog_drop_wan2self -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.WAN2SELF DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlogdrop -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlogreject -j LOG --log-prefix \"UTOPIA: FW.REJECT \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
      }


      if (isLogSecurityEnabled) {

         fprintf(fp, "-A xlog_drop_wanattack -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.WANATTACK DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
         
	 fprintf(fp, "-A xlog_drop_lan2wan_misc -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"UTOPIA: FW.IPv4 ln2wnmis drop\"\n",syslog_level);

         fprintf(fp, "-A xlog_drop_lanattack -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.LANATTACK DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A xlog_drop_lan2self -m state --state NEW -j LOG --log-prefix \"UTOPIA: FW.LAN2SELF DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp,  "-A xlog_drop_lan2wan -j LOG --log-prefix \"UTOPIA: FW.LAN2WAN DROP \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         if(isComcastImage) {
             fprintf(fp, "-A LOG_TR69_DROP -j LOG --log-prefix \"TR-069 ACS Server Blocked: \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
         }

         fprintf(fp, "-A LOG_SSH_DROP -j LOG --log-prefix \"SSH Connection Blocked: \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);

         fprintf(fp, "-A SNMPDROPLOG -j LOG --log-prefix \"SNMP DROP Connection Blocked: \" --log-level %d  -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
      }

   }

   fprintf(fp, "-A xlog_accept_lan2wan -j ACCEPT\n");

   fprintf(fp, "-A xlog_accept_wan2lan -j ACCEPT\n");

   fprintf(fp, "-A xlog_accept_wan2self -j ACCEPT\n");
#if !(defined INTEL_PUMA7) && !(defined _COSA_BCM_ARM_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_) && !defined(_COSA_QCA_ARM_)
   fprintf(fp, "-A xlog_drop_wan2lan -j DROP\n");
#endif
   fprintf(fp, "-A xlog_drop_wan2self -j DROP\n");

   fprintf(fp, "-A xlog_drop_wanattack -j DROP\n");

   fprintf(fp, "-A xlog_drop_lan2wan_misc -j DROP\n");
   
   fprintf(fp, "-A xlog_drop_lanattack -j DROP\n");

   fprintf(fp, "-A xlog_drop_lan2self -j DROP\n");

   fprintf(fp, "-A xlog_drop_lan2wan -j DROP\n");

   fprintf(fp, "-A xlogdrop -j DROP\n");

   fprintf(fp, "-A xlogreject -p tcp -m tcp -j REJECT --reject-with tcp-reset\n");

   if(isComcastImage) {
       fprintf(fp, "-A LOG_TR69_DROP -j DROP\n");
   }

   fprintf(fp, "-A LOG_SSH_DROP -j DROP\n");

   //SNMPv3 
   fprintf(fp, "-A SNMPDROPLOG -j DROP\n");

   // for non tcp
   fprintf(fp, "-A xlogreject -j DROP\n");
    //       FIREWALL_DEBUG("Exiting do_logs\n");       
   return(0);
}


#if defined (AMENITIES_NETWORK_ENABLED)
#define AMENITY_QUEUE_NUM_START 61
void updateAmenityNetworkRules(FILE *filter_fp , FILE *mangle_fp , int iptype )
{
   char query[MAX_QUERY];
   int  rc, bridgecount;
   char param[BUFLEN_64] = {'\0'};
   char bridgename[BUFLEN_8] = {'\0'};
   char bridgeindex[BUFLEN_8] = {'\0'};
   const char *amenityBridgeIdx[] = {VAP_NAME_2G_INDEX , VAP_NAME_5G_INDEX , VAP_NAME_6G_INDEX} ;
   query[0] = '\0';
   FIREWALL_DEBUG("Entering updateAmenityNetworkRules\n");
   rc = syscfg_get(NULL, "Amenity_Bridge_Count", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto AmenityExit;
   } else {
      bridgecount = atoi(query);
      if (0 == bridgecount) {
         goto AmenityExit;
      }
   }
   for(int idx = 0 ; idx < bridgecount ; idx++)
   {
      char namespace[BUFLEN_64] = {'\0'};
      snprintf(query, sizeof(query), "Amenity_Bridge_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      } else if ( (0 == strcmp("0", query)) || (0 == strcasecmp("false", query)) ) {
        FIREWALL_DEBUG("skipping Amenity rule for %s\n" COMMA param);
        continue;
      }
      FIREWALL_DEBUG("Amenity rule for %s\n" COMMA query);
      psmGet(bus_handle, (char *)amenityBridgeIdx[idx], bridgeindex, sizeof(bridgeindex));
      if ('\0' == bridgeindex[0])
      {
         FIREWALL_DEBUG(" Failed to get %s\n" COMMA amenityBridgeIdx[idx]);
         goto AmenityExit;
      }
      snprintf(param, BUFLEN_64, AMENITY_WIFI_BRIDGE_NAME, bridgeindex );
      psmGet(bus_handle, param, bridgename, sizeof(bridgename));
      if ('\0' == bridgename[0])
      {
         FIREWALL_DEBUG(" Failed to get %s\n" COMMA param);
         goto AmenityExit;
      }
      FIREWALL_DEBUG(" Applying Amenity network IPv%d rules for %s \n" COMMA iptype COMMA bridgename);
      if(iptype == AF_INET)
      {
         //DHCP option 82 handling rule for Amenity bridge interfaces
         fprintf(filter_fp, "-A FORWARD -o %s -p udp --dport=67:68 -j NFQUEUE --queue-bypass --queue-num %d\n", bridgename, AMENITY_QUEUE_NUM_START+idx);
         fprintf(mangle_fp, "-A POSTROUTING -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 \n" , bridgename);
      }
      else
      {
         fprintf(filter_fp, "-A INPUT -i %s -j ACCEPT  \n" , bridgename );
         // Allow forward within same Amenity network interface
         fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", bridgename, bridgename);
      }
   }
AmenityExit:
   FIREWALL_DEBUG("Exiting updateAmenityNetworkRules\n");

}
#endif

/*
 =================================================================
              Port Forwarding
 =================================================================
 */
/*
 *  Procedure     : do_single_port_forwarding
 *  Purpose       : prepare the iptables-restore statements for single port forwarding
 *  Parameters    : 
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
int do_single_port_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6)
{
   /*
    * syscfg tuple SinglePortForward_x, where x is a digit
    * keeps track of the syscfg namespace of a defined port forwarding rule.
    * We iterate through these tuples until we dont find another instance in syscfg.
    */ 

   int idx;
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];
   int  rc;
   int  count;
#ifndef INTEL_PUMA7
   char *tmp = NULL;
#endif
           FIREWALL_DEBUG("Entering do_single_port_forwarding\n");
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   BOOL isBothProtocol = FALSE;
   BOOL isFeatureDisabled = TRUE;
#endif
   query[0] = '\0';
   rc = syscfg_get(NULL, "SinglePortForwardCount", query, sizeof(query)); 
   if (0 != rc || '\0' == query[0]) {
      goto SinglePortForwardNext;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto SinglePortForwardNext;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   {
       FIREWALL_DEBUG("PortMapping:Feature Enable %d\n" COMMA TRUE);
       isFeatureDisabled = FALSE;
   }
#endif

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "SinglePortForward_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }
   
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Index %d\n" COMMA idx);
#endif
      // is the rule enabled
      query[0] = '\0';
      rc = syscfg_get(namespace, "enabled", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if ( (0 == strcmp("0", query)) || (0 == strcasecmp("false", query)) ) {
        continue;
      }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
        FIREWALL_DEBUG("PortMapping:Enable %s\n" COMMA query);
#endif
   
      // what is the ip address to forward to
      char toip[40];
      toip[0] = '\0';
      char toipv6[64];
      toipv6[0] = '\0';
      
      if(iptype == AF_INET){
          rc = syscfg_get(namespace, "to_ip", toip, sizeof(toip));
          /* some time user only need IPv6 forwarding, in this case 255.255.255.255 will be set as toip. 
          * so we needn't do anything about those entry */
          if (0 != rc || '\0' == toip[0] || !strcmp("255.255.255.255", toip)) {
             FIREWALL_DEBUG("PortMapping:Internal Client IPv4 (null)\n");
             continue;
          }
      }else{
        rc = syscfg_get(namespace, "to_ipv6", toipv6, sizeof(toipv6));
        if (0 != rc || '\0' == toipv6[0] || strcmp("x", toipv6) == 0) {
            FIREWALL_DEBUG("PortMapping:Internal Client IPv6 (null)\n");
            continue;
        }
      }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if(iptype == AF_INET){
          FIREWALL_DEBUG("PortMapping:Internal Client IPv4 %s\n" COMMA toip);
      } else {
          FIREWALL_DEBUG("PortMapping:Internal Client IPv6 %s\n" COMMA toipv6);
      }
#endif

      // what is the destination port for the protocol we are forwarding
      char external_port[10];
      external_port[0] = '\0';
      rc = syscfg_get(namespace, "external_port", external_port, sizeof(external_port));
      if (0 != rc || '\0' == external_port[0]) {
         continue;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:External Port %s\n" COMMA external_port);
#endif

      // what is the forwarded destination port for the protocol
      char internal_port[10];
      internal_port[0] = '\0';
      rc = syscfg_get(namespace, "internal_port", internal_port, sizeof(internal_port));
      if (0 != rc || '\0' == internal_port[0]) {
         snprintf(internal_port, sizeof(internal_port), "%s", external_port);
      }

      if ( 80 == atoi(external_port)  )
         isDefHttpPortUsed = TRUE ;
      else if ( 443 == atoi(external_port) )
         isDefHttpsPortUsed = TRUE ;
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Internal Port %s\n" COMMA internal_port);
#endif

      char port_modifier[12];
      if ('\0' == internal_port[0] || 0 == strcmp(internal_port, external_port) || 0 == strcmp(internal_port, "0") ) {
        port_modifier[0] = '\0';
      } else {
        snprintf(port_modifier, sizeof(port_modifier), ":%s", internal_port);
      }

#if defined(SPEED_BOOST_SUPPORTED)
      if(IsPortOverlapWithSpeedboostPortRange(atoi(external_port) , atoi(external_port) , atoi(internal_port) , atoi(internal_port) )) {
         FIREWALL_DEBUG("do_single_port_forwarding: Skip - overlapping with Speedboost port range \n" );
         continue;
      }
#endif

      // what is the forwarded protocol
      char prot[10];
      prot[0] = '\0';
      rc = syscfg_get(namespace, "protocol", prot, sizeof(prot));
      if (0 != rc || '\0' == prot[0]) {
         snprintf(prot, sizeof(prot), "%s", "both");
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Protocol %s\n" COMMA prot);
#endif

      //PortForwarding in IPv6 is to overwrite the Firewall wan2lan rules
      if(iptype == AF_INET6) {
          if (0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) {
              fprintf(filter_fp_v6, "-A wan2lan -p tcp -m tcp -d %s --dport %s -j ACCEPT\n", toipv6, external_port);
          }

          if (0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) {
              fprintf(filter_fp_v6, "-A wan2lan -p udp -m udp -d %s --dport %s -j ACCEPT\n", toipv6, external_port);
          }

          continue;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isMAPTReady == TRUE )
      {
          if (0 == strcmp("both", prot))
          {
              isBothProtocol = TRUE;
          }
      
          if (isBothProtocol == TRUE)
          {
#if defined(IVI_KERNEL_SUPPORT) 
              int both_protocol = 110;
              int ret =0;
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %s -q %s -P %d ",
                      toip, external_port, external_port, both_protocol);
#endif
              ret = v_secure_system("ivictl -p -a %s -p %s -q %s -P %d ",
                      toip, external_port, external_port, both_protocol);
              FIREWALL_DEBUG("ret val of v_secure_system %d\n",ret);
              
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
          {

#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Single Port Forwarding --- BOTH" );
#endif
             fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
 
             fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
          }
#endif //IVI_KERNEL_SUPPORT
          }
       }
#endif //FEATURE_MAPT
      
      
    if ( (0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) && (privateIpCheck(toip)) )
	  {
	     if (isNatReady) {
            fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
         }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
#if defined(IVI_KERNEL_SUPPORT)              
      
             int tcp_protocol = 100;
             int ret =0;
             fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
             if (isBothProtocol == FALSE)
             {
#ifdef FEATURE_MAPT_DEBUG
                 LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %s -q %s -P %d ",
                     toip, external_port, external_port, tcp_protocol);
#endif
                 ret = v_secure_system("ivictl -p -a %s -p %s -q %s -P %d ",
                     toip, external_port, external_port, tcp_protocol);
                 FIREWALL_DEBUG("ret val of v_secure_system %d\n",ret);
            }
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
            if (isBothProtocol == FALSE)
            {
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Single Port Forwarding --- TCP" );
#endif
                fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
            }
#endif //IVI_KERNEL_SUPPORT
         }
#endif //FEATURE_MAPT
         if(isHairpin){
             if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
                #ifndef INTEL_PUMA7
                if(strcmp(internal_port, "0")){
                    tmp = internal_port; 
                }else{
                    tmp = external_port;
                }
                //ARRISXB6-4723 - Below SNAT rule is causing access issues for LAN-wifi clients when port forwarding is enabled in XB6, hence the conditional check.
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, tmp, natip4);
                #endif
            }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
          else
          {
              if(isMAPTReady)
              {
                  fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);

                  if(strcmp(internal_port, "0")){
                      tmp = internal_port; 
                  }else{
                      tmp = external_port;
                  }

                  fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, tmp, mapt_ip_address);
              }
          }
#endif
         }else if (!isNatRedirectionBlocked) {
            fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", lan_ipaddr, external_port, toip, port_modifier);
         
            if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
            }

            if(strcmp(internal_port, "0")){
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, internal_port, lan_ipaddr);
            }else{
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, external_port, lan_ipaddr);
            }
         }
         if (filter_fp) {
            if(strcmp(internal_port, "0")){
                fprintf(filter_fp, "-A wan2lan_forwarding_accept -p tcp -m tcp -d %s --dport %s -j xlog_accept_wan2lan\n", toip, internal_port);
#ifdef PORTMAPPING_2WAY_PASSTHROUGH
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -p tcp -m tcp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, internal_port);
#endif
         }else{
            fprintf(filter_fp, "-A wan2lan_forwarding_accept -p tcp -m tcp -d %s --dport %s -j xlog_accept_wan2lan\n", toip, external_port);
#ifdef PORTMAPPING_2WAY_PASSTHROUGH
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -p tcp -m tcp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, external_port);
#endif
         }

        }
      }
      if ((0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) &&  (privateIpCheck(toip)) )	
	  {
		 if (isNatReady) {
            fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
         }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
#if defined(IVI_KERNEL_SUPPORT)
             char udp_protocol[BUFLEN_8] = "010";
             int ret = 0;
             fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
             if (isBothProtocol == FALSE)
             {
#ifdef FEATURE_MAPT_DEBUG
                 LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %s -q %s -P %s ",
                         toip, external_port, external_port, udp_protocol);
#endif                
                 ret = v_secure_system("ivictl -p -a %s -p %s -q %s -P %s ",
                         toip, external_port, external_port, udp_protocol);
                 FIREWALL_DEBUG("ret val of v_secure_system %d\n",ret);
             }
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
             if (isBothProtocol == FALSE)
             {
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Single Port Forwarding --- UDP" );
#endif
                 fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
             }
#endif //IVI_KERNEL_SUPPORT
         }
#endif //FEATURE_MAPT
         if(isHairpin){
             if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
               #ifndef INTEL_PUMA7 
                if(strcmp(internal_port, "0")){
                    tmp = internal_port; 
                }else{
                    tmp = external_port;
                }
                //ARRISXB6-4723 - Below SNAT rule is causing access issues for LAN-wifi clients when port forwarding is enabled in XB6, hence the conditional check.
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, tmp, natip4);
                #endif
            }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
    else{ 
            if(isMAPTReady)
            {
                if(IsValidIPv4Addr(mapt_ip_address))
                {
                    fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_port, toip, port_modifier);
                }
            }
            if(strcmp(internal_port, "0")){
                tmp = internal_port; 
            }else{
                tmp = external_port;
            }

            if(IsValidIPv4Addr(mapt_ip_address))
            {
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, tmp, mapt_ip_address);
            }
        }
#endif
         }else if (!isNatRedirectionBlocked) {
            fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", lan_ipaddr, external_port, toip, port_modifier);

            if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s -j DNAT --to-destination %s%s\n", natip4, external_port, toip, port_modifier);
            }

            if(strcmp(internal_port, "0")){
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, internal_port, lan_ipaddr);
            }else{
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, external_port, lan_ipaddr);
            }
         }
         if (filter_fp) {
            if(strcmp(internal_port, "0")){
                fprintf(filter_fp, "-A wan2lan_forwarding_accept -p udp -m udp -d %s --dport %s -j xlog_accept_wan2lan\n", toip, internal_port);
#ifdef PORTMAPPING_2WAY_PASSTHROUGH
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -p udp -m udp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, internal_port);
#endif
         }else{
            fprintf(filter_fp, "-A wan2lan_forwarding_accept -p udp -m udp -d %s --dport %s -j xlog_accept_wan2lan\n",  toip, external_port);
#ifdef PORTMAPPING_2WAY_PASSTHROUGH
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -p udp -m udp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, external_port);
#endif
            }
         }
      }
#ifndef PORTMAPPING_2WAY_PASSTHROUGH
            if (filter_fp) {
                fprintf(filter_fp, "-A lan2wan_forwarding_accept -m conntrack --ctstate DNAT -j xlog_accept_lan2wan\n", toip, internal_port);
            }
#endif
   }
SinglePortForwardNext:
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
     if(isFeatureDisabled == TRUE)
     {
         FIREWALL_DEBUG("PortMapping:Feature Enable %d\n" COMMA FALSE);
     }
#endif
           FIREWALL_DEBUG("Exiting do_single_port_forwarding\n");       
   return(0);
}

/*
 *  Procedure     : do_port_range_forwarding
 *  Purpose       : prepare the iptables-restore statements for port range forwarding
 *  Parameters    : 
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
int do_port_range_forwarding(FILE *nat_fp, FILE *filter_fp, int iptype, FILE *filter_fp_v6)
{
   int idx;
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];
   int  rc;
   int count;
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   BOOL isBothProtocol = FALSE;
   BOOL isFeatureDisabled = TRUE;
#endif

#ifdef CISCO_CONFIG_TRUE_STATIC_IP 

   memset(PfRangeIP,0,sizeof(PfRangeIP));
#endif
   query[0] = '\0';
           FIREWALL_DEBUG("Entering do_port_range_forwarding\n");       
   rc = syscfg_get(NULL, "PortRangeForwardCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto PortRangeForwardNext;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto PortRangeForwardNext;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   FIREWALL_DEBUG("PortMapping:Feature Enable %d\n" COMMA TRUE);
   isFeatureDisabled = FALSE;
#endif

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "PortRangeForward_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Index %d\n" COMMA idx);
#endif

      // is the rule enabled
      query[0] = '\0';
      rc = syscfg_get(namespace, "enabled", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if ( (0 == strcmp("0", query)) || (0 == strcasecmp("false", query)) ) {
        continue;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
        FIREWALL_DEBUG("PortMapping:Feature %s\n" COMMA query);
#endif

      // what is the ip address to forward to
      char toip[40];
      toip[0] = '\0';
      char toipv6[64];
      toipv6[0] = '\0';
      char public_ip[40]; 
      public_ip[0] = '\0';

      /* seting IPv4 rule */
      if(iptype == AF_INET){ 
          rc = syscfg_get(namespace, "to_ip", toip, sizeof(toip));
          /* some time user only need IPv6 forwarding, in this case 255.255.255.255 will be set as toip. 
           * so we needn't do anything about those entry */
          if ( 0 != rc || '\0' == toip[0] || strcmp("255.255.255.255", toip) == 0 ) {
             continue;
          }
#ifdef CISCO_CONFIG_TRUE_STATIC_IP 
          strncpy(PfRangeIP[PfRangeCount],toip,MAX_IP4_SIZE-1);
          PfRangeCount++ ;
#endif
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
          FIREWALL_DEBUG("PortMapping:Internal Client IPv4 %s\n" COMMA toip);
#endif

          rc = syscfg_get(namespace, "public_ip", public_ip, sizeof(public_ip));
          /* In older version public ip field is not exist.
           * so if it get failed, keep doing the next step */ 
          if(0 == rc && '\0' != public_ip[0] ){
              // do one-2-one nat 
              if ((0 != strcmp("0.0.0.0", public_ip)) &&  ( privateIpCheck(toip) ))
			  {
/* if TRUE static IP not be configed , skip one 2 one nat */
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
                 if (isWanReady && isWanStaticIPReady) {
                    fprintf(nat_fp, "-A prerouting_fromwan -d %s -j DNAT --to-destination %s\n", public_ip, toip);
                    fprintf(nat_fp, "-A postrouting_towan -s %s -j SNAT --to-source %s\n", toip, public_ip);

		    #if defined(_BWG_PRODUCT_REQ_)
		    fprintf(stderr, "%s:1-to-1 NAT StaticIP =%s StaticNatCount =%d \n",__FUNCTION__, public_ip, StaticNatCount);
		    strncpy(StaticClientIP[StaticNatCount].ip, public_ip,sizeof(StaticClientIP[StaticNatCount].ip));
                    StaticNatCount++;
                    fprintf(stderr, "%s:1-to-1 NAT StaticIP =%s StaticNatCount =%d \n",__FUNCTION__, StaticClientIP[StaticNatCount-1].ip, StaticNatCount);
		    #endif

                    if (filter_fp) {
                        fprintf(filter_fp, "-A wan2lan_forwarding_accept  -d %s -j xlog_accept_wan2lan\n", toip);
                        /* one 2 one should work even nat disable */ 
                        if(!isNatReady){
                            fprintf(filter_fp, "-I lan2wan_disable -s %s -j xlog_accept_lan2wan\n", toip);
                            fprintf(filter_fp, "-I wan2lan_disabled -d %s -j xlog_accept_wan2lan\n", toip);
                        }

#ifdef PORTMAPPING_2WAY_PASSTHROUGH
                        fprintf(filter_fp, "-A lan2wan_forwarding_accept -s %s -j xlog_accept_lan2wan\n", toip);
#endif
                    }
                 }
#endif
                 continue;
              }
          }
      /* setting IPv6 rule */
      }else{
          rc = syscfg_get(namespace, "to_ipv6", toipv6, sizeof(toipv6));
          if (0 != rc || toipv6[0] == '\0' || strcmp("x", toipv6) == 0 || strcmp("0", toipv6) == 0) {
             continue;
          }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
          FIREWALL_DEBUG("PortMapping:Internal Client IPv6 %s\n" COMMA toipv6);
#endif
      }

      // what is the destination port for the protocol we are forwarding
      char sdport[10];
      char edport[10];
      char portrange[30];
      portrange[0]='\0';
      sdport[0] = '\0';
      edport[0] = '\0';
      rc = syscfg_get(namespace, "external_port_range", portrange, sizeof(portrange));
      if (0 != rc || '\0' == portrange[0]) {
         continue;
      } else {
         if (2 != sscanf(portrange, "%10s %10s", sdport, edport)) {
            continue;
         }
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:External Port Start Range %s\n" COMMA sdport);
      FIREWALL_DEBUG("PortMapping:External Port End Range %s\n" COMMA edport);
#endif

      // how long is the port range
      int s = atoi(sdport);
      int e = atoi(edport);
      int range= e-s;
      if (0 > range) {
         range=0;
      }

      // what is the forwarded destination port for the protocol
      char toport[10];
      int internal_port = 0;
      toport[0] = '\0';
      rc = syscfg_get(namespace, "internal_port", toport, sizeof(toport));
      if (0 == rc && '\0' != toport[0]) {
         internal_port = atoi(toport);
         if (internal_port < 0) internal_port = 0;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Internal Port %s\n" COMMA internal_port);
#endif

      // what is the last port of the destination range
      char rangesize[10] = "";
      int internal_port_range_size = 0;
      rc = syscfg_get(namespace, "internal_port_range_size", rangesize, sizeof(rangesize));
      if (0 == rc && '\0' != rangesize[0]) {
         internal_port_range_size = atoi(rangesize);
         if (internal_port_range_size < 0) internal_port_range_size = 0;
      }

#if defined(SPEED_BOOST_SUPPORTED)
      if(IsPortOverlapWithSpeedboostPortRange(atoi(sdport) , atoi(edport) , atoi(toport), atoi(toport)+ internal_port_range_size)) {
         FIREWALL_DEBUG("do_port_range_forwarding: Skip - overlapping with Speedboost port range \n" );
         continue;
      }
#endif

      // what is the forwarded protocol
      char prot[10];
      prot[0] = '\0';
      rc = syscfg_get(namespace, "protocol", prot, sizeof(prot));
      if (0 != rc || '\0' == prot[0]) {
         snprintf(prot, sizeof(prot), "%s", "both");
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortMapping:Protocol %s\n" COMMA prot);
#endif

      char target_internal_port[40] = "";
      char match_internal_port[40] = "";

      if (internal_port)
      {
         if (internal_port_range_size)
         {
            // range -> range, random port translation
            snprintf(match_internal_port, sizeof(match_internal_port), "%d:%d", internal_port, internal_port+internal_port_range_size);
            snprintf(target_internal_port, sizeof(target_internal_port), ":%d-%d", internal_port, internal_port+internal_port_range_size);
         }
         else
         {
            // range -> one port translation
            snprintf(match_internal_port, sizeof(match_internal_port), "%d", internal_port);
            snprintf(target_internal_port, sizeof(target_internal_port), ":%d", internal_port);
         }
      }
      else
      {
         // no port translation
         snprintf(match_internal_port, sizeof(match_internal_port), "%s:%s", sdport, edport);
      }

      //PortForwarding in IPv6 is to overwrite the Firewall wan2lan rules
      if(iptype == AF_INET6) {
          if (0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) {
              fprintf(filter_fp_v6, "-A wan2lan -p tcp -m tcp -d %s --dport %s:%s -j ACCEPT\n", toipv6, sdport, edport);
          }

          if (0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) {
              fprintf(filter_fp_v6, "-A wan2lan -p udp -m udp -d %s --dport %s:%s -j ACCEPT\n", toipv6, sdport, edport);
          }

          continue;
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isMAPTReady == TRUE)
      {
          if (0 == strcmp("both", prot))
          {
              isBothProtocol = TRUE;
          }

          if (isBothProtocol == TRUE)
          {
#if defined(IVI_KERNEL_SUPPORT)
              int both_protocol = 110;
              int index;
              int range = 0;
              int ret =0;
              range = atoi(edport) - atoi(sdport);
              for (index = 0; index <= range ; index++)
              {
#ifdef FEATURE_MAPT_DEBUG
                  LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %d -q %d -P %d ",
                          toip, atoi(sdport) + index, atoi(sdport) + index, both_protocol);
#endif
                  ret = v_secure_system("ivictl -p -a %s -p %d -q %d -P %d ",
                          toip, atoi(sdport) + index, atoi(sdport) + index, both_protocol);
                  
                  memset(cmdIvictlPf, 0, sizeof(cmdIvictlPf));
              }
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Range Port Forwarding --- BOTH" );
#endif
              fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
              fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
#endif //IVI_KERNEL_SUPPORT
          }
      }
#endif //FEATURE_MAPT
      
      
      if ((0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) && (privateIpCheck(toip)))
	  {
		 if (isNatReady) {
            fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
         }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
#if defined(IVI_KERNEL_SUPPORT)
            int tcp_protocol = 100;
            int index;
            int range = 0;
            int ret =0;
            fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
            if (isBothProtocol == FALSE)
            {
                    range = atoi(edport) - atoi(sdport);
                    for (index = 0; index <= range ; index++)
                    {
#ifdef FEATURE_MAPT_DEBUG
                        LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %d -q %d -P %d ",
                                toip, atoi(sdport) + index, atoi(sdport) + index, tcp_protocol);
#endif
                        ret = v_secure_system("ivictl -p -a %s -p %d -q %d -P %d ",
                                toip, atoi(sdport) + index, atoi(sdport) + index, tcp_protocol);
                        FIREWALL_DEBUG("ret val of v_secure_system %d\n",ret);
                    }
            }
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
            if (isBothProtocol == FALSE)
            {
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Range Port Forwarding --- TCP" );
#endif
              fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
            }
#endif //IVI_KERNEL_SUPPORT
         }
#endif //FEATURE_MAPT
         if(isHairpin){
             if (isNatReady) {
                fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
 
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, natip4);
            }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
             fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
             if (IsValidIPv4Addr(mapt_ip_address))
             {
                 fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, mapt_ip_address);
             }
         }
#endif 
         }else if (!isNatRedirectionBlocked) {
            fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", lan_ipaddr, sdport, edport, toip, target_internal_port);

            if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
            }

            fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, lan_ipaddr);
         }

         if (filter_fp) {
            fprintf(filter_fp, "-A wan2lan_forwarding_accept -p tcp -m tcp -d %s --dport %s -j xlog_accept_wan2lan\n", toip, match_internal_port);

#ifdef PORTMAPPING_2WAY_PASSTHROUGH
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -p tcp -m tcp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, match_internal_port);
#endif
         }
      }
      if ((0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) &&  (privateIpCheck(toip)) )
	  {
		 if (isNatReady) {
            fprintf(nat_fp,  "-A prerouting_fromwan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
         }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
#if defined(IVI_KERNEL_SUPPORT)              
            char udp_protocol[BUFLEN_8] = "010";
            int range = 0;
            int index;
            int ret =0;
            fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
              
            if (isBothProtocol == FALSE )
            {
                range = atoi(edport) - atoi(sdport); 
                for (index = 0; index <= range ; index++)
                {    
#ifdef FEATURE_MAPT_DEBUG
                    LOG_PRINT_MAIN("ivictl: ivictl -p -a %s -p %d -q %d -P %s",
                        toip, atoi(sdport) + index, atoi(sdport) + index, udp_protocol);
#endif
                    ret = v_secure_system("ivictl -p -a %s -p %d -q %d -P %s",
                        toip, atoi(sdport) + index, atoi(sdport) + index, udp_protocol);
                   FIREWALL_DEBUG("ret val of v_secure_system %d\n",ret);
                }
            }
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
            if (isBothProtocol == FALSE)
            {
#ifdef FEATURE_MAPT_DEBUG
              LOG_PRINT_MAIN("Enabling Range Port Forwarding --- UDP" );
#endif
              fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
            }
#endif //IVI_KERNEL_SUPPORT
         }
#endif //FEATURE_MAPT
         if(isHairpin){
             if (isNatReady) {
                fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
 
                fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, natip4);
            }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         if(isMAPTReady)
         {
             if (IsValidIPv4Addr(mapt_ip_address))
             {
                 fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", mapt_ip_address, sdport, edport, toip, target_internal_port);
            
                 fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, mapt_ip_address);
             }
         }
#endif
         }else if (!isNatRedirectionBlocked) {
            fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", lan_ipaddr, sdport, edport, toip, target_internal_port);

            if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s --dport %s:%s -j DNAT --to-destination %s%s\n", natip4, sdport, edport, toip, target_internal_port);
            }

            fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, match_internal_port, lan_ipaddr);
        }

        if(filter_fp){
            fprintf(filter_fp, "-A wan2lan_forwarding_accept -p udp -m udp -d %s --dport %s -j xlog_accept_wan2lan\n", toip, match_internal_port);

#ifdef PORTMAPPING_2WAY_PASSTHROUGH
         fprintf(filter_fp, "-A lan2wan_forwarding_accept -p udp -m udp -s %s --sport %s -j xlog_accept_lan2wan\n", toip, match_internal_port);
#endif
        }
      }
#ifndef PORTMAPPING_2WAY_PASSTHROUGH
    if(filter_fp) {
            fprintf(filter_fp, "-A lan2wan_forwarding_accept -m conntrack --ctstate DNAT -j xlog_accept_lan2wan\n", toip, internal_port);
    }
#endif

   }
PortRangeForwardNext:
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isFeatureDisabled == TRUE)
      {
          FIREWALL_DEBUG("PortMapping:Feature Enable %d\n" COMMA FALSE);
      }
#endif

         FIREWALL_DEBUG("Exiting do_port_range_forwarding\n");

   return(0);
}

/*
 *  Procedure     : do_wellknown_ports_forwarding
 *  Purpose       : prepare the iptables-restore statements for port forwarding based on
 *                  lookups to /etc/services
 *  Parameters    : 
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_wellknown_ports_forwarding(FILE *nat_fp, FILE *filter_fp)
{
   int idx;
   char *filename = wellknown_ports_file_dir"/"wellknown_ports_file;
   FILE *wkp_fp = NULL;
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];
   int  rc;

           FIREWALL_DEBUG("Entering do_wellknown_ports_forwarding\n");       
   wkp_fp = fopen(filename, "r");
   if (NULL == wkp_fp) {
      return(-1);
   }

   query[0] = '\0';
   int count;
   rc = syscfg_get(NULL, "WellKnownPortForwardCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto WellKnownPortForwardNext;
   } else {
      count = atoi(query);
      ulogf(ULOG_FIREWALL, UL_INFO, "\n @@@@@ WellKnownCount = %d \n", count);
      if (0 == count) {
         goto WellKnownPortForwardNext;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "WellKnownPortForward_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }
   
      // is the rule enabled
      query[0] = '\0';
      rc = syscfg_get(namespace, "enabled", query, sizeof(query));
      ulogf(ULOG_FIREWALL, UL_INFO, "\n @@@@@ WellKnown::Enabled = %d \n", atoi(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if (0 == strcmp("0", query)) {
        continue;
      }

      // what is the last octet of the ip address to forward to
      char toip[10];
      toip[0] = '\0';
      rc = syscfg_get(namespace, "to_ip", toip, sizeof(toip));
      ulogf(ULOG_FIREWALL, UL_INFO, "\n @@@@@ WellKnown::to_ip = %s \n", toip);
      if (0 != rc || '\0' == toip[0]) {
         continue;
      }
   
      // what is the name of the well known port
      char name[50];
      name[0] = '\0';
      rc = syscfg_get(namespace, "name", name, sizeof(name));
      if (0 != rc || '\0' == name[0]) {
         continue;
      } 

      // what is the forwarded destination port for the protocol
      char toport[10];
      toport[0] = '\0';
      syscfg_get(namespace, "internal_port", toport, sizeof(toport));
      ulogf(ULOG_FIREWALL, UL_INFO, "\n @@@@@ WellKnown::port = %s \n", toport);

      // what is the destination port for the protocol we are forwarding based on its name
      char *next_token;
      char *port_prot;
      char *port_val;
      char  line[MAX_QUERY];

      while (NULL != (next_token = match_keyword(wkp_fp, name, ' ', line, sizeof(line))) ) {
         char port_str[50];
         sscanf(next_token, "%50s ", port_str);
         port_val = port_str;
         port_prot = strchr(port_val, '/');
         if (NULL != port_prot) {
            *port_prot = '\0';
            port_prot++;
         } else {
            continue;
         }
         char port_modifier[11];
         if ('\0' == toport[0] || 0 == strcmp(toport, port_val) ) {
           port_modifier[0] = '\0';
         } else {
           snprintf(port_modifier, sizeof(port_modifier), ":%s", toport);
         }

		 if  (privateIpCheck(toip))
		 {
		 	if (isWanReady) {
	            fprintf(nat_fp, "-A prerouting_fromwan -p %s -m %s -d %s --dport %s -j DNAT --to-destination %s.%s%s\n", port_prot, port_prot, current_wan_ipaddr, port_val, lan_3_octets, toip, port_modifier);
    	     }

        	 if (!isNatRedirectionBlocked) {
        	    fprintf(nat_fp, "-A prerouting_fromlan -p %s -m %s -d %s --dport %s -j DNAT --to-destination %s.%s%s\n", port_prot, port_prot, lan_ipaddr, port_val, lan_3_octets, toip, port_modifier);

            	if (isWanReady) {
        	       fprintf(nat_fp, "-A prerouting_fromlan -p %s -m %s -d %s --dport %s -j DNAT --to-destination %s.%s%s\n", port_prot, port_prot, current_wan_ipaddr, port_val, lan_3_octets, toip, port_modifier);
            	}

        	    fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p %s -m %s -d %s.%s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, port_prot, port_prot, lan_3_octets, toip, '\0' == toport[0] ? port_val : toport, lan_ipaddr);
         	}

		    if(filter_fp) {
            	fprintf(filter_fp, "-A wan2lan_forwarding_accept -p %s -m %s -d %s.%s --dport %s -j xlog_accept_wan2lan\n", port_prot, port_prot, lan_3_octets, toip, '\0' == toport[0] ? port_val : toport);
         	}
		 }
      }
   }
WellKnownPortForwardNext:
   fclose(wkp_fp);
           FIREWALL_DEBUG("Exiting do_wellknown_ports_forwarding\n");       
   return(0);
}

/*
 *  Procedure     : do_ephemeral_port_forwarding
 *  Purpose       : prepare the iptables-restore statements for port forwarding statements
 *                  defined in sysevent
 *  Parameters    :
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */

static int do_ephemeral_port_forwarding(FILE *nat_fp, FILE *filter_fp)
{
   /*unsigned int iterator;*/
   char          name[MAX_QUERY];
   char          rule[MAX_QUERY];
   char          in_rule[MAX_QUERY];
   char          subst[MAX_QUERY];
           FIREWALL_DEBUG("Entering do_ephemeral_port_forwarding\n");       
//   iterator = SYSEVENT_NULL_ITERATOR;
   int count = 0,
   	   index = 1;
   char buf[128] = {0};
   char upnpEnabled[16] = {0};
   syscfg_get(NULL, "upnp_igd_enabled", upnpEnabled, sizeof(upnpEnabled));
   if (!atoi(upnpEnabled))
   {
        FIREWALL_DEBUG("Upnp is Disabled");
        return(0);
   }

   sysevent_get(sysevent_fd, sysevent_token, "portmap_dyn_count", buf, sizeof(buf));
   if (*buf) {
	   count = atoi(buf);
   }

   for( index = 1; index <= count; ++index ) 
   {
		name[0] = rule[0] = subst[0] = '\0';
		memset(in_rule, 0, sizeof(in_rule));
#if 0
      sysevent_get_unique(sysevent_fd, sysevent_token,
                          "portmap_dyn_pool", &iterator,
                          name, sizeof(name), in_rule, sizeof(in_rule));
#else
		snprintf(name, sizeof(name), "portmap_dyn_%d", index);
		sysevent_get(sysevent_fd, sysevent_token, name, in_rule, sizeof(in_rule));
#endif /* 0 */

      if ('\0' != in_rule[0]) {
         // the rule we have looks like enabled|disabled,external_ip,external_port,internal_ip,internal_port,protocol,...
         char *next;
         char *token = in_rule;
         if(token) { /*RDKB-7145, CID-33102, null check before use*/
            next = token_get(token, ',');
         }
         if (NULL == token || NULL == next || 0 == strcmp(token, "disabled")) {
            continue;
         }
         char *fromip;
         fromip = next;
         next = token_get(fromip, ',');
         if (NULL == fromip || NULL == next) {
            continue;
         }
         char *fromport;
         fromport = next;
         next = token_get(fromport, ',');
         if (NULL == fromport || NULL == next) {
            continue;
         }
         char *toip;
         toip = next;
         next = token_get(toip, ',');
         if (NULL == toip || NULL == next) {
            continue;
         }
         char *dport;
         dport = next;
         next = token_get(dport, ',');
         if (NULL == dport || NULL == next) {
            continue;
         }

#if defined(SPEED_BOOST_SUPPORTED)
         if(IsPortOverlapWithSpeedboostPortRange(atoi(fromport) , atoi(fromport) , atoi(dport) , atoi(dport))) {
            FIREWALL_DEBUG("do_ephemeral_port_forwarding: Skip - overlapping with Speedboost port range \n" );
            continue;
         }
#endif
         char *prot;
         prot = next;
         next = token_get(prot, ',');
         /* Logically dead code */
         // if (NULL == prot) {
         //    continue;
         // }

         char external_ip[50];
         char external_dest_port[50];
         external_ip[0] ='\0';
         external_dest_port[0] ='\0';
         if (0 != strcmp("none", fromip)) {
            snprintf(external_ip, sizeof(external_ip), "-s %s", fromip); 
         } 
         if (0 != strcmp("none", fromport)) {
            snprintf(external_dest_port, sizeof(external_dest_port), "--dport %s", fromport);
         } 

         char port_modifier[10];
         if ('\0' == dport[0] || 0 == strcmp(dport, fromport) || 0 == strcmp(dport, "0")) {
           port_modifier[0] = '\0';
         } else {
           snprintf(port_modifier, sizeof(port_modifier), ":%s", dport);
         }

         
         if ((0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) &&  (privateIpCheck(toip)) )
		 {
			if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s %s %s -j DNAT --to-destination %s%s\n", natip4, external_dest_port, external_ip, toip, port_modifier);
            }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
        if (isMAPTReady)
        {
           if (IsValidIPv4Addr(mapt_ip_address))
           {
               fprintf(nat_fp, "-A prerouting_fromwan -p tcp -m tcp -d %s %s %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_dest_port, external_ip, toip, port_modifier);
           }
        }
#endif
            if (!isNatRedirectionBlocked) {
               if (0 == strcmp("none", fromip)) {
                  fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s %s %s -j DNAT --to-destination %s%s\n", lan_ipaddr, external_dest_port, external_ip, toip, port_modifier);

                  if (isNatReady) {
                     fprintf(nat_fp, "-A prerouting_fromlan -p tcp -m tcp -d %s %s %s -j DNAT --to-destination %s%s\n", natip4, external_dest_port, external_ip, toip, port_modifier);
                  }

                  fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p tcp -m tcp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, dport, lan_ipaddr);
               }
            }

            if(filter_fp) {
                fprintf(filter_fp, "-A wan2lan_forwarding_accept -p tcp -m tcp %s -d %s --dport %s -j xlog_accept_wan2lan\n", external_ip, toip, dport);
            }
         }
         if ((0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) &&  (privateIpCheck(toip)) )
		 {
			if (isNatReady) {
               fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s %s %s -j DNAT --to-destination %s%s\n", natip4, external_dest_port, external_ip, toip, port_modifier);
            }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
        if (isMAPTReady)
        {
           if (IsValidIPv4Addr(mapt_ip_address))
           {
               fprintf(nat_fp, "-A prerouting_fromwan -p udp -m udp -d %s %s %s -j DNAT --to-destination %s%s\n", mapt_ip_address, external_dest_port, external_ip, toip, port_modifier);
           }
        }
#endif        
            if (!isNatRedirectionBlocked) {
               if (0 == strcmp("none", fromip)) {
                  fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s %s %s -j DNAT --to-destination %s%s\n", lan_ipaddr, external_dest_port, external_ip, toip, port_modifier);

                  if (isNatReady) {
                     fprintf(nat_fp, "-A prerouting_fromlan -p udp -m udp -d %s %s %s -j DNAT --to-destination %s%s\n", natip4, external_dest_port, external_ip, toip, port_modifier);
                  }

                  fprintf(nat_fp, "-A postrouting_tolan -s %s.0/%s -p udp -m udp -d %s --dport %s -j SNAT --to-source %s\n", lan_3_octets, lan_netmask, toip, dport, lan_ipaddr);
               }
            }

            if(filter_fp) {
                fprintf(filter_fp, "-A wan2lan_forwarding_accept -p udp -m udp %s -d %s --dport %s -j xlog_accept_wan2lan\n", external_ip, toip, dport);
            }
         }
      }
   }

  //while (SYSEVENT_NULL_ITERATOR != iterator);
           FIREWALL_DEBUG("Exiting do_ephemeral_port_forwarding\n");       
   return(0);
}

/*
 *  Procedure     : do_static_route_forwarding
 *  Purpose       : prepare the iptables-restore statements for port forwarding statements
 *                  to allow wan to reach static routes in lan
 *  Parameters    :
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_static_route_forwarding(FILE *filter_fp)
{
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];
   int  rc;
   int idx;
           FIREWALL_DEBUG("Entering do_static_route_forwarding\n");       
   query[0] = '\0';
   int count;
   rc = syscfg_get(NULL, "StaticRouteCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto StaticRouteForwardDone;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto StaticRouteForwardDone;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "StaticRoute_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      // is the rule for the lan interface
      query[0] = '\0';
      rc = syscfg_get(namespace, "interface", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if (0 != strcmp("lan", query)) {
        continue;
      }

      // extract the dest network
      char dest[MAX_QUERY];
      char netmask[MAX_QUERY];
      dest[0] = '\0';
      rc = syscfg_get(namespace, "dest", dest, sizeof(dest));
      if (0 != rc || '\0' == dest[0]) {
         continue;
      }
      netmask[0] = '\0';
      rc = syscfg_get(namespace, "netmask", netmask, sizeof(netmask));
      if (0 != rc || '\0' == netmask[0]) {
         continue;
      }

       fprintf(filter_fp, "-A wan2lan_forwarding_accept -d %s/%s -j xlog_accept_wan2lan\n", dest, netmask);
    }
StaticRouteForwardDone:
           FIREWALL_DEBUG("Exiting do_static_route_forwarding\n");       
   return(0);
}


/*
 *  Procedure     : do_port_forwarding
 *  Purpose       : prepare the iptables-restore statements for forwarding incoming packets to a lan host
 *  Parameters    : 
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 */
static int do_port_forwarding(FILE *nat_fp, FILE *filter_fp)
{

   /*
    * For each type of port forwarding (single_port, port_range etc) there are two distinct iptables rules:
    *   a PREROUTING DNAT rule
    *   an ACCEPT rule
    */
      //     FIREWALL_DEBUG("Entering do_port_forwarding\n"); 
   if(isBridgeMode)
   {
        FIREWALL_DEBUG("do_port_forwarding : Device is in bridge mode returning\n");  
        return(0);    
   
   }  
   
   WAN_FAILOVER_SUPPORT_CHECK
   do_single_port_forwarding(nat_fp, filter_fp, AF_INET, NULL);
   do_port_range_forwarding(nat_fp, filter_fp, AF_INET, NULL);
   do_wellknown_ports_forwarding(nat_fp, filter_fp);
   do_ephemeral_port_forwarding(nat_fp, filter_fp);
   if (filter_fp)
    do_static_route_forwarding(filter_fp);
   WAN_FAILOVER_SUPPORT_CHECk_END
  
        //   FIREWALL_DEBUG("Exiting do_port_forwarding\n");       
   return(0);
}

/*
 =================================================================
              No NAT
 =================================================================
 */
/*
 *  Procedure     : do_nonat
 *  Purpose       : prepare the iptables-restore statements for forwarding incoming packets to a lan hosts
 *  Parameters    :
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 */
static int do_nonat(FILE *filter_fp)
{

   if (isNatEnabled == NAT_DISABLE) {
      return(0);
   } 
           FIREWALL_DEBUG("Entering do_nonat\n");       
   if (strncasecmp(firewall_level, "High", strlen("High")) != 0)
   {
      // if we are not doing nat, restrict wan to lan traffic per security settings
      if (strncasecmp(firewall_level, "Medium", strlen("Medium")) == 0)
      {
         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 113 -j RETURN\n"); // IDENT

         fprintf(filter_fp, "-A wan2lan_nonat -p icmp --icmp-type 8 -j RETURN\n"); // ICMP PING

         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 1214 -j RETURN\n"); // Kazaa
         fprintf(filter_fp, "-A wan2lan_nonat -p udp --dport 1214 -j RETURN\n"); // Kazaa
         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 6881:6999 -j RETURN\n"); // Bittorrent
         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 6346 -j RETURN\n"); // Gnutella
         fprintf(filter_fp, "-A wan2lan_nonat -p udp --dport 6346 -j RETURN\n"); // Gnutella
         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 49152:65534 -j RETURN\n"); // Vuze
      }
      else if (strncasecmp(firewall_level, "Low", strlen("Low")) == 0)
      {
         fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 113 -j RETURN\n"); // IDENT
      }
      else
      {
         if (isHttpBlocked)
         {
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 80 -j RETURN\n"); // HTTP
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 443 -j RETURN\n"); // HTTPS
         }
         if (isIdentBlocked)
         {
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 113 -j RETURN\n"); // IDENT
         }
         if (isPingBlocked)
         {
            fprintf(filter_fp, "-A wan2lan_nonat -p icmp --icmp-type 8 -j RETURN\n"); // ICMP PING
         }
         if (isP2pBlocked)
         {
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 1214 -j RETURN\n"); // Kazaa
            fprintf(filter_fp, "-A wan2lan_nonat -p udp --dport 1214 -j RETURN\n"); // Kazaa
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 6881:6999 -j RETURN\n"); // Bittorrent
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 6346 -j RETURN\n"); // Gnutella
            fprintf(filter_fp, "-A wan2lan_nonat -p udp --dport 6346 -j RETURN\n"); // Gnutella
            fprintf(filter_fp, "-A wan2lan_nonat -p tcp --dport 49152:65534 -j RETURN\n"); // Vuze
         }
      }

      fprintf(filter_fp, "-A wan2lan_nonat -d %s/%s -j xlog_accept_wan2lan\n", lan_ipaddr, lan_netmask);
   }
           FIREWALL_DEBUG("Exiting do_nonat\n");       
   return(0);
}

/*
 =================================================================
              DMZ
 =================================================================
 */
/*
 *  Procedure     : do_dmz
 *  Purpose       : prepare the iptables-restore statements for forwarding incoming packets to a dmz lan host
 *  Parameters    : 
 *     nat_fp          : An open file for nat table writes
 *     filter_fp       : An open file for filter table writes
 *  Return Values :
 *     0               : done
 */
static int do_dmz(FILE *nat_fp, FILE *filter_fp)
{


   int rc;
   int  src_type = 0; // 0 is all networks, 1 is an ip[/netmask], 2 is ip range
           FIREWALL_DEBUG("Entering do_dmz\n");       
   if (!isDmzEnabled) {
      return(0);
   } 
 
   // what is the src ip address to forward to our dmz
   char src_str[64];
   src_str[0] = '\0';
   rc = syscfg_get(NULL, "dmz_src_addr_range", src_str, sizeof(src_str));
   if (0 != rc || '\0' == src_str[0]) {
      src_type = 0;
   } else {
      if (0 == strcmp("*", src_str)) {
          src_type = 0;
      } else if (strchr(src_str, '-')) {
         src_type = 2;
      } else {
         src_type = 1;
      }
   }

   // what is the dmz host 
   char tohost[50];
   tohost[0] = '\0';

   rc = syscfg_get(NULL, "dmz_dst_ip_addr", tohost, sizeof(tohost));
   if (0 != rc || '\0' == tohost[0]) {
      // there is no statement for a dmz host found by ip address
      // so check if there is a statement for dmz host found by mac address
      tohost[0] = '\0';
      char mac_addr[50];
      mac_addr[0] = '\0';
      rc = syscfg_get(NULL, "dmz_dst_mac_addr", mac_addr, sizeof(mac_addr));
      if (0 != rc || '\0' == mac_addr[0]) {
         return(0);
      } else {
         // look for the mac address in the dnsmasq file
         FILE *fp2 = fopen("/etc/dnsmasq.leases","r");
         if (NULL != fp2) {
            char line[512];
            while (NULL != fgets(line, sizeof(line), fp2)) {
               if (NULL != strcasestr(line, mac_addr)) {
                  char field1[50];
                  char field2[50];
                  char field3[50];
                  char field4[50];
                  char field5[50];
                  sscanf(line, "%50s %50s %50s %50s %50s", field1, field2, field3, field4, field5);
                  // ip address is in field 3
                  // extract last octet of ip addr
                  char *idx = strrchr(field3, '.');
                  if (NULL != idx) {
                     snprintf(tohost, sizeof(tohost), "%s", idx+1);
                  }
               }
            }
            fclose(fp2);
         }

         if ('\0' == tohost[0]) {
            // we couldnt find the host in the dhcp server file, so try the discovered hosts file
            FILE *kh_fp = fopen(lan_hosts_dir"/"hosts_filename, "r");
            char buf[1024];
            if (NULL != kh_fp) {
                while (NULL != fgets(buf, sizeof(buf), kh_fp)) {
                   char ip[50];
                   char mac[50];
                   sscanf(buf, "%50s %50s", ip, mac);
                   if (0 == strcasecmp(mac, mac_addr)) {
                      // extract last octet of ip address
                      char *idx = strrchr(ip, '.');
                      if (NULL != idx) {
                         snprintf(tohost, sizeof(tohost), "%s", idx+1);
                      }
                     break;
                   }
                }
                fclose(kh_fp);
             }
         }

         if ('\0' == tohost[0]) {
            return(0);
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
         } else {
            isTriggerMonitorRestartNeeded = 1;
#endif
         }
      }
   }

   if ('\0' == tohost[0]) {
      return(0);
   }
      
   char dst_str[100];
   int status_http, status_http_ert, status_https;
   char Httpport[20],Httpsport[20], tmphttpQuery[20];
   Httpport[0] = '\0';
   Httpsport[0] = '\0';

   status_http = syscfg_get(NULL, "mgmt_wan_httpport", Httpport, sizeof(Httpport));
   #if defined(CONFIG_CCSP_WAN_MGMT_PORT)
   tmphttpQuery[0] = '\0';
   status_http_ert = syscfg_get(NULL, "mgmt_wan_httpport_ert", tmphttpQuery, sizeof(tmphttpQuery));
if(status_http_ert == 0){
       errno_t safec_rc = strcpy_s(Httpport, sizeof(Httpport),tmphttpQuery);
       ERR_CHK(safec_rc);
   }
   #endif

   if (0 != status_http || '\0' == Httpport[0]) {
            snprintf(Httpport, sizeof(Httpport), "%d", 8080);
   }

   status_https = syscfg_get(NULL, "mgmt_wan_httpsport", Httpsport, sizeof(Httpsport));
   if (0 != status_https || '\0' == Httpsport[0]) {
            snprintf(Httpsport, sizeof(Httpsport), "%d", 8181);
   }

   //snprintf(dst_str, sizeof(dst_str), "--to-destination %s.%s ", lan_3_octets, tohost);
   /* tohost is now a full ip address */
   snprintf(dst_str, sizeof(dst_str), "--to-destination %s ", tohost);

   switch (src_type) {
      case(0):
         if (isNatReady &&
             strcmp(tohost, "0.0.0.0") != 0) { /* 0.0.0.0 stands for disable in SA-RG-MIB */
#if defined(SPEED_BOOST_SUPPORTED)
   if (speedboostports[0] != '\0' && (isPvDEnable)) {
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p tcp -m multiport ! --dports %s,%s,%s -j DNAT %s\n", natip4, Httpport, Httpsport, speedboostports, dst_str);

            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p udp -m multiport ! --dports %s,%s,%s -j DNAT %s\n", natip4, Httpport, Httpsport, speedboostports, dst_str);
   }
   else
   {
#endif
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p tcp -m multiport ! --dports %s,%s -j DNAT %s\n", natip4, Httpport, Httpsport, dst_str);
            
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p udp -m multiport ! --dports %s,%s -j DNAT %s\n", natip4, Httpport, Httpsport, dst_str);
#if defined(SPEED_BOOST_SUPPORTED)
   }
#endif
#ifdef _ICMP_ON_DMZ_HOST_
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p icmp  -j DNAT %s\n", natip4, dst_str);
#endif
         }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         else
         {
             /*  Check mapt config flag is SET*/
             if (isMAPTReady  == TRUE)
             {
                 if (IsValidIPv4Addr(mapt_ip_address))
                 {
#ifdef FEATURE_MAPT_DEBUG
                     LOG_PRINT_MAIN("Enabling DMZ(All) --- BOTH" );
#endif
                     fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p tcp -m multiport ! --dports %s,%s -j DNAT %s\n", mapt_ip_address, Httpport, Httpsport, dst_str);
 
                     fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -p udp -m multiport ! --dports %s,%s -j DNAT %s\n", mapt_ip_address, Httpport, Httpsport, dst_str);
                 }
             }
         }
#endif
         /*snprintf(str, sizeof(str),
                  "-A wan2lan_dmz -d %s.%s -j xlog_accept_wan2lan", lan_3_octets, tohost);*/
         fprintf(filter_fp, "-A wan2lan_dmz -d %s -j xlog_accept_wan2lan\n", tohost);
         fprintf(filter_fp, "-A lan2wan_dmz_accept -s %s -j xlog_accept_wan2lan\n", tohost);

         break;
      case(1):
         if (isNatReady) {
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --src %s --dst %s -j DNAT %s\n", src_str, natip4, dst_str);
         }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         else
         {
             /*  Check mapt config flag is SET*/
             if (isMAPTReady  == TRUE)
             {
                 if (IsValidIPv4Addr(mapt_ip_address))
                 {
#ifdef FEATURE_MAPT_DEBUG
                     LOG_PRINT_MAIN("Enabling DMZ --- IP" );
#endif
                     fprintf(nat_fp, "-A prerouting_fromwan_todmz --src %s --dst %s -j DNAT %s\n", src_str, mapt_ip_address, dst_str);
                 }
             }
         }
#endif
         /*snprintf(str, sizeof(str),
                  "-A wan2lan_dmz -s %s -d %s.%s -j xlog_accept_wan2lan", src_str, lan_3_octets, tohost);*/
         fprintf(filter_fp, "-A wan2lan_dmz -s %s -d %s -j xlog_accept_wan2lan\n", src_str, tohost);
#ifdef PORTMAPPING_2WAY_PASSTHROUGH
         fprintf(filter_fp, "-A lan2wan_dmz_accept -d %s -s %s -j xlog_accept_lan2wan\n", src_str, tohost);
#endif
         break;
      case(2):
         if (isNatReady) {
            fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -m iprange --src-range %s -j DNAT %s\n", natip4, src_str,  dst_str);
         }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
         else
         {
             /*  Check mapt config flag is SET*/
             if (isMAPTReady  == TRUE)
             {
                 if (IsValidIPv4Addr(mapt_ip_address))
                 {
#ifdef FEATURE_MAPT_DEBUG
                     LOG_PRINT_MAIN("Enabling DMZ --- Range" );
#endif
                     fprintf(nat_fp, "-A prerouting_fromwan_todmz --dst %s -m iprange --src-range %s -j DNAT %s\n", mapt_ip_address, src_str,  dst_str);
                 }
             }
         }
#endif
 
         /*snprintf(str, sizeof(str),
                  "-A wan2lan_dmz -m iprange --src-range %s -d %s.%s -j xlog_accept_wan2lan", src_str, lan_3_octets, tohost);*/
         fprintf(filter_fp, "-A wan2lan_dmz -m iprange --src-range %s -d %s -j xlog_accept_wan2lan\n", src_str, tohost);

#ifdef PORTMAPPING_2WAY_PASSTHROUGH
         fprintf(filter_fp, "-A lan2wan_dmz_accept -m iprange --dst-range %s -s %s -j xlog_accept_lan2wan\n", src_str, tohost);
#endif
         break;
      default:
         break;
   }
           FIREWALL_DEBUG("Exiting do_dmz\n");       
   return(0);
}

/*
 =================================================================
              QoS
 =================================================================
 */

/*
 *  Procedure     : write_qos_classification_statement
 *  Purpose       : prepare the iptables-restore statements with all qos marking rules for a particular
 *                  protocol as known in the file known as qos_fp.
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *     qos_fp          : An open file containing qos rules in the format
 *                         rule name | friendly name | type | match | iptables hook 
 *                            where type is application | game
 *                       eg.  name | Name Protocol | application | -p tcp -m tcp --dport 22 | PREROUTING |
 *     name            : name of the qos rule.  
 *     class           : DSCP class to mark packets fitting the rule
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 *  Note          : prerouting statements will be put in the mangle table, prerouting_qos subtable
 *  Note          : postrouting statements will be put in the mangle table, postrouting_qos subtable
 *
 */
static int write_qos_classification_statement (FILE *fp, FILE *qos_fp, char *name, char *class)
{
   rewind(qos_fp);
   char line[512];
   char *next_token;
   errno_t safec_rc = -1;
           FIREWALL_DEBUG("Entering write_qos_classification_statement\n");       
   while (NULL != (next_token = match_keyword(qos_fp, name, '|', line, sizeof(line))) ) {

      char *friendly_name = next_token;
      next_token = token_get(friendly_name, '|');
      if (NULL == next_token || NULL == friendly_name) {
         continue;
      }

      char *type = next_token;
      next_token = token_get(type, '|');
      if (NULL == next_token || NULL == type) {
         continue;
      }

      char *match = next_token;
      next_token = token_get(match, '|');
      /* Logically dead code*/
      // if (NULL == match) {
      //    continue;
      // }

      char *hook = next_token;
      char subst_hook[MAX_QUERY];
      if(hook){ /*RDKB-7145, CID-33153, null check before use*/
         next_token = token_get(hook, '|');
      }
      if (NULL == next_token || NULL == hook) {
         continue;
      } else {
         if (0 == strcasestr(hook, "PREROUTING")) {
           safec_rc = strcpy_s(subst_hook, sizeof(subst_hook),"prerouting_qos");
           ERR_CHK(safec_rc);
         } else if (0 == strcasestr(hook, "POSTROUTING") ) {
            safec_rc = strcpy_s(subst_hook, sizeof(subst_hook),"postrouting_qos");
            ERR_CHK(safec_rc);
         } else {
            continue;
         }
      } 

      char subst[MAX_QUERY];
      char subst2[MAX_QUERY];
      fprintf(fp, "-A %s %s -j DSCP --set-dscp-class %s\n", subst_hook, make_substitutions(match,subst,sizeof(subst)), make_substitutions(class, subst2,sizeof(subst2)));
   }
           FIREWALL_DEBUG("Exiting write_qos_classification_statement\n");       
   return(0); 
}

/*
 *  Procedure     : add_qos_marking_statements
 *  Purpose       : prepare the iptables-restore statements for marking packets with DSCP
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int add_qos_marking_statements(FILE *fp)
{
   if (NULL == fp) {
      return(-1);
   }
   char *filename;
   FILE *qos_fp;
   int rc;
   char query[MAX_QUERY];
           FIREWALL_DEBUG("Entering add_qos_marking_statements\n");       
   // is the qos enabled
   query[0] = '\0';
   rc = syscfg_get(NULL, "qos_enable", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      return(0);
   } else if (0 == strcmp("0", query)) {
      return(0);
   }
   int count;

   query[0] = '\0';
   rc = syscfg_get(NULL, "QoSPolicyCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto QoSUserDefinedPolicies;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto QoSUserDefinedPolicies;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   /* 
    * syscfg tuple QoSPolicy_x, where x is a digit
    * We iterate through these tuples until we dont find an instance in syscfg.
    */
   int idx;
   char namespace[MAX_NAMESPACE];

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "QoSPolicy_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      char rule[MAX_QUERY];
      int i;
      for (i=1; i<MAX_SYSCFG_ENTRIES ; i++) {
         snprintf(query, sizeof(query), "qos_rule_%d", i);
         rc = syscfg_get(namespace, query, rule, sizeof(rule));
         if (0 != rc || '\0' == rule[0]) {
            break;
         } else {
            char subst[MAX_QUERY];
            char str[MAX_QUERY];
            if (NULL != make_substitutions(rule, subst, sizeof(subst))) {
               if (1 == substitute(subst, str, sizeof(str), "PREROUTING", "prerouting_qos") ||
                  (1 == substitute(subst, str, sizeof(str), "POSTROUTING", "postrouting_qos")) ) {
                  fprintf(fp, "%s\n", str);
               }
            }
         }
      }
   }

QoSUserDefinedPolicies:
   query[0] = '\0';
   rc = syscfg_get(NULL, "QoSUserDefinedPolicyCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto QoSDefinedPolicies;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto QoSDefinedPolicies;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "QoSUserDefinedPolicy_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      char prot[10];
      int  proto;
      char portrange[30];
      char sdport[10];
      char edport[10];
      int i;
      for (i=1; i<MAX_SYSCFG_ENTRIES ; i++) {
         proto = 0; // 0 is both, 1 is tcp, 2 is udp
         snprintf(query, sizeof(query), "protocol_%d", i);
         rc = syscfg_get(namespace, query, prot, sizeof(prot));
         if (0 != rc || '\0' == prot[0]) {
            proto = 0;
         } else if (0 == strcmp("tcp", prot)) {
            proto = 1;
         } else   if (0 == strcmp("udp", prot)) {
            proto = 2;
         }

         portrange[0]= '\0';
         sdport[0]   = '\0';
         edport[0]   = '\0';
         snprintf(query, sizeof(query), "port_range_%d", i);
         rc = syscfg_get(namespace, query, portrange, sizeof(portrange));
         if (0 != rc || '\0' == portrange[0]) {
            break;
         } else {
            int r = 0;
            if (2 != (r = sscanf(portrange, "%10s %10s", sdport, edport))) {
               if (1 == r) {
                  snprintf(edport, sizeof(edport), "%s", sdport);
               } else {
                  break;
               }
            }
         }

         char class[MAX_QUERY];
         class[0] = '\0';
         snprintf(query, sizeof(query), "class_%d", i);
         rc = syscfg_get(namespace, query, class, sizeof(class));
         if (0 != rc || '\0' == class[0]) {
            break;
         }

         char rule[350];
         char subst[MAX_QUERY];
         if (0 == proto || 1 == proto) {
            snprintf(rule, sizeof(rule), "-A prerouting_qos -p tcp -m tcp --dport %s:%s -j DSCP --set-dscp-class %s", sdport, edport, class);
            fprintf(fp, "%s\n", make_substitutions(rule, subst, sizeof(subst)));
         }
         if (0 == proto || 2 == proto) {
            snprintf(rule, sizeof(rule), "-A prerouting_qos -p udp -m udp --dport %s:%s -j DSCP --set-dscp-class %s", sdport, edport, class);
            fprintf(fp, "%s\n", make_substitutions(rule, subst, sizeof(subst)));
         }
      }
   }

QoSDefinedPolicies:
   /*
    * syscfg tuple QoSDefinedPolicy_x, where x is a digit
    * keeps track of the names of policies which are defined
    * in an external file with format
    *    name | user friendly name | type | iptables hook | match criterea |
    *  eg foo | Foo Tool and Game | game | PREROUTING | -p tcp --destination-port 666 |
    */
   query[0] = '\0';
   rc = syscfg_get(NULL, "QoSDefinedPolicyCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto QoSMacAddrs;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto QoSMacAddrs;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }
   filename = qos_classification_file_dir"/"qos_classification_file;
   qos_fp = fopen(filename, "r"); 
   if (NULL != qos_fp) {
      for (idx=1 ; idx<=count ; idx++) {
         namespace[0] = '\0';
         snprintf(query, sizeof(query), "QoSDefinedPolicy_%d", idx);
         rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
         if (0 != rc || '\0' == namespace[0]) {
           continue; 
         }

         char name[MAX_QUERY];
         char class[MAX_QUERY];
      
         name[0] = '\0';
         class[0] = '\0';
         rc = syscfg_get(namespace, "name", name, sizeof(name));
         if (0 != rc || '\0' == name[0]) {
            break;
         } else {
            rc = syscfg_get(namespace, "class", class, sizeof(class));
            if (0 != rc || '\0' == class[0]) {
               break;
            } else {
               char subst[MAX_QUERY];
               write_qos_classification_statement(fp, qos_fp, name, make_substitutions(class, subst, sizeof(subst))); 
           }
         }
      }
      fclose(qos_fp);
   }

QoSMacAddrs:
   query[0] = '\0';
   rc = syscfg_get(NULL, "QoSMacAddrCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto QoSVoiceDevices;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto QoSVoiceDevices;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "QoSMacAddr_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      char mac[MAX_QUERY];
      char class[MAX_QUERY];
      mac[0]   = '\0';
      class[0] = '\0';
      rc = syscfg_get(namespace, "mac", mac, sizeof(mac));
      if (0 != rc || '\0' == mac[0]) {
         break;
      } else {
         rc = syscfg_get(namespace, "class", class, sizeof(class));
         if (0 != rc || '\0' == class[0]) {
            break;
         } else {
            char subst[MAX_QUERY];
            fprintf(fp, "-A prerouting_qos -m mac --mac-source %s -j DSCP --set-dscp-class %s\n", mac, make_substitutions(class, subst, sizeof(subst)));
        }
      }
   }

QoSVoiceDevices:
   query[0] = '\0';
   rc = syscfg_get(NULL, "QoSVoiceDeviceCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto QoSDone;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto QoSDone;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "QoSVoiceDevice_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      char mac[MAX_QUERY];
      char class[MAX_QUERY];
      mac[0]   = '\0';
      class[0] = '\0';
      rc = syscfg_get(namespace, "mac", mac, sizeof(mac));
      if (0 != rc || '\0' == mac[0]) {
         break;
      } else {
         rc = syscfg_get(namespace, "class", class, sizeof(class));
         if (0 != rc || '\0' == class[0]) {
            break;
         } else {
            char subst[MAX_QUERY];
            fprintf(fp, "-A prerouting_qos -m mac --mac-source %s -j DSCP --set-dscp-class %s\n", mac, make_substitutions(class, subst, sizeof(subst)));
        }
      }
   }

QoSDone:
           FIREWALL_DEBUG("Exiting add_qos_marking_statements\n");       
   return(0);
}

/*
 =================================================================
            Misc Postrouting NAT 
 =================================================================
 */

/*
 *  Procedure     : do_nat_ephemeral
 *  Purpose       : prepare the iptables-restore statements for nat statements gleaned from the sysevent
 *                  NatFirewallRule pool
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 *  Notes         : These rules will be placed into the iptables nat table, and use target
 *                     prerouting_ephemeral for PREROUTING statements, or
 *                     postrouting_ephemeral for POSTROUTING statements
 */
static int do_nat_ephemeral(FILE *fp)
{

   unsigned  int iterator;
   char      name[MAX_QUERY];
   char      in_rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   char      str[MAX_QUERY];
           FIREWALL_DEBUG("Entering do_nat_ephemeral\n");       
   iterator = SYSEVENT_NULL_ITERATOR;
   do {
      name[0] = subst[0] = '\0';
      memset(in_rule, 0, sizeof(in_rule));
      sysevent_get_unique(sysevent_fd, sysevent_token,
                          "NatFirewallRule", &iterator,
                          name, sizeof(name), in_rule, sizeof(in_rule));
      if ('\0' != in_rule[0]) {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
        if (NULL != make_substitutions(in_rule, subst, sizeof(subst))) {
           if (1 == substitute(subst, str, sizeof(str), "PREROUTING", "prerouting_ephemeral") ||
              (1 == substitute(subst, str, sizeof(str), "POSTROUTING", "postrouting_ephemeral")) ) {
              fprintf(fp, "%s\n", str);
           }
        }
      }
   } while (SYSEVENT_NULL_ITERATOR != iterator);
           FIREWALL_DEBUG("Exiting do_nat_ephemeral\n");       
   return(0);
}

#if defined(_BWG_PRODUCT_REQ_)
/*
 *  Procedure     : do_raw_table_staticip
 *  Purpose       : prepare the iptables for static IP clients dont track in raw tables
 *  Parameters    :
 *     fp              : An open file that will be used for iptables
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_raw_table_staticip(FILE *raw_fp)
{
   int i=0;
   isRawTableUsed = 1;
   FIREWALL_DEBUG("Entering do_raw_table_staticip...!\n");

   if(isWanStaticIPReady){
   	/*
    	* Keep the conntrack for any NAT.
    	* NAT relies on conntrack to built up, all the inbound traffic towards
    	* internel spot needs records there for translation.
    	*/
	if (((0 < StaticIPSubnetNum) && (isNatEnabled == 1)) || ((0 < StaticIPSubnetNum) && (isNatEnabled == 2))){
	if ((0 != strcmp("0.0.0.0", natip4)) || (0 != strcmp("", natip4)))
	{
       	   fprintf(raw_fp, "-A PREROUTING -d %s -j ACCEPT \n ", natip4);
	}
	}

	/*1-to-1 NAT configurations */
	fprintf(stderr, "do_raw_table_staticip: 1-to-1 NAT Configured Static IP= %s StaticNatCount=%d ...!!\n",StaticClientIP[0].ip,StaticNatCount);
	for(i = 0; i < StaticNatCount ;i++ ){
	fprintf(stderr, "do_raw_table_staticip: 1-to-1 NAT Configured Static IP= %s ...!!\n",StaticClientIP[i].ip);
	if ((0 != strcmp("0.0.0.0", StaticClientIP[i].ip)) || (0 != strcmp("", StaticClientIP[i].ip)))
	{
           fprintf(stderr, "do_raw_table_staticip: 1-to-1 NAT Configured Static IP= %s ...!!\n",StaticClientIP[i].ip);
           fprintf(raw_fp, "-A PREROUTING -d %s -j ACCEPT \n ", StaticClientIP[i].ip);
           fprintf(stderr, "do_raw_table_staticip: 1-to-1 NAT Config rule = -A PREROUTING -d %s -j ACCEPT  ...!!\n",StaticClientIP[i].ip);
	}
 	}
	//Set the NO track rules in raw table for STATIC IP clients
	for(i = 0; i < StaticIPSubnetNum ;i++ ){
	if ((0 != strcmp("0.0.0.0", StaticIPSubnet[i].mask)) || (0 != strcmp("", StaticIPSubnet[i].mask)))
	{
	   fprintf(raw_fp, "-A PREROUTING -d %s/%s -j CT --notrack \n ", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);
	   /*fprintf(raw_fp, "-A PREROUTING -s %s/%s -j CT --notrack \n ", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);*/
	}
	}
   }
   FIREWALL_DEBUG("Exist do_raw_table_staticip...!!\n");
   return 0;
}
#endif

/*
 *  Procedure     : do_wan_nat_lan_clients
 *  Purpose       : prepare the iptables-restore statements for natting the outgoing packets from lan
 *                  to the filter table 
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_wan_nat_lan_clients(FILE *fp)
{
   if (!isNatReady) {
      return(0);
   }

   FIREWALL_DEBUG("Entering do_wan_nat_lan_clients\n");

#ifdef CISCO_CONFIG_TRUE_STATIC_IP
  //do not do SNAT on public ip
  int i;
  for(i = 0; i < StaticIPSubnetNum ;i++ ){
    fprintf(fp, "-A postrouting_towan -s %s/%s -j RETURN\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);
  }
  //do not do SNAT if packet is come from erouter0
  fprintf(fp, "-A postrouting_towan -s %s -j RETURN\n", current_wan_ipaddr); 
#endif 
#if defined(_ENABLE_EPON_SUPPORT_)
  if (isBridgeMode) {// Dont NAT network devices that are part of erouter0    
    DIR * dirp = opendir("/sys/devices/virtual/net/erouter0/brif");
    if (dirp) {
      struct dirent * dp = NULL;
      while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, "pon0") == 0 ||
            strcmp(dp->d_name, "..") == 0 ||
            strcmp(dp->d_name, ".") == 0) {
          continue;
        }
        fprintf(fp, "-A postrouting_towan -m physdev --physdev-in %s -j RETURN\n", dp->d_name);
        fprintf(fp, "-A postrouting_towan -m physdev --physdev-out %s -j RETURN\n", dp->d_name);
      }
      closedir(dirp);
    }
  }
#endif

#if (defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)) && !defined (_HUB4_PRODUCT_REQ_)
  if(bEthWANEnable || isBridgeMode) // Check is required for TCHXB6 TCHXB7 CBR and not for HUB4
#else
  if(bEthWANEnable)
#endif
  {/*fix RDKB-21704, SNAT is required only for private IP ranges. */
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
  if (!isMAPTReady)
#endif //FEATURE_MAPT
     if(!IS_EMPTY_STRING(natip4))
     {
         fprintf(fp, "-A postrouting_towan -s 10.0.0.0/8 -j SNAT --to-source %s\n", natip4);
         fprintf(fp, "-A postrouting_towan -s 192.168.0.0/16 -j SNAT --to-source %s\n", natip4);
         fprintf(fp, "-A postrouting_towan -s 172.16.0.0/12 -j SNAT --to-source %s\n", natip4);

         if (FALSE == bAmenityEnabled)
         {
            #if defined (WIFI_MANAGE_SUPPORTED)
            #define BUFF_LEN_64 64
            #define BUFF_LEN_32 32

            if (true == isManageWiFiEnabled())
            {
               char aParamName[BUFF_LEN_64];
               char aParamVal[BUFF_LEN_32];
               char aV4Addr[BUFF_LEN_32];

               psmGet(bus_handle, MANAGE_WIFI_PSM_STR, aParamVal, sizeof(aParamVal));
               if ('\0' != aParamVal[0])
               {
                  snprintf(aParamName, sizeof(aParamName), MANAGE_WIFI_V4_ADDR, aParamVal);
                  psmGet(bus_handle,aParamName, aV4Addr, sizeof(aV4Addr));
                  if ('\0' != aV4Addr[0])
                  {
                     snprintf(aParamName, sizeof(aParamName), "%s/24", aV4Addr);
                     fprintf(fp, "-A postrouting_towan -s %s -j SNAT --to-source %s\n", aParamName, natip4);
                  }
               }
            }
            #endif /*WIFI_MANAGE_SUPPORTED*/
         }
     }
  }
  else
  {
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
     if (!isMAPTReady)
     {
#endif
      #ifdef RDKB_EXTENDER_ENABLED
         fprintf(fp, "-A postrouting_towan -j MASQUERADE\n");
      #else
	     fprintf(fp, "-A postrouting_towan  -j SNAT --to-source %s\n", natip4);
      #endif
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
     }
#endif
  }

  // fprintf(fp, "%s\n", str);
  
   if (isCacheActive) {
      fprintf(fp, "-A PREROUTING -i %s -p tcp --dport 80 -j DNAT --to %s:%s\n", lan_ifname, lan_ipaddr, "3128");
   }
           FIREWALL_DEBUG("Exiting do_wan_nat_lan_clients\n");       
   return(0);
}

#if defined (MULTILAN_FEATURE)
 /*
 *  Procedure     : do_multinet_lan2self_attack
 *  Purpose       : prepare rules for ipv4 firewall to prevent attacks
 *                  from LAN addresses associated with multinet LANs
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int do_multinet_lan2self_attack (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(filter_fp, "-A lanattack -s %s -d %s -j xlog_drop_lanattack\n", net_resp, net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif

/*
 ==========================================================================
                     lan2self
 ==========================================================================
 */
/*
 *  Procedure     : do_lan2self_attack
 *  Purpose       : detect attacks from the lan side
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
static int do_lan2self_attack(FILE *fp)
{
   /* LAND ATTACK */
// TODO: Add for each lan ip
           FIREWALL_DEBUG("Entering do_lan2self_attack\n");       
   fprintf(fp, "-A lanattack -s %s -d %s -j xlog_drop_lanattack\n", lan_ipaddr, lan_ipaddr);

#if defined (MULTILAN_FEATURE)
   do_multinet_lan2self_attack(fp);
#endif

   fprintf(fp, "-A lanattack -s 127.0.0.1 -j xlog_drop_lanattack\n");

   fprintf(fp, "-A lanattack -d 127.0.0.1 -j xlog_drop_lanattack\n");
           FIREWALL_DEBUG("Exiting do_lan2self_attack\n");       
   return(0);
}

/*
 * enable / disable telnet and ssh from lan side
 */
int lan_telnet_ssh(FILE *fp, int family)
{
   int rc;
   char query[MAX_QUERY];
   query[0] = '\0';
           FIREWALL_DEBUG("Entering lan_telnet_ssh\n");     
   //telnet access control for lan side
   memset(query, 0, MAX_QUERY);
   rc = syscfg_get(NULL, "mgmt_lan_telnetaccess", query, sizeof(query));
   if (rc != 0 || (rc == 0 && '\0' != query[0] && 0 == strncmp(query, "0", sizeof(query))) ) {

       if(family == AF_INET6) {
           if(!isBridgeMode) //brlan0 exists
               fprintf(fp, "-A %s -i %s -p tcp --dport 23 -j DROP\n", "INPUT", lan_ifname);

           fprintf(fp, "-A %s -i %s -p tcp --dport 23 -j DROP\n", "INPUT", cmdiag_ifname); //lan0 always exist
       }
       else {
           fprintf(fp, "-A %s -p tcp --dport 23 -j DROP\n", "lan2self_mgmt");
       }

   }
   else if(family == AF_INET && isFirewallEnabled && !isBridgeMode && isWanServiceReady){ //only valid in router mode when wan is ready
       fprintf(fp, "-I %s -i %s -p tcp --dport 23 -j ACCEPT\n", "general_input", cmdiag_ifname);
   }

   //ssh access control for lan side
   memset(query, 0, MAX_QUERY);
   rc = syscfg_get(NULL, "mgmt_lan_sshaccess", query, sizeof(query));
   if (rc != 0 || (rc == 0 && '\0' != query[0] && 0 == strncmp(query, "0", sizeof(query))) ) {

       if(family == AF_INET6) {
           if(!isBridgeMode) //brlan0 exists
               fprintf(fp, "-A %s -i %s -p tcp --dport 22 -j DROP\n", "INPUT", lan_ifname);

           fprintf(fp, "-A %s -i %s -p tcp --dport 22 -j DROP\n", "INPUT", cmdiag_ifname); //lan0 always exist
       }
       else {
           fprintf(fp, "-A %s -p tcp --dport 22 -j DROP\n", "lan2self_mgmt");
       }
   }
#ifdef _HUB4_PRODUCT_REQ_
   else if(rc != 0 || (rc == 0 && '\0' != query[0] && 0 == strncmp(query, "1", sizeof(query))) ) {
       /* Enable LAN side SSH access. SSH enabled only for DEV Images.*/
       if (!isProdImage) {
           if(family == AF_INET6) {
               if(!isBridgeMode) //brlan0 exists
                   fprintf(fp, "-I %s -i %s -p tcp --dport 22 -j ACCEPT\n", "INPUT", lan_ifname);
               }
           else {
               fprintf(fp, "-I %s -i %s -p tcp --dport 22 -j ACCEPT\n", "INPUT", lan_ifname);
               fprintf(fp, "-I %s -p tcp --dport 22 -j ACCEPT\n", "lan2self_mgmt");
           }
       }
       else //Drop SSH connection for PROD images.
       {
           if(family == AF_INET6) {
               if(!isBridgeMode) //brlan0 exists
                   fprintf(fp, "-A %s -i %s -p tcp --dport 22 -j DROP\n", "INPUT", lan_ifname);

               fprintf(fp, "-A %s -i %s -p tcp --dport 22 -j DROP\n", "INPUT", cmdiag_ifname); //lan0 always exist
           }
           else {
               fprintf(fp, "-A %s -p tcp --dport 22 -j DROP\n", "lan2self_mgmt");
           }

       }
   }
#if defined (ENABLE_WTS) // Enabling WFA Wi-Fi Test suite port 9000
   if(family == AF_INET6) {
       if(!isBridgeMode) //brlan0 exists
           fprintf(fp, "-I %s -i %s -p tcp --dport 9000 -j ACCEPT\n", "INPUT", lan_ifname);
   }
   else {
           fprintf(fp, "-I %s -i %s -p tcp --dport 9000 -j ACCEPT\n", "INPUT", lan_ifname);
           fprintf(fp, "-I %s -p tcp --dport 9000 -j ACCEPT\n", "lan2self_mgmt");
   }
#endif
#endif // _HUB4_PRODUCT_REQ_

   FIREWALL_DEBUG("Exiting lan_telnet_ssh\n");
   return 0;
}

int do_lan2self_by_wanip6(FILE *filter_fp)
{
           FIREWALL_DEBUG("Entering do_lan2self_by_wanip6\n");     
    int i;
    for(i = 0; i < ecm_wan_ipv6_num; i++){
        fprintf(filter_fp, "-A INPUT -i %s -d %s -p tcp --match multiport --dports 23,22,80,443,161 -j LOG_INPUT_DROP\n", lan_ifname, ecm_wan_ipv6[i]);
    }
    FIREWALL_DEBUG("Exiting do_lan2self_by_wanip6\n");
    return 0;
}

#if defined (MULTILAN_FEATURE)
/*
 *  Procedure     : do_multinet_lan2self_by_wanip
 *  Purpose       : prepare rules for ipv4 firewall pertaining to access
 *                  to the local host via a WAN address
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int do_multinet_lan2self_by_wanip (FILE *filter_fp)
{
    char *tok = NULL;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char net_subnet[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    // First skip packets destined to primary LAN instance
    fprintf(filter_fp, "-A lan2self_by_wanip -s %s/%s -d %s -j RETURN\n", lan_ipaddr, lan_netmask, lan_ipaddr);

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4subnet", tok);
        net_subnet[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_subnet, sizeof(net_subnet));

        fprintf(filter_fp, "-A lan2self_by_wanip -s %s/%s -d %s -j RETURN\n", net_resp, net_subnet, net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif

static int do_lan2self_by_wanip(FILE *filter_fp, int family)
{
   //As requested, we don't allow SNMP/HTTP/HTTPs/Ping
   char httpport[64], tmpQuery[64];
   char httpsport[64];
   int rc = 0, ret;
   httpport[0] = '\0';
   httpsport[0] = '\0';
           FIREWALL_DEBUG("Entering do_lan2self_by_wanip\n");

#if defined (MULTILAN_FEATURE)
   do_multinet_lan2self_by_wanip(filter_fp);
#endif

   fprintf(filter_fp, "-A lan2self_by_wanip -d %s -j RETURN\n", current_wan_ipaddr); //eRouter address doesn't have any restrictions
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   if(isWanStaticIPReady){
         int i;
//       fprintf(filter_fp, "-A lan2self_by_wanip -d %s -j RETURN \n", current_wan_static_ipaddr); //true static ip doesn't have any restrictions
         for(i = 0; i < StaticIPSubnetNum ;i++ )
            fprintf(filter_fp, "-A lan2self_by_wanip -d %s -j RETURN \n", StaticIPSubnet[i].ip); //true static ip doesn't have any restrictions
   }
#endif
   //Setting wan_mgmt_httpport/httpsport to 12368 will block ATOM dbus connection. Add exception to avoid this situation.
   // TODO: REMOVE THIS EXCEPTION SINCE DBUS WILL BE ON PRIVATE NETWORK
   fprintf(filter_fp, "-A lan2self_by_wanip -s 192.168.100.3 -d 192.168.100.1 -j RETURN\n");

   rc = syscfg_get(NULL, "mgmt_wan_httpport", httpport, sizeof(httpport));
#if defined(CONFIG_CCSP_WAN_MGMT_PORT)
   tmpQuery[0] = '\0';
   ret = syscfg_get(NULL, "mgmt_wan_httpport_ert", tmpQuery, sizeof(tmpQuery));
   if(ret == 0){
       errno_t safec_rc = strcpy_s(httpport, sizeof(httpport),tmpQuery);
       ERR_CHK(safec_rc);
   }
#endif
   //>>zqiu 
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 192.168.101.1/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 169.254.101.1/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   //<<
#if defined(_WNXL11BWL_PRODUCT_REQ_) 
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 169.254.70.254/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 169.254.71.254/32 -j xlog_drop_lan2self\n", lan_ipaddr);
#else
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 169.254.0.254/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 169.254.1.254/32 -j xlog_drop_lan2self\n", lan_ipaddr);
#endif
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 172.16.12.1/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 192.168.106.1/32 -j xlog_drop_lan2self\n", lan_ipaddr);
   fprintf(filter_fp, "-A lan2self_by_wanip -s %s/24 -d 192.168.251.1/32 -j xlog_drop_lan2self\n", lan_ipaddr);

   if (rc == 0 && httpport[0] != '\0' && atoi(httpport) != 80 && (atoi(httpport) >= 0 && atoi(httpport) <= 65535 ))
       fprintf(filter_fp, "-A lan2self_by_wanip -p tcp --dport %s -j xlog_drop_lan2self\n", httpport); //GUI on mgmt_wan port

   rc = syscfg_get(NULL, "mgmt_wan_httpsport", httpsport, sizeof(httpsport));
   if (rc == 0 && httpsport[0] != '\0' && atoi(httpsport) != 443 && (atoi(httpsport) >= 0 && atoi(httpsport) <= 65535 ))
       fprintf(filter_fp, "-A lan2self_by_wanip -p tcp --dport %s -j xlog_drop_lan2self\n", httpsport); //GUI on mgmt_wan port

   fprintf(filter_fp, "-A lan2self_by_wanip -p tcp -m multiport --dports 80,443 -j xlog_drop_lan2self\n"); //GUI on standard ports
   fprintf(filter_fp, "-A lan2self_by_wanip -p udp --dport 161 -j xlog_drop_lan2self\n"); //SNMP
   fprintf(filter_fp, "-A lan2self_by_wanip -p icmp --icmp-type 8 -j xlog_drop_lan2self\n"); // ICMP PING request
   FIREWALL_DEBUG("Exiting do_lan2self_by_wanip\n");
   return 0;
}
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
/*
 *  Procedure     : do_lan2wan_staticip
 *  Purpose       : allow or deny true static subnet  access
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
static void do_lan2wan_staticip(FILE *filter_fp){
    int i;
           FIREWALL_DEBUG("Entering do_lan2wan_staticip\n");     
    if(isWanStaticIPReady && isFWTS_enable ){
        for(i = 0; i < StaticIPSubnetNum; i++){
            fprintf(filter_fp, "-A lan2wan_staticip -s %s/%s -j ACCEPT\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);
        }
    }
           FIREWALL_DEBUG("Exiting do_lan2wan_staticip\n");     
}
#endif
/*
 * Disable LAN http access while CmWebAccessUserIfLevel.all-users.lan = off(0)
 */
void lan_http_access(FILE *fp) {
    char lan_ip_webaccess[2];
           FIREWALL_DEBUG("Entering lan_http_access\n");     
    if (0 == sysevent_get(sysevent_fd, sysevent_token, "lan_ip_webaccess", lan_ip_webaccess, sizeof(lan_ip_webaccess))) {
       if(lan_ip_webaccess[0]!='\0' && strcmp(lan_ip_webaccess, "0")==0) {          
           if(!isBridgeMode) //brlan0 exists
               fprintf(fp, "-A %s -i %s -p tcp --dport %s -j xlog_drop_lan2self\n", "lan2self_mgmt", lan_ifname, reserved_mgmt_port);

           fprintf(fp, "-A %s -i %s -p tcp --dport %s -j xlog_drop_lan2self\n", "lan2self_mgmt", cmdiag_ifname, reserved_mgmt_port); //lan0 always exist
       }
   } 
           FIREWALL_DEBUG("Exiting lan_http_access\n");     
}
/*
 *  Procedure     : do_lan2self_mgmt
 *  Purpose       : allow or deny local access
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
static int do_lan2self_mgmt(FILE *fp)
{
   int rc;
   char query[MAX_QUERY];
         //  FIREWALL_DEBUG("Entering do_lan2self_mgmt\n");     
 query[0] = '\0';
   rc = syscfg_get(NULL, "mgmt_wifi_access", query, sizeof(query));
   if (0 == rc && '\0' != query[0] && 0 == strncmp(query, "0", sizeof(query)) ) {
      /* disallow wifi access */
      query[0] = '\0';
      rc = syscfg_get(NULL, "lan_wl_physical_ifnames", query, sizeof(query));
      if (0 == rc && '\0' != query[0]) {
         char *q = trim(query);
         char *next_token;
         while (NULL != q)  {
            next_token = token_get(q, ' ');
            if ( 0 != strcmp(q, "") ) {
                /* TODO: is this used / accurate? */
               fprintf(fp, "-A lan2self_mgmt -p tcp  -m tcp --dport %s -m physdev --physdev-in %s -j DROP\n",  reserved_mgmt_port, q);

            }
            q = next_token;
         } 
      }
   }

   lan_telnet_ssh(fp, AF_INET);

#if defined(CONFIG_CCSP_LAN_HTTP_ACCESS)
   lan_http_access(fp);
#endif
          // FIREWALL_DEBUG("Exiting do_lan2self_mgmt\n");     
   return(0);
}
 
/*
 *  Procedure     : do_lan2self
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic 
 *                  from the lan to utopia
 *  Parameters    :
 *    fp             : An open file to write lan2self rules to
 * Return Values  :
 *    0              : Success
 *
 */
static int do_lan2self(FILE *fp)
{
        // FIREWALL_DEBUG("Entering do_lan2self\n");     
#if (defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)) || defined(FEATURE_SUPPORT_MAPT_NAT46)
   if((!isMAPTReady) & isWanReady) // Pass for Dual Stack Line
#else
   if(isWanReady)
#endif //FEATURE_MAPT
       do_lan2self_by_wanip(fp, AF_INET);

   do_lan2self_attack(fp);
   do_lan2self_mgmt(fp);
        // FIREWALL_DEBUG("Exiting do_lan2self\n");     
   return(0);
}

#if defined (MULTILAN_FEATURE)
/*
 *  Procedure     : do_multinet_wan2self_attack
 *  Purpose       : prepare rules for ipv4 firewall to prevent attacks
 *                  from LAN addresses associated with multinet LANs
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int do_multinet_wan2self_attack (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(filter_fp, "-A wanattack -s %s -j xlog_drop_wanattack\n", net_resp);
        fprintf(filter_fp, "-A wanattack -d %s -j xlog_drop_wanattack\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif

/*
 ==========================================================================
                     wan2self
 ==========================================================================
 */

/*
 *  Procedure     : do_wan2self_attack
 *  Purpose       : prepare the iptables-restore statements with
 *                  counter measures against well known attacks
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *  Note          : wanattack table is immediately followed by a rule to drop all packets.
 *                  Therefore the only reason to detect wan attacks is for security logging purposes.
 *                  If another subtable is inserted between wanattack and drop all, then you MUST
 *                  enable wanattack for all packets so that you have a chance at avoiding attacks
 *                  before interpreting the packets.
 */
int do_wan2self_attack(FILE *fp,char* wan_ip)
{
   if ( !isLogEnabled || wan_ip == NULL || strlen(wan_ip) == 0 ) { 
      return(0);
   }

   char *logRateLimit = "-m limit --limit 6/h --limit-burst 1";

   // Define framework chains
   /*fprintf(fp, "-N wanattack\n");
   fprintf(fp, "-N wanattack_log\n");*/

   // Define feature chains
   fprintf(fp, "-N SmurfAttack\n");
   fprintf(fp, "-N ICMPSmurfAttack\n");
   fprintf(fp, "-N ICMPFlooding\n");
   fprintf(fp, "-N TCPSYNFlooding\n");
   fprintf(fp, "-N LANDAttack\n");
   fprintf(fp, "-N RFC1918Spoofing\n");
   fprintf(fp, "-N TCPResetAttack\n");
   fprintf(fp, "-N SYNFlood\n");
   fprintf(fp, "-N PortScanning\n");
   fprintf(fp, "-N BlockPrivateSourceIP\n");

   // Link feature chains to framework chains
   fprintf(fp, "-A wanattack -j SmurfAttack\n");
   fprintf(fp, "-A wanattack -j ICMPSmurfAttack\n");
   fprintf(fp, "-A wanattack -j ICMPFlooding\n");
   fprintf(fp, "-A wanattack -j TCPSYNFlooding\n");
   fprintf(fp, "-A wanattack -j LANDAttack\n");
   fprintf(fp, "-A wanattack -j RFC1918Spoofing\n");
   fprintf(fp, "-A wanattack -j TCPResetAttack\n");
   fprintf(fp, "-A wanattack -j SYNFlood\n");
   fprintf(fp, "-A wanattack -j PortScanning\n");
   fprintf(fp, "-A wanattack -j BlockPrivateSourceIP\n");

   // Link framework chains to root chains
   fprintf(fp, "-A INPUT -j wanattack\n");

   //Smurf attack, actually the below rules are to prevent us from being the middle-man host
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_)
   fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\" --log-level 7\n", logRateLimit);
#elif defined(_PROPOSED_BUG_FIX_)
   if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
   {
      fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\" --log-level 7\n", logRateLimit);
   }
   else
   {
      fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j ULOG --ulog-prefix \"DoS Attack - Smurf Attack\" --ulog-cprange 50\n", logRateLimit);
   }
#elif defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
   fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\"\n", logRateLimit);
#elif defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_))  
   fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j NFLOG --nflog-group 2 --nflog-prefix \"DoS Attack - Smurf Attack\" --nflog-size 50\n", logRateLimit);
#else
   fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request %s -j ULOG --ulog-prefix \"DoS Attack - Smurf Attack\" --ulog-cprange 50\n", logRateLimit);
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(fp, "-A SmurfAttack -p icmp -m icmp --icmp-type address-mask-request -j xlog_drop_wanattack\n");
   // ICMP Smurf Attack (timestamp)
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_) /* ULOG target removed in kernels 3.17+ */
   fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\" --log-level 7\n", logRateLimit);
#elif defined(_PROPOSED_BUG_FIX_)
   if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
   {
      fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\" --log-level 7\n", logRateLimit);
   }
   else
   {
      fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j ULOG --ulog-prefix \"DoS Attack - Smurf Attack\" --ulog-cprange 50\n", logRateLimit);
   }
#elif defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
   fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j LOG --log-prefix \"DoS Attack - Smurf Attack\"\n", logRateLimit);
#elif defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) 
   fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j NFLOG --nflog-group 2 --nflog-prefix \"DoS Attack - Smurf Attack\" --nflog-size 50\n", logRateLimit);
#else
   fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request %s -j ULOG --ulog-prefix \"DoS Attack - Smurf Attack\" --ulog-cprange 50\n", logRateLimit);
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(fp, "-A ICMPSmurfAttack -p icmp -m icmp --icmp-type timestamp-request -j xlog_drop_wanattack\n");

   //ICMP Flooding. Mark traffic bit rate > 5/s as attack and limit 6 log entries per hour
   fprintf(fp, "-A ICMPFlooding -p icmp -m limit --limit 5/s --limit-burst 10 -j RETURN\n");
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_) /* ULOG target removed in kernels 3.17+ */
   fprintf(fp, "-A ICMPFlooding -p icmp %s -j LOG --log-prefix \"DoS Attack - ICMP Flooding\" --log-level 7\n", logRateLimit);
#elif defined(_PROPOSED_BUG_FIX_)
   if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
   {
      fprintf(fp, "-A ICMPFlooding -p icmp %s -j LOG --log-prefix \"DoS Attack - ICMP Flooding\" --log-level 7\n", logRateLimit);
   }
   else
   {
      fprintf(fp, "-A ICMPFlooding -p icmp %s -j ULOG --ulog-prefix \"DoS Attack - ICMP Flooding\" --ulog-cprange 50\n", logRateLimit);
   }
#elif defined(_PLATFORM_RASPBERRYPI_) || defined (_PLATFORM_TURRIS_) ||  defined(_PLATFORM_BANANAPI_R4_)
   fprintf(fp, "-A ICMPFlooding -p icmp %s -j LOG --log-prefix \"DoS Attack - ICMP Flooding\"\n", logRateLimit);
#elif defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) 
   fprintf(fp, "-A ICMPFlooding -p icmp %s -j NFLOG --nflog-group 2 --nflog-prefix \"DoS Attack - ICMP Flooding\" --nflog-size 50\n", logRateLimit);
#else
   fprintf(fp, "-A ICMPFlooding -p icmp %s -j ULOG --ulog-prefix \"DoS Attack - ICMP Flooding\" --ulog-cprange 50\n", logRateLimit);
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(fp, "-A ICMPFlooding -p icmp -j xlog_drop_wanattack\n");

   //TCP SYN Flooding
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j RETURN\n");
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_)/* ULOG target removed in kernels 3.17+ */
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j LOG --log-prefix \"DoS Attack - TCP SYN Flooding\" --log-level 7\n", logRateLimit);
#elif defined(_PROPOSED_BUG_FIX_)
   if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
   {
      fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j LOG --log-prefix \"DoS Attack - TCP SYN Flooding\" --log-level 7\n", logRateLimit);
   }
   else
   {
      fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j ULOG --ulog-prefix \"DoS Attack - TCP SYN Flooding\" --ulog-cprange 50\n", logRateLimit);
   }
#elif defined(_PLATFORM_RASPBERRYPI_) || defined (_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j LOG --log-prefix \"DoS Attack - TCP SYN Flooding\"\n", logRateLimit);
#elif defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) 
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j NFLOG --nflog-group 2 --nflog-prefix \"DoS Attack - TCP SYN Flooding\" --nflog-size 50\n", logRateLimit);
#else
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn %s -j ULOG --ulog-prefix \"DoS Attack - TCP SYN Flooding\" --ulog-cprange 50\n", logRateLimit);
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(fp, "-A TCPSYNFlooding -p tcp --syn -j xlog_drop_wanattack\n");

   //LAND Aattack - sending a spoofed TCP SYN pkt with the target host's IP address to an open port as both source and destination
   if(isWanReady) {
       /* Allow multicast packet through */
      fprintf(fp, "-A LANDAttack -p udp -s %s -d 224.0.0.0/8 -j RETURN\n", wan_ip);
#if defined(_HUB4_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_XER5_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_) /* ULOG target removed in kernels 3.17+ */
      fprintf(fp, "-A LANDAttack -s %s %s -j LOG --log-prefix \"DoS Attack - LAND Attack\" --log-level 7\n", wan_ip, logRateLimit);
#elif defined(_PROPOSED_BUG_FIX_)
       if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
       {
         fprintf(fp, "-A LANDAttack -s %s %s -j LOG --log-prefix \"DoS Attack - LAND Attack\" --log-level 7\n", wan_ip, logRateLimit);
       }
       else
       {
         fprintf(fp, "-A LANDAttack -s %s %s -j ULOG --ulog-prefix \"DoS Attack - LAND Attack\" --ulog-cprange 50\n", wan_ip, logRateLimit);
       }
#elif defined(_PLATFORM_RASPBERRYPI_) || defined (_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
      fprintf(fp, "-A LANDAttack -s %s %s -j LOG --log-prefix \"DoS Attack - LAND Attack\"\n", wan_ip, logRateLimit);
#elif defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) 
      fprintf(fp, "-A LANDAttack -s %s %s -j NFLOG --nflog-group 2 --nflog-prefix \"DoS Attack - LAND Attack\" --nflog-size 50\n", wan_ip, logRateLimit);
#else
      fprintf(fp, "-A LANDAttack -s %s %s -j ULOG --ulog-prefix \"DoS Attack - LAND Attack\" --ulog-cprange 50\n", wan_ip, logRateLimit);
#endif /*_HUB4_PRODUCT_REQ_*/
      fprintf(fp, "-A LANDAttack -s %s -j xlog_drop_wanattack\n", wan_ip);
   }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   else
   {
       if (IsValidIPv4Addr(mapt_ip_address))
       {
         fprintf(fp, "-A LANDAttack -p udp -s %s -d 224.0.0.0/8 -j RETURN\n", mapt_ip_address);
         fprintf(fp, "-A LANDAttack -s %s %s -j LOG --log-prefix \"DoS Attack - LAND Attack\" --log-level 7\n", mapt_ip_address, logRateLimit);
         fprintf(fp, "-A LANDAttack -s %s -j xlog_drop_wanattack\n", mapt_ip_address);
       }
   }
#endif

   /*
    * Reject packets from RFC1918 class networks (i.e., spoofed)
    */
   if (isRFC1918Blocked) {
      fprintf(fp, "-A RFC1918Spoofing -s 10.0.0.0/8 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 169.254.0.0/16 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 172.16.0.0/12 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 192.168.0.0/16 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -i ! lo -s 127.0.0.0/8 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 224.0.0.0/4 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -d 224.0.0.0/4 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 240.0.0.0/5 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -d 240.0.0.0/5 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -s 0.0.0.0/8 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -d 0.0.0.0/8 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -d 239.255.255.0/24 -j xlog_drop_wanattack\n");
      fprintf(fp, "-A RFC1918Spoofing -d 255.255.255.255 -j xlog_drop_wanattack\n");
   }

   /*
    * TCP reset attack
    *  Drop excessive RST packets to avoid SMURF attacks, by given the
    *  next real data packet in the sequence a better chance to arrive first.
    */
   fprintf(fp, "-A TCPResetAttack -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j xlog_accept_wan2lan\n");

   /*
    * SYN Flood
    * Protect against SYN floods by rate limiting the number of new
    * connections from any host to 60 per second.  This does *not* do rate
    * limiting overall, because then someone could easily shut us down by
    * saturating the limit.
    */
    //snprintf(str, sizeof(str), "-A wanattack -m state --state NEW -p tcp -m tcp --syn -m recent --name synflood --set");
    //fprintf(fp, "%s\n", str);
    //snprintf(str, sizeof(str), "-A wanattack -m state --state NEW -p tcp -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 60 -j xlog_drop_wanattack");
    //fprintf(fp, "%s\n", str);

    // since some wan protocols have an ip address for a connection to the isp
    // and a different one for the wan itself. We make sure to protect the isp
    // connection as well 
    char isp_connection[MAX_QUERY];
    isp_connection[0] = '\0';
    sysevent_get(sysevent_fd, sysevent_token, "ipv4_wan_ipaddr", isp_connection, sizeof(isp_connection));
    if ('\0' != isp_connection[0] && 
        0 != strcmp("0.0.0.0", isp_connection) && 
        0 != strcmp(isp_connection, wan_ip)) {
      fprintf(fp, "-A BlockPrivateSourceIP -s %s -j xlog_drop_wanattack\n", isp_connection);
    }

   fprintf(fp, "-A BlockPrivateSourceIP -s %s -j xlog_drop_wanattack\n", lan_ipaddr);


#if defined (MULTILAN_FEATURE)
    do_multinet_wan2self_attack(fp);
#endif

   fprintf(fp, "-A BlockPrivateSourceIP -d %s -j xlog_drop_wanattack\n", lan_ipaddr);
   fprintf(fp, "-A BlockPrivateSourceIP -s 127.0.0.1 -j xlog_drop_wanattack\n");
   fprintf(fp, "-A BlockPrivateSourceIP -d 127.0.0.1 -j xlog_drop_wanattack\n");

   /*
    * Port Scanning
    * This technique relies on looking for connection attempts to port 139 (Windows File Sharing)
    * so it is unsuitable for situations where we want windows file sharing on the wan side.
    */
   if (isPortscanDetectionEnabled) {

      // Anyone who tried to portscan us is locked out for an entire day.
      fprintf(fp, "-A PortScanning -m recent --name portscan --rcheck --seconds 86400 -j xlog_drop_wanattack\n");

      // Once the day has passed, remove them from the portscan list
      fprintf(fp, "-A PortScanning -m recent --name portscan --remove\n");


      // These rules add scanners to the portscan list, and log the attempt.
      fprintf(fp, "-A PortScanning -i %s -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix \"Portscan:\" -m limit --limit 1/minute --limit-burst 1\n", current_wan_ifname);

      fprintf(fp, "-A PortScanning -i %s -p tcp -m tcp --dport 139 -m recent --name portscan --set -j xlog_drop_wanattack\n", current_wan_ifname);
   }
        // FIREWALL_DEBUG("Exiting do_wan2self_attack\n");     
   return(0);
}

/*
 *  Procedure     : do_mgmt_override
 *  Purpose       : ensure that mgmt port access cannot be taken by forward/dmz
 *  Parameters    :
 *     nat_fp
 *  Return Values :
 *     0               : done
 */
static int do_mgmt_override(FILE *nat_fp)
{
       //  FIREWALL_DEBUG("Entering do_mgmt_override\n");     
   fprintf(nat_fp, "-I prerouting_mgmt_override 1 -s %s/%s -d %s -p tcp  -m tcp --dport %s -j ACCEPT\n", lan_ipaddr, lan_netmask, lan_ipaddr, reserved_mgmt_port);
        // FIREWALL_DEBUG("Exiting do_mgmt_override\n");     
   return(0);
}

/*
 *  Procedure     : remote_access_set_proto
 *  Purpose       : allow or deny remote access
 *  Parameters    :
 *     nat_fp
 *     filter_fp
 *  Return Values :
 *     0               : done
 */

static int remote_access_set_proto(FILE *filt_fp, FILE *nat_fp, const char *port, const char *src, int family, const char *interface)
{
  	int ret = 0;
  	char httpport[64] = {0};
  	char httpsport[64] = {0};
  	char tmpQuery[MAX_QUERY];
		
         FIREWALL_DEBUG("Entering remote_access_set_proto\n");   
        ret = syscfg_get(NULL, "mgmt_wan_httpport", httpport, sizeof(port));
#if defined(CONFIG_CCSP_WAN_MGMT_PORT)
          tmpQuery[0] = '\0';
          ret = syscfg_get(NULL, "mgmt_wan_httpport_ert", tmpQuery, sizeof(tmpQuery));
          if(ret == 0)
              strcpy(httpport, tmpQuery);
#endif
  	if ((ret != 0) || ('\0' == httpport[0])) {
            strcpy(httpport, "8080");
   	}

  	ret = syscfg_get(NULL, "mgmt_wan_httpsport", httpsport, sizeof(httpsport));
  	if ((ret != 0) || ('\0' == httpsport[0])) {
             strcpy(httpsport, "8181");
        }
    if (family == AF_INET) {
        if ((0 == strcmp(httpport, port)) || (0 == strcmp(httpsport, port))) {
          fprintf(filt_fp, "-A wan2self_mgmt -i %s %s -p tcp -m tcp --dport %s -j webui_limit\n", interface, src, port);
        } else {
          fprintf(filt_fp, "-A wan2self_mgmt -i %s %s -p tcp -m tcp --dport %s -j ACCEPT \n", interface, src, port);
        }          
    } else { 
#if defined(_COSA_BCM_MIPS_) //Fix  for XF3-5627
		if(0 == strcmp("80", port)) {
                    char IPv6[INET6_ADDRSTRLEN];
      		    memset(IPv6, 0, INET6_ADDRSTRLEN);
      		    if (0 == sysevent_get(sysevent_fd, sysevent_token, "lan_ipaddr_v6", IPv6, sizeof(IPv6))) 
		        fprintf(filt_fp, "-A INPUT -i %s  -p tcp -m tcp --dport %s -d %s -j DROP\n", interface, port, IPv6 );
		}
#endif
      if ((0 == strcmp(httpport, port)) || (0 == strcmp(httpsport, port))) {
        fprintf(filt_fp, "-A INPUT -i %s %s -p tcp -m tcp --dport %s -j webui_limit\n", interface, src, port); 
      } else {
        fprintf(filt_fp, "-A INPUT -i %s %s -p tcp -m tcp --dport %s -j ACCEPT\n", interface, src, port); 
      }
    }
         FIREWALL_DEBUG("Exiting remote_access_set_proto\n");    
    return 0;
}
int wan_lan_webui_attack(FILE *fp, const char *interface)
{
      int rc = 0;
      char httpport[64] = {0};
      char httpsport[64] = {0};
      char query[MAX_QUERY];
      //lan side attack protection
      fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 80 -j UPLOAD_ATTACK_FILTER\n", interface);
      fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 443 -j UPLOAD_ATTACK_FILTER\n", interface);
      //wan side attack protection
      rc = syscfg_get(NULL, "mgmt_wan_httpaccess", query, sizeof(query));
      rc |= syscfg_get(NULL, "mgmt_wan_httpport", httpport, sizeof(httpport));
      if ((rc == 0) && atoi(query) == 1)
          fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport %s -j UPLOAD_ATTACK_FILTER\n", current_wan_ifname, httpport);
      rc = syscfg_get(NULL, "mgmt_wan_httpsaccess", query, sizeof(query));
      rc |= syscfg_get(NULL, "mgmt_wan_httpsport", httpsport, sizeof(httpsport));
      if ((rc == 0) && atoi(query) == 1)
          fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport %s -j UPLOAD_ATTACK_FILTER\n", current_wan_ifname, httpsport );
      return 0;
}
int lan_access_set_proto(FILE *fp,const char *port, const char *interface)
{
	if ((0 == strcmp("80", port)) || (0 == strcmp("443", port))) {
	    fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport %s -j webui_limit\n", interface, port);
	}
	else
	{
	    fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport %s -j ACCEPT\n", interface, port);
	}
	return 0;
}



void do_container_allow(FILE *pFilter, FILE *pMangle, FILE *pNat, int family)
{
    FIREWALL_DEBUG("Entering do_container_allow\n");

    if (NULL == pFilter || NULL == pMangle || NULL == pNat)
       return;

    if (family == AF_INET) {
       fprintf(pFilter, "-I INPUT -i %s -p udp --dport 67 -j ACCEPT\n", lxcBridgeName);
       fprintf(pFilter, "-I INPUT -i %s -p tcp --dport 67 -j ACCEPT\n", lxcBridgeName);
       fprintf(pFilter, "-I INPUT -i %s -p udp --dport 53 -j ACCEPT\n", lxcBridgeName);
       fprintf(pFilter, "-I INPUT -i %s -p tcp --dport 53 -j ACCEPT\n", lxcBridgeName);
       fprintf(pMangle, "-I POSTROUTING -o %s -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill\n", lxcBridgeName);
       fprintf(pNat, "-I POSTROUTING -s 147.0.3.0/24 ! -d 147.0.3.0/24 -j MASQUERADE\n");
    }
 
    if (family == AF_INET6) {
       fprintf(pNat, "-I POSTROUTING -s 2301:db8:1::/64 ! -d 2301:db8:1::/64 -j MASQUERADE\n");
    }

    fprintf(pFilter, "-I FORWARD -i %s -j ACCEPT\n", lxcBridgeName);
    fprintf(pFilter, "-I FORWARD -o %s -j ACCEPT\n", lxcBridgeName);
    
    FIREWALL_DEBUG("Exiting do_container_allow\n");
    return;
}

 /*
  *  RDKB-7836 setting the ssh rules for production image
  *  Procedure     : remote_ssh_access_set_proto_prod
  *  Purpose       : For Droping all the packets from .AF_INET6 family.
  *  Parameters    :
  *     filter_fp  : file to save ip table entry
  *     port       : port string to which the protocol applied
  *     src        : source ip str
  *     family     : internet family
  *     interface  : ip interface name
  *  Return Values :
  */
 //unused function
 #if 0
 static void remote_ssh_access_set_proto_prodImg(FILE *filt_fp, const char *port, const char *src, int family, const char *interface)
 {
    FIREWALL_DEBUG("Entering remote_ssh_access_set_proto_prodImg\n");
    if (family == AF_INET) {
        fprintf(filt_fp, "-A wan2self_mgmt -i %s %s -p tcp -m tcp --dport %s -j ACCEPT\n", interface, src, port);
    } else {
        fprintf(filt_fp, "-A INPUT -i %s %s -p tcp -m tcp --dport %s -j DROP\n", interface, src, port);
    }
    FIREWALL_DEBUG("Exiting remote_ssh_access_set_proto_prodImg\n");
 }
 #endif

  static void checkandblock_remote_access(FILE *filter_fp)
  {
	int rc, ret;
	char query[MAX_QUERY], tmpQuery[MAX_QUERY];
	char httpportno[64];
	char httpsportno[64];
	
	memset(query, 0, sizeof(query));
	memset(tmpQuery, 0, sizeof(tmpQuery));
	memset(httpportno, 0, sizeof(httpportno));
	memset(httpsportno, 0, sizeof(httpsportno));	

	tmpQuery[0] = '\0';
	ret =  syscfg_get(NULL, "mgmt_wan_httpsaccess", tmpQuery, sizeof(tmpQuery));
	if ((ret == 0) && atoi(tmpQuery) == 0){
	    syscfg_get(NULL, "mgmt_wan_httpsport", httpsportno, sizeof(httpsportno));
	    if(('\0' != httpsportno[0]) && ('\0' != current_wan_ip6_addr[0])) {
	    fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport %s -d %s -j DROP\n", current_wan_ifname, httpsportno, current_wan_ip6_addr );
	    }
	}
	query[0] = '\0';
        rc =  syscfg_get(NULL, "mgmt_wan_httpaccess", query, sizeof(query));
#if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
      tmpQuery[0] = '\0';
      ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
      if(ret == 0)
          strcpy(query, tmpQuery);
#endif
	if((rc == 0)&& atoi(query) == 0 ) {
#if defined(_COSA_BCM_MIPS_) || defined(CONFIG_CCSP_WAN_MGMT_PORT)
        syscfg_get(NULL, "mgmt_wan_httpport_ert", httpportno, sizeof(httpportno));
	if('\0' == httpportno[0]) {
		syscfg_get(NULL, "mgmt_wan_httpport", httpportno, sizeof(httpportno));
	}
#else
        syscfg_get(NULL, "mgmt_wan_httpport", httpportno, sizeof(httpportno));
#endif
	if(('\0' != httpportno[0]) && ('\0' != current_wan_ip6_addr[0])) {
	    fprintf(filter_fp, "-A INPUT -i %s  -p tcp -m tcp --dport %s -d %s -j DROP\n", current_wan_ifname, httpportno, current_wan_ip6_addr );
	}
	}
  }
  
int do_remote_access_control(FILE *nat_fp, FILE *filter_fp, int family)
{
    int rc, ret;
    char query[MAX_QUERY], tmpQuery[MAX_QUERY];
    char srcaddr[64 + 64 + 40];
    char iprangeAddr[REMOTE_ACCESS_IP_RANGE_MAX_RULE][64 + 64 + 40];
    unsigned long count, i;
    char countStr[16];
    char startip[64];
    char endip[64];
    char httpport[64];
    char httpsport[64];
    char port[64];
    char utKey[64];
    unsigned char srcany = 0, validEntry = 0, noIPv6Entry = 0;
    errno_t safec_rc = -1;
#if !defined(CONFIG_CCSP_CM_IP_WEBACCESS)
    char cm_ip_webaccess[2];
    cm_ip_webaccess[0] = '\0';
#endif
#if !defined(CONFIG_CCSP_WAN_MGMT)
    char rg_ip_webaccess[2];
    rg_ip_webaccess[0] = '\0';
#endif

    FIREWALL_DEBUG("Entering do_remote_access_control\n");    

    httpport[0] = '\0';
    httpsport[0] = '\0';

    /* global flag */
    rc = syscfg_get(NULL, "mgmt_wan_access", query, sizeof(query));
    if (rc != 0 || atoi(query) != 1) {
        return 0;
    }
    
    srcaddr[0] = '\0';

#if defined(CONFIG_CCSP_CM_IP_WEBACCESS)
#if defined(_ENABLE_EPON_SUPPORT_)
    // XF3 only has this interface available on IPv6 erouter0
    if (family == AF_INET6)
    {
#endif
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_)  && !defined(_PLATFORM_BANANAPI_R4_)
	   remote_access_set_proto(filter_fp, nat_fp, "80", srcaddr, family, ecm_wan_ifname);
       remote_access_set_proto(filter_fp, nat_fp, "443", srcaddr, family, ecm_wan_ifname);
#endif
#if defined(_ENABLE_EPON_SUPPORT_)
    }
#endif
#endif

    for (i = 0; i < REMOTE_ACCESS_IP_RANGE_MAX_RULE; i++)
    {
        iprangeAddr[i][0] = 0;
    }

    rc = syscfg_get(NULL, "mgmt_wan_iprange_count", countStr, sizeof(countStr));
    if(rc == 0)
        count = strtoul(countStr, NULL, 10);
    else
        count = 0;

    if (count > REMOTE_ACCESS_IP_RANGE_MAX_RULE)
    {
        count = REMOTE_ACCESS_IP_RANGE_MAX_RULE;
    }

    rc = syscfg_get(NULL, "mgmt_wan_srcany", query, sizeof(query));
    if (rc == 0)
        srcany = (strcmp (query, "1") == 0) ? 1 : 0;
    else
        srcany = 0;

    if (!srcany)
    {
        if (family == AF_INET) {
            //get iprange src IP address first
            for(i = 0; i < count; i++) {
                snprintf(utKey, sizeof(utKey), "mgmt_wan_iprange_%lu_startIP", i);
                syscfg_get(NULL, utKey, startip, sizeof(startip));
                snprintf(utKey, sizeof(utKey), "mgmt_wan_iprange_%lu_endIP", i);
                syscfg_get(NULL, utKey, endip, sizeof(endip));

                if (strcmp(startip, endip) == 0)
                    snprintf(iprangeAddr[i], sizeof(iprangeAddr[i]), "-s %s", startip);
                else
                    snprintf(iprangeAddr[i], sizeof(iprangeAddr[i]), "-m iprange --src-range %s-%s", startip, endip);
            }

            //this is the remote access IP address on GUI
            rc = syscfg_get(NULL, "mgmt_wan_srcstart_ip", startip, sizeof(startip));
            rc |= syscfg_get(NULL, "mgmt_wan_srcend_ip", endip, sizeof(endip));
            if (rc != 0)
                fprintf(stderr, "[REMOTE ACCESS] fail to get mgmt ip address\n");
            else {
                if (strcmp(startip, endip) == 0) {
                    snprintf(srcaddr, sizeof(srcaddr), "-s %s", startip);
                } else {
                    snprintf(srcaddr, sizeof(srcaddr), "-m iprange --src-range %s-%s", startip, endip);
                }
            }
        }
        else {
            startip[0] = endip[0] = '\0';
            rc = syscfg_get(NULL, "mgmt_wan_srcstart_ipv6", startip, sizeof(startip));
            rc |= syscfg_get(NULL, "mgmt_wan_srcend_ipv6", endip, sizeof(endip));
            if (rc != 0 || startip[0] == '\0' || endip[0] == '\0') {
                noIPv6Entry = 1;
            }
            else {
                if (strcmp(startip, endip) == 0) {
                    snprintf(srcaddr, sizeof(srcaddr), "-s %s", startip);
                } else {
                    snprintf(srcaddr, sizeof(srcaddr), "-m iprange --src-range %s-%s", startip, endip);
                }
            }
        }
    }

   // 255.255.255.255 or x to cover the use case of leave either IPv4 or IPv6 address blank on GUI
   if( srcany == 1 
        || (family == AF_INET && strcmp("255.255.255.255", startip) != 0 && strcmp("255.255.255.255", endip) != 0) \
        || (family == AF_INET6 && strcmp("x", startip) != 0 && strcmp("x", endip) != 0 && noIPv6Entry != 1) \
     ) {
       validEntry = 1;
   }

   /* HTTP access */
   // CM-IP: wan0
#if defined(CONFIG_CCSP_CM_IP_WEBACCESS)
/*
   if(validEntry)
       remote_access_set_proto(filter_fp, nat_fp, "80", srcaddr, family, ecm_wan_ifname);

   for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
       remote_access_set_proto(filter_fp, nat_fp, "80", iprangeAddr[i], family, ecm_wan_ifname);
*/
#else
   if (0 == sysevent_get(sysevent_fd, sysevent_token, "cm_ip_webaccess", cm_ip_webaccess, sizeof(cm_ip_webaccess))) {
       if(cm_ip_webaccess[0]!='\0' && strcmp(cm_ip_webaccess, "1")==0) {
           if(validEntry)
               remote_access_set_proto(filter_fp, nat_fp, "80", srcaddr, family, ecm_wan_ifname);

           for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
               remote_access_set_proto(filter_fp, nat_fp, "80", iprangeAddr[i], family, ecm_wan_ifname);
       }
   }
#endif
   // RG-IP: erouter0
#if defined(CONFIG_CCSP_WAN_MGMT)
   rc = syscfg_get(NULL, "mgmt_wan_httpaccess", query, sizeof(query));
#if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
   tmpQuery[0] = '\0';
   ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
   if(ret == 0){
       safec_rc = strcpy_s(query, sizeof(query),tmpQuery);
       ERR_CHK(safec_rc);
   }
       
#endif

   rc |= syscfg_get(NULL, "mgmt_wan_httpport", httpport, sizeof(httpport));
#if defined(CONFIG_CCSP_WAN_MGMT_PORT)
   tmpQuery[0] = '\0';
   ret = syscfg_get(NULL, "mgmt_wan_httpport_ert", tmpQuery, sizeof(tmpQuery));
   if(ret == 0){
       safec_rc = strcpy_s(httpport, sizeof(httpport),tmpQuery);
       ERR_CHK(safec_rc);
   }
#endif

   if (rc == 0 && atoi(query) == 1)
   {
       // allows remote GUI access on erouter0 interface
       if(validEntry) {
           remote_access_set_proto(filter_fp, nat_fp, httpport, srcaddr, family, current_wan_ifname);
#if defined(_ENABLE_EPON_SUPPORT_)
           if (family == AF_INET6) {
               // Remote Management on EPON products IPV6 wan management is only on brlan0, not erouter0
               remote_access_set_proto(filter_fp, nat_fp, httpport, srcaddr, family, lan_ifname);
           }
#endif
       }

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, httpport, iprangeAddr[i], family, current_wan_ifname);
   }
#else
   rc = syscfg_get(NULL, "mgmt_wan_httpport", httpport, sizeof(httpport));
   if(rc == 0) {
       if (0 == sysevent_get(sysevent_fd, sysevent_token, "rg_ip_webaccess", rg_ip_webaccess, sizeof(rg_ip_webaccess))) {
           if(rg_ip_webaccess[0]!='\0' && strcmp(rg_ip_webaccess, "1")==0) {
              if(validEntry)
                  remote_access_set_proto(filter_fp, nat_fp, httpport, srcaddr, family, current_wan_ifname);

              for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
                  remote_access_set_proto(filter_fp, nat_fp, httpport, iprangeAddr[i], family, current_wan_ifname);
           }
       }
   }   
#endif

   /* HTTPS access */
   // CM-IP: wan0
#if defined(CONFIG_CCSP_CM_IP_WEBACCESS)
/*
   if(validEntry)
       remote_access_set_proto(filter_fp, nat_fp, "443", srcaddr, family, ecm_wan_ifname);

   for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
       remote_access_set_proto(filter_fp, nat_fp, "443", iprangeAddr[i], family, ecm_wan_ifname);
*/
#else
   if (0 == sysevent_get(sysevent_fd, sysevent_token, "cm_ip_webaccess", cm_ip_webaccess, sizeof(cm_ip_webaccess))) {
       if(cm_ip_webaccess[0]!='\0' && strcmp(cm_ip_webaccess, "1")==0) {
           if(validEntry)
               remote_access_set_proto(filter_fp, nat_fp, "443", srcaddr, family, ecm_wan_ifname);

           for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
               remote_access_set_proto(filter_fp, nat_fp, "443", iprangeAddr[i], family, ecm_wan_ifname);
       }
   }
#endif

   // RG-IP: erouter0
#if defined(CONFIG_CCSP_WAN_MGMT)
   rc = syscfg_get(NULL, "mgmt_wan_httpsaccess", query, sizeof(query));
   rc |= syscfg_get(NULL, "mgmt_wan_httpsport", httpsport, sizeof(httpsport));
   if (rc == 0 && atoi(query) == 1)
   {

       if(validEntry) {
           remote_access_set_proto(filter_fp, nat_fp, httpsport, srcaddr, family, current_wan_ifname);
#if defined(_ENABLE_EPON_SUPPORT_)
           if (family == AF_INET6) {
               // Remote Management on EPON products IPV6 wan management is only on brlan0, not erouter0
               remote_access_set_proto(filter_fp, nat_fp, httpsport, srcaddr, family, lan_ifname);
           }
#endif
       }

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, httpsport, iprangeAddr[i], family, current_wan_ifname);
   }
#else
   rc = syscfg_get(NULL, "mgmt_wan_httpsport", httpsport, sizeof(httpsport));
   if(rc == 0) {
       if (0 == sysevent_get(sysevent_fd, sysevent_token, "rg_ip_webaccess", rg_ip_webaccess, sizeof(rg_ip_webaccess))) {
           if(rg_ip_webaccess[0]!='\0' && strcmp(rg_ip_webaccess, "1")==0) {
              if(validEntry)
                  remote_access_set_proto(filter_fp, nat_fp, httpsport, srcaddr, family, current_wan_ifname);

              for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
                  remote_access_set_proto(filter_fp, nat_fp, httpsport, iprangeAddr[i], family, current_wan_ifname);
           }
       }
   }  
#endif

   
   /* eCM SSH access */
   /*
   ** COMCAST Bussiness Requirement (RDKB-7836 )
   ** Allow only certain IP's for ssh in production image.
   ** Defining Dropbear ssh management IP for iptable Init
   ** "/etc/dropbear/prodMgmtIps.cfg" contains the list jump servers that can "ssh" access box
   ** In case it is reuqire to update then add/remove entry in "/etc/dropbear/prodMgmtIps.cfg".
   ** In "prod" image if "" is then SSH will be disabled, esle available only to available IPs.
   ** In "dev" image ssh is allowed.
   */
   rc = syscfg_get(NULL, "mgmt_wan_sshaccess", query, sizeof(query));
   rc |= syscfg_get(NULL, "mgmt_wan_sshport", port, sizeof(port));
   if (rc == 0 && atoi(query) == 1) {

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, port, iprangeAddr[i], family, ecm_wan_ifname);
      
   }

   /* eCM Telnet access */
   rc = syscfg_get(NULL, "mgmt_wan_telnetaccess", query, sizeof(query));
   rc |= syscfg_get(NULL, "mgmt_wan_telnetport", port, sizeof(port));
   if (rc == 0 && atoi(query) == 1) {
       if(validEntry)
           remote_access_set_proto(filter_fp, nat_fp, port, srcaddr, family, ecm_wan_ifname);

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, port, iprangeAddr[i], family, ecm_wan_ifname);
   }

   /* eMTA SSH access */
   rc = syscfg_get(NULL, "mgmt_mta_sshaccess", query, sizeof(query));
   rc |= syscfg_get(NULL, "mgmt_wan_sshport", port, sizeof(port));
   if (rc == 0 && atoi(query) == 1) {
       if(validEntry)
           remote_access_set_proto(filter_fp, nat_fp, port, srcaddr, family, emta_wan_ifname);

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, port, iprangeAddr[i], family, emta_wan_ifname);
   }

   /* eMTA Telnet access */
   rc = syscfg_get(NULL, "mgmt_mta_telnetaccess", query, sizeof(query));
   rc |= syscfg_get(NULL, "mgmt_wan_telnetport", port, sizeof(port));
   if (rc == 0 && atoi(query) == 1) {
       if(validEntry)
           remote_access_set_proto(filter_fp, nat_fp, port, srcaddr, family, emta_wan_ifname);

       for(i = 0; i < count && family == AF_INET && srcany == 0; i++)
           remote_access_set_proto(filter_fp, nat_fp, port, iprangeAddr[i], family, emta_wan_ifname);
   }

#if defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
    // RDKB-21814 
    // Drop only remote managment port(8080,8181) in bridge_mode 
    // because port 80, 443 will be used to access MSO page / local admin page.

    rc = syscfg_get(NULL, "mgmt_wan_httpaccess", query, sizeof(query));
#if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
      tmpQuery[0] = '\0';
      ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
      if(ret == 0)
          strcpy(query, tmpQuery);
#endif

    tmpQuery[0] = '\0';
    ret =  syscfg_get(NULL, "mgmt_wan_httpsaccess", tmpQuery, sizeof(tmpQuery));

    if (isBridgeMode)
    {
        int port;
        port = (httpport[0]) ? atoi(httpport) : -1;
        if (port < 0 || port > 65535 || port == 80) {
           safec_rc = strcpy_s(httpport, sizeof(httpport),"8080");
           ERR_CHK(safec_rc);
        }

        port = (httpsport[0]) ? atoi(httpsport) : -1;
        if (port < 0 || port > 65535 || port == 443) {
           safec_rc = strcpy_s(httpsport, sizeof(httpport),"8181");
           ERR_CHK(safec_rc);
        }		
        if(!bEthWANEnable)
        {
                fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 80 -j DROP\n", current_wan_ifname);
                fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 443 -j DROP\n", current_wan_ifname);
        }
    }
    else
#endif
    {		
		int port;
        port = (httpport[0]) ? atoi(httpport) : -1;
        if (port < 0 || port > 65535) {
           port = 80;
           safec_rc = strcpy_s(httpport, sizeof(httpport), "80");
           ERR_CHK(safec_rc);
        }
        if (port != 80) {
           safec_rc = strcat_s(httpport, sizeof(httpport), ",80");
           ERR_CHK(safec_rc);
        }

        port = (httpsport[0]) ? atoi(httpsport) : -1;
        if (port < 0 || port > 65535) {
            port = 443;
            safec_rc = strcpy_s(httpsport, sizeof(httpport),"443");
            ERR_CHK(safec_rc);
        }
        if (port != 443) {
           safec_rc = strcat_s(httpport, sizeof(httpport), ",443");
           ERR_CHK(safec_rc);
        }
		
    }
	
	if(family == AF_INET6){	
#if defined(_COSA_BCM_MIPS_) // RDKB-35063
		checkandblock_remote_access(filter_fp);
		ethwan_mso_gui_acess_rules(filter_fp,NULL);
#else
		if( bEthWANEnable )
		{
			checkandblock_remote_access(filter_fp);
			ethwan_mso_gui_acess_rules(filter_fp,NULL);
		}
#endif
	}
    //remote management is only available on eCM interface if it is enabled
#ifdef _COSA_INTEL_XB3_ARM_ 
   if(family == AF_INET)
        fprintf(filter_fp, "-A wan2self_mgmt -p tcp -m multiport --dports 21,23,%s,%s -j xlog_drop_wan2self\n", httpport, httpsport);
    else
        fprintf(filter_fp, "-A INPUT ! -i %s -p tcp -m multiport --dports 21,23,%s,%s -j DROP\n", isBridgeMode == 0 ? lan_ifname : cmdiag_ifname, httpport, httpsport);
         FIREWALL_DEBUG("Exiting do_remote_access_control\n");    
    return 0;
#else
    if(family == AF_INET)
        fprintf(filter_fp, "-A wan2self_mgmt -p tcp -m multiport --dports 23,%s,%s -j xlog_drop_wan2self\n", httpport, httpsport);
    else
        fprintf(filter_fp, "-A INPUT ! -i %s -p tcp -m multiport --dports 23,%s,%s -j DROP\n", isBridgeMode == 0 ? lan_ifname : cmdiag_ifname, httpport, httpsport);
         FIREWALL_DEBUG("Exiting do_remote_access_control\n");
    return 0;
#endif
}

/*
 *  Procedure     : do_wan2self_ports
 *  Purpose       : allow or deny access to some ports
 *  Parameters    :
 *     mangle_fp     
 *     nat_fp     
 *     filter_fp
 *  Return Values :
 *     0               : done
 */
static int do_wan2self_ports(FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{

        // FIREWALL_DEBUG("Entering do_wan2self_ports\n");    
   // since connection tracking is turned of if current_wan_ipaddr = 0.0.0.0
   // we need to explicitly allow dns
   if (!isWanReady) {
      fprintf(filter_fp, "-A wan2self_ports -i %s -p udp -m udp --sport 53 -j xlog_accept_wan2self\n", default_wan_ifname);
   }

   /*
    * if we are doing rip on the wan
    * if rip is enabled then we need to allow multicast udp port 520 for version2
    * as well as unicast
    */
   if (isRipWanEnabled) {
      fprintf(filter_fp, "-A wan2self_ports -d 224.0.0.9 -p udp -m udp --dport 520 -j xlog_accept_wan2self\n");
      if (isDmzEnabled) {
         fprintf(nat_fp, "-I prerouting_fromwan_todmz 1 -d 224.0.0.9 -p udp -m udp --dport 520 -j ACCEPT\n");
      }

      fprintf(filter_fp, "-A wan2self_ports -p udp -m udp --dport 520 -j xlog_accept_wan2self\n");
      if (isDmzEnabled) {
         fprintf(nat_fp, "-I prerouting_fromwan_todmz 1 --dport 520  -j ACCEPT\n");
      }

      // set QoS DSCP markings
     fprintf(mangle_fp, "-A postrouting_qos -p udp -m udp --dport 520 -j DSCP --set-dscp-class cs6\n");
   }

   /*
    * if the development override switch is enabled then allow ssh, http, https, from wan side
    */
   if (isDevelopmentOverride) {
      fprintf(filter_fp, "-A wan2self_ports -p tcp -m tcp --dport 22 -j xlog_accept_wan2self\n");
      if (isDmzEnabled) {
         fprintf(nat_fp, "-I prerouting_fromwan_todmz 1 -p tcp -m tcp --dport 22  -j ACCEPT\n");
      }

      fprintf(filter_fp, "-A wan2self_ports -p tcp -m tcp --dport 80 -j xlog_accept_wan2self\n");
      if (isDmzEnabled) {
         fprintf(nat_fp, "-I prerouting_fromwan_todmz 1 -p tcp -m tcp --dport 80  -j ACCEPT\n");
      }

      fprintf(filter_fp, "-A wan2self_ports -p tcp -m tcp --dport 443 -j xlog_accept_wan2self\n");
      if (isDmzEnabled) {
         fprintf(nat_fp, "-I prerouting_fromwan_todmz 1 -p tcp -m tcp --dport 443  -j ACCEPT\n");
      }

   }

   if (strncasecmp(firewall_level, "High", strlen("High")) != 0)
   {
      if (strncasecmp(firewall_level, "Medium", strlen("Medium")) == 0)
      {
         fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 113 -j xlog_drop_wan2self\n"); // IDENT
         fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -j xlog_drop_wan2self\n"); // Drop ICMP PING
      }
      else if (strncasecmp(firewall_level, "Low", strlen("Low")) == 0)
      {
         fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 113 -j xlog_drop_wan2self\n"); // IDENT
      #if defined(CONFIG_CCSP_DROP_ICMP_PING)
         fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -j xlog_drop_wan2self\n"); // Drop ICMP PING
      #else
         fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -m limit --limit 3/second -j xlog_accept_wan2self\n"); // Allow ICMP PING with limited rate
      #endif
      }
      else if (strncasecmp(firewall_level, "Custom", strlen("Custom")) == 0)
      {
         /*Since the WebGUI only indicates the wan2lan traffic should be blocked, wan2self http traffic should be controled by wan2self_mgmt
         if (isHttpBlocked)
         {
            fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 80 -j xlog_drop_wan2self\n"); // HTTP
            fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 443 -j xlog_drop_wan2self\n"); // HTTPs
         }
         */
         fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 113 -j %s\n", isIdentBlocked ? "xlog_drop_wan2self" : "xlog_accept_wan2self"); // IDENT
         if(isPingBlocked) {
             fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -j %s\n", "xlog_drop_wan2self"); // ICMP PING
         }
         else {
             fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -m limit --limit 3/second -j %s\n", "xlog_accept_wan2self"); // ICMP PING
         }
      }
      else //None
      {
         fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -m limit --limit 3/second -j xlog_accept_wan2self\n"); // ACCEPT ICMP PING if Firewall is disabled
      }

      // we still need to protect against other icmp besides ping
      fprintf(filter_fp, "-A wan2self_ports -p icmp -m limit --limit 1/second -j xlog_accept_wan2self\n");
//#ifdef _COSA_INTEL_XB3_ARM_
//      fprintf(filter_fp, "-A wan2self_ports ! -i erouter0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec --limit-burst 20 -j ACCEPT\n");
//      fprintf(filter_fp, "-A wan2self_ports ! -i erouter0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP\n");
//#endif
      //rule for IGMP(protocol num is 2)
      fprintf(filter_fp, "-A wan2self_ports -p 2 -j %s\n", "xlog_accept_wan2self");
   }
   else //High Level
   {
       fprintf(filter_fp, "-A wan2self_ports -p tcp --dport 113 -j xlog_drop_wan2self\n"); // IDENT
       fprintf(filter_fp, "-A wan2self_ports -p icmp --icmp-type 8 -j xlog_drop_wan2self\n"); // DROP ICMP PING
   }
        // FIREWALL_DEBUG("Exiting do_wan2self_ports\n");    
   return(0);
}
/*
 *  Procedure     : do_wan2self_allow
 *  Purpose       :   
 *  Parameters    :
 *    filter_fp     : An open file to write filter rules to
 * Return Values  :
 *    0              : Success
 */
static int do_wan2self_allow(FILE *filter_fp)
{
        // FIREWALL_DEBUG("Entering do_wan2self_allow\n");    
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   int i;
   //always allow ping if disable true static on firewall
   if(isFWTS_enable && isWanStaticIPReady){
//      fprintf(filter_fp, "-A wan2self_allow -d %s -p icmp --icmp-type 8 -m limit --limit 3/second -j %s\n", current_wan_static_ipaddr,"xlog_accept_wan2self");
      for(i = 0; i < StaticIPSubnetNum ;i++ )
         fprintf(filter_fp, "-A wan2self_allow -d %s -p icmp --icmp-type 8 -m limit --limit 3/second -j %s\n",  StaticIPSubnet[i].ip,"xlog_accept_wan2self");
  }
#endif
    return 0;
}

/*
 *  Procedure     : do_wan2self
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the wan to utopia
 *  Parameters    :
 *    mangle_fp     : An open file to write mangle rules to
 *    nat_fp        : An open file to write nat rules to
 *    filter_fp     : An open file to write filter rules to
 * Return Values  :
 *    0              : Success
 */
static int do_wan2self(FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
  //       FIREWALL_DEBUG("Entering do_wan2self\n");    
   do_wan2self_allow(filter_fp);
   do_wan2self_attack(filter_fp,current_wan_ipaddr);
   do_wan2self_ports(mangle_fp, nat_fp, filter_fp);
   do_mgmt_override(nat_fp);
   WAN_FAILOVER_SUPPORT_CHECK
   do_remote_access_control(nat_fp, filter_fp, AF_INET);
   WAN_FAILOVER_SUPPORT_CHECk_END
    //     FIREWALL_DEBUG("Exiting do_wan2self\n");    
   return(0);
}

#if 0
/*
 ==========================================================================
                     lan2wan
 ==========================================================================
 */

/*
 *  Procedure     : write_block_application_statement
 *  Purpose       : prepare the iptables-restore statements with statements for dropping packets from well known applications
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *                  protocol.
 *     wkp_fp          : An open file containing well known port mappings
 *                       /etc/services is a standard linux format
 *     table           : table rule belongs to
 *     name            : name of the service  
 *  Return Values :
 *     0               : done
 */
static int write_block_application_statement (FILE *fp, FILE *wkp_fp, char *table, char *name)
{
   rewind(wkp_fp);
   char line[512];

   char *next_token;
   char *port_prot;
   char *port_val;
         FIREWALL_DEBUG("Entering write_block_application_statement\n");    
   while (NULL != (next_token = match_keyword(wkp_fp, name, ' ', line, sizeof(line))) ) {
      char port_str[50];
      sscanf(next_token, "%50s ", port_str);
      port_val = port_str;
      port_prot = strchr(port_val, '/');
      if (NULL != port_prot) {
         *port_prot = '\0';
         port_prot++;
      } else {
         continue;
      }
      
      char str[MAX_QUERY];
      fprintf(fp, "-A %s -p %s -m %s --dport %s -j xlogreject\n", table, port_prot, port_prot, port_val);

   }
         FIREWALL_DEBUG("Exiting write_block_application_statement\n");    
   return(0); 
}
#endif

/*
 *  Procedure     : do_lan2wan_webfilters
 *  Purpose       : prepare the iptables-restore statements for all
 *                  syscfg defined web filters
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
//unused function
#if 0
static int do_lan2wan_webfilters(FILE *filter_fp)
{
   char webfilter_enable[4];
         FIREWALL_DEBUG("Entering do_lan2wan_webfilters\n");    
if ( 0 == syscfg_get(NULL, "block_webproxy", webfilter_enable, sizeof(webfilter_enable)) ) {
      if ('\0' != webfilter_enable[0] && 0 != strncmp("0", webfilter_enable, sizeof(webfilter_enable)) ) {
#if 1 // RDKB-19924 Intel Proposed RDKB Generic Bug Fix
         //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m webstr --url -j xlogreject\n");
#else
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m httpurl --match-proxy -j xlogreject\n");
#endif
         // fprintf(filter_fp, "%s\n", str);
      }
   }
   if ( 0 == syscfg_get(NULL, "block_java", webfilter_enable, sizeof(webfilter_enable)) ) {
      if ('\0' != webfilter_enable[0] && 0 != strncmp("0", webfilter_enable, sizeof(webfilter_enable)) ) {
#if 1 // RDKB-19924 Intel Proposed RDKB Generic Bug Fix
         //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
	  fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m webstr --url -j xlogreject\n");
#else
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m httpurl --match-java -j xlogreject\n");
#endif
         // fprintf(filter_fp, "%s\n", str);
      }
   }
   if ( 0 == syscfg_get(NULL, "block_activex", webfilter_enable, sizeof(webfilter_enable)) ) {
      if ('\0' != webfilter_enable[0] && 0 != strncmp("0", webfilter_enable, sizeof(webfilter_enable)) ) {
#if 1 // RDKB-19924 Intel Proposed RDKB Generic Bug Fix
         //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m webstr --url -j xlogreject\n");
#else
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m httpurl --match-activex -j xlogreject\n");
#endif
         //fprintf(filter_fp, "%s\n", str);
      }
   }
   if ( 0 == syscfg_get(NULL, "block_cookies", webfilter_enable, sizeof(webfilter_enable)) ) {
      if ('\0' != webfilter_enable[0] && 0 != strncmp("0", webfilter_enable, sizeof(webfilter_enable)) ) {
#if 1 // RDKB-19924 Intel Proposed RDKB Generic Bug Fix
         //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m webstr --content\n");
#else
	 fprintf(filter_fp, "-A lan2wan_webfilters -p tcp -m tcp --dport 80 -m httpcookie --block-cookies\n");
#endif
         // fprintf(filter_fp, "%s\n", str);
      }
   }
         FIREWALL_DEBUG("Exiting do_lan2wan_webfilters\n");    
   return(0);
}
#endif

/*
 *  Procedure     : set_lan_access_restriction_start_stop
 *  Purpose       : set cron wakeups for the start and stop of a policy
 *  Parameters    :
 *     fp              : An open file where we write cron rules
 *     days            : A bit field describing the days that this policy is active
 *     start           : A string describing the start policy
 *     stop            : A string describing the stop policy
 *     h24             : 1 if this policy is for 24 hours, else 0
 *  Return Values :
 *     0               : done
 *    -1               : error
 */
static int set_lan_access_restriction_start_stop(FILE *fp, int days, char *start, char *stop, int h24)
{
   /*RDKB-7145, CID-33449, CID-33381,  initialize before use */
   int sh = 0;
   int sm = 0; 
   int eh = 0;
   int em = 0;
      FIREWALL_DEBUG("Entering set_lan_access_restriction_start_stop\n");    
   /*
    * If the policy is for 7 days per week and NO start/stop times, then we dont need
    * a cron rule because the policy is always active
    */
   if (0x7F == days && 0 != h24 ) {
      return(0);
   }

   if (h24) {
      sh = sm = eh = em = 0;   
   } else {
      if ('\0' != start[0]) {
         if (2 != sscanf(start, "%d:%d", &sh, &sm)) {
            return(-1);
         } else {
            if (2 != sscanf(stop, "%d:%d", &eh, &em)) {
               return(-1);
            }
         }
      }
   }

   char str[MAX_QUERY];
   char *strp;
   int   bytes;
   int   rc;


   // 1) set a wakeup for starting 
   strp = str;
   bytes = sizeof(str);
   str[0] = '\0';

   // minutes field
   rc = snprintf(strp, bytes, " %d", sm);
   strp += rc;
   bytes -= rc;

   // hours field
   rc = snprintf(strp, bytes, " %d", sh);
   strp += rc;
   bytes -= rc;

   // days of month, and month of year
   rc = snprintf(strp, bytes, " %s", "* * ");
   strp += rc;
   bytes -= rc;
           
   // day of the week
   int first = 0;
   int day;

   int mask;
   for (day=0; day<=6; day++) {
      mask = 1 << day;
      if (days & mask) {
         rc = snprintf(strp, bytes, "%s%d", (0 == first ? "" : ","), day);
         first=1;
         strp += rc;
         bytes -= rc;
      }
   }
   *strp = '\0';
   fprintf(fp, " %s %s\n", str, "sysevent set pp_flush 1 && sysevent set firewall-restart");

   // 2) set a wakeup for stopping 
   strp = str;
   bytes = sizeof(str);
   str[0] = '\0';
   rc = snprintf(strp, bytes, " %d", em);
   strp += rc;
   bytes -= rc;

   // hours field
   rc = snprintf(strp, bytes, " %d", eh);
   strp += rc;
   bytes -= rc;

   // days of month, and month of year
   rc = snprintf(strp, bytes, " %s", "* * ");
   strp += rc;
   bytes -= rc;
           
   // day of the week
   first = 0;
   for (day=0; day<=6; day++) {
      mask = 1 << day;
      if (days & mask) {
         // if this is a 24 hour policy then the stop time is the next day
         rc = snprintf(strp, bytes, "%s%d", (0 == first ? "" : ","), (0 == h24 ? day : 6 == day ? 0 : day+1) );
         first=1;
         strp += rc;
         bytes -= rc;
      }
   }
   *strp = '\0';
   fprintf(fp, " %s %s\n", str, "sysevent set pp_flush 1 && sysevent set firewall-restart");
      FIREWALL_DEBUG("Exiting set_lan_access_restriction_start_stop\n");    
   return(0);
}

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int set_lan_access_restriction_start(FILE *fp, int days, char *start, int h24)
{
   int sh;
   int sm;
      FIREWALL_DEBUG("Entering set_lan_access_restriction_start\n");    
   sscanf(start, "%d:%d", &sh, &sm);

   char str[MAX_QUERY];
   char *strp;
   int   bytes;
   int   rc;

   // 1) set a wakeup for starting 
   strp = str;
   bytes = sizeof(str);
   str[0] = '\0';

   // minutes field
   rc = snprintf(strp, bytes, " %d", sm);
   strp += rc;
   bytes -= rc;

   // hours field
   rc = snprintf(strp, bytes, " %d", sh);
   strp += rc;
   bytes -= rc;

   // days of month, and month of year
   rc = snprintf(strp, bytes, " %s", "* * ");
   strp += rc;
   bytes -= rc;
           
   // day of the week
   int first = 0;
   int day;

   int mask;
   for (day=0; day<=6; day++) {
      mask = 1 << day;
      if (days & mask) {
         rc = snprintf(strp, bytes, "%s%d", (0 == first ? "" : ","), day);
         first=1;
         strp += rc;
         bytes -= rc;
      }
   }
   *strp = '\0';
   fprintf(fp, " %s %s\n", str, "sysevent set firewall-restart");
      FIREWALL_DEBUG("Exiting set_lan_access_restriction_start\n");    
   return(0);
}
#endif

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int set_lan_access_restriction_stop(FILE *fp, int days, char *stop, int h24)
{
   int eh;
   int em;
   // FIREWALL_DEBUG("Entering set_lan_access_restriction_stop\n");  
   sscanf(stop, "%d:%d", &eh, &em);

   char str[MAX_QUERY];
   char *strp;
   int   bytes;
   int   rc;

   // 2) set a wakeup for stopping 
   strp = str;
   bytes = sizeof(str);
   str[0] = '\0';
   rc = snprintf(strp, bytes, " %d", em);
   strp += rc;
   bytes -= rc;

   // hours field
   rc = snprintf(strp, bytes, " %d", eh);
   strp += rc;
   bytes -= rc;

   // days of month, and month of year
   rc = snprintf(strp, bytes, " %s", "* * ");
   strp += rc;
   bytes -= rc;
           
   // day of the week
   int first = 0;
   int day;
   int mask;

   for (day=0; day<=6; day++) {
      mask = 1 << day;
      if (days & mask) {
         // if this is a 24 hour policy then the stop time is the next day
         rc = snprintf(strp, bytes, "%s%d", (0 == first ? "" : ","), (0 == h24 ? day : 6 == day ? 0 : day+1) );
         first=1;
         strp += rc;
         bytes -= rc;
      }
   }
   *strp = '\0';
   fprintf(fp, " %s %s\n", str, "sysevent set firewall-restart");
   // FIREWALL_DEBUG("Exiting set_lan_access_restriction_stop\n");  
   return(0);
}
#endif


/*
 *  Procedure     : do_lan_access_restrictions
 *  Purpose       : prepare the iptables-restore statements for all
 *                  syscfg defined Internet Access Restrictions lists
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
//unused function
#if 0
static int do_lan_access_restrictions(FILE *fp, FILE *nat_fp)
{

   char *cron_file = crontab_dir"/"crontab_filename;
   FILE *cron_fp = NULL; // the crontab file we use to set wakeups for timed firewall events
   cron_fp = fopen(cron_file, "w");
      
    FIREWALL_DEBUG("Entering do_lan_access_restrictions\n");  
   /*
    * syscfg tuple InternetAccessPolicy_x, where x is a digit
    * keeps track of the syscfg namespace of a user defined internet access policy.
    * We iterate through these tuples until we dont find an instance in syscfg.
    */ 
   int idx;
   int  rc;
   char namespace[MAX_QUERY];
   char query[MAX_QUERY];

   isCronRestartNeeded = 0;

   int count;
   query[0] = '\0';
   rc = syscfg_get(NULL, "InternetAccessPolicyCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      if(cron_fp){ /*RDKB-7145,CID-33038, free resource before exit*/
          fclose(cron_fp);
      }
      return(0);
   } else {
      count = atoi(query);
      if (0 == count) {
         if(cron_fp){ /*RDKB-7145,CID-33038, free resource before exit*/
             fclose(cron_fp);
         }
         return(0);
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      query[0] = '\0';
      snprintf(query, sizeof(query), "InternetAccessPolicy_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }
   
      // is this Internet Access Control list enabled
      query[0] = '\0';
      rc = syscfg_get(namespace, "enabled", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if (0 == strcmp("0", query)) {
        continue;
      }
   
      // Determine enforcement schedule and whether we are within the enforcement schedule right now
      int within_policy_start_stop = 0;

      query[0] = '\0';
      rc = syscfg_get(namespace, "enforcement_schedule", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         within_policy_start_stop = 1;
      } else  {
         int   policy_days = 127;
         char  policy_time_start[25];
         char  policy_time_stop[25];
 
         policy_time_start[0] = policy_time_stop[0] = '\0';
         sscanf(query, "%d %25s %25s", &policy_days, policy_time_start, policy_time_stop); 

         int h24 = 0;  // not 24 hours
         if ('\0' == policy_time_start[0] || '\0' == policy_time_stop[0]) {
            snprintf(policy_time_start, sizeof(policy_time_start), "0:0");
            snprintf(policy_time_stop, sizeof(policy_time_stop), "0:0");
            h24 = 1;
         }

         /*
          * Figure out if we are within the start/stop policy times
          * and prepare cron times to reevaluate the firewall based on policy changes
          * Note that if policy is not 24/7 and there is no reliable NTP, then we dont
          * apply policies
          */

         if (0x7F == policy_days && 1 == h24 ) {
            within_policy_start_stop = 1;
         } else if (isNtpFinished) {
            if (NULL != cron_fp) {
               set_lan_access_restriction_start_stop(cron_fp, policy_days, policy_time_start, policy_time_stop, h24);
               isCronRestartNeeded = 1;
            }

            /*
             * local time field wday provides the number of days since sunday
             * we convert that to a bit field where:
             *    1  = sunday
             *    2  = monday
             *    4  = tuesday
             *    8  = wednesday
             *   16  = thursday
             *   32  = friday
             *   64  = saturday
             */
            int today_bits = 0;
            today_bits = (1 << local_now.tm_wday);
            if(!(today_bits & policy_days)) {
            } else {
               if (1 == h24) {
                  within_policy_start_stop = 1;
               } else {
                  int hours, mins; 
                  if ( (-1 == time_delta(&local_now, policy_time_start, &hours, &mins)) ||
                         (hours == 0 && mins == 0) ) {
                     // if return from time_delta is -1 then we are past the policy_time_start.
                     // if return is 0 and hours = mins = 0, then we are at the policy_time_start
                     if (0 == time_delta(&local_now, policy_time_stop, &hours, &mins)) {
                        // we are before the end time too
                        within_policy_start_stop = 1;
                     }
                  }
               }
            }
         } else {
            continue;
         } 
      }

      // is this an allow or deny group
      int access_mode = 0; // deny
      char access[20];
      access[0] = '\0';
      rc = syscfg_get(namespace, "access", access, sizeof(access));
      if (0 == rc && 0 == strcmp("allow", access)) {
         access_mode = 1; 
      }

      /*
       * If this is a deny policy and we are not within the start/stop period
       * then ignore it
       */
      if (0 == access_mode && 0 == within_policy_start_stop) {
         continue;
      }

      char classification_table[50];
      char rules_table[50];
      snprintf(classification_table, sizeof(classification_table), "%s_classification", namespace);
      snprintf(rules_table, sizeof(rules_table), "%s_rules", namespace);


      // is there a list of local hosts to which this policy is applied
      char namespace2[MAX_QUERY];
      namespace2[0] = '\0';
      rc = syscfg_get(namespace, "local_host_list", namespace2, sizeof(namespace2));
      if (0 != rc || '\0' == namespace2[0]) {
         continue;
      }

      char str[MAX_QUERY];
      fprintf(fp, ":%s - [0:0]\n", classification_table);
      snprintf(str, sizeof(str),
               "-N %s", classification_table); 
      snprintf(str, sizeof(str),
               "-F %s", classification_table); 

      fprintf(fp, ":%s - [0:0]\n", rules_table);
      snprintf(str, sizeof(str),
               "-N %s", rules_table); 
      snprintf(str, sizeof(str),
               "-F %s", rules_table); 

      fprintf(fp, "-A lan2wan_iap -j %s\n", classification_table);

      fprintf(fp, "-A lan2wan_iap -j %s\n", rules_table);

      char block_device[MAX_QUERY];
      char block_site[MAX_QUERY];
      char block_service[MAX_QUERY];

      snprintf(block_device, sizeof(block_device), "LOG_DeviceBlocked_%d_DROP", idx);
      snprintf(block_site, sizeof(block_site), "LOG_SiteBlocked_%d_DROP", idx);
      snprintf(block_service, sizeof(block_service), "LOG_ServiceBlocked_%d_DROP", idx);

      fprintf(fp, ":LOG_DeviceBlocked_%d_DROP: - [0:0]\n", idx);
      fprintf(fp, "-N LOG_DeviceBlocked_%d_DROP\n", idx);
      fprintf(fp, "-F LOG_DeviceBlocked_%d_DROP\n", idx);

      fprintf(fp, ":LOG_SiteBlocked_%d_DROP: - [0:0]\n", idx);
      fprintf(fp, "-N LOG_SiteBlocked_%d_DROP\n", idx);
      fprintf(fp, "-F LOG_SiteBlocked_%d_DROP\n", idx);

      fprintf(fp, ":LOG_ServiceBlocked_%d_DROP: - [0:0]\n", idx);
      fprintf(fp, "-N LOG_ServiceBlocked_%d_DROP\n", idx);
      fprintf(fp, "-F LOG_ServiceBlocked_%d_DROP\n", idx);

      if (isLogEnabled)
      {
         fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1 -j LOG --log-prefix LOG_DeviceBlocked_%d_DROP\n", idx, idx);
         fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1 -j LOG --log-prefix LOG_SiteBlocked_%d_DROP\n", idx, idx);
         fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1 -j LOG --log-prefix LOG_ServiceBlocked_%d_DROP\n", idx, idx);
      }

      fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -j DROP\n", idx);
      fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -j DROP\n", idx);
      fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -j DROP\n", idx);
         
      char query2[100];
      query2[0] = '\0';
      int count2;

      rc = syscfg_get(namespace2, "InternetAccessPolicyIPHostCount", query2, sizeof(query2));
      if (0 != rc || '\0' == query2[0]) {
         goto InternetAccessPolicyNext;
      } else {
         count2 = atoi(query2);
         if (0 == count2) {
            goto InternetAccessPolicyNext;
         }
         if (MAX_SYSCFG_ENTRIES < count2) {
            count2 = MAX_SYSCFG_ENTRIES;
         }
      }

      int i;
      int srcNum = 0;
      char src_ip[MAX_SRC_IP_TABLE_ROW][MAX_SRC_IP_ENTRY_LEN];
      // add ip hosts to classification table
      for (i=1; i<=count2; i++) {
         char tstr[50];
         char ip[25];
         ip[0] = '\0';
         snprintf(tstr, sizeof(tstr), "ip_%d", i);
         rc = syscfg_get(namespace2, tstr, ip, sizeof(ip));

         /* RDKB-7145, CID-33123, Out-of-bounds read
         ** "srcNum" can reach a MAX value of "MAX_SYSCFG_ENTRIES-1".
         ** Using which to access array src_ip[srcNum][] will lead to out of bound access.
         ** Adding upper and lower boundary check to comply with Coverity Static analysis
         */
         if(i > MAX_SRC_IP_TABLE_ROW-1)
         {
             srcNum = MAX_SRC_IP_TABLE_ROW-1;
         }
         else
         {
             srcNum = i-1;
         }

         sprintf(src_ip[srcNum], "%s.%s", lan_3_octets, ip);
         if (0 != rc || '\0' == ip[0]) {
            continue;
         } else {
           fprintf(fp, "-A %s -s %s.%s -j %s\n", classification_table, lan_3_octets, ip, ( (0 == access_mode) || (1 == access_mode && 0 == within_policy_start_stop)) ? block_device : rules_table);

         }   
      }

InternetAccessPolicyNext:
      query2[0] = '\0';
      rc = syscfg_get(namespace2, "InternetAccessPolicyIPRangeCount", query2, sizeof(query2));
      if (0 != rc || '\0' == query2[0]) {
         goto InternetAccessPolicyNext2;
      } else {
         count2 = atoi(query2);
         if (0 == count2) {
            goto InternetAccessPolicyNext2;
         }
         if (MAX_SYSCFG_ENTRIES < count2) {
            count2 = MAX_SYSCFG_ENTRIES;
         }
      }

      // add ip ranges to classification table
      for (i=1; i<=count2 ; i++) {
         char tstr[100];
         char ip[25];
         ip[0] = '\0';
         snprintf(tstr, sizeof(tstr), "ip_range_%d", i);
         rc = syscfg_get(namespace2, tstr, ip, sizeof(ip));
         if (0 != rc || '\0' == ip[0]) {
            continue;
         } else {
            int first, last;
            if (2 == sscanf(ip, "%d %d", &first, &last)) {
              fprintf(fp, "-A %s -m iprange --src-range %s.%d-%s.%d -j %s\n", classification_table, lan_3_octets, first, lan_3_octets, last, ( (0 == access_mode) || (1 == access_mode && 0 == within_policy_start_stop)) ? block_device : rules_table);
            }
         }   
      }

InternetAccessPolicyNext2:
      query2[0] = '\0';
      rc = syscfg_get(namespace2, "InternetAccessPolicyMacCount", query2, sizeof(query2));
      if (0 != rc || '\0' == query2[0]) {
         goto InternetAccessPolicyNext3;
      } else {
         count2 = atoi(query2);
         if (0 == count2) {
            goto InternetAccessPolicyNext3;
         }
         if (MAX_SYSCFG_ENTRIES < count2) {
            count2 = MAX_SYSCFG_ENTRIES;
         }
      }

      // add mac hosts to classification table
      for (i=1; i<=count2; i++) {
         char tstr[100];
         char mac[25];
         mac[0] = '\0';
         snprintf(tstr, sizeof(tstr), "mac_%d", i);
         rc = syscfg_get(namespace2, tstr, mac, sizeof(mac));
         if (0 != rc || '\0' == mac[0]) {
            continue;
         } else {
            fprintf(fp, "-A %s -m mac --mac-source %s -j %s\n", classification_table, mac, ( (0 == access_mode) || (1 == access_mode && 0 == within_policy_start_stop)) ? block_device : rules_table);
         }   
      }

InternetAccessPolicyNext3:
   if (1 == access_mode && 1 == within_policy_start_stop) {
         int count;
         char count_str[MAX_QUERY];
         //char dst_host[MAX_QUERY] ={'\0'};
         char block_page[MAX_QUERY] ={'\0'};
         char blockPage[MAX_QUERY] ={'\0'};
         int host_name_offset = 0; 
         //syscfg_get(NULL, "lan_ipaddr", dst_host, sizeof(dst_host));
         
         /*Currently the redirection is happening only to an IP*/ 
         rc = syscfg_get(NULL, "blocked_error_url", blockPage, sizeof(blockPage));
         if(rc !=0 || '\0' != blockPage[0]){
             strcpy(block_page, "/cosa/cpehelp/");
         }else{
             sprintf(block_page, "%sPolicy=%d", blockPage, idx);
         }
         //ulogf(ULOG_FIREWALL, UL_INFO, "dst_host=%s, block_page=%s@@@\n", dst_host, block_page);

         // block urls
         count_str[0] = '\0';
         rc = syscfg_get(namespace, "BlockUrlCount", count_str, sizeof(count_str));
         if (0 == rc && '\0' != count_str[0]) {
            count = atoi(count_str);
         } else { 
            count = 0;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }

         for (i=1; i<=count ; i++) {
            char tstr[100];
            int src_cnt;
            //char cmd[512] = {'\0'};
            char url[MAX_QUERY];
            url[0] = '\0';
            snprintf(tstr, sizeof(tstr), "BlockUrl_%d", i);
            rc = syscfg_get(namespace, tstr, url, sizeof(url));
            if (0 != rc || '\0' == url[0]) {
               continue;
            } else {
               host_name_offset = 0;
               
               // Strip http:// or https:// from the beginning of the URL
               // string so that only the host name is passed in
               if (0 == strncmp(url, "http://", STRLEN_HTTP_URL_PREFIX)) {
                  host_name_offset = STRLEN_HTTP_URL_PREFIX;
               }
               else if (0 == strncmp(url, "https://", STRLEN_HTTPS_URL_PREFIX)) {
                  host_name_offset = STRLEN_HTTPS_URL_PREFIX;
               }
#if defined (INTEL_PUMA7)
               //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
               snprintf(str, sizeof(str), 
                        "-A %s -p tcp -m tcp --dport 80 -m webstr --host \"%s\" -j %s",
                        rules_table, url + host_name_offset, block_site);
#elif defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
               snprintf(str, sizeof(str), 
                        "-A %s -p tcp -m tcp --dport 80 -d \"%s\" -j %s",
                        rules_table, url + host_name_offset, block_site);
#else
               snprintf(str, sizeof(str), 
                        "-A %s -p tcp -m tcp --dport 80 -m httphost --host \"%s\" -j %s",
                        rules_table, url + host_name_offset, block_site);
#endif
               fprintf(fp, "%s\n", str);

               for(src_cnt = 0; src_cnt <= srcNum; src_cnt++){
                   snprintf(str, sizeof(str),
                            "-A prerouting_fromlan -p tcp -s %s -d %s --dport 80 -j REDIRECT --to-port 81",
                                                                src_ip[src_cnt], url + host_name_offset);
                   fprintf(nat_fp, "%s\n", str);
                   //sprintf(cmd, "iptables %s", str);
                   //system(cmd);
                   ulogf(ULOG_FIREWALL, UL_INFO, "Hitting Policy-%d, HTTP request for %s from client %s", idx, url, src_ip[src_cnt]);
                   memset(str, 0, sizeof(str));
                   //memset(cmd, 0, sizeof(cmd));
	       }
            }   
         }

         // block keywords in http GET
         count_str[0] = '\0';
         rc = syscfg_get(namespace, "BlockKeywordCount", count_str, sizeof(count_str));
         if (0 == rc && '\0' != count_str[0]) {
            count = atoi(count_str);
         } else { 
            count = 0;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }
         for (i=1; i<=count ; i++) {
            char tstr[100];
            char url[MAX_QUERY];
            url[0] = '\0';
            snprintf(tstr, sizeof(tstr), "BlockKeyword_%d", i);
            rc = syscfg_get(namespace, tstr, url, sizeof(url));
            if (0 != rc || '\0' == url[0]) {
               continue;
            } else {
               fprintf(fp, "-A %s -p tcp -m tcp  -m string --string \"%s\" --algo kmp -j %s\n", rules_table, url, block_site);
            }   
         }

         // block normalized applications
         count_str[0] = '\0';
         rc = syscfg_get(namespace, "BlockApplicationCount", count_str, sizeof(count_str));
         if (0 == rc && '\0' != count_str[0]) {
            count = atoi(count_str);
         } else {
            count = 0;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }

         for (i=1;i<=count; i++) {
            char tstr[100];
            snprintf(tstr, sizeof(tstr), "BlockApplication_%d", i);
            char namespace2[MAX_QUERY];
            namespace2[0] = '\0';
            rc = syscfg_get(namespace, tstr, namespace2, sizeof(namespace2));
            if (0 != rc || '\0' == namespace2[0]) {
               continue;
            } else {
               char prot[10];
               int  proto;
               char portrange[30];
               char sdport[10];
               char edport[10];

               proto = 0; // 0 is both, 1 is tcp, 2 is udp
               prot[0] = '\0';
               rc = syscfg_get(namespace2, "protocol", prot, sizeof(prot));
               if (0 != rc || '\0' == prot[0]) {
                  proto = 0;
               } else if (0 == strcmp("tcp", prot)) {
                  proto = 1;
               } else   if (0 == strcmp("udp", prot)) {
                  proto = 2;
               }

               portrange[0]= '\0';
               sdport[0]   = '\0';
               edport[0]   = '\0';
               rc = syscfg_get(namespace2, "port_range", portrange, sizeof(portrange));
               if (0 != rc || '\0' == portrange[0]) {
                  continue;
               } else {
                  int r = 0;
                  if (2 != (r = sscanf(portrange, "%10s %10s", sdport, edport))) {
                     if (1 == r) {
                        snprintf(edport, sizeof(edport), "%s", sdport);
                     } else {
                        continue;
                     }
                  }
               }
               if (0 == proto || 1 ==  proto) {
                  fprintf(fp, "-A %s -p tcp -m tcp --dport %s:%s -j %s\n", rules_table, sdport, edport, block_service);

               }

               if (0 == proto || 2 ==  proto) {
                  fprintf(fp, "-A %s -p udp -m udp --dport %s:%s -j %s\n", rules_table, sdport, edport, block_service);
               }
            }
         }

         // block applications
         count_str[0] = '\0';
         rc = syscfg_get(namespace, "BlockApplicationRuleCount", count_str, sizeof(count_str));
         if (0 == rc && '\0' != count_str[0]) {
            count = atoi(count_str);
         } else {
            count = 0;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }

         for (i=1;i<=count; i++) {
            char tstr[100];
            char app[1025];
            app[0] = '\0';
            snprintf(tstr, sizeof(tstr), "BlockApplicationRule_%d", i);
            rc = syscfg_get(namespace, tstr, app, sizeof(app));
            if (0 != rc || '\0' == app[0]) {
               continue;
            } else {
               char str[MAX_QUERY];
               fprintf(fp, "-A %s %s -j %s\n", rules_table, app, block_service);

            }   
         }

         // block well-known applications
         count_str[0] = '\0';
         rc = syscfg_get(namespace, "BlockWellknownApplicationCount", count_str, sizeof(count_str));
         if (0 == rc && '\0' != count_str[0]) {
            count = atoi(count_str);
         } else {
            count = 0;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }
         if (0 < count) {
            char *filename = wellknown_ports_file_dir"/"wellknown_ports_file;
            FILE *wkp_fp = fopen(filename, "r");
            if (NULL != wkp_fp) {
               for (i=1; i<=count; i++) {
                  char tstr[100];
                  char name[100];
                  name[0] = '\0';
                  snprintf(tstr, sizeof(tstr), "BlockWellknownApplication_%d", i);
                  rc = syscfg_get(namespace, tstr, name, sizeof(name));
                  if (0 != rc || '\0' == name[0]) {
                     continue;
                  } else {
                     write_block_application_statement(fp, wkp_fp, rules_table, name); 
                  }
               }   
               fclose(wkp_fp);
            }
         }
      }

      if (1 == access_mode && 1 == within_policy_start_stop) {
         // block special application - ping
         char tstr[100];
         tstr[0] = '\0';
         rc = syscfg_get(namespace, "BlockPing", tstr, sizeof(tstr));
         if (0 == rc && 0 == strcmp(tstr, "1")) {
            fprintf(fp, "-A %s -p icmp --icmp-type 8 -j xlogreject\n", rules_table);
         }
      }
   }

   if (cron_fp) { /*RDKB-7145,CID-33038, free resource before exit*/
       fclose(cron_fp);
   }
   if (!isCronRestartNeeded) {
      unlink(cron_file);
   }
    FIREWALL_DEBUG("Exiting do_lan_access_restrictions\n");  
   return(0);
}
#endif

// Determine enforcement schedule and whether we are within the enforcement schedule right now
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
static int determine_enforcement_schedule(FILE *cron_fp, const char *namespace) 
{
   int rc;
   char query[MAX_QUERY];
    FIREWALL_DEBUG("Entering determine_enforcement_schedule\n");  
   int always = 1;
   query[0] = '\0';
   errno_t safec_rc = -1;
   rc = syscfg_get(namespace, "always", query, sizeof(query));
   if (0 != rc || '\0' == query[0] || query[0] == '0') always = 0;

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   if (always) return 0;
#else
   if (always) return 1;
#endif

   int policy_days = 0;
   char policy_time_start[25], policy_time_stop[25];

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   char timeStr[sizeof("00:00,12:00")];
   char policy_time_start_weekends[sizeof("00:00")], policy_time_stop_weekends[sizeof("00:00")];

   rc = syscfg_get(namespace, "end_time", timeStr, sizeof(timeStr));
   if (rc != 0 || timeStr[0] == '\0'){
       safec_rc = strcpy_s(timeStr, sizeof(timeStr),"0:0,0:0");
       ERR_CHK(safec_rc);
   }
   char *pch = strchr(timeStr, ',');
   *pch = '\0';

   safec_rc = strcpy_s(policy_time_start, sizeof(policy_time_start),timeStr);
   ERR_CHK(safec_rc);
   safec_rc = strcpy_s(policy_time_start_weekends, sizeof(policy_time_start_weekends),pch+1);
   ERR_CHK(safec_rc);

   rc = syscfg_get(namespace, "start_time", timeStr, sizeof(timeStr));
   if (rc != 0 || timeStr[0] == '\0'){
       safec_rc = strcpy_s(timeStr, sizeof(timeStr),"0:0,0:0");
       ERR_CHK(safec_rc);
   }

   pch = strchr(timeStr, ',');
   *pch = '\0';

   safec_rc = strcpy_s(policy_time_stop, sizeof(policy_time_stop),timeStr);
   ERR_CHK(safec_rc);
   safec_rc = strcpy_s(policy_time_stop_weekends, sizeof(policy_time_stop_weekends),pch+1);
   ERR_CHK(safec_rc);
#else
   rc = syscfg_get(namespace, "start_time", policy_time_start, sizeof(policy_time_start));
   if (rc != 0 || policy_time_start[0] == '\0'){
      safec_rc = strcpy_s(policy_time_start, sizeof(policy_time_start),"0:0");
      ERR_CHK(safec_rc);
   }

   rc = syscfg_get(namespace, "end_time", policy_time_stop, sizeof(policy_time_stop));
   if (rc != 0 || policy_time_stop[0] == '\0'){
      safec_rc = strcpy_s(policy_time_stop, sizeof(policy_time_stop),"0:0");
      ERR_CHK(safec_rc);
   }
#endif

   query[0] = '\0';
   rc = syscfg_get(namespace, "days", query, sizeof(query));

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   if(strcasecmp(query, "never") == 0 || query[0] == 0)
       return 1;
#endif

   if (rc == 0)
   {
      char *ptr, *next_ptr;
      for (ptr = query; ptr && *ptr;ptr = next_ptr)
      {
         next_ptr = strchr(ptr, ',');
         if (next_ptr) *(next_ptr++) = '\0';
         if (strncasecmp(ptr, "SUN", 3) == 0) policy_days |= 1<<0;
         else if (strncasecmp(ptr, "MON", 3) == 0) policy_days |= 1<<1;
         else if (strncasecmp(ptr, "TUE", 3) == 0) policy_days |= 1<<2;
         else if (strncasecmp(ptr, "WED", 3) == 0) policy_days |= 1<<3;
         else if (strncasecmp(ptr, "THU", 3) == 0) policy_days |= 1<<4;
         else if (strncasecmp(ptr, "FRI", 3) == 0) policy_days |= 1<<5;
         else if (strncasecmp(ptr, "SAT", 3) == 0) policy_days |= 1<<6;
      }
   }

   int h24 = 0;  // not 24 hours

   if (cron_fp)
   {
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
      set_lan_access_restriction_start(cron_fp, 0x3e, policy_time_start, 0); //Mon ~ Fri
      set_lan_access_restriction_stop(cron_fp, 0x1F, policy_time_stop, 0); //Sun ~ Thu
      set_lan_access_restriction_start(cron_fp, 0x41, policy_time_start_weekends, 0); //Sat, Sun
      set_lan_access_restriction_stop(cron_fp, 0x60, policy_time_stop_weekends, 0); //Fri, Sat
      policy_days = 0x7f;
#else
      set_lan_access_restriction_start_stop(cron_fp, policy_days, policy_time_start, policy_time_stop, h24);
#endif
      isCronRestartNeeded = 1;
   }

   int within_policy_start_stop = 0;

   int today_bits = 0;
   today_bits = (1 << local_now.tm_wday);
   if(!(today_bits & policy_days)) {
   } else {
      if (1 == h24) {
         within_policy_start_stop = 1;
      } else {
         int startPassedHours, startPassedMins;
         int stopPassedHours, stopPassedMins;
         int startPass, stopPass;
         int sh, sm, eh, em;

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
         if(today_bits & 0x3e) { //Mon ~ Fri
             sscanf(policy_time_start, "%d:%d", &sh, &sm);
             startPass = time_delta(&local_now, policy_time_start, &startPassedHours, &startPassedMins);
         }

         if(today_bits & 0x1F) { //Sun ~ Thu
             sscanf(policy_time_stop, "%d:%d", &eh, &em);
             stopPass = time_delta(&local_now, policy_time_stop, &stopPassedHours, &stopPassedMins);
         }

         if(today_bits & 0x41) { //Sat, Sun
             sscanf(policy_time_start_weekends, "%d:%d", &sh, &sm);
             startPass = time_delta(&local_now, policy_time_start_weekends, &startPassedHours, &startPassedMins);
         }

         if(today_bits & 0x60) { //Fri, Sat
             sscanf(policy_time_stop_weekends, "%d:%d", &eh, &em);
             stopPass = time_delta(&local_now, policy_time_stop_weekends, &stopPassedHours, &stopPassedMins);
         }
#else
         sscanf(policy_time_start, "%d:%d", &sh, &sm);
         sscanf(policy_time_stop, "%d:%d", &eh, &em);

         startPass = time_delta(&local_now, policy_time_start, &startPassedHours, &startPassedMins);
         stopPass = time_delta(&local_now, policy_time_stop, &stopPassedHours, &stopPassedMins);
#endif
         //start time > stop time
         if(sh > eh || (sh == eh && sm >= em)) {
             if(!((stopPass == -1 || (stopPass == 0 && stopPassedHours == 0 && stopPassedMins == 0))
                 && startPass == 0))
               within_policy_start_stop = 1;
         }
         else { //start time < stop time
             //printf("today is %d, start time is %d, stop time is %d\n", today_bits, sh, eh);
             if((startPass == -1 || (startPass == 0 && startPassedHours == 0 && startPassedMins == 0))
                 && stopPass == 0) {
               within_policy_start_stop = 1;
             }
         }
       }
   }
    FIREWALL_DEBUG("Exiting determine_enforcement_schedule\n");  
   return within_policy_start_stop;
}
#endif

static int determine_enforcement_schedule2(FILE *cron_fp, const char *namespace) 
{
   int rc;
   char query[MAX_QUERY];
    FIREWALL_DEBUG("Entering determine_enforcement_schedule2\n");  
   int always = 1;
   query[0] = '\0';
   rc = syscfg_get(namespace, "always", query, sizeof(query));
   if (0 != rc || '\0' == query[0] || query[0] == '0') always = 0;

   if (always) return 1;

   int policy_days = 0;
   char policy_time_start[25], policy_time_stop[25];
   errno_t safec_rc = -1;

   rc = syscfg_get(namespace, "start_time", policy_time_start, sizeof(policy_time_start));
   if (rc != 0 || policy_time_start[0] == '\0'){
     safec_rc = strcpy_s(policy_time_start, sizeof(policy_time_start),"0:0");
     ERR_CHK(safec_rc);
   }

   rc = syscfg_get(namespace, "end_time", policy_time_stop, sizeof(policy_time_stop));
   if (rc != 0 || policy_time_stop[0] == '\0'){
      safec_rc = strcpy_s(policy_time_stop, sizeof(policy_time_stop),"0:0");
      ERR_CHK(safec_rc);
   }

   query[0] = '\0';
   rc = syscfg_get(namespace, "days", query, sizeof(query));

   if (rc == 0)
   {
      char *ptr, *next_ptr;
      for (ptr = query; ptr && *ptr;ptr = next_ptr)
      {
         next_ptr = strchr(ptr, ',');
         if (next_ptr) *(next_ptr++) = '\0';
         if (strncasecmp(ptr, "SUN", 3) == 0) policy_days |= 1<<0;
         else if (strncasecmp(ptr, "MON", 3) == 0) policy_days |= 1<<1;
         else if (strncasecmp(ptr, "TUE", 3) == 0) policy_days |= 1<<2;
         else if (strncasecmp(ptr, "WED", 3) == 0) policy_days |= 1<<3;
         else if (strncasecmp(ptr, "THU", 3) == 0) policy_days |= 1<<4;
         else if (strncasecmp(ptr, "FRI", 3) == 0) policy_days |= 1<<5;
         else if (strncasecmp(ptr, "SAT", 3) == 0) policy_days |= 1<<6;
      }
   }

   int h24 = 0;  // not 24 hours

   if (cron_fp)
   {
      set_lan_access_restriction_start_stop(cron_fp, policy_days, policy_time_start, policy_time_stop, h24);
      isCronRestartNeeded = 1;
   }

   int within_policy_start_stop = 0;

   int today_bits = 0;
   today_bits = (1 << local_now.tm_wday);
   if(!(today_bits & policy_days)) {
   } else {
      if (1 == h24) {
         within_policy_start_stop = 1;
      } else {
         int startPassedHours, startPassedMins;
         int stopPassedHours, stopPassedMins;
         int startPass, stopPass;
         int sh, sm, eh, em;


         sscanf(policy_time_start, "%d:%d", &sh, &sm);
         sscanf(policy_time_stop, "%d:%d", &eh, &em);

         startPass = time_delta(&local_now, policy_time_start, &startPassedHours, &startPassedMins);
         stopPass = time_delta(&local_now, policy_time_stop, &stopPassedHours, &stopPassedMins);
         
         //start time > stop time
         if(sh > eh || (sh == eh && sm >= em)) {
             if(!((stopPass == -1 || (stopPass == 0 && stopPassedHours == 0 && stopPassedMins == 0))
                 && startPass == 0))
               within_policy_start_stop = 1;
         }
         else { //start time < stop time
             //printf("today is %d, start time is %d, stop time is %d\n", today_bits, sh, eh);
             if((startPass == -1 || (startPass == 0 && startPassedHours == 0 && startPassedMins == 0))
                 && stopPass == 0) {
               within_policy_start_stop = 1;
             }
         }
       }
   }
    FIREWALL_DEBUG("Exiting determine_enforcement_schedule2\n");  
   return within_policy_start_stop;
}

#ifndef _HUB4_PRODUCT_REQ_
static int getipv4_fromhostdesc(char *listname,char *hostdesc, char *ipv4, int ipv4_max_size)
{
    int count=0, idx, rc;
    char query[MAX_QUERY], result[MAX_QUERY];

    if (!listname || !hostdesc || !ipv4 || !ipv4_max_size)
        return -1;

    snprintf(query, sizeof(query), "%sCount", listname);
    result[0] = '\0';
    rc = syscfg_get(NULL, query, result, sizeof(result));
    if (rc == 0 && result[0] != '\0') count = atoi(result);
    if (count < 0) count = 0;
    if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;
    for (idx = 1; idx <= count; idx++)
    {
        char namespace[MAX_QUERY];
        snprintf(query, sizeof(query), "%s_%d", listname, idx);
        namespace[0] = '\0';
        rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
        if (0 != rc || '\0' == namespace[0]) {
            continue;
        }
        int this_iptype = 4;
        query[0] = '\0';
        rc = syscfg_get(namespace, "ip_type", query, sizeof(query));
        if (rc == 0 && query[0] != '\0') this_iptype = atoi(query);
        if (this_iptype != 6) this_iptype = 4;

        if (6 == this_iptype)
            continue;
        query[0] = '\0';
        rc = syscfg_get(namespace, "desc", query, sizeof(query));
        if (rc == 0 && query[0] != '\0')
        {
            if (!strcmp(query,hostdesc))
            {
                query[0] = '\0';
                rc = syscfg_get(namespace, "ip_addr", query, sizeof(query));
                if (rc == 0 && query[0] != '\0')
                {
                    strncpy(ipv4,query,ipv4_max_size);
                    break;
                }
            }
        }
    }

    return 0; 
}

static int getmacaddress_fromip(char *ipaddress, int iptype, char *mac, int mac_size)
{
    FILE *fp = NULL;
    char buf[200] = {0};
    char output[50] = {0};

    if (!ipaddress || !mac || !mac_size)
        return -1;
    memset(buf,0,200);
    memset(output,0,50);
    if (4 == iptype)
    {
        fp = v_secure_popen("r","ip nei show | grep brlan0 | grep -i %s | awk '{print $5}' ", ipaddress);
    }
    else
    {
        fp = v_secure_popen("r","ip -6 nei show | grep brlan0 | grep -i %s | awk '{print $5}' ", ipaddress);
    }
    if(!fp)
    {
        return -1;
    }
    while(fgets(output, sizeof(output), fp)!=NULL)
    {
        output[strlen(output) - 1] = '\0';
        strncpy(mac,output,mac_size);
        break;
    }
    v_secure_pclose(fp);
    return 0;
}
#endif

/*
 *  Procedure     : do_parental_control_allow_trusted
 *  Purpose       : prepare the iptables-restore statements for parental control trusted user
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *     iptype          : 4 or 6
 *     list_name       : syscfg name for user list
 *     table_name      : iptable name for rules
 *  Return Values :
 *     0               : done
 */
static int do_parental_control_allow_trusted(FILE *fp, int iptype, const char* list_name, const char* table_name)
{
   int count=0, idx, rc;
   int count_v4=0, count_v6=0;
   char query[MAX_QUERY], result[MAX_QUERY];
    FIREWALL_DEBUG("Entering do_parental_control_allow_trusted\n");  
   snprintf(query, sizeof(query), "%sCount", list_name);

   result[0] = '\0';
   rc = syscfg_get(NULL, query, result, sizeof(result)); 
   if (rc == 0 && result[0] != '\0') count = atoi(result);
   if (count < 0) count = 0;
   if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;
   for (idx = 1; idx <= count; idx++)
   {
      char namespace[MAX_QUERY];
      snprintf(query, sizeof(query), "%s_%d", list_name, idx);
      namespace[0] = '\0';
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }

      int trusted = 1;
      query[0] = '\0';
      rc = syscfg_get(namespace, "trusted", query, sizeof(query));
      if (0 != rc || '\0' == query[0] || query[0] == '0') trusted = 0;

      if (!trusted) continue;

      int this_iptype = 4;
      query[0] = '\0';
      rc = syscfg_get(namespace, "ip_type", query, sizeof(query)); 
      if (rc == 0 && query[0] != '\0') this_iptype = atoi(query);
      if (this_iptype != 6) this_iptype = 4;

#if defined(_HUB4_PRODUCT_REQ_) || defined(FEATURE_MAPT)
      /* Add the service rules for V6 table on MAPT line and Dual stack, since this rules were added only for V4, needed for v6 also. 
         As of now 'this_iptype' value is always '4', blocking the rule for v6 */
      if ((this_iptype == iptype) || (iptype == 6))
#else
      if (this_iptype == iptype)
#endif
      {
#if defined(_HUB4_PRODUCT_REQ_)
         char mac[32];
         memset(mac,0,sizeof(mac));

         rc = syscfg_get(namespace, "mac_addr", mac, sizeof(mac));
         if (rc == 0 && mac[0] != '\0')
         {
                this_iptype == 4 ? ++count_v4 : ++count_v6;
                fprintf(fp, "-A %s -m mac --mac-source %s -j RETURN\n", table_name, mac);
         }
#else
         query[0] = '\0';
         rc = syscfg_get(namespace, "ip_addr", query, sizeof(query)); 
         if (rc == 0 && query[0] != '\0')
         {
            char mac[32];
            int ret = 0;
            char hostDesc[64];
            char ipaddress[64];
            memset(mac,0,sizeof(mac));
            // ARRISXB6-10410 - Allow Trusted computer based on mac address.
            ret = getmacaddress_fromip(query,iptype,mac,sizeof(mac));
            if ((0 == ret) && (strlen(mac) > 0))
            {
                this_iptype == 4 ? ++count_v4 : ++count_v6;
                fprintf(fp, "-A %s -m mac --mac-source %s -j RETURN\n", table_name, mac);
            }
            else
            {   // !!! fail safe for ipv6: check and get mac address using ipv4.
                if (6 == iptype)
                {
                    memset(hostDesc,0,sizeof(hostDesc));
                    memset(ipaddress,0,sizeof(ipaddress));
                    rc = syscfg_get(namespace, "desc", hostDesc, sizeof(hostDesc));
                    if (rc == 0 && (strlen(hostDesc) > 0))
                    {
                        int retval = 0;
                        retval = getipv4_fromhostdesc((char *)list_name,hostDesc,ipaddress,sizeof(ipaddress));  
                        if (strlen(ipaddress) > 0 && (retval == 0))
                        {
                            ret = getmacaddress_fromip(ipaddress,4,mac,sizeof(mac));
                            if ((0 == ret) && (strlen(mac) > 0))
                            {
                                ++count_v6;
                                fprintf(fp, "-A %s -m mac --mac-source %s -j RETURN\n", table_name, mac);
                            }
                        }
                    }
                }
            }
         }
#endif
      }
   }
    FIREWALL_DEBUG("Exiting do_parental_control_allow_trusted\n");  
   return iptype == 4 ? count_v4 : count_v6;
}
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
void block_url_by_ipaddr(FILE *fp, char *url, char *dropLog, int ipver, char *insNum, const char *nstdPort)
{
    //IPv4, NAT table will REDIRECT those ip, so needn't add rule in filter table 
//    if(ipver == 6){
//         if(nstdPort[0] == '\0')
//         {
//            fprintf(fp, "-A lan2wan_pc_site  -p tcp -m tcp --dport 80 -m set --match-set %s_v6 dst -m comment --comment \"host match %s \" -j %s\n", insNum, url, dropLog);
//            fprintf(fp, "-A lan2wan_pc_site  -p tcp -m tcp --dport 443 -m set --match-set %s_v6 dst -m comment --comment \"host match %s \" -j %s\n", insNum, url, dropLog);
//         }
//         else
//            fprintf(fp, "-A lan2wan_pc_site  -p tcp -m tcp --dport %s -m set --match-set %s_v6 dst -m comment --comment \"host match %s \" -j %s\n", nstdPort, insNum, url, dropLog);
//    }
}
#else
void block_url_by_ipaddr(FILE *fp, char *url, char *dropLog, int ipver, char *insNum, const char *nstdPort)
{
    char filePath[256];
    char ipAddr[40];
    FILE *ipRecords = NULL;
    int len;
    int dnsResponse = 0;
    FIREWALL_DEBUG("Entering block_url_by_ipaddr\n");  
    if(ipver == 6)
        snprintf(filePath, sizeof(filePath), "/var/.pc_url2ipv6_%s", insNum);
    else
        snprintf(filePath, sizeof(filePath), "/var/.pc_url2ip_%s", insNum);

/* * Actually needs to get IP address of every firewall-restart iteration otherwise blocking wont work properly */
#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      ipRecords = fopen(filePath, "r");
   }
#endif /* * _HUB4_PRODUCT_REQ_ */

    if(ipRecords == NULL) {
        struct addrinfo hints, *res, *p;
        int status;
        ipRecords = fopen(filePath, "w+"); /*RDKB-7145, CID-32907, optimizing the resource used*/
 	if (ipRecords != NULL) { /*RDKB-12965 & CID:-32907 & CID:-34143 */
        memset(&hints, 0, sizeof(hints));
        if(ipver == 6)
            hints.ai_family = AF_INET6;
        else
            hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if ((status = getaddrinfo(url, NULL, &hints, &res)) != 0) {
            fclose(ipRecords);
            if(dnsResponse == 0)
                unlink(filePath);
            FIREWALL_DEBUG("Exiting block_url_by_ipaddr\n");  
            return;
        }

        for(p = res;p != NULL; p = p->ai_next) {
            if((ipver == 6 && p->ai_family == AF_INET) || \
               (ipver == 4 && p->ai_family == AF_INET6))
                continue;

            void *addr;
            if(ipver == 4){
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = &(ipv4->sin_addr);
            }else{
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }
            inet_ntop(p->ai_family, addr, ipAddr, sizeof(ipAddr));
            fprintf(ipRecords, "%s\n", ipAddr);
        }

        freeaddrinfo(res);
        rewind(ipRecords);
	}
    }

    memset(ipAddr, 0, sizeof(ipAddr));

    if(ipRecords) {
        while(fgets(ipAddr, sizeof(ipAddr), ipRecords) != NULL) {
            dnsResponse = 1;
            len = strlen(ipAddr);
            if(len > 0 && ipAddr[len-1] == '\n')
                ipAddr[len-1] = '\0';
            
            //Check the ipaddr, url and droplog are not NULL
            if((len > 0) && (url != NULL) && (dropLog != NULL))
            {   
                if(nstdPort[0] == '\0')
                {
                    fprintf(fp, "-A lan2wan_pc_site -d %s -p tcp -m tcp --dport 80 -m comment --comment \"host match %s \" -j %s\n", ipAddr, url, dropLog);
                    fprintf(fp, "-A lan2wan_pc_site -d %s -p tcp -m tcp --dport 443 -m comment --comment \"host match %s \" -j %s\n", ipAddr, url, dropLog);
                }
                else
                    fprintf(fp, "-A lan2wan_pc_site -d %s -p tcp -m tcp --dport %s -m comment --comment \"host match %s \" -j %s\n", ipAddr, nstdPort, url, dropLog);
            }
            else
                fprintf(fp, "-A lan2wan_pc_site -d %s -p tcp -m tcp --dport %s -m comment --comment \"host match %s \" -j %s\n", ipAddr, nstdPort, url, dropLog);
        }

        fclose(ipRecords);
    }

    if(dnsResponse == 0)
        unlink(filePath);
    FIREWALL_DEBUG("Exiting block_url_by_ipaddr\n");  
    return;
}
#endif

#if defined(CONFIG_CISCO_FEATURE_CISCOCONNECT) || defined(CONFIG_CISCO_PARCON_WALLED_GARDEN)
static char *convert_url_to_hex_fmt(const char *url, char *dnsHexUrl)
{
    char s1[256], s2[512 + 32];
    char *p = s1, *tok;
    int i, len;
    FIREWALL_DEBUG("Entering convert_url_to_hex_fm\n"); 
    /* CID 135652 -BUFFER_SIZE_WARNING */
    if(strlen(url) >= sizeof(s1)) {
        fprintf(stderr, "firewall: %s - maxium length of url is 255\n", __FUNCTION__);
        return NULL;
    }
    strcpy(s1, url);

    *dnsHexUrl = '\0';

    while ((tok = strsep(&p, ".")) != NULL) {
        len = strlen(tok);
        sprintf(s2, "%02d", len);

        for(i = 0; i < len; i++) {
            sprintf(&s2[2*(i+1)], "%2x", tok[i]);
        }
        strcat(dnsHexUrl, s2);
    }
    FIREWALL_DEBUG("Exiting convert_url_to_hex_fm\n"); 
    return dnsHexUrl;
}
#endif

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
/*
 * Device based parental control for Rogers Cisco Connect. Used in conjunction with Walled Garden.
 */
static void do_device_based_parcon_allow(FILE *fp)
{
    FILE *allowList = fopen(PARCON_ALLOW_LIST, "r");
    char line[256];
    char *t;
    FIREWALL_DEBUG("Entering do_device_based_parcon_allow\n"); 
    if(!allowList)
        return;

    //each line in PARCON_ALLOW_LIST file should looks exactly like "00:11:22:33:44:55,XXXXXXXX"
    while(fgets(line, sizeof(line), allowList) != NULL) {
        if((t = strchr(line, ',')) != NULL) {
            *t = '\0';
            fprintf(fp, "-A parcon_allow_list -m mac --mac-source %s -j ACCEPT\n", line);
        }
    }
    FIREWALL_DEBUG("Exiting do_device_based_parcon_allow\n"); 
    return;
}

static int do_device_based_parcon(FILE *natFp, FILE* filterFp)
{
   char *cron_file = crontab_dir"/"crontab_filename;
   FILE *cron_fp = NULL; // the crontab file we use to set wakeups for timed firewall events
   FILE *fp;
   char ipAddr[256];
   int len;
   char filePath[256];
    FIREWALL_DEBUG("Entering do_device_based_parcon\n"); 
   cron_fp = fopen(cron_file, "a+");

   int rc;
   char query[1024]; //max url list length is 1024

   query[0] = '\0';
   rc = syscfg_get(NULL, "managedsites_enabled", query, sizeof(query)); 
   if (rc == 0 && query[0] != '\0' && query[0] != '0') // managed site list enabled
   {
      int count = 0, idx, ruleIndex = 0;

      // first, we let traffic from allow list get through
      // bypass ipset redirect rules in nat PREROUTING
      do_device_based_parcon_allow(natFp);
      // bypass HTTP GET spoof rules in filter FORWARD
      do_device_based_parcon_allow(filterFp);

      query[0] = '\0';
      rc = syscfg_get(NULL, "ManagedSiteBlockCount", query, sizeof(query)); 
      if (rc == 0 && query[0] != '\0') count = atoi(query);
      if (count < 0) count = 0;
      if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;
      
      for (idx = 1; idx <= count; idx++)
      {
         char namespace[MAX_QUERY];
         snprintf(query, sizeof(query), "ManagedSiteBlock_%d", idx);

         namespace[0] = '\0';
         rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
         if (0 != rc || '\0' == namespace[0]) {
            continue;
         }

         char ins_num[16] = "";
         rc = syscfg_get(namespace, "ins_num", ins_num, sizeof(ins_num));
         if (0 != rc || '\0' == ins_num[0]) continue;

         query[0] = '\0';
         rc = syscfg_get(namespace, "days", query, sizeof(query)); 
         if (0 != rc || strcmp("disable", query) == 0) continue;

         query[0] = '\0';
         rc = syscfg_get(namespace, "mac", query, sizeof(query)); 
         if (0 != rc || '\0' == query[0]) continue;

         fprintf(natFp, ":device_%s - [0:0]\n", ins_num);
         fprintf(natFp, "-A parcon_walled_garden -m mac --mac-source %s -j device_%s\n", query, ins_num);

         // parental control walled garden SFS
         // -> device try to access a website
         // -> check if current time is blocked (if blocked then walled garden)
         // -> check if this site is blocked (if blocked then walled garden)
         // -> if no violation then grant access, else goto walled garden
         // -> if password is correct then grant access to all websites including blocked sites
         int within_policy_start_stop = determine_enforcement_schedule(cron_fp, namespace);
         if (!within_policy_start_stop){
             fprintf(natFp, "-A device_%s -p tcp --dport 80 -j REDIRECT --to-port %s\n", \
                                                        ins_num, PARCON_WALLED_GARDEN_HTTP_PORT_TIMEBLK);
             fprintf(natFp, "-A device_%s -p tcp --dport 443 -j REDIRECT --to-port %s\n", \
                                                        ins_num, PARCON_WALLED_GARDEN_HTTPS_PORT_TIMEBLK);
             continue;
         }
         
         fprintf(natFp, "-A device_%s -p tcp --dport 80 -m set --match-set %s dst -j REDIRECT --to-port %s\n", \
                                                        ins_num, ins_num, PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK);
         fprintf(natFp, "-A device_%s -p tcp --dport 443 -m set --match-set %s dst -j REDIRECT --to-port %s\n", \
                                                        ins_num, ins_num, PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK);

         fprintf(filterFp, ":device_%s_container - [0:0]\n", ins_num);
         fprintf(filterFp, "-A wan2lan_dns_intercept -j device_%s_container\n", ins_num);

         //lan2wan dns query interception per device
         fprintf(filterFp, ":lan2wan_dnsq_nfqueue_%s - [0:0]\n", ins_num);
         //lan2wan http interception per device
         fprintf(filterFp, ":lan2wan_http_nfqueue_%s - [0:0]\n", ins_num);

         do_device_based_pp_disabled_appendrule(filterFp, ins_num, lan_ifname, query);

         //these rules are for http and dns query interception per device
         fprintf(filterFp, "-A lan2wan_httpget_intercept -m mac --mac-source %s -j lan2wan_http_nfqueue_%s\n", query, ins_num);
         fprintf(filterFp, "-A lan2wan_dnsq_intercept -m mac --mac-source %s -m limit --limit 2/m --limit-burst 2 -j lan2wan_dnsq_nfqueue_%s\n", query, ins_num);
         fprintf(filterFp, "-A lan2wan_dnsq_nfqueue_%s -j MARK --set-mark %s\n", ins_num, ins_num);
         fprintf(filterFp, "-A lan2wan_dnsq_nfqueue_%s -j NFQUEUE --queue-num %d\n", ins_num, DNS_QUERY_QUEUE_NUM);

         //these rules are for disable wan2lan pp
         fprintf(filterFp, ":wan2lan_dnsr_nfqueue_%s - [0:0]\n", ins_num);

         snprintf(filePath, sizeof(filePath), PARCON_IP_URL"/%s", query);
         FILE *mac2Ip = fopen(filePath, "r");
         if(mac2Ip != NULL) {
             fgets(ipAddr, sizeof(ipAddr), mac2Ip);
             fprintf(filterFp, "-A device_%s_container -d %s -m limit --limit 1/s --limit-burst 1 -j wan2lan_dnsr_nfqueue_%s\n", ins_num, ipAddr, ins_num);
             do_device_based_pp_disabled_ip_appendrule(filterFp, ins_num, ipAddr);
             fclose(mac2Ip);
         }

         query[0] = '\0';
         rc = syscfg_get(namespace, "site", query, sizeof(query));
         if (0 != rc || '\0' == query[0]) continue;

         char *token, *str = query;
         int index = 0;
         char hexUrl[512 + 32];

         uint32_t insNum = (uint32_t)atoi(ins_num);
         uint32_t siteIndex = 0;

         //these rules are for dns response interception of all blocked sites
         while((token = strsep(&str, ",")) != NULL) {
             siteIndex++;
             if(convert_url_to_hex_fmt(token, hexUrl) != NULL) {

                 //if Host: XXX is found, DROP and send spoof HTTP redirect in nfqueue handler
                 fprintf(filterFp, "-A lan2wan_http_nfqueue_%s -m webstr --url %s -j MARK --set-mark 0x%x\n", ins_num, token, insNum);

                 if(HTTP_GET_QUEUE_NUM_START == HTTP_GET_QUEUE_NUM_END)
                     fprintf(filterFp, "-A lan2wan_http_nfqueue_%s -m webstr --url %s -j NFQUEUE --queue-num %d\n", \
                                                                ins_num, token, HTTP_GET_QUEUE_NUM_START);
                 else
                     fprintf(filterFp, "-A lan2wan_http_nfqueue_%s -m webstr --url %s -j NFQUEUE --queue-balance %d:%d\n", \
                                                                ins_num, token, HTTP_GET_QUEUE_NUM_START, HTTP_GET_QUEUE_NUM_END);

                 fprintf(filterFp, "-A wan2lan_dnsr_nfqueue_%s -m string --algo kmp --hex-string \"|%s|\" -j MARK --set-mark 0x%x\n", \
                                                                ins_num, hexUrl, insNum);

                 if(DNS_RES_QUEUE_NUM_START == DNS_RES_QUEUE_NUM_END)
                     fprintf(filterFp, "-A wan2lan_dnsr_nfqueue_%s -m string --algo kmp --hex-string \"|%s|\" -j NFQUEUE --queue-num %d\n", \
                                                                ins_num, hexUrl, DNS_RES_QUEUE_NUM_START);
                 else
                     fprintf(filterFp, "-A wan2lan_dnsr_nfqueue_%s -m string --algo kmp --hex-string \"|%s|\" -j NFQUEUE --queue-balance %d:%d\n", \
                                                                ins_num, hexUrl, DNS_RES_QUEUE_NUM_START, DNS_RES_QUEUE_NUM_END);
             }
         }

         //TO DO: log needed?
         //char drop_log[40];
         //snprintf(drop_log, sizeof(drop_log), "LOG_SiteBlocked_%d_DROP", idx);
         //fprintf(fp, ":%s - [0:0]\n", drop_log);
         //fprintf(fp, "-A %s -j LOG --log-prefix %s --log-level %d\n", drop_log, drop_log, syslog_level);
         //fprintf(fp, "-A %s -j DROP\n", drop_log);
      }
   }

   if (cron_fp){ 
	   fclose(cron_fp);
   }
   FIREWALL_DEBUG("Exiting do_device_based_parcon\n"); 
   return(0);
}
#endif


/*
** XDNS - Route DNS requests from LAN through dnsmasq.
**/
#ifdef XDNS_ENABLE
int do_dns_route(FILE *nat_fp, int iptype) {

	char xdnsflag[20] = {0};
	int rc = syscfg_get(NULL, "X_RDKCENTRAL-COM_XDNS", xdnsflag, sizeof(xdnsflag));
	if (0 != rc || '\0' == xdnsflag[0] ) //if flag not found
	{
		FIREWALL_DEBUG("### XDNS - Disabled. X_RDKCENTRAL-COM_XDNS not found. ### \n");
	}
	else if(0 == strcmp("0", xdnsflag)) //flag set to false
	{
		FIREWALL_DEBUG("### XDNS - Disabled. X_RDKCENTRAL-COM_XDNS is FALSE ###\n");
	}
	else if (0 == strcmp("1", xdnsflag)) //if set to true
	{
		// Route DNS requests from LAN through dnsmasq.
		// To enable sending LAN device MAC upstream in DNS requests through dnsmasq with option '--add-mac'
		if (iptype == 4)
		{
			// Check if lan ip is up. Need to route dns requests to dnsmasq through lan0.
			if ('\0' != lan_ipaddr[0] && 0 != strcmp("0.0.0.0", lan_ipaddr) )
			{
	                #if defined (INTEL_PUMA7)
				// Prerouting is bypassed for the Xi devices (Needed only for XB6)
                                fprintf(nat_fp, "-A prerouting_fromlan -i %s ! -s 169.254.0.0/16 -p udp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipaddr);
                                fprintf(nat_fp, "-A prerouting_fromlan -i %s ! -s 169.254.0.0/16 -p tcp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipaddr);
                                printf("### XDNS : Feature Enabled XDNS ipv4 ### \n");
                        #else

                                fprintf(nat_fp, "-A prerouting_fromlan -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipaddr);
                                fprintf(nat_fp, "-A prerouting_fromlan -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipaddr);
                                printf("### XDNS : Feature Enabled XDNS ipv4 ### \n");
                        #endif

			}
			else
			{
				FIREWALL_DEBUG("### XDNS - Disabled for ipv4. LAN IPv4 not up, iptables rule for xDNS not set!\n");
			}
		}
		else if(iptype == 6)
		{
			char lan_ipv6addr[INET6_ADDRSTRLEN] = {0}; // MURUGAN - XDNS : ipv6 address of the lan interface
			memset(lan_ipv6addr, 0, INET6_ADDRSTRLEN);
			sysevent_get(sysevent_fd, sysevent_token, "lan_ipaddr_v6", lan_ipv6addr, sizeof(lan_ipv6addr));
			printf("#########  XDNS : lan_ipv6addr = \"%s\"\n" COMMA lan_ipv6addr);
			// Check if lan ipv6 is up.
			if ('\0' != lan_ipv6addr[0] && 0 != strcmp("", lan_ipv6addr) && 0 != strcmp("::", lan_ipv6addr))
			{
	                #if defined (INTEL_PUMA7)
                                // Prerouting is bypassed for the Xi devices (Needed only for XB6)
                                fprintf(nat_fp, "-A PREROUTING -i %s ! -s 2603:2000::/20  -p udp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipv6addr);
			        fprintf(nat_fp, "-A PREROUTING -i %s ! -s 2603:2000::/20  -p tcp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipv6addr);
				printf("### XDNS : Feature Enabled (XDNS ipv6) ### \n");
                        #else
				fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipv6addr);
                                fprintf(nat_fp, "-A PREROUTING -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",lan_ifname,lan_ipv6addr);
                                printf("### XDNS : Feature Enabled (XDNS ipv6) ### \n");
                        #endif
			}
			else
			{
				FIREWALL_DEBUG("######## XDNS - Disabled for Ipv6. LAN IPv6 not up, ip6tables rule for xDNS not set ! ########\n");
			}
		}
		else
		{
			FIREWALL_DEBUG("### XDNS - Disabled. Invalid iptype!\n");
		}
	}
	else
	{
		FIREWALL_DEBUG("### XDNS - Disabled. Invalid xdnsflag!\n");
	}

	return 0;
}
#endif

/*
 *  Procedure     : do_parental_control
 *  Purpose       : prepare the iptables-restore statements for all
 *                  syscfg defined Parental Control Rules
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */

static int do_parcon_mgmt_device(FILE *fp, int iptype, FILE *cron_fp);
static int do_parcon_device_cloud_mgmt(FILE *fp, int iptype, FILE *cron_fp);
static int do_parcon_mgmt_service(FILE *fp, int iptype, FILE *cron_fp);
static int do_parcon_mgmt_site_keywd(FILE *fp, FILE *nat_fp, int iptype, FILE *cron_fp);

int do_parental_control(FILE *fp,FILE *nat_fp, int iptype) {

    char *cron_file = crontab_dir"/"crontab_filename;
    int bCloudEnable = FALSE;
    FILE *cron_fp = NULL; // the crontab file we use to set wakeups for timed firewall events
    FIREWALL_DEBUG("Entering do_parental_control\n"); 
    //only do cron configuration once   
    if (iptype == 4) {
        cron_fp = fopen(cron_file, "a+");
    }
	char buf[8];
	memset(buf, 0, sizeof(buf));
        syscfg_get( NULL, "X_RDKCENTRAL-COM_AkerEnable", buf, sizeof(buf));
	// CID 75054: Array compared against 0 (NO_EFFECT)
        if( buf[0] != '\0' )
    		{
    		    if (strcmp(buf,"true") == 0)
    		        bCloudEnable = TRUE;
    		    else
    		        bCloudEnable = FALSE;
    		}

	if (iptype == 4)
	{
		if(bCloudEnable)
		{
			do_parcon_device_cloud_mgmt(nat_fp, iptype, cron_fp);
		}
		else
    		do_parcon_mgmt_device(nat_fp, iptype, cron_fp);
	}
	else
	{
		if(bCloudEnable)
		{
		do_parcon_device_cloud_mgmt(nat_fp,iptype, NULL);
		}
		else
		do_parcon_mgmt_device(nat_fp,iptype, NULL);
		
	}
#ifndef CONFIG_CISCO_FEATURE_CISCOCONNECT
    do_parcon_mgmt_site_keywd(fp,nat_fp, iptype, cron_fp);
#endif
    do_parcon_mgmt_service(fp, iptype, cron_fp);

    if (cron_fp) { /*RDKB-7145, CID-33097,  free only a valid resource*/
        fclose(cron_fp);
    }
    FIREWALL_DEBUG("Exiting do_parental_control\n"); 
    return 0;
}

/*
 * add parental control managed device rules
 */
static int do_parcon_mgmt_device(FILE *fp, int iptype, FILE *cron_fp)
{
   int rc,flag = 0;
   char query[MAX_QUERY];
   FIREWALL_DEBUG("Entering do_parcon_mgmt_device\n"); 
   query[0] = '\0';
   rc = syscfg_get(NULL, "manageddevices_enabled", query, sizeof(query)); 
   if (rc == 0 && query[0] != '\0' && query[0] != '0') { // managed device list enabled
      int allow_all = 0;
      query[0] = '\0';
      rc = syscfg_get(NULL, "manageddevices_allow_all", query, sizeof(query)); 
      if (rc == 0 && query[0] != '\0' && query[0] != '0') allow_all = 1;

      int count = 0;
      query[0] = '\0';
      rc = syscfg_get(NULL, "ManagedDeviceCount", query, sizeof(query)); 
      if (rc == 0 && query[0] != '\0') count = atoi(query);
      if (count < 0) count = 0;
      if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;

      int idx;
      for (idx = 1; idx <= count; idx++) {
         char namespace[MAX_QUERY];
         snprintf(query, sizeof(query), "ManagedDevice_%d", idx);
         namespace[0] = '\0';
         rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
         if (0 != rc || '\0' == namespace[0]) {
            continue;
         }

         int block = 1;
         query[0] = '\0';
         rc = syscfg_get(namespace, "block", query, sizeof(query));
         if (0 != rc || '\0' == query[0] || query[0] == '0') block = 0;

        if((allow_all == 0) && (block == 0)) flag = 1; 

        if (allow_all != block) continue;

	//     if (iptype == 4){
	        int within_policy_start_stop = determine_enforcement_schedule2(cron_fp, namespace);

         	if (!within_policy_start_stop) continue;
	//	 }
		 

         query[0] = '\0';
         rc = syscfg_get(namespace, "mac_addr", query, sizeof(query));
         if (0 != rc || '\0' == query[0]) continue;
         if(flag == 1)
         {
            fprintf(fp, "-A prerouting_devices -p tcp -m mac --mac-source %s -j ACCEPT\n",query);
         }
         else
         {
//Managed Devices - Reports not get generated. so we need to log below rules 
#if 0
			fprintf(fp, "-A prerouting_devices -p tcp -m mac --mac-source %s -j prerouting_redirect\n",query);
#else
			fprintf(fp, ":LOG_DeviceBlocked_%d_DROP - [0:0]\n", idx);
			fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1  -j LOG --log-prefix LOG_DeviceBlocked_%d_DROP --log-level %d\n", idx, idx, syslog_level);
			fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -j prerouting_redirect\n", idx);
			fprintf(fp, "-A prerouting_devices -p tcp -m mac --mac-source %s -j LOG_DeviceBlocked_%d_DROP\n",query,idx);
			fprintf(fp, "-A prerouting_devices -p udp -m mac --mac-source %s -j LOG_DeviceBlocked_%d_DROP\n",query,idx);
#endif /* 0 */
            if(cron_fp)
            {
               v_secure_system("echo %s >> /tmp/conn_mac", query);
            }
         }
      }

      if (!allow_all) 
	  {
// Managed Devices - Reports not get generated. so we need to log below rules 
#if 0
		fprintf(fp, "-A prerouting_devices -p tcp -j prerouting_redirect\n");
#else
		fprintf(fp, ":LOG_DeviceBlocked_DROP - [0:0]\n");
		fprintf(fp, "-A LOG_DeviceBlocked_DROP -m limit --limit 1/minute --limit-burst 1  -j LOG --log-prefix LOG_DeviceBlocked_DROP --log-level %d\n",  syslog_level);
		fprintf(fp, "-A LOG_DeviceBlocked_DROP -j prerouting_redirect\n");

        fprintf(fp, "-A prerouting_devices -p tcp -j LOG_DeviceBlocked_DROP\n");
#endif /* 0 */
      }
   }
   FIREWALL_DEBUG("Exiting do_parcon_mgmt_device\n"); 
   return(0);
}

devMacSt * getPcmdList(int *devCount)
{
int count = 0;
int numDev = 0;
FILE * fp;
char buf[19];
devMacSt *devMacs = NULL;
devMacSt *dev = NULL;
memset(buf, 0, sizeof(buf));
   fp = fopen (PCMD_LIST, "r");
   if(fp != NULL)
   {
       if(flock(fileno(fp), LOCK_EX) == -1)
           FIREWALL_DEBUG("Error while locking file\n");
       while( fgets ( buf, sizeof(buf), fp ) != NULL ) 
       {
           if(count == 0){
               numDev = atoi(buf);            		
               printf("numDev = %d \n" COMMA numDev);
               *devCount = numDev;
               devMacs = (devMacSt *)calloc(numDev,sizeof(devMacSt));
               dev = devMacs;
           }
           else
           {
               memset(devMacs->mac, 0, sizeof(devMacs->mac));
               strncpy(devMacs->mac,buf,17);		
               printf("devMacs->mac = %s \n" COMMA devMacs->mac);
               ++devMacs;
           }
           count++;
           memset(buf, 0, sizeof(buf));
       }
    fflush(fp); flock(fileno(fp), LOCK_UN);
    fclose(fp);
   }
   else
   FIREWALL_DEBUG("Error: Not able to read " PCMD_LIST "\n" );


FIREWALL_DEBUG("Exit getPcmdList\n");
return dev;
}

static int do_parcon_device_cloud_mgmt(FILE *fp, int iptype, FILE *cron_fp)
{
   FIREWALL_DEBUG("Entering do_parcon_device_cloud_mgmt\n"); 
   int count = 0;
   int idx;
   devMacSt *devM;
   devMacSt *devMacs2 = getPcmdList(&count);
   devM = devMacs2;
      for (idx = 0; idx < count; idx++) {
//Managed Devices - Reports not get generated. so we need to log below rules 
	if(devMacs2)
	{

			fprintf(fp, ":LOG_DeviceBlocked_%d_DROP - [0:0]\n", idx+1);
			fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1  -j LOG --log-prefix LOG_DeviceBlocked_%d_DROP --log-level %d\n", idx+1, idx+1, syslog_level);
			fprintf(fp, "-A LOG_DeviceBlocked_%d_DROP -j prerouting_redirect\n", idx+1);

            fprintf(fp, "-A prerouting_devices -p tcp -m mac --mac-source %s -j LOG_DeviceBlocked_%d_DROP\n",devMacs2->mac,idx+1);  
            fprintf(fp, "-A prerouting_devices -p udp -m mac --mac-source %s -j LOG_DeviceBlocked_%d_DROP\n",devMacs2->mac,idx+1);                      

               v_secure_system("echo %s >> /tmp/conn_mac", devMacs2->mac);
	}
	++devMacs2;
	
      }
	if(devM)
	free(devM);
   
   FIREWALL_DEBUG("Exiting do_parcon_device_cloud_mgmt\n"); 
   return(0);
}

static int validate_port(char* port_num)
{
   int port = atoi(port_num);
   if ( port <= 0 || port > MAX_PORT )
      return -1;

   return 0;
}
/*
 * add parental control managed service(ports) rules
 */
static int do_parcon_mgmt_service(FILE *fp, int iptype, FILE *cron_fp)
{
   FIREWALL_DEBUG("Entering do_parcon_mgmt_service\n"); 
   int rc;
   char query[MAX_QUERY];

   query[0] = '\0';
   rc = syscfg_get(NULL, "managedservices_enabled", query, sizeof(query)); 
   if (rc == 0 && query[0] != '\0' && query[0] != '0') {// managed site list enabled
      int count=0, idx;

      // first, we let traffic from trusted user get through
      do_parental_control_allow_trusted(fp, iptype, "ManagedServiceTrust", "lan2wan_pc_service");

#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
     /* only ipv4 has nat table, so cannot use nat table to redirect service port */ 
     fprintf(fp, ":%s - [0:0]\n", "parcon_service_nfq");
     fprintf(fp, "-A parcon_service_nfq -p tcp --syn -j ACCEPT\n");
     fprintf(fp, "-A parcon_service_nfq -j MARK --set-mark 0x00\n");
     fprintf(fp, "-A parcon_service_nfq -m string --string \"HTTP\" --algo kmp  -m string --string \"GET\" --algo kmp -j NFQUEUE "HTTP_GET_QUEUE_CONFIG "\n");
     fprintf(fp, "-A parcon_service_nfq -p tcp --tcp-flag FIN FIN -j REJECT --reject-with tcp-reset\n");
     fprintf(fp, "-A parcon_service_nfq -j DROP\n");
#endif
      query[0] = '\0';
      rc = syscfg_get(NULL, "ManagedServiceBlockCount", query, sizeof(query)); 
      if (rc == 0 && query[0] != '\0') count = atoi(query);
      if (count < 0) count = 0;
      if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;
      for (idx = 1; idx <= count; idx++) {
         char namespace[MAX_QUERY];
         snprintf(query, sizeof(query), "ManagedServiceBlock_%d", idx);
         syscfg_get(NULL, query, namespace, sizeof(namespace));
         if ('\0' == namespace[0]) {
            continue;
         }

         int within_policy_start_stop = determine_enforcement_schedule2(cron_fp, namespace);
         if (!within_policy_start_stop) continue;

         char prot[10];
         int  proto;
         char sdport[10];
         char edport[10];

         proto = 0; // 0 is both, 1 is tcp, 2 is udp
         syscfg_get(namespace, "proto", prot, sizeof(prot));
         if ('\0' == prot[0]) {
            proto = 0;
         } else if (0 == strncasecmp("tcp", prot, 3)) {
            proto = 1;
         } else if (0 == strncasecmp("udp", prot, 3)) {
            proto = 2;
         }

         syscfg_get(namespace, "start_port", sdport, sizeof(sdport));
         if (('\0' == sdport[0]) || (0 != validate_port(sdport))) {
            continue;
         }

         syscfg_get(namespace, "end_port", edport, sizeof(edport));
         if (('\0' == edport[0]) || (0 != validate_port(edport))) {
            continue;
         }

         fprintf(fp, ":LOG_ServiceBlocked_%d_DROP - [0:0]\n", idx);
         fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1 -j LOG --log-prefix LOG_ServiceBlocked_%d_DROP --log-level %d\n", idx, idx, syslog_level);
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN

         fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -p tcp -m multiport --dports 80,8080 -j parcon_service_nfq\n", idx);
		 /* if we dorp the tcp SYN packet without any FIN or RST, some client will retry many times*/ 
         fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -j DROP\n", idx);
//         fprintf(fp, "-A %s -p tcp -j REJECT --reject-with tcp-reset\n", drop_log);
//         if(iptype == 4)
//            fprintf(fp, "-A %s -p udp -j REJECT --reject-with icmp-port-unreachable\n", drop_log);
//         else
//            fprintf(fp, "-A %s -p udp -j REJECT --reject-with icmp6-port-unreachable\n", drop_log);
#else
         fprintf(fp, "-A LOG_ServiceBlocked_%d_DROP -j DROP\n", idx);
#endif
         if (0 == proto || 1 ==  proto) {
            fprintf(fp, "-A lan2wan_pc_service -p tcp -m tcp --dport %s:%s -j LOG_ServiceBlocked_%d_DROP\n", sdport, edport, idx);
         }

         if (0 == proto || 2 ==  proto) {
            fprintf(fp, "-A lan2wan_pc_service -p udp -m udp --dport %s:%s -j LOG_ServiceBlocked_%d_DROP\n", sdport, edport, idx);
         }
      }
   }
   FIREWALL_DEBUG("Exiting do_parcon_mgmt_service\n"); 
   return(0);
}

// convert_word_to_host_hex converts string to lowercase hex
static int convert_word_to_host_hex(const char *input, char *output, size_t outsize)
{
    if (!input || !output || outsize == 0) return 0;

    size_t len = strlen(input);
    if (len == 0 || outsize < len * 2 + 1) return 0;

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)input[i];

        if (isspace(c) || !isprint(c) || c == '"' || c == '\\') {
            return 0;
        }

        snprintf(output + i * 2, outsize - i * 2, "%02x", tolower(c));
    }

    output[len * 2] = '\0';
    return 1;
}

/*
 * add parental control managed site/keyword rules
 */
static int do_parcon_mgmt_site_keywd(FILE *fp, FILE *nat_fp, int iptype, FILE *cron_fp)
{
    int rc;
    char query[MAX_QUERY];
   FIREWALL_DEBUG("Entering do_parcon_mgmt_site_keywd\n"); 
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
    int isHttps = 0;
    if(iptype == 4)
        fprintf(nat_fp, "-A prerouting_fromlan -j managedsite_based_parcon\n");
#endif

    query[0] = '\0';
    rc = syscfg_get(NULL, "managedsites_enabled", query, sizeof(query)); 
    if (rc == 0 && query[0] != '\0' && query[0] != '0') // managed site list enabled
    {
        int count = 0, idx;
#if !defined(_COSA_BCM_MIPS_)
        int ruleIndex = 0;

        // first, we let traffic from trusted user get through
        ruleIndex = do_parental_control_allow_trusted(fp, iptype, "ManagedSiteTrust", "lan2wan_pc_site");
#endif
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
        if(iptype == 4){
            ruleIndex = do_parental_control_allow_trusted(nat_fp, iptype, "ManagedSiteTrust", "managedsite_based_parcon");
            fprintf(nat_fp, "-A managedsite_based_parcon -j parcon_walled_garden\n");
        }
#endif

        query[0] = '\0';
        rc = syscfg_get(NULL, "ManagedSiteBlockCount", query, sizeof(query)); 
        if (rc == 0 && query[0] != '\0') count = atoi(query);
        if (count < 0) count = 0;
        if (count > MAX_SYSCFG_ENTRIES) count = MAX_SYSCFG_ENTRIES;

#if !defined(_COSA_BCM_MIPS_) && !defined(_CBR_PRODUCT_REQ_) && !defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_TURRIS_) && !defined(_COSA_QCA_ARM_) && !defined(_PLATFORM_BANANAPI_R4_)
        ruleIndex += do_parcon_mgmt_lan2wan_pc_site_appendrule(fp);
#endif

        for (idx = 1; idx <= count; idx++)
        {
            char namespace[MAX_QUERY];
            snprintf(query, sizeof(query), "ManagedSiteBlock_%d", idx);
            namespace[0] = '\0';
            rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
            if (0 != rc || '\0' == namespace[0]) {
                continue;
            }

            char method[20] = "";
            rc = syscfg_get(namespace, "method", method, sizeof(method));
            if (0 != rc || '\0' == method[0]) continue;

            char ins_num[16] = "";
            rc = syscfg_get(namespace, "ins_num", ins_num, sizeof(ins_num));
            if (0 != rc || '\0' == ins_num[0]) continue;

            query[0] = '\0';
            rc = syscfg_get(namespace, "site", query, sizeof(query)); 
            if (0 != rc || '\0' == query[0]) continue;
            
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
            if (strncasecmp(method, "URL", 3)==0)
            {
                char hexUrl[MAX_URL_LEN * 2 + 32];
                int host_name_offset = 0;
                isHttps = 0;
                if (0 == strncasecmp(query, "http://", STRLEN_HTTP_URL_PREFIX)) {
                    host_name_offset = STRLEN_HTTP_URL_PREFIX;
                }
                else if (0 == strncasecmp(query, "https://", STRLEN_HTTPS_URL_PREFIX)) {
                    host_name_offset = STRLEN_HTTPS_URL_PREFIX;
                    isHttps = 1;
                }
                else
                     continue;
                char *tmp;
                int is_dnsr_nfq = 1;
                if(strncmp(query+host_name_offset, "[", 1) == 0){ /* if this is a ipv6 address stop monitor dns */
                    is_dnsr_nfq = 0;
                }else if((tmp = strstr(query+host_name_offset, ":")) != NULL ){ 
                    /* remove the port */
                    *tmp = '\0';
                    is_dnsr_nfq = 2;
                }
                if( is_dnsr_nfq >= 1 && NULL != convert_url_to_hex_fmt(query+host_name_offset, hexUrl)){
                    strncat(hexUrl, "00",sizeof(hexUrl));
                    if(is_dnsr_nfq == 2 )
                        *tmp=':';
                    fprintf(fp, ":wan2lan_dnsr_nfqueue_%s - [0:0]\n", ins_num);
                    fprintf(fp, "-A wan2lan_dnsr_nfqueue -m string --algo kmp --hex-string \"|%s|\" -j wan2lan_dnsr_nfqueue_%s \n", hexUrl, ins_num);   
                    fprintf(fp, "-A wan2lan_dnsr_nfqueue_%s  -j MARK --set-mark 0x%x\n", ins_num, atoi(ins_num));
                    if(iptype == 4)
                        fprintf(fp, "-A wan2lan_dnsr_nfqueue_%s  -m limit --limit 1/minute --limit-burst 1 -j NFQUEUE " DNSR_GET_QUEUE_CONFIG "\n",ins_num); 
                    else
                        fprintf(fp, "-A wan2lan_dnsr_nfqueue_%s  -m limit --limit 1/minute --limit-burst 1 -j NFQUEUE " DNSV6R_GET_QUEUE_CONFIG "\n",ins_num); 
                }
            } 
#endif
            int within_policy_start_stop = determine_enforcement_schedule2(cron_fp, namespace);
            if (!within_policy_start_stop) continue;

            char drop_log[40];
	    snprintf(drop_log, sizeof(drop_log), "LOG_SiteBlocked_%d_DROP", idx);
            fprintf(fp, ":LOG_SiteBlocked_%d_DROP - [0:0]\n", idx);
            fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1  -j LOG --log-prefix LOG_SiteBlocked_%d_DROP --log-level %d\n", idx, idx, syslog_level);
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
            fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -j MARK --set-mark 0x%x\n", idx, atoi(ins_num));
            if(iptype==4){
                fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -j NFQUEUE "HTTP_GET_QUEUE_CONFIG "\n", idx);
                fprintf(nat_fp, ":LOG_SiteBlocked_%d_DROP - [0:0]\n", idx);
                fprintf(nat_fp, "-A LOG_SiteBlocked_%d_DROP -m limit --limit 1/minute --limit-burst 1  -j LOG --log-prefix LOG_SiteBlocked_%d_DROP --log-level %d\n", idx, idx, syslog_level);
                //if(isHttps)
                //    fprintf(nat_fp, "-A %s -m tcp -p tcp -j REDIRECT --to-port %s\n\n", drop_log, PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK);
                //else
                //    fprintf(nat_fp, "-A %s -m tcp -p tcp -j REDIRECT --to-port %s\n\n", drop_log, PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK);
            }else    
                fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -j NFQUEUE "HTTPV6_GET_QUEUE_CONFIG "\n", idx);
#else
            fprintf(fp, "-A LOG_SiteBlocked_%d_DROP -j DROP\n", idx);
#endif
            if (strncasecmp(method, "URL", 3)==0)
            {
                int host_name_offset = 0;

                // Strip http:// or https:// from the beginning of the URL
                // string so that only the host name is passed in
                if (0 == strncasecmp(query, "http://", STRLEN_HTTP_URL_PREFIX)) {
                    host_name_offset = STRLEN_HTTP_URL_PREFIX;
                }
                else if (0 == strncasecmp(query, "https://", STRLEN_HTTPS_URL_PREFIX)) {
                    host_name_offset = STRLEN_HTTPS_URL_PREFIX;
                }
                else
                    continue;

                char nstdPort[8] = {'\0'};
                char *pch;

                //We only need host name in url, so eliminate everything comes after '/'
                //This can also eliminate the '/' postfix in some url e.g. "www.google.com/"
                pch = strstr(query+host_name_offset, "/");
                if(pch != NULL)
                    *pch = '\0';

                enum urlType_t {TEXT_URL, IPv4_URL, IPv6_URL} urlType = IPv4_URL;
                char *urlStart = query + host_name_offset;
                int pos = 0, len = strlen(urlStart);

                if(*urlStart == '[')
                    urlType = IPv6_URL;
                else
                    while(pos < len)
                    {
                        if(urlStart[pos] == ':')
                            break;

                        if(!isdigit(urlStart[pos]) && urlStart[pos] != '.')
                        {
                            urlType = TEXT_URL;
                            break;
                        }

                        ++pos;
                    }

                if(urlType == IPv6_URL && iptype == 4)
                    continue;

                if(urlType == IPv4_URL && iptype == 6)
                    continue;

                if(urlType == IPv6_URL)
                    pch = strstr(query+host_name_offset, "]:");
                else
                    pch = strstr(query+host_name_offset, ":");

                if(pch != NULL)
                {
		    /* CID 135335 :BUFFER_SIZE_WARNING */
                    strncpy(nstdPort, urlType == IPv6_URL ? pch+2 : pch+1, sizeof(nstdPort)-1);
		    nstdPort[sizeof(nstdPort)-1] = '\0';
                    if(urlType == IPv6_URL)
                        *(pch+1) = '\0';
                    else
                        *pch = '\0';
#if defined (INTEL_PUMA7)
                    //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                    fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport %s -m webstr --host \"%s:%s\" -j LOG_SiteBlocked_%d_DROP\n", nstdPort, query + host_name_offset, nstdPort, idx);
#else
                    fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport %s -m httphost --host \"%s:%s\" -j LOG_SiteBlocked_%d_DROP\n", nstdPort, query + host_name_offset, nstdPort, idx);
#endif
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
                    if(iptype == 4){
                        if(isHttps){
                            fprintf(nat_fp, "-A parcon_walled_garden -p tcp --dport %s -m set --match-set %s dst -m comment --comment \"host match %s \"  -j LOG_SiteBlocked_%d_DROP\n",\
                                    nstdPort, ins_num, query, idx);
                            fprintf(nat_fp, "-A LOG_SiteBlocked_%d_DROP -m tcp -p tcp -j REDIRECT --to-port %s\n\n", idx, PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK);
                        }else{
                            fprintf(nat_fp, "-A parcon_walled_garden -p tcp --dport %s -m set --match-set %s dst -m comment --comment \"host match %s \"  -j LOG_SiteBlocked_%d_DROP\n",\
                                    nstdPort, ins_num, query, idx);
                            fprintf(nat_fp, "-A LOG_SiteBlocked_%d_DROP -m tcp -p tcp -j REDIRECT --to-port %s\n\n", idx, PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK);
                        }
                    }
                    
#endif
#if !defined(_COSA_BCM_MIPS_)
                    do_parcon_mgmt_lan2wan_pc_site_insertrule(fp, ruleIndex, nstdPort);
#endif
                }
                else
                {
#if defined (INTEL_PUMA7)
					//Intel Proposed RDKB Generic Bug Fix from XB6 SDK
					fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 80 -m webstr --host \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
					fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 443 -m webstr --host \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
#elif defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
                    fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 80 -d \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
                    fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 443 -d \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
#elif !defined(_XER5_PRODUCT_REQ_)
					fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 80 -m httphost --host \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
                    fprintf(fp, "-A lan2wan_pc_site -p tcp -m tcp --dport 443 -m httphost --host \"%s\" -j LOG_SiteBlocked_%d_DROP\n", query + host_name_offset, idx);
#endif
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
                    if(iptype == 4)
                    {
                        fprintf(nat_fp, "-A parcon_walled_garden -p tcp --dport 80 -m set --match-set %s dst -m comment --comment \"host match %s \"  -j  LOG_SiteBlocked_%d_DROP\n", \
                                ins_num, query, idx);
                        fprintf(nat_fp, "-A parcon_walled_garden -p tcp --dport 443 -m set --match-set %s dst -m comment --comment \"host match %s \" -j  LOG_SiteBlocked_%d_DROP\n", \
                                ins_num, query, idx);
                        fprintf(nat_fp, "-A LOG_SiteBlocked_%d_DROP -m tcp -p tcp --dport 443 -j REDIRECT --to-port %s\n\n", idx, PARCON_WALLED_GARDEN_HTTPS_PORT_SITEBLK);
                        fprintf(nat_fp, "-A LOG_SiteBlocked_%d_DROP -m tcp -p tcp --dport 80 -j REDIRECT --to-port %s\n\n", idx, PARCON_WALLED_GARDEN_HTTP_PORT_SITEBLK);
                    }
#endif
                }

                block_url_by_ipaddr(fp, query + host_name_offset, drop_log, iptype, ins_num, nstdPort);
            }
            else if (strncasecmp(method, "KEYWD", 5) == 0)
            {
                const char *queryKw = query;
                char hexKw[256] = {0};
                int kmpAlgoLen = 128; //upto 128 bytes

                // Extract hostname part if full URL
                if (strstr(query, "://") != NULL) {
                    queryKw = strstr(query, "://") + 3;
                }

                // Log warning for very short keywords
                if (strlen(queryKw) < 3) {
                    FIREWALL_DEBUG("Keyword '%s' too short to safely match\n", queryKw);
                }

                // Match using httphost
                fprintf(fp, "-A lan2wan_pc_site -p tcp --dport 80 -m httphost --host \"%s\" -j %s\n", queryKw, drop_log);

                // Match using "Host: <domain>" string
                fprintf(fp, "-A lan2wan_pc_site -p tcp --dport 80 -m string --string \"Host: %s\" --algo kmp --to %d --icase -j %s\n",
                    queryKw, kmpAlgoLen, drop_log);

                // Match using hex-string
                if (convert_word_to_host_hex(queryKw, hexKw, sizeof(hexKw))) {
                    fprintf(fp, "-A lan2wan_pc_site -p tcp --dport 80 -m string --algo kmp --to %d --hex-string \"|0D0A486F73743A20%s|\" -j %s\n",
                        kmpAlgoLen, hexKw, drop_log);
                }

#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                if (strncmp(devicePartnerId, "sky-", 4) == 0)
#endif
                {
                    // In Hub4, DNS proxy prevents FORWARD chain rules from working — use INPUT
                    fprintf(fp, "-I INPUT -i %s -j lan2wan_pc_site\n", lan_ifname);
                }
#endif
            }	    
        }
    }
   FIREWALL_DEBUG("Exiting do_parcon_mgmt_site_keywd\n"); 
    return(0);
}



#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
#define GUEST_ALLOW_LIST "/var/.guest_allow_list"
static void do_allowed_guest(FILE *natFp)
{
    FILE *allowList = fopen(GUEST_ALLOW_LIST, "r");
    char line[256];
    char *t;
    int len; 
   FIREWALL_DEBUG("Entering do_allowed_guest\n"); 
    if(!allowList)
        return;

    while(fgets(line, sizeof(line), allowList) != NULL) {
        if((t = strrchr(line, ',')) != NULL) {
            t++;
            len = strlen(t);
            if(t[len-1] == '\n')
                t[len-1] = '\0';
            fprintf(natFp, "-A guestnet_allow_list -s %s -j ACCEPT\n", t);
        }
    }
   FIREWALL_DEBUG("Exiting do_allowed_guest\n"); 
    return;
}

static void do_guestnet_walled_garden(FILE *natFp)
{
    do_allowed_guest(natFp);
   FIREWALL_DEBUG("Entering do_guestnet_walled_garden\n"); 
    fprintf(natFp, "-A guestnet_walled_garden -d %s -p tcp --dport 80 -j ACCEPT\n", guest_network_ipaddr);
    fprintf(natFp, "-A guestnet_walled_garden -d %s -p tcp --dport 443 -j ACCEPT\n", guest_network_ipaddr);
    fprintf(natFp, "-A guestnet_walled_garden -p tcp --dport 80 -j REDIRECT --to-port 28080\n");
    fprintf(natFp, "-A guestnet_walled_garden -p tcp --dport 443 -j REDIRECT --to-port 20443\n");
   FIREWALL_DEBUG("Exiting do_guestnet_walled_garden\n"); 
}
#endif

#ifdef CONFIG_BUILD_TRIGGER
/*
 *  Procedure     : do_prepare_port_range_triggers
 *  Purpose       : prepare the iptables-restore statements for triggers
 *  Parameters    :
 *     mangle_fp              : An open file that will be used for iptables-restore
 *     filter_fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
static int do_prepare_port_range_triggers(FILE *nat_fp, FILE *filter_fp)
#else
static int do_prepare_port_range_triggers(FILE *mangle_fp, FILE *filter_fp)
#endif
{
   FIREWALL_DEBUG("Entering do_prepare_port_range_triggers\n"); 
   int idx;
   int  rc;
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];

   int count;
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   BOOL isFeatureDisabled = TRUE;
#endif

   query[0] = '\0';
   rc = syscfg_get(NULL, "PortRangeTriggerCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto end_do_prepare_port_range_triggers;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto end_do_prepare_port_range_triggers;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   FIREWALL_DEBUG("PortTriggers:Feature Enable %d\n" COMMA TRUE);
   isFeatureDisabled = FALSE;
#endif

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "PortRangeTrigger_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == namespace[0]) {
         continue;
      }
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Index %d\n" COMMA idx);
#endif
  
      // is the rule enabled
      query[0] = '\0';
      rc = syscfg_get(namespace, "enabled", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } else if (0 == strcmp("0", query)) {
        continue;
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
      } else {
         isTriggerMonitorRestartNeeded = 1;
#endif
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Enable %s\n" COMMA query);
#endif

      // what is the trigger id
      char id[10];
      id[0] = '\0';
      rc = syscfg_get(namespace, "trigger_id", id, sizeof(id));
      if (0 != rc || '\0' == id[0]) {
         continue;
      } 

      // what is the triggering protocol
      char prot[10];
      prot[0] = '\0';
      rc = syscfg_get(namespace, "trigger_protocol", prot, sizeof(prot));
      if (0 != rc || '\0' == prot[0]) {
         snprintf(prot, sizeof(prot), "%s", "both");
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Trigger Protocol %s\n" COMMA prot);
#endif

      // what is the triggering port range
      char portrange[30];
      char sdport[10];
      char edport[10];
      portrange[0]= '\0';
      sdport[0]   = '\0';
      edport[0]   = '\0';
      rc = syscfg_get(namespace, "trigger_range", portrange, sizeof(portrange));
      if (0 != rc || '\0' == portrange[0]) {
         continue;
      } else {
         int r = 0;
         if (2 != (r = sscanf(portrange, "%10s %10s", sdport, edport))) {
            if (1 == r) {
               snprintf(edport, sizeof(edport), "%s", sdport);
            } else {
               continue;
            }
         }
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Trigger Port Start %s\n" COMMA sdport);
      FIREWALL_DEBUG("PortTriggers:Trigger Port End %s\n" COMMA edport);
#endif

#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
      // what is the forward protocol
      char fprot[10];
      fprot[0] = '\0';
      rc = syscfg_get(namespace, "forward_protocol", fprot, sizeof(fprot));
      if (0 != rc || '\0' == fprot[0]) {
         snprintf(fprot, sizeof(fprot), "%s", "both");
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Forward Protocol %s\n" COMMA fprot);
#endif

      // what is the forwarding port range
      char sfport[10];
      char efport[10];
      portrange[0]= '\0';
      sfport[0]   = '\0';
      efport[0]   = '\0';
      rc = syscfg_get(namespace, "forward_range", portrange, sizeof(portrange));
      if (0 != rc || '\0' == portrange[0]) {
         continue;
      } else {
         int r = 0;
         if (2 != (r = sscanf(portrange, "%10s %10s", sfport, efport))) {
            if (1 == r) {
               snprintf(efport, sizeof(efport), "%s", sfport);
            } else {
               continue;
            }
         }
      }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      FIREWALL_DEBUG("PortTriggers:Forward Port Start %s\n" COMMA sfport);
      FIREWALL_DEBUG("PortTriggers:Forward Port End %s\n" COMMA efport);
#endif

#endif

#if defined(SPEED_BOOST_SUPPORTED)
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
      if(IsPortOverlapWithSpeedboostPortRange(atoi(sdport) , atoi(edport) , atoi(sfport) , atoi(efport) )) {
#else
      if(IsPortOverlapWithSpeedboostPortRange(atoi(sdport) , atoi(edport) , 0 , 0 )) {
#endif
           FIREWALL_DEBUG("do_prepare_port_range_triggers: Skip - overlapping with Speedboost port range \n" );
           continue;
      }
#endif

      if (0 == strcmp("both", prot) || 0 == strcmp("tcp", prot)) {
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
         fprintf(nat_fp, "-A prerouting_fromlan_trigger -p tcp -m tcp --dport %s:%s -j TRIGGER --trigger-type out --trigger-proto %s --trigger-match %s:%s --trigger-relate %s:%s\n", sdport, edport, fprot, sdport, edport, sfport, efport);
         fprintf(filter_fp, "-A lan2wan_triggers -p tcp -m tcp --dport %s:%s -j xlog_accept_lan2wan\n", sdport, edport);
         fprintf(filter_fp, "-A lan2wan_triggers -p tcp -m tcp --sport %s:%s -j xlog_accept_lan2wan\n", sfport, efport);

#else
         fprintf(mangle_fp, "-A prerouting_trigger -p tcp -m tcp --dport %s:%s -j MARK --set-mark %d\n", sdport, edport, atoi(id));

         fprintf(filter_fp, "-A lan2wan_triggers -p tcp -m tcp --dport %s:%s -j NFQUEUE --queue-num 22\n", sdport, edport);
#endif
      }
  
      if (0 == strcmp("both", prot) || 0 == strcmp("udp", prot)) {
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
         fprintf(nat_fp, "-A prerouting_fromlan_trigger -p udp -m udp --dport %s:%s -j TRIGGER --trigger-type out --trigger-proto %s --trigger-match %s:%s --trigger-relate %s:%s\n", sdport, edport, fprot, sdport, edport, sfport, efport);
         fprintf(filter_fp, "-A lan2wan_triggers -p udp -m udp --dport %s:%s -j xlog_accept_lan2wan\n", sdport, edport);
         fprintf(filter_fp, "-A lan2wan_triggers -p udp -m udp --sport %s:%s -j xlog_accept_lan2wan\n", sfport, efport);

#else
         fprintf(mangle_fp, "-A prerouting_trigger -p udp -m udp --dport %s:%s -j MARK --set-mark %d\n", sdport, edport, atoi(id));

         fprintf(filter_fp, "-A lan2wan_triggers -p udp -m udp --dport %s:%s -j NFQUEUE --queue-num 22\n", sdport, edport);
#endif
      }

#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
      if (0 == strcmp("both", fprot) || 0 == strcmp("tcp", fprot)) {
         fprintf(nat_fp, "-A prerouting_fromwan_trigger -p tcp -m tcp --dport %s:%s -j TRIGGER --trigger-type dnat\n", sfport, efport);
         fprintf(filter_fp, "-A wan2lan_trigger -p tcp -m tcp --dport %s:%s -j TRIGGER --trigger-type in\n", sfport, efport);
      }
      if (0 == strcmp("both", fprot) || 0 == strcmp("udp", fprot)) {
         fprintf(nat_fp, "-A prerouting_fromwan_trigger -p udp -m udp --dport %s:%s -j TRIGGER --trigger-type dnat\n", sfport, efport);
         fprintf(filter_fp, "-A wan2lan_trigger -p udp -m udp --dport %s:%s -j TRIGGER --trigger-type in\n", sfport, efport);
      }
#endif
   }

end_do_prepare_port_range_triggers:
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   if (isFeatureDisabled == TRUE)
   {
       FIREWALL_DEBUG("PortTriggers:Feature Enable %d\n" COMMA FALSE);
   }
#endif
   FIREWALL_DEBUG("Exiting do_prepare_port_range_triggers\n"); 
   return(0);
}
#endif // CONFIG_BUILD_TRIGGER

/*
 *  Procedure     : prepare_host_detect
 *  Purpose       : prepare the iptables-restore statements for detecting when new hosts join the lan
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 */
static int prepare_host_detect(FILE * fp)
{
   FIREWALL_DEBUG("Entering prepare_host_detect\n"); 
   if (isLanHostTracking || isDMZbyMAC) {
      /*
       * add all known hosts and have them be accepted, but if not, then the last statement is the new host
       */
      FILE *kh_fp = fopen(lan_hosts_dir"/"hosts_filename, "r");
      char buf[1024];
      if (NULL != kh_fp) { 
         while (NULL != fgets(buf, sizeof(buf), kh_fp)) {
            char ip[20];
            char mac[20];
            sscanf(buf, "%20s %20s", ip, mac);
           fprintf(fp, "-A host_detect -i %s -s %s -j RETURN\n", lan_ifname, ip);
         }
         fclose(kh_fp);
      }
      fprintf(fp, "-A host_detect -m state --state NEW -j LOG --log-level 1 --log-prefix \"%s.NEWHOST \" --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", LOG_TRIGGER_PREFIX);
   }
   FIREWALL_DEBUG("Exiting prepare_host_detect\n"); 
   return(0);
}

#ifdef OBSOLETE
/*
 *  Procedure     : prepare_lan_bandwidth_tracking
 *  Purpose       : prepare the iptables-restore statements for tracking bandwidth usage of hosts
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 * Note:   This will place a file in cron.everyminute
 * Note:   This is not efficient, and also no longer necessary
 *         iptables-restore -c maintains the counters, so it is not
 *         necessary to run a script every minute to save the counters
 */
static int prepare_lan_bandwidth_tracking(FILE *fp)
{
   FIREWALL_DEBUG("Entering prepare_lan_bandwidth_tracking\n"); 
   int hosts = 0;
   FILE *kh_fp = fopen(lan_hosts_dir"/"hosts_filename, "r");
   char buf[1024];
   if (NULL != kh_fp) {
      while (NULL != fgets(buf, sizeof(buf), kh_fp)) {
         char ip[20];
         char mac[20];
         sscanf(buf, "%20s %20s", ip, mac);
         char str[MAX_QUERY];
         fprintf(fp, ":bandwidth_%s - [0:0]\n", ip);
	 fprintf(fp, "-N bandwidth_%s\n", ip);
         fprintf(fp, "-A bandwidth_%s -j RETURN\n", ip);

         fprintf(fp, "-A lan2wan_bandwidth -s %s -o %s -j bandwidth_%s\n", ip, current_wan_ifname, ip);

         hosts++;
      }
      fclose(kh_fp);
   }
   FIREWALL_DEBUG("Exiting prepare_lan_bandwidth_tracking\n"); 
   return(0);
}
#endif
/*
 *  Procedure     : do_lan2wan_misc
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  IoT firewall rules pertaining to traffic
 *                  from the lan to the wan
 *  Parameters    :
 *    filter_fp             : An open file to write lan2wan rules to
 * Return Values  :
 *    0              : Success
 */
//unused function
#if 0
static int do_lan2wan_IoT_Allow(FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_lan2wan_IoT_Allow\n"); 
   /*
    * if the wan is currently unavailable, then drop any packets from lan to wan
    */
      fprintf(filter_fp, "-A lan2wan_iot_allow -p udp --dport 53 -j ACCEPT\n");
      fprintf(filter_fp, "-A lan2wan_iot_allow -d ntp01.cmc.co.denver.comcast.net -j ACCEPT\n");
      char query[MAX_QUERY];
      char name[MAX_QUERY];
      int index = 1;
      for( index = 1; index <= 5; ++index ) 
      {
        memset(query, 0, sizeof(query));
        snprintf(name, sizeof(name), "ntp_server%d", index);
        syscfg_get( NULL, name, query, sizeof(query));
        if( query[0] != '\0')
        {
            fprintf(filter_fp, "-A lan2wan_iot_allow -d %s -j ACCEPT\n", query );
        }
      }
  
      //fprintf(filter_fp, "-A lan2wan_iot_allow -d cpentp.services.cox.net -j ACCEPT\n");
      //fprintf(filter_fp, "-A lan2wan_iot_allow -d cpentp.services.coxlab.net -j ACCEPT\n");
      fprintf(filter_fp, "-A lan2wan_iot_allow -d fkps.ccp.xcal.tv -j ACCEPT\n");
      fprintf(filter_fp, "-A lan2wan_iot_allow -d xacs.ccp.xcal.tv -j ACCEPT\n");
      //fprintf(filter_fp, "-A lan2wan_iot_allow -d x1.xcal.tv -j ACCEPT\n");
      fprintf(filter_fp, "-A lan2wan_iot_allow -d decider.r53.xcal.tv -j ACCEPT\n");
      fprintf(filter_fp, "-A lan2wan_iot_allow -j REJECT\n");
   FIREWALL_DEBUG("Exiting do_lan2wan_IoT_Allow\n"); 
   return(0);
}
#endif

//zqiu:R5337
static int do_wan2lan_IoT_Allow(FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_wan2lan_IoT_Allow\n"); 
      //Low firewall
      fprintf(filter_fp, "-A wan2lan_iot_allow -p tcp --dport 113 -j RETURN\n"); // IDENT
      fprintf(filter_fp, "-A wan2lan_iot_allow -j ACCEPT\n");
   FIREWALL_DEBUG("Exiting do_wan2lan_IoT_Allow\n"); 
   return(0);
}

#if defined (MULTILAN_FEATURE)
/*
 *  Procedure     : do_multinet_lan2wan_disable
 *  Purpose       : prepare rules for ipv4 firewall for multinet LANs
                    when in the disabled state
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int do_multinet_lan2wan_disable (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char net_resp2[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4subnet", tok);
        net_resp2[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp2, sizeof(net_resp2));

        fprintf(filter_fp, "-A lan2wan_disable -s %s/%s -j DROP\n", net_resp, net_resp2);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif

/*
 *  Procedure     : do_lan2wan_disable
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the lan to the wan for disable case 
 *  Parameters    :
 *    filter_fp             : An open file to write lan2wan rules to
 * Return Values  :
 *    0              : Success
 */
static void do_lan2wan_disable(FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_lan2wan_disable\n");
#if defined (_WNXL11BWL_PRODUCT_REQ_) 
   fprintf(filter_fp, "-A lan2wan_disable -d 169.254.70.0/16 -j DROP\n");
   fprintf(filter_fp, "-A lan2wan_disable -s 169.254.70.0/16 -j DROP\n");
#else
   fprintf(filter_fp, "-A lan2wan_disable -d 169.254.0.0/16 -j DROP\n");
   fprintf(filter_fp, "-A lan2wan_disable -s 169.254.0.0/16 -j DROP\n");
#endif

   /* if nat is disable or
     * wan is not ready or
     * nat is not ready
     * all private packet from lan to wan should be blocked
     * public packet should be allowed 
     */
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
     if (isMAPTReady)
         return ;
#endif
    if(!isNatReady){
         fprintf(filter_fp, "-A lan2wan_disable -s %s/%s -o %s -j DROP\n", lan_ipaddr, lan_netmask, current_wan_ifname);

#if defined (MULTILAN_FEATURE)
         do_multinet_lan2wan_disable(filter_fp);
#endif

    }
   FIREWALL_DEBUG("Exiting do_lan2wan_disable\n"); 
}

#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
/*
 *  Procedure     : do_lan2wan_helpers
 *  Purpose       : prepare the rules which will trigger connection tracking helpers
 *                  to allow certain LAN to WAN natted traffic
 *  Parameters    :
 *    raw_fp      : An open file to write lan2wan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_lan2wan_helpers(FILE *raw_fp)
{
   FIREWALL_DEBUG("Entering do_lan2wan_helpers\n");

   /* Allow FTP passthrough to work */
   fprintf(raw_fp, "-A lan2wan_helpers -p tcp --dport 21 -j CT --helper ftp\n");

#if defined(CONFIG_CCSP_VPN_PASSTHROUGH)
   char query[2] = {'\0'};

   query[0] = '\0';
   if(!((0==syscfg_get(NULL, "PPTPPassthrough", query, sizeof(query))) && (atoi(query)==0))) {
       fprintf(raw_fp, "-A lan2wan_helpers -p tcp --dport 1723 -j CT --helper pptp\n"); //Load PPTP helper
       FIREWALL_DEBUG("Enabling PPTP passthrough helper\n");
   }
#endif

   /* RTSP helper */
#ifdef CONFIG_CCSP_RTSP_HELPER
   fprintf(raw_fp, "-A lan2wan_helpers -p tcp --dport 554 -j CT --helper rtsp\n");
#endif
   FIREWALL_DEBUG("Exiting do_lan2wan_helpers\n");
   return(0);
}
#endif

/*
 *  Procedure     : do_lan2wan_misc
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the lan to the wan for misc cases
 *  Parameters    :
 *    filter_fp             : An open file to write lan2wan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_lan2wan_misc(FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering do_lan2wan_misc\n");
   /*
    * if the wan is currently unavailable, then drop any packets from lan to wan
    */ 
   if (!isWanReady) {
      fprintf(filter_fp, "-I lan2wan_misc 1 -o %s -j DROP\n", current_wan_ifname);
   }
   char mtu[26];
   int tcp_mss_limit;
   if ( 0 == sysevent_get(sysevent_fd, sysevent_token, "ppp_clamp_mtu", mtu, sizeof(mtu)) ) {
      if ('\0' != mtu[0] && 0 != strncmp("0", mtu, sizeof(mtu)) ) {
         tcp_mss_limit=atoi(mtu) + 1;
         fprintf(filter_fp, "-A lan2wan_misc -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss %d: -j TCPMSS --set-mss %s\n", tcp_mss_limit, mtu);
      }
   }

#if defined(CONFIG_CCSP_VPN_PASSTHROUGH)
    if(isWanReady)
    {
        char query[10];

        syscfg_get("blockipsec", "result", query, sizeof(query));
        if (strcmp(query,"DROP") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 500  -j DROP\n");
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 4500  -j DROP\n");
        }
        else if (strcmp(query,"ACCEPT") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 500  -j ACCEPT\n");
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 4500  -j ACCEPT\n");
        }

        syscfg_get("blockl2tp", "result", query, sizeof(query));
        if (strcmp(query,"DROP") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 1701  -j DROP\n");
        }
        else if (strcmp(query,"ACCEPT") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 1701  -j ACCEPT\n");
        }

        syscfg_get("blockpptp", "result", query, sizeof(query));
        if (strcmp(query,"DROP") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 1723  -j DROP\n");
        }
        else if (strcmp(query,"ACCEPT") == 0) {
            fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 1723  -j ACCEPT\n");
        }
        char sites_enabled[MAX_QUERY];
        sites_enabled[0] = '\0';
        syscfg_get(NULL, "managedsites_enabled", sites_enabled, sizeof(sites_enabled));
        if (sites_enabled[0] != '\0' && sites_enabled[0] == '0') // managed site list enabled
        {
            syscfg_get("blockssl", "result", query, sizeof(query));
            if (strcmp(query,"DROP") == 0) {
                fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 443  -j DROP\n");
                fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 443  -j DROP\n");
            }
            else if(strcmp(query,"ACCEPT") == 0) {
                fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 443  -j ACCEPT\n");
                fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 443  -j ACCEPT\n");
            }
        }
    }
#endif

   if (isWanReady && strncasecmp(firewall_level, "High", strlen("High")) == 0)
   {
      // enforce high security - per requirement
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 80   -j RETURN\n"); // HTTP
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 8080 -j RETURN\n"); // WEBPA
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 443  -j RETURN\n"); // HTTPS
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 53   -j RETURN\n"); // DNS
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 53   -j RETURN\n"); // DNS
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 119  -j RETURN\n"); // NTP
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 119  -j RETURN\n"); // NTP
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 123  -j RETURN\n"); // NTP
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 123  -j RETURN\n"); // NTP
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 25   -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 110  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 143  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 465  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 587  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 993  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 995  -j RETURN\n"); // EMAIL
      fprintf(filter_fp, "-A lan2wan_misc -p gre              -j RETURN\n"); // GRE
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 500  -j RETURN\n"); // VPN
      //zqiu>> cisco vpn
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 4500  -j RETURN\n"); // VPN
      fprintf(filter_fp, "-A lan2wan_misc -p udp --dport 62515  -j RETURN\n"); // VPN
      //zqiu<<
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 1723 -j RETURN\n"); // VPN
      fprintf(filter_fp, "-A lan2wan_misc -p tcp --dport 3689 -j RETURN\n"); // ITUNES
      fprintf(filter_fp, "-A lan2wan_misc -m state --state RELATED,ESTABLISHED -j RETURN\n");
#if !defined(_PLATFORM_IPQ_)
      fprintf(filter_fp, "-A lan2wan_misc -j xlog_drop_lan2wan_misc\n");
#endif
   }
   FIREWALL_DEBUG("Exiting do_lan2wan_misc\n");
   return(0);
}

static void do_add_TCP_MSS_rules(FILE *mangle_fp)
{
    fprintf(mangle_fp, "-I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n");
    fprintf(mangle_fp, "-I OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n");
}

/*
 *  Procedure     : do_lan2wan
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the lan to the wan
 *  Parameters    :
 *    mangle_fp             : An open file to write lan2wan rules to
 *    filter_fp             : An open file to write lan2wan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_lan2wan(FILE *mangle_fp, FILE *filter_fp, FILE *nat_fp)
{
   FIREWALL_DEBUG("Entering do_lan2wan\n");
#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_) && !defined(_SCXF11BFL_PRODUCT_REQ_)
   if (isNatReady)
   {
       FILE *f = NULL;
       char request[256], response[256], cm_ipaddr[20];
       unsigned int a = 0, b = 0, c = 0, d = 0;

       snprintf(request, 256, "snmpget -cpub -v2c -Ov %s %s", CM_SNMP_AGENT, kOID_cmRemoteIpAddress);

       if ((f = popen(request, "r")) != NULL)
       {
           fgets(response, 255, f);
           sscanf(response, "Hex-STRING: %02x %02x %02x %02x", &a, &b, &c, &d);
           sprintf(cm_ipaddr, "%d.%d.%d.%d", a, b, c, d);

           if (!(a == 0 && b == 0 && c == 0 && d == 0))
           {
               fprintf(filter_fp, "-I lan2wan -d %s -p icmp -m icmp --icmp-type 8 -j DROP\n", cm_ipaddr);
               fprintf(filter_fp, "-I lan2wan -d %s -p tcp -m tcp --dport 80 -j DROP\n", cm_ipaddr);
           }

           pclose(f);
       }
   }
#endif
   do_lan2wan_misc(filter_fp);
   //do_lan2wan_IoT_Allow(filter_fp);
   //Not used in USGv2
   //do_lan2wan_webfilters(filter_fp);
   //do_lan_access_restrictions(filter_fp, nat_fp);
   do_lan2wan_disable(filter_fp);
   do_parental_control(filter_fp, nat_fp, 4);

   do_add_TCP_MSS_rules(mangle_fp);
   /* XDNS - route dns req though dnsmasq */
#ifdef XDNS_ENABLE
   do_dns_route(nat_fp, 4);
#endif

   #ifdef CISCO_CONFIG_TRUE_STATIC_IP
   do_lan2wan_staticip(filter_fp);
   #endif
#ifdef CONFIG_BUILD_TRIGGER
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   WAN_FAILOVER_SUPPORT_CHECK
   do_prepare_port_range_triggers(nat_fp, filter_fp);
   WAN_FAILOVER_SUPPORT_CHECk_END
#else
    WAN_FAILOVER_SUPPORT_CHECK	   
    do_prepare_port_range_triggers(mangle_fp, filter_fp);
    WAN_FAILOVER_SUPPORT_CHECk_END
#endif
#endif

   if (isLanHostTracking || isDMZbyMAC) {
      prepare_host_detect(filter_fp);
   }

#ifdef OBSOLETE
   if (isLanHostTracking) {
      prepare_lan_bandwidth_tracking(filter_fp);
   }
#endif

   FIREWALL_DEBUG("Exiting do_lan2wan\n"); 

   return(0);
}



static void add_usgv2_wan2lan_general_rules(FILE *fp)
{
   FIREWALL_DEBUG("Entering add_usgv2_wan2lan_general_rules\n"); 
    fprintf(fp, "-A wan2lan_misc -m state --state RELATED,ESTABLISHED -j ACCEPT\n");

    if (strncasecmp(firewall_level, "High", strlen("High")) == 0) {
        if (isDmzEnabled) {
            fprintf(fp, "-A wan2lan_misc -j wan2lan_dmz\n");
        }
        fprintf(fp, "-A wan2lan_misc -j xlog_drop_wan2lan\n");

    } else if (strncasecmp(firewall_level, "Medium", strlen("Medium")) == 0) {

        fprintf(fp, "-A wan2lan_misc -p tcp --dport 113 -j xlog_drop_wan2lan\n"); // IDENT
        fprintf(fp, "-A wan2lan_misc -p icmp --icmp-type 8 -j xlog_drop_wan2lan\n"); // ICMP PING

        fprintf(fp, "-A wan2lan_misc -p tcp --dport 1214 -j xlog_drop_wan2lan\n"); // Kazaa
        fprintf(fp, "-A wan2lan_misc -p udp --dport 1214 -j xlog_drop_wan2lan\n"); // Kazaa
        fprintf(fp, "-A wan2lan_misc -p tcp --dport 6881:6999 -j xlog_drop_wan2lan\n"); // Bittorrent
        fprintf(fp, "-A wan2lan_misc -p tcp --dport 6346 -j xlog_drop_wan2lan\n"); // Gnutella
        fprintf(fp, "-A wan2lan_misc -p udp --dport 6346 -j xlog_drop_wan2lan\n"); // Gnutella
        fprintf(fp, "-A wan2lan_misc -p tcp --dport 49152:65534 -j xlog_drop_wan2lan\n"); // Vuze

    } else if (strncasecmp(firewall_level, "Low", strlen("Low")) == 0) {

        fprintf(fp, "-A wan2lan_misc -p tcp --dport 113 -j xlog_drop_wan2lan\n"); // IDENT

    } else if (strncasecmp(firewall_level, "Custom", strlen("Custom")) == 0) {
        
        if (isHttpBlocked) {
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 80 -j xlog_drop_wan2lan\n"); // HTTP
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 443 -j xlog_drop_wan2lan\n"); // HTTPS
        }

        if (isIdentBlocked) {
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 113 -j xlog_drop_wan2lan\n"); // IDENT
        }

        if (isPingBlocked) {
            fprintf(fp, "-A wan2lan_misc -p icmp --icmp-type 8 -j xlog_drop_wan2lan\n"); // ICMP PING
        }

        if (isP2pBlocked) {
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 1214 -j xlog_drop_wan2lan\n"); // Kazaa
            fprintf(fp, "-A wan2lan_misc -p udp --dport 1214 -j xlog_drop_wan2lan\n"); // Kazaa
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 6881:6999 -j xlog_drop_wan2lan\n"); // Bittorrent
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 6346 -j xlog_drop_wan2lan\n"); // Gnutella
            fprintf(fp, "-A wan2lan_misc -p udp --dport 6346 -j xlog_drop_wan2lan\n"); // Gnutella
            fprintf(fp, "-A wan2lan_misc -p tcp --dport 49152:65534 -j xlog_drop_wan2lan\n"); // Vuze
        }

        if(isMulticastBlocked) {
            fprintf(fp, "-A wan2lan_misc -p 2 -j xlog_drop_wan2lan\n"); // IGMP
        }
    }
   FIREWALL_DEBUG("Exiting add_usgv2_wan2lan_general_rules\n"); 
}

/*
 ==========================================================================
                     wan2lan
 ==========================================================================
 */

/*
 *  Procedure     : do_wan2lan_misc
 *  Purpose       : prepare the iptables-restore statements for forwarding incoming packets to a lan host
 *  Parameters    : 
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_wan2lan_misc(FILE *fp) 
{
   if (NULL == fp) {
      return(-1);
   }
   FIREWALL_DEBUG("Entering do_wan2lan_misc\n"); 
   /*
    * PLATFORM_IPQ: These generic rules should be populated to the do_wan2lan_misc chain
    * after user-defined rules have been added.
    */
#ifndef _PLATFORM_IPQ_
   add_usgv2_wan2lan_general_rules(fp);
#endif
   /*
    * syscfg tuple W2LFirewallRule_, where x is a digit
    * keeps track of the syscfg namespace of a user defined forwarding rule.
    * We iterate through these tuples until we dont find an instance in syscfg.
    */ 
   int idx;
   int  rc;
   char namespace[MAX_NAMESPACE];
   char query[MAX_QUERY];

   int count;

   query[0] = '\0';
   rc = syscfg_get(NULL, "W2LFirewallRuleCount", query, sizeof(query));
   if (0 != rc || '\0' == query[0]) {
      goto FirewallRuleNext;
   } else {
      count = atoi(query);
      if (0 == count) {
         goto FirewallRuleNext;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   for (idx=1 ; idx<=count ; idx++) {
      namespace[0] = '\0';
      snprintf(query, sizeof(query), "W2LFirewallRule_%d", idx);
      rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
      if (0 != rc || '\0' == query[0]) {
         continue;
      } 

      char match[MAX_QUERY];
      match[0] = '\0';
      rc = syscfg_get(namespace, "match", match, sizeof(match));
      if (0 != rc || '\0' == match[0]) {
         continue;
      } 
      char result[26];
      result[0] = '\0';
      rc = syscfg_get(namespace, "result", result, sizeof(result));
      if (0 != rc || '\0' == result[0]) {
         continue;
      } 

      char subst[MAX_QUERY];
      fprintf(fp, "-A wan2lan_misc %s -j %s\n", match, make_substitutions(result, subst, sizeof(subst)));

   }
FirewallRuleNext:

   count = 0;
   /*
    * syscfg tuple W2LWellKnownFirewallRule_x, where x is a digit
    * keeps track of the syscfg namespace of a user defined forwarding rule.
    * We iterate through these tuples until we dont find an instance in syscfg.
    */ 

   char *filename = otherservices_dir"/"otherservices_file;
   FILE *os_fp = fopen(filename, "r");
   if (NULL != os_fp) {

      query[0] = '\0';
      rc = syscfg_get(NULL, "W2LWellKnownFirewallRuleCount", query, sizeof(query));
      if (0 != rc || '\0' == query[0]) {
         goto FirewallRuleNext2;
      } else {
         count = atoi(query);
         if (0 == count) {
            goto FirewallRuleNext2;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }
      }

      for (idx=1 ; idx<=count ; idx++) {
         namespace[0] = '\0';
         snprintf(query, sizeof(query), "W2LWellKnownFirewallRule_%d", idx);
         rc = syscfg_get(NULL, query, namespace, sizeof(namespace));
         if (0 != rc || '\0' == namespace[0]) {
            continue;
         } 

         char name[56];
         name[0] = '\0';
         rc = syscfg_get(namespace, "name", name, sizeof(name));
         if (0 != rc || '\0' == name[0]) {
            continue;
         } 
         char result[26];
         result[0] = '\0';
         rc = syscfg_get(namespace, "result", result, sizeof(result));
         if (0 != rc || '\0' == result[0]) {
            continue;
         } 

         /*
          * look up the rules for this service
          */
         rewind(os_fp);
         char line[512];
         char *next_token;

         while (NULL != (next_token = match_keyword(os_fp, name, '|', line, sizeof(line))) ) {
            char *friendly_name = next_token;

            next_token = token_get(friendly_name, '|');
            if (NULL == next_token || NULL == friendly_name) {
               continue;
            }

            char *match = next_token;
            next_token = token_get(match, '|');
            /* Logically dead code*/
            // if (NULL == match) {
            //    continue;
            // }

	    char subst[MAX_QUERY];
            /*
             * The wan2lan iptables chain contains packets from wan destined to lan.
             * The wan2lan chain is linked to from the FORWARD chain
             */
            fprintf(fp, "-A wan2lan_misc %s -j %s\n", match, make_substitutions(result, subst, sizeof(subst)));
         }
      }
FirewallRuleNext2:

      fclose(os_fp);
   }

  // mtu clamping
   char mtu[26];
   int tcp_mss_limit;
   if ( 0 == sysevent_get(sysevent_fd, sysevent_token, "ppp_clamp_mtu", mtu, sizeof(mtu)) ) {
      if ('\0' != mtu[0] && 0 != strncmp("0", mtu, sizeof(mtu)) ) {
         tcp_mss_limit=atoi(mtu) + 1;
         fprintf(fp, "-A wan2lan_misc -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss %d: -j TCPMSS --set-mss %s\n", tcp_mss_limit, mtu);
      }
   }

   /*
    * PLATFORM_IPQ: These generic rules should be populated to the do_wan2lan_misc chain
    * after user-defined rules have been added.
    */
#ifdef _PLATFORM_IPQ_
   add_usgv2_wan2lan_general_rules(fp);
#endif
   FIREWALL_DEBUG("Exiting do_wan2lan_misc\n"); 
   return(0);
}

#if defined (MULTILAN_FEATURE) && !defined (FEATURE_SUPPORT_MAPT_NAT46)
/*
 *  Procedure     : do_multinet_wan2lan_disable
 *  Purpose       : prepare rules for ipv4 firewall for multinet LANs
                    when in the disabled state
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int do_multinet_wan2lan_disable (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char net_resp2[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4subnet", tok);
        net_resp2[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp2, sizeof(net_resp2));

        fprintf(filter_fp, "-A wan2lan_disabled -d %s/%s -j DROP\n", net_resp, net_resp2);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif

/*
 *  Procedure     : do_wan2lan_disabled
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the wan to the lan for the case where lan2wan traffic is disabled
 *  Parameters    :
 *    fp             : An open file to write wan2lan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_wan2lan_disabled(FILE *fp)
{
   FIREWALL_DEBUG("Entering do_wan2lan_disabled\n");
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   char mapt_config_value[BUFLEN_8] = {0};
   /* Check sysevent fd availabe at this point. */
   if (sysevent_fd < 0)
   {
       FIREWALL_DEBUG("ERROR: Sysevent FD is not available \n");
       return RET_ERR;
   }

   if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_CONFIG_FLAG, mapt_config_value, sizeof(mapt_config_value)) != 0)
   {
       FIREWALL_DEBUG("ERROR: Failed to get MAPT configuration value from sysevent \n");
       return RET_ERR;
   }
   /*  Check mapt config flag is reset, then drop any packets from wan to lan*/
   if (strncmp(mapt_config_value,SET, 3) != 0)
   {
      if (!isNatReady ) {
         fprintf(fp, "-A wan2lan_disabled -d %s/%s -j DROP\n", lan_ipaddr, lan_netmask);
      }
   }
#endif //FEATURE_MAPT

#ifndef _HUB4_PRODUCT_REQ_
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      /*
      * if the wan is currently unavailable, then drop any packets from wan to lan
      */
      if (!isNatReady ) {
         fprintf(fp, "-A wan2lan_disabled -i %s -d %s/%s -j DROP\n", current_wan_ifname, lan_ipaddr, lan_netmask);

   #if defined (MULTILAN_FEATURE)
         do_multinet_wan2lan_disable(fp);
   #endif

      }
   }
#endif
   FIREWALL_DEBUG("Exiting do_wan2lan_disabled\n"); 
   return(0);
}

/*
 *  Procedure     : do_wan2lan_accept
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the wan to the lan for which we are allowing
 *  Parameters    :
 *    fp             : An open file to write wan2lan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_wan2lan_accept(FILE *fp)
{

   FIREWALL_DEBUG("Entering do_wan2lan_accept\n"); 

   if (!isMulticastBlocked) {
      // accept multicast from our wan
      fprintf(fp, "-A wan2lan_accept -p udp -m udp --destination 224.0.0.0/4 -j ACCEPT\n");
   }
   FIREWALL_DEBUG("Exiting do_wan2lan_accept\n"); 
   return(0);
}

#ifdef CISCO_CONFIG_TRUE_STATIC_IP
/*
 *  Procedure     : do_wan2lan_staticip
 *  Purpose       : Accept or deny static ip subnet packet from wan to lan
 *  Parameters    :
 *    fp             : An open file to write wan2lan rules to
 * Return Values  :
 *    0              : Success
 */
static void do_wan2lan_staticip(FILE *filter_fp)
{
    int i;
   FIREWALL_DEBUG("Entering do_wan2lan_staticip\n"); 	  
    if(isWanStaticIPReady && isFWTS_enable){
        for(i = 0; i < StaticIPSubnetNum; i++){
            fprintf(filter_fp, "-A wan2lan_staticip -d %s/%s -j ACCEPT\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);
        }
    }
    
    for(i = 0; i < StaticIPSubnetNum; i++){
        fprintf(filter_fp, "-A wan2lan_staticip_post -d %s/%s -j ACCEPT\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask);
    }
   FIREWALL_DEBUG("Exiting do_wan2lan_staticip\n"); 	  
}

//Add True Static IP port mgmt rules
#define PT_MGMT_PREFIX "tsip_pm_"
static void do_wan2lan_tsip_pm(FILE *filter_fp)
{
    int rc, i, count, j;
    char query[MAX_QUERY], countStr[16], utKey[64];
    char startIP[sizeof("255.255.255.255")], endIP[sizeof("255.255.255.255")];
    char startPort[sizeof("65535")], endPort[sizeof("65535")];
    unsigned char type = 0;
   FIREWALL_DEBUG("Entering do_wan2lan_tsip_pm\n"); 	  
    query[0] = '\0';
    rc = syscfg_get(NULL, PT_MGMT_PREFIX"enabled", query, sizeof(query));

    //if the key tsip_pm_enabled doesn't exist, e.g. rc != 0 we treat it as enabled.
    if ((rc == 0 && atoi(query) != 1) || !isWanStaticIPReady) { //key exists and the value is 0 or tsi not ready
        return ;
    }

    query[0] = '\0';
    rc = syscfg_get(NULL, PT_MGMT_PREFIX"type", query, sizeof(query));

    if (rc != 0)
        type = 0; //if the key doesn't exist, the default mode is white list
    else if(strcmp("white", query) == 0)
        type = 0;
    else if(strcmp("black", query) == 0)
        type = 1;

    rc = syscfg_get(NULL, PT_MGMT_PREFIX"count", countStr, sizeof(countStr));
    if(rc == 0)
        count = strtoul(countStr, NULL, 10);
    else
        count = 0;
    
    //allow the return traffic of lan initiated traffic
    fprintf(filter_fp, "-A wan2lan_staticip_pm -p tcp -m state --state ESTABLISHED -j ACCEPT\n");
    fprintf(filter_fp, "-A wan2lan_staticip_pm -p udp -m state --state ESTABLISHED -j ACCEPT\n");

    for(i = 0; i < count; i++) {
        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_enabled", i);
        query[0] = '\0';
        rc = syscfg_get(NULL, utKey, query, sizeof(query));
        if(rc != 0 || atoi(query) != 1)
            continue;

        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_protocol", i);
        query[0] = '\0';
        syscfg_get(NULL, utKey, query, sizeof(query));
        
        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_startIP", i);
        syscfg_get(NULL, utKey, startIP, sizeof(startIP));
        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_endIP", i);
        syscfg_get(NULL, utKey, endIP, sizeof(endIP));
        
        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_startPort", i);
        syscfg_get(NULL, utKey, startPort, sizeof(startPort));
        snprintf(utKey, sizeof(utKey), PT_MGMT_PREFIX"%u_endPort", i);
        syscfg_get(NULL, utKey, endPort, sizeof(endPort));

        if(strcmp("tcp", query) == 0 || strcmp("both", query) == 0)
        {
            fprintf(filter_fp, "-A wan2lan_staticip_pm -p tcp -m tcp --dport %s:%s -m iprange --dst-range %s-%s -j %s\n", startPort, endPort, startIP, endIP, type == 0 ? "ACCEPT" : "DROP");
            for(j = 0; j < PfRangeCount; j++) {
                  fprintf(filter_fp, "-A wan2lan_staticip_pm -d %s -p tcp -m tcp --dport %s:%s -j %s\n",  PfRangeIP[j], startPort, endPort, type == 0 ? "ACCEPT" : "DROP");
             }
        }
        if(strcmp("udp", query) == 0 || strcmp("both", query) == 0)
        {
            fprintf(filter_fp, "-A wan2lan_staticip_pm -p udp -m udp --dport %s:%s -m iprange --dst-range %s-%s -j %s\n", startPort, endPort, startIP, endIP, type == 0 ? "ACCEPT" : "DROP");

            for(j = 0; j < PfRangeCount; j++) {
                  fprintf(filter_fp, "-A wan2lan_staticip_pm -d %s -p udp -m udp --dport %s:%s -j %s\n",  PfRangeIP[j], startPort, endPort, type == 0 ? "ACCEPT" : "DROP");
             }
        }
    }
    
    for(i = 0; i < StaticIPSubnetNum; i++) {
        fprintf(filter_fp, "-A wan2lan_staticip_pm -p tcp -d %s/%s -j %s\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask, type == 0 ? "DROP" : "ACCEPT");
        fprintf(filter_fp, "-A wan2lan_staticip_pm -p udp -d %s/%s -j %s\n", StaticIPSubnet[i].ip, StaticIPSubnet[i].mask, type == 0 ? "DROP" : "ACCEPT");
    }

   for(j = 0; j < PfRangeCount; j++) {
        fprintf(filter_fp, "-A wan2lan_staticip_pm -p tcp -d %s -j %s\n",  PfRangeIP[j], type == 0 ? "DROP" : "ACCEPT");
        fprintf(filter_fp, "-A wan2lan_staticip_pm -p udp -d %s -j %s\n", PfRangeIP[j], type == 0 ? "DROP" : "ACCEPT");
    }

   FIREWALL_DEBUG("Exiting do_wan2lan_tsip_pm\n"); 	  
}
#endif

/*
 *  Procedure     : do_wan2lan
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  from the wan to the lan
 *  Parameters    :
 *    fp             : An open file to write wan2lan rules to
 * Return Values  :
 *    0              : Success
 */
static int do_wan2lan(FILE *fp)
{
   FIREWALL_DEBUG("Entering do_wan2lan\n"); 	  
   do_wan2lan_disabled(fp);
   do_wan2lan_misc(fp);
   do_wan2lan_accept(fp);
   #ifdef CISCO_CONFIG_TRUE_STATIC_IP
   do_wan2lan_staticip(fp);
   do_wan2lan_tsip_pm(fp);
   #endif
   FIREWALL_DEBUG("Exiting do_wan2lan\n"); 	  
   return(0);
}

/*
 ==========================================================================
              Ephemeral filter rules
 ==========================================================================
 */

/*
 *  Procedure     : do_filter_table_general_rules
 *  Purpose       : prepare the iptables-restore statements for syscfg/syseventstatements that are applied directly 
 *                  to the filter table 
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 */
static int do_filter_table_general_rules(FILE *fp)
{
   // add rules from syscfg
   int  idx;
   char rule_query[MAX_QUERY];
   int  count = 1;

   char      rule[MAX_QUERY];
   char      in_rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   FIREWALL_DEBUG("Entering do_filter_table_general_rules\n"); 	  
   in_rule[0] = '\0';
   syscfg_get(NULL, "GeneralPurposeFirewallRuleCount", in_rule, sizeof(in_rule));
   if ('\0' == in_rule[0]) {
      goto GPFirewallRuleNext;
   } else {
      count = atoi(in_rule);
      if (0 == count) {
         goto GPFirewallRuleNext;
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   memset(in_rule, 0, sizeof(in_rule));
   for (idx=1; idx<=count; idx++) {
      snprintf(rule_query, sizeof(rule_query), "GeneralPurposeFirewallRule_%d", idx);
      syscfg_get(NULL, rule_query, in_rule, sizeof(in_rule));
      if ('\0' == in_rule[0]) {
         continue;
      } else {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
         char str[MAX_QUERY];
         if (NULL != make_substitutions(in_rule, subst, sizeof(subst))) {
            if ((1 == substitute(subst, str, sizeof(str), "INPUT", "general_input")) ||
                (1 == substitute(subst, str, sizeof(str), "OUTPUT", "general_output")) ||
                (1 == substitute(subst, str, sizeof(str), "FORWARD", "general_forward")) ) {
               fprintf(fp, "%s\n", str);
            }
         }
      }
      memset(in_rule, 0, sizeof(in_rule));
   }

GPFirewallRuleNext:

{};// this statement is just to keep the compiler happy. otherwise it has  a problem with the lable:
   // add rules from sysevent
   unsigned int iterator; 
   char          name[MAX_QUERY];

   iterator = SYSEVENT_NULL_ITERATOR;
   do {
      name[0] = rule[0] = '\0';
      sysevent_get_unique(sysevent_fd, sysevent_token, 
                                  "GeneralPurposeFirewallRule", &iterator, 
                                  name, sizeof(name), rule, sizeof(rule));
      if ('\0' != rule[0]) {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
         char str[MAX_QUERY];
         if (NULL != make_substitutions(rule, subst, sizeof(subst))) {
            if ((1 == substitute(subst, str, sizeof(str), "INPUT", "general_input"))   ||
               (1 == substitute(subst, str, sizeof(str), "OUTPUT", "general_output"))  ||
               (1 == substitute(subst, str, sizeof(str), "FORWARD", "general_forward")) ) {
                    fprintf(fp, "%s\n", str);
            }
         }
      }

   } while (SYSEVENT_NULL_ITERATOR != iterator);
                FIREWALL_DEBUG("Exiting do_filter_table_general_rules\n"); 	  
   return (0);
}

#ifdef MULTILAN_FEATURE
/*
 *  Procedure     : prepare_multinet_prerouting_nat
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be evaluated by NAT table before routing
 *  Parameters    :
 *    nat_fp      : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_prerouting_nat (FILE *nat_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromlan\n", net_resp);
        fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_devices\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}

/*
 *  Procedure     : prepare_multinet_postrouting_nat
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be evaluated by NAT table after routing
 *  Parameters    :
 *    nat_fp      : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_postrouting_nat (FILE *nat_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_tolan\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#else //else of MULTILAN_FEATURE
// TODO: ALL THESE THINGSZ
static int prepare_multinet_prerouting_nat(FILE *nat_fp) {
    return 0;
}

static int prepare_multinet_postrouting_nat(FILE *nat_fp) {
    return 0;
}
#endif //end of MULTILAN_FEATURE

static void prepare_ipc_filter(FILE *filter_fp) {
                FIREWALL_DEBUG("Entering prepare_ipc_filter\n"); 	  
#if !defined (_COSA_BCM_ARM_) && !defined(INTEL_PUMA7) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_) && !defined(_COSA_QCA_ARM_)
    // TODO: fix this hard coding
    fprintf(filter_fp, "-I OUTPUT -o %s -j ACCEPT\n", "l2sd0.500");
    fprintf(filter_fp, "-I INPUT -i %s -j ACCEPT\n", "l2sd0.500");
//zqiu>>
//  make sure rpc channel are not been blocked
    fprintf(filter_fp, "-I OUTPUT -o %s -j ACCEPT\n", "l2sd0.4093");
    fprintf(filter_fp, "-I INPUT -i %s -j ACCEPT\n", "l2sd0.4093");
//zqiu<<
#endif

#if (defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)) && !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(filter_fp, "-I INPUT -i %s -j ACCEPT\n", "privbr");
   }
#endif

                FIREWALL_DEBUG("Exiting prepare_ipc_filter\n"); 	  
}

static void prepare_hotspot_gre_ipv4_rule(FILE *filter_fp) {
   char fw_rule[MAX_QUERY] = {0};

   FIREWALL_DEBUG("Entering prepare_hotspot_gre_ipv4_rule\n");
   sysevent_get(sysevent_fd, sysevent_token, "gre_ipv4_fw_rule", fw_rule, sizeof(fw_rule));
   if (strlen(fw_rule))
       fprintf(filter_fp, "%s\n", fw_rule);
}

/*
 *  Procedure     : prepare_multinet_filter_input
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be sent from LAN to the local host
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_filter_input (FILE *filter_fp)
{
#if defined (MULTILAN_FEATURE)
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];
    FIREWALL_DEBUG("Entering prepare_multinet_filter_input\n"); 	  

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(filter_fp, "-A INPUT -i %s -j lan2self\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);
#else
    FIREWALL_DEBUG("Entering prepare_multinet_filter_input\n");
#endif

#if (defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    if (isMAPTReady)
    {
        fprintf(filter_fp, "-I INPUT -i %s -p gre -j ACCEPT\n", NAT46_INTERFACE);
    }
#endif //FEATURE_MAPT
    FIREWALL_DEBUG("Exiting prepare_multinet_filter_input\n"); 	 
    return 0;  
}

#ifdef MULTILAN_FEATURE
/*
 *  Procedure     : prepare_multinet_filter_output
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be sent from local host to LAN
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_filter_output (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(filter_fp, "-A OUTPUT -o %s -j self2lan\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);
  
    return 0;
}
#else //else of MULTILAN_FEATURE
static int prepare_multinet_filter_output(FILE *filter_fp) {
    return 0;
}
#endif //end of MULTILAN_FEATURE

/*
 *  Procedure     : prepare_multinet_filter_forward
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules pertaining to traffic
 *                  which will be either forwarded or received locally
 *  Parameters    :
 *    filter_fp   : An open file to write wan2lan rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_filter_forward (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];
    char ip[MAX_QUERY];

    FIREWALL_DEBUG("Entering prepare_multinet_filter_forward\n"); 	 

    do_block_ports (filter_fp);

    //L3 rules
    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));
    
    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));
    
    tok = strtok(inst_resp, " ");
    
    if (tok) do {
        // TODO: IGNORING Primary INSTANCE FOR NOW
        if (strcmp(primary_inst,tok) == 0) 
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;
        
        snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        
        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        ip[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, ip, sizeof(ip));
        
//         fprintf(filter_fp, "-I INPUT -i %s -d %s -j ACCEPT\n", net_resp, net_ip);
#if !defined(_HUB4_PRODUCT_REQ_) /* Rules for pod interface */
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
        fprintf(filter_fp, "-A INPUT -i %s -d %s -j ACCEPT\n", net_resp, ip);
        fprintf(filter_fp, "-A INPUT -i %s -m pkttype ! --pkt-type unicast -j ACCEPT\n", net_resp);
#ifdef MULTILAN_FEATURE
	if ( 0 == strncmp( lan_ifname, net_resp, strlen(lan_ifname))){
        fprintf(filter_fp, "-A FORWARD -i %s -o %s -j lan2wan\n", net_resp, current_wan_ifname);
	}
        fprintf(filter_fp, "-A FORWARD -i %s -o %s -j wan2lan\n", current_wan_ifname, net_resp);
#else
        fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", net_resp, current_wan_ifname);
        fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", current_wan_ifname, net_resp);
#endif /*MULTILAN_FEATURE*/
   }
#endif /*_HUB4_PRODUCT_REQ_*/
        //fprintf(filter_fp, "-A OUTPUT -o %s -j ACCEPT\n", net_resp);

#if defined (INTEL_PUMA7) || ((defined (_COSA_BCM_ARM_) || defined (_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) || defined(_COSA_QCA_ARM_)) && !defined(_CBR_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_))
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      if ( 0 != strncmp( lan_ifname, net_resp, strlen(lan_ifname))) { // block forwarding between bridge
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", lan_ifname, net_resp);
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", net_resp, lan_ifname);
      }
   }
#endif
        
    } while ((tok = strtok(NULL, " ")) != NULL);
    
    //zqiu: Mesh >>
#if defined(ENABLE_FEATURE_MESHWIFI)
#if defined(_COSA_INTEL_XB3_ARM_) // XB3 ARM
    fprintf(filter_fp, "-A INPUT -i l2sd0.112 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i l2sd0.112 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i l2sd0.113 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i l2sd0.113 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i l2sd0.4090 -d 192.168.251.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i l2sd0.4090 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    //RDKB-15951
    fprintf(filter_fp, "-A INPUT -i br403 -d 192.168.245.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined(_WNXL11BWL_PRODUCT_REQ_) 
    fprintf(filter_fp, "-A INPUT -i brlan112 -d 169.254.70.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan112 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan113 -d 169.254.71.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan113 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined(_XB7_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_)
    fprintf(filter_fp, "-A INPUT -i brlan112 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan112 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A FORWARD -i brlan112 -o erouter0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan0 -o brlan112 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan1 -o brlan112 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan112 -o brlan0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan112 -o brlan1 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i erouter0 -o brlan112 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan112 -d 192.168.100.1/32 -p tcp -m multiport --dport 22,80,443 -j DROP\n");

    fprintf(filter_fp, "-A INPUT -i brlan113 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan113 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A FORWARD -i brlan113 -o erouter0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan0 -o brlan113 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan1 -o brlan113 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan113 -o brlan0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan113 -o brlan1 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i erouter0 -o brlan113 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan113 -d 192.168.100.1/32 -p tcp -m multiport --dport 22,80,443 -j DROP\n");

    fprintf(filter_fp, "-A INPUT -i brlan115 -d 169.254.5.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan115 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A FORWARD -i brlan115 -o erouter0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan0 -o brlan115 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan1 -o brlan115 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan115 -o brlan0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan115 -o brlan1 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i erouter0 -o brlan115 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan115 -d 192.168.100.1/32 -p tcp -m multiport --dport 22,80,443 -j DROP\n");

    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined (INTEL_PUMA7) || (defined (_COSA_BCM_ARM_) && !defined(_CBR_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_)) || defined(_COSA_QCA_ARM_) // ARRIS XB6 ATOM, TCXB6
    fprintf(filter_fp, "-A INPUT -i ath12 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i ath12 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A FORWARD -i ath12 -o erouter0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan0 -o ath12 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan1 -o ath12 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath12 -o brlan0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath12 -o brlan1 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i erouter0 -o ath12 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath12 -d 192.168.100.1/32 -p tcp -m multiport --dport 22,80,443 -j DROP\n");

    fprintf(filter_fp, "-A INPUT -i ath13 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i ath13 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A FORWARD -i ath13 -o erouter0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan0 -o ath13 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i brlan1 -o ath13 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath13 -o brlan0 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath13 -o brlan1 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i erouter0 -o ath13 -j DROP\n");
    fprintf(filter_fp, "-A FORWARD -i ath13 -d 192.168.100.1/32 -p tcp -m multiport --dport 22,80,443 -j DROP\n");

    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined (_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
    fprintf(filter_fp, "-A INPUT -i wifi2 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi2 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi3 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi3 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi6 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi6 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi7 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i wifi7 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i bhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i bhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined(_COSA_BCM_MIPS_)
    FIREWALL_DEBUG("after cosa_bcm check\n");
    fprintf(filter_fp, "-A INPUT -i brlan112 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan112 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan113 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan113 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -d 192.168.245.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#elif defined(_HUB4_PRODUCT_REQ_)
    fprintf(filter_fp, "-A INPUT -i brlan6 -d 169.254.0.0/24 -p tcp -m multiport --dport 22,80,443 -j DROP\n");
    fprintf(filter_fp, "-A INPUT -i brlan7 -d 169.254.1.0/24 -p tcp -m multiport --dport 22,80,443 -j DROP\n");
    fprintf(filter_fp, "-A INPUT -i brlan6 -d 169.254.0.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan6 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan7 -d 169.254.1.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brlan7 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -d 192.168.245.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -d 169.254.85.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i brebhaul -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#endif
#endif
#if !defined(_HUB4_PRODUCT_REQ_)
    fprintf(filter_fp, "-A INPUT -i l2sd0.4090 -d 192.168.251.0/24 -p tcp --dport 6666 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -d 192.168.245.0/24 -p tcp --dport 6666 -j ACCEPT\n");
#endif /*_HUB4_PRODUCT_REQ_*/

#if defined(FEATURE_COGNITIVE_WIFIMOTION)
    fprintf(filter_fp, "-A INPUT -i br403 -s 192.168.245.0/24 -p tcp -m tcp --dport 8883 -j ACCEPT\n");
#endif

#if defined (INTEL_PUMA7) || ((defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) || defined(_COSA_QCA_ARM_)) && !defined(_CBR_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_)) || defined (_CBR2_PRODUCT_REQ_)
    fprintf(filter_fp, "-A INPUT -i br403 -d 192.168.245.0/24 -j ACCEPT\n");
    fprintf(filter_fp, "-A INPUT -i br403 -m pkttype ! --pkt-type unicast -j ACCEPT\n");
#endif
    //<<

#if defined (FEATURE_RDKB_INTER_DEVICE_MANAGER) && defined (GATEWAY_FAILOVER_SUPPORTED) 
        if ( idmInterface[0] != '\0'  && (strcmp(idmInterface,"br403") != 0 ) )
        {
            fprintf(filter_fp, "-A INPUT -i %s -d 192.168.245.0/24 -j ACCEPT\n",idmInterface);
            fprintf(filter_fp, "-A INPUT -i %s -m pkttype ! --pkt-type unicast -j ACCEPT\n", idmInterface);
        }
#endif

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "multinet-instances", inst_resp, sizeof(inst_resp));
    
    tok = strtok(inst_resp, " ");
    
    if (tok) do {
        snprintf(net_query, sizeof(net_query), "multinet_%s-localready", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("1", net_resp) != 0)
            continue;
        
        snprintf(net_query, sizeof(net_query), "multinet_%s-name", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        
        fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", net_resp, net_resp);
        
    } while ((tok = strtok(NULL, " ")) != NULL);

    FIREWALL_DEBUG("Exiting prepare_multinet_filter_forward\n"); 	 

    return 0;
}

/*
** Clamping the MSS of brlan1 traffic when GRE interface is present in the brlan1 during 
** Ethernet backhaul. 
*/
static int prepare_ethernetbhaul_greclamp( FILE *mangle_fp) {
   char xhs[16] = {0};
   char *pVal = NULL;
   char eb_gre_status[20] = {0};
   int isEBGreup = 0;
   const char *XHSLan = "dmsb.l2net.2.Name";
   errno_t safec_rc = -1;

   eb_gre_status[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "eb_gre", eb_gre_status, sizeof(eb_gre_status));
   isEBGreup = (0 == strcmp("up", eb_gre_status)) ? 1 : 0; 
   FIREWALL_DEBUG("Entering prepare_ethernetbhaul_greclamp status:%s\n" COMMA eb_gre_status);
   if( isEBGreup) {
    if(bus_handle && PSM_VALUE_GET_STRING(XHSLan, pVal) == CCSP_SUCCESS && pVal){
            safec_rc = strcpy_s(xhs, sizeof(xhs),pVal);
            ERR_CHK(safec_rc);
    }else {
            safec_rc = strcpy_s(xhs, sizeof(xhs),"brlan1");
            ERR_CHK(safec_rc);
    }
    if(pVal) {
        Ansc_FreeMemory_Callback(pVal);
        pVal = NULL;
    }
    FIREWALL_DEBUG("prepare_ethernetbhaul_greclamp clamping mss since gre present\n");
    fprintf(mangle_fp, "-A PREROUTING -i %s -j MARK --set-mark %d\n", xhs, XHS_EB_MARK);
    fprintf(mangle_fp, "-A POSTROUTING -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d\n", xhs, XHS_GRE_CLAMP_MSS);
    fprintf(mangle_fp, "-A POSTROUTING -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN -m mark --mark %d -j TCPMSS --set-mss %d\n",current_wan_ifname, XHS_EB_MARK, XHS_GRE_CLAMP_MSS);
   } else {
    FIREWALL_DEBUG("prepare_ethernetbhaul_greclamp skip clamping mss since gre not present\n");
   }
   FIREWALL_DEBUG("Exiting prepare_ethernetbhaul_greclamp\n");
   return 0;
}

static int prepare_multinet_mangle(FILE *mangle_fp) {
        unsigned int iterator; 
   char          name[MAX_QUERY];
   FILE* fp = mangle_fp;
   char      rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   FIREWALL_DEBUG("Entering prepare_multinet_mangle\n"); 	
   iterator = SYSEVENT_NULL_ITERATOR;
   do {
      name[0] = rule[0] = '\0';
      sysevent_get_unique(sysevent_fd, sysevent_token, 
                                  "GeneralPurposeMangleRule", &iterator, 
                                  name, sizeof(name), rule, sizeof(rule));
      if ('\0' != rule[0]) {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
         
         if (NULL != make_substitutions(rule, subst, sizeof(subst))) {
            fprintf(fp, "%s\n", subst);
         }
      }

   } while (SYSEVENT_NULL_ITERATOR != iterator);
      FIREWALL_DEBUG("Exiting prepare_multinet_mangle\n");
   return 0;
}

#if defined (INTEL_PUMA7)
static int prepare_multinet_mangle_v6(FILE *mangle_fp) {
   unsigned int iterator;
   char          name[MAX_QUERY];
   FILE* fp = mangle_fp;
   char      rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   FIREWALL_DEBUG("Entering prepare_multinet_mangle_v6\n");
   iterator = SYSEVENT_NULL_ITERATOR;
   do {
      name[0] = rule[0] = '\0';
      sysevent_get_unique(sysevent_fd, sysevent_token,
                                  "v6GeneralPurposeMangleRule", &iterator,
                                  name, sizeof(name), rule, sizeof(rule));
      if ('\0' != rule[0]) {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */

         if (NULL != make_substitutions(rule, subst, sizeof(subst))) {
            fprintf(fp, "%s\n", subst);
         }
      }

   } while (SYSEVENT_NULL_ITERATOR != iterator);
      FIREWALL_DEBUG("Exiting prepare_multinet_mangle_v6\n");
    return 0;
}
#endif
//Captive Portal
static int isInCaptivePortal()
{
   //Captive Portal
   int retCode = 0;
   int retPsm = 0;
   char *pVal = NULL;
   int isNotifyDefault=0;
   int isRedirectionDefault=0;
   int isResponse204=0;
   FILE *responsefd;
   char responseCode[10];
   int iresCode;
   char *networkResponse = "/var/tmp/networkresponse.txt";
   FIREWALL_DEBUG("Entering isInCaptivePortal\n"); 	
   /* Get the syscfg DB value to check if we are in CP redirection mode*/


   retCode=syscfg_get(NULL, "CaptivePortal_Enable", captivePortalEnabled, sizeof(captivePortalEnabled));  
   if (0 != retCode || '\0' == captivePortalEnabled[0])
   {
 	     	FIREWALL_DEBUG("%s Syscfg read failed to get CaptivePortal_Enable value\n" COMMA __FUNCTION__); 		
   }
   else
   {
        // Set a flag which we can check later to add DNS redirection
        if(!strcmp("false", captivePortalEnabled))
        {
 	     	FIREWALL_DEBUG("CaptivePortal is disabled : Return 0\n"); 	
      	     return 0;
        }
   }

   retCode=syscfg_get(NULL, "redirection_flag", redirectionFlag, sizeof(redirectionFlag));  
   if (0 != retCode || '\0' == redirectionFlag[0])
   {
	FIREWALL_DEBUG("CP DNS Redirection %s, Syscfg read failed\n"COMMA __FUNCTION__); 	
   }
   else
   {
        // Set a flag which we can check later to add DNS redirection
        if(!strcmp("true", redirectionFlag))
        {
            isRedirectionDefault = 1;
        }
   }

   // Check the PSM value to check we are having default WiFi configuration
   if(bus_handle != NULL)
   {
       retPsm = PSM_VALUE_GET_STRING(PSM_NAME_CP_NOTIFY_VALUE, pVal);
       if(retPsm == CCSP_SUCCESS && pVal != NULL)
       {
          /* If value is true then we are in default onfiguration mode */
          if(strcmp("true", pVal) == 0)
          {
             isNotifyDefault = 1;
          }
          Ansc_FreeMemory_Callback(pVal);
          pVal = NULL;
       }  
   }  
   //Check the reponse code received from Web Service
   if((responsefd = fopen(networkResponse, "r")) != NULL) 
   {
       if(fgets(responseCode, sizeof(responseCode), responsefd) != NULL)
       {
          iresCode = atoi(responseCode);
          if( iresCode == 204 ) 
          {
            isResponse204=1;
          }
       }
       fclose(responsefd); /*RDKB-7145, CID-32924, free unused resources before exit */
   }

   FIREWALL_DEBUG("Exiting isInCaptivePortal\n");	 

   if((isRedirectionDefault) && (isNotifyDefault) && (isResponse204))
   {
         FIREWALL_DEBUG("CP DNS Redirection : Return 1\n"); 	
      return 1;
   }
   else
   {
       FIREWALL_DEBUG("CP DNS Redirection : Return 0\n"); 
      return 0;
   }
}

//RF Captive Portal
static int isInRFCaptivePortal()
{
#if defined (_XB6_PRODUCT_REQ_)
   int retCode = 0;

   retCode=syscfg_get(NULL, "rf_captive_portal", rfCaptivePortalEnabled, sizeof(rfCaptivePortalEnabled));
   if (0 != retCode || '\0' == rfCaptivePortalEnabled[0])
   {
        FIREWALL_DEBUG("%s Syscfg read failed to get rf_captive_portal value\n" COMMA __FUNCTION__);
   }
   else
   {
        if(!strcmp("true", rfCaptivePortalEnabled))
        {
            FIREWALL_DEBUG("RF CaptivePortal is enabled : Return 1\n");
            return 1;
        }
   }
#endif
   return 0;
}

#if defined (_XB6_PRODUCT_REQ_)
static int do_ipv4_norf_captiveportalrule(FILE *nat_fp)
{
    if (!nat_fp)
        return -1;

    //RF Captive Portal
    if(1 == rfstatus)
    {
        fprintf(nat_fp, "-I PREROUTING -i %s -j prerouting_noRFCP_redirect \n", lan_ifname);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -p udp -m udp --dport 80 -j DNAT --to-destination %s:80\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -p tcp -m tcp --dport 80 -j DNAT --to-destination %s:80\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -p udp -m udp --dport 443 -j DNAT --to-destination %s:443\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -p tcp -m tcp --dport 443 -j DNAT --to-destination %s:443\n", lan_ipaddr);


        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -s %s/%s -d %s -p tcp  -m tcp --dport 80 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -s %s/%s -d %s -p udp  -m udp --dport 80 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -s %s/%s -d %s -p tcp  -m tcp --dport 443 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_noRFCP_redirect -s %s/%s -d %s -p udp  -m udp --dport 443 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
    }
    return 0;
}
#endif

#if defined (SR300_FEATURE_SELFHEAL) || defined (HUB4_FEATURE_SELFHEAL)
static int do_ipv4_selfheal_enable_rule(FILE *nat_fp)
{
    char captivePortalEnabled[16] = { 0 };
    int retCode = 0;

    if (!nat_fp)
        return -1;
    retCode = syscfg_get(NULL, "CaptivePortal_Enable", captivePortalEnabled, sizeof(captivePortalEnabled));  

    if (0 != retCode || '\0' == captivePortalEnabled[0])
    {
        return -1;
    }

    //if captive portal is enabled and wan is down,  apply the rules to redirect the traffic
    if ((!strcmp("true", captivePortalEnabled)) && isInSelfHealMode() == 1)
    {

        fprintf(nat_fp, "-I PREROUTING -i %s -j prerouting_selfheal_redirect \n", lan_ifname);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -p udp -m udp --dport 80 -j DNAT --to-destination %s:80\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -p tcp -m tcp --dport 80 -j DNAT --to-destination %s:80\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -p udp -m udp --dport 443 -j DNAT --to-destination %s:443\n", lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -p tcp -m tcp --dport 443 -j DNAT --to-destination %s:443\n", lan_ipaddr);


        fprintf(nat_fp, "-I prerouting_selfheal_redirect -s %s/%s -d %s -p tcp  -m tcp --dport 80 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -s %s/%s -d %s -p udp  -m udp --dport 80 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -s %s/%s -d %s -p tcp  -m tcp --dport 443 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
        fprintf(nat_fp, "-I prerouting_selfheal_redirect -s %s/%s -d %s -p udp  -m udp --dport 443 -j ACCEPT\n",
                lan_ipaddr, lan_netmask, lan_ipaddr);
    }
    return 0;
}
#endif

/*
 ==========================================================================
              IPv4 Firewall 
 ==========================================================================
 */

#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
/*
 *  Procedure     : AutoConntrackHelperDisabled
 *  Purpose       : Check whether kernel automatic connection tracker helper
                  : loading is disabled, meaning helpers must be explicitly
                  : enabled
 * Return Values  :
 *    0              : Connection tracking helpers will be loaded automatically
 *    1              : Connection tracking helpers must be explicitly loaded
*/
static int AutoConntrackHelperDisabled (void)
{
    FILE * fp;
    char output[MAX_QUERY];
    int result = 1;

    FIREWALL_DEBUG("Entering AutoConntrackHelperDisabled\n");         

    if ((fp = fopen ("/proc/sys/net/netfilter/nf_conntrack_helper", "r")) == NULL)
    {
   	FIREWALL_DEBUG("fopen call failed for /proc/sys/net/netfilter/nf_conntrack_helper, returning\n");
        return result;
    }

    if (fgets (output, sizeof(output), fp) == NULL)
        goto cleanup;

    if (output[0] == 0)
        goto cleanup;

    /* Return 0 if value is 0, 1 othersie */
    result = !(atoi(output) == 1);

cleanup:
    fclose(fp);

    FIREWALL_DEBUG("Exinting AutoConntrackHelperDisabled\n");         
    return result;
}
#endif

int prepare_lnf_internet_rules(FILE *mangle_fp,int iptype)
{
    char block_lnf_internet[20];
    if (!mangle_fp)
        return -1;
    memset(block_lnf_internet, 0, sizeof(block_lnf_internet));
    syscfg_get(NULL, "BlockLostandFoundInternet", block_lnf_internet, sizeof(block_lnf_internet));

    if(0 != strcmp("true",block_lnf_internet))
    {
        return -1;
    }
    if (4 == iptype)
    {
        char lnf_ipaddress[50];
        memset(lnf_ipaddress, 0, sizeof(lnf_ipaddress));
        syscfg_get(NULL, "iot_ipaddr", lnf_ipaddress, sizeof(lnf_ipaddress));
        fprintf(mangle_fp, "-A FORWARD -i %s -d %s/24 -m dscp --dscp-class cs0 -m limit --limit 1/minute -j LOG --log-prefix \"Internet packets in LnF\"\n",
                current_wan_ifname,lnf_ipaddress);
        fprintf(mangle_fp, "-A FORWARD -i %s -d %s/24 -m dscp --dscp-class cs0 -j DROP\n",current_wan_ifname,lnf_ipaddress);

        fprintf(mangle_fp, "-A FORWARD -i %s -d %s/24 -m dscp --dscp-class cs1 -m limit --limit 1/minute -j LOG --log-prefix \"Internet packets in LnF\"\n",
                current_wan_ifname,lnf_ipaddress);
        fprintf(mangle_fp, "-A FORWARD -i %s -d %s/24 -m dscp --dscp-class cs1 -j DROP\n",current_wan_ifname,lnf_ipaddress);
        fprintf(mangle_fp, "-A FORWARD -i %s -d %s/24 -j ACCEPT\n",current_wan_ifname,lnf_ipaddress);
    }
    else 
    {
        char lnf_ifName[50];
        char ipv6prefix[100];
        char cmd_buff[100];
        errno_t safec_rc = -1;
        memset(lnf_ifName, 0, sizeof(lnf_ifName));
        memset(cmd_buff, 0, sizeof(cmd_buff));
        syscfg_get(NULL, "iot_ifname", lnf_ifName, sizeof(lnf_ifName));
        if (strlen(lnf_ifName) > 0)
        {
            memset(ipv6prefix, 0, sizeof(ipv6prefix));
            #ifdef WAN_FAILOVER_SUPPORTED
               if (0 == checkIfULAEnabled())
               {
                  safec_rc = sprintf_s(cmd_buff, sizeof(cmd_buff),"%s_ipaddr_v6_ula",lnf_ifName);
               }
               else
               {
                  safec_rc = sprintf_s(cmd_buff, sizeof(cmd_buff),"%s_ipaddr_v6",lnf_ifName);
               }
            #else
               safec_rc = sprintf_s(cmd_buff, sizeof(cmd_buff),"%s_ipaddr_v6",lnf_ifName);
            #endif

            if(safec_rc < EOK)
            {
              ERR_CHK(safec_rc);
            }
            sysevent_get(sysevent_fd, sysevent_token, cmd_buff, ipv6prefix, sizeof(ipv6prefix));
            if (strlen(ipv6prefix) > 0 )
            {
                fprintf(mangle_fp, "-A FORWARD -i %s -d %s -m dscp --dscp-class cs0 -m limit --limit 1/minute -j LOG --log-prefix \"Internet packets in LnF\"\n",
                    current_wan_ifname,ipv6prefix);
                fprintf(mangle_fp, "-A FORWARD -i %s -d %s -m dscp --dscp-class cs0 -j DROP\n",current_wan_ifname,ipv6prefix);

                fprintf(mangle_fp, "-A FORWARD -i %s -d %s -m dscp --dscp-class cs1 -m limit --limit 1/minute -j LOG --log-prefix \"Internet packets in LnF\"\n",
                    current_wan_ifname,ipv6prefix);
                fprintf(mangle_fp, "-A FORWARD -i %s -d %s -m dscp --dscp-class cs1 -j DROP\n",current_wan_ifname,ipv6prefix);
                fprintf(mangle_fp, "-A FORWARD -i %s -d %s -j ACCEPT\n",current_wan_ifname,ipv6prefix);
            }
        }
    }
    return 0;
}

#if defined (MULTILAN_FEATURE)
/*
 *  Procedure     : prepare_multinet_disabled_ipv4_firewall
 *  Purpose       : prepare the iptables-restore file that establishes
 *                  ipv4 firewall rules for when the firewall is disabled
 *  Parameters    :
 *    filter_fp   : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
static int prepare_multinet_disabled_ipv4_firewall (FILE *filter_fp)
{
    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];
    char primary_inst[MAX_QUERY];

    inst_resp[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    primary_inst[0] = 0;
    sysevent_get(sysevent_fd, sysevent_token, "primary_lan_l3net", primary_inst, sizeof(primary_inst));

    tok = strtok(inst_resp, " ");

    if (tok) do {
        // Skip primary LAN instance, it is handled elsewhere
        if (strcmp(primary_inst,tok) == 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
        if (strcmp("up", net_resp) != 0)
            continue;

        snprintf(net_query, sizeof(net_query), "ipv4_%s-ipv4addr", tok);
        net_resp[0] = 0;
        sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

        fprintf(filter_fp, "-A INPUT -i %s -j lan2self_mgmt\n", net_resp);

    } while ((tok = strtok(NULL, " ")) != NULL);

    return 0;
}
#endif
static void do_ipv4_UIoverWAN_filter(FILE* fp) {
 FIREWALL_DEBUG("Inside do_ipv4_UIoverWAN_filter \n"); 
      if(strlen(current_wan_ipaddr)>0)
      {
         if (!isDefHttpPortUsed)
            fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 80 -j DROP\n", lan_ifname,current_wan_ipaddr);

         if (!isDefHttpsPortUsed)
            fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 443 -j DROP\n", lan_ifname,current_wan_ipaddr);
        int rc = 0;
        char buf[16] ;
        memset(buf,0,sizeof(buf));
        rc = syscfg_get(NULL, "mgmt_wan_httpaccess", buf, sizeof(buf));
        if ( rc == 0 && atoi(buf) == 0 )
        {
            memset(buf,0,sizeof(buf));
            rc = syscfg_get(NULL, "mgmt_wan_httpport", buf, sizeof(buf));
            if ( rc == 0 && buf[0] != '\0' )
            {
                fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport %s -j DROP\n", lan_ifname,current_wan_ipaddr,buf);
            }

        }
        memset(buf,0,sizeof(buf));
        rc = syscfg_get(NULL, "mgmt_wan_httpsaccess", buf, sizeof(buf));
        if ( rc == 0 && atoi(buf) == 0 )
        {
            memset(buf,0,sizeof(buf));
            rc = syscfg_get(NULL, "mgmt_wan_httpsport", buf, sizeof(buf));
            if ( rc == 0 && buf[0] != '\0' )
            {
                fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport %s -j DROP\n", lan_ifname,current_wan_ipaddr,buf);
            }

        }
      }

        #if defined (_COSA_BCM_ARM_)
        fprintf(fp, "-A PREROUTING -i %s -d 192.168.100.1 -p tcp -m tcp --dport 80 -j DROP\n", lan_ifname);
        fprintf(fp, "-A PREROUTING -i %s -d 192.168.100.1 -p tcp -m tcp --dport 443 -j DROP\n", lan_ifname);
        FIREWALL_DEBUG("Exiting do_ipv4_UIoverWAN_filter \n"); 
        #endif
}

/*
 * Rules for secure backhaul bridge
 */
#ifdef SECURE_BHAUL
#if defined (INTEL_PUMA7) || ((defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_COSA_QCA_ARM_)) && !defined(_CBR_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_)) || defined (_CBR2_PRODUCT_REQ_)
static void do_secure_backhaul(FILE *filter_fp)
{
    FIREWALL_DEBUG("Inside do_secure_backhaul\n");
    fprintf(filter_fp, "-N SECURE_BHAUL\n");
    fprintf(filter_fp, "-A INPUT -i br412 -j SECURE_BHAUL\n");
    fprintf(filter_fp, "-A FORWARD -i br412 -o %s -j SECURE_BHAUL\n", current_wan_ifname);
    fprintf(filter_fp, "-A FORWARD -i %s -o br412 -j SECURE_BHAUL\n", current_wan_ifname);
    fprintf(filter_fp, "-A FORWARD -i br412 -j DROP\n");

    fprintf(filter_fp, "-A SECURE_BHAUL -p udp --dport 67:68 --sport 67:68 -j ACCEPT\n");  // Allow DHCP
    fprintf(filter_fp, "-A SECURE_BHAUL -p udp --dport 53 -j ACCEPT\n");  // Allow DNS
    fprintf(filter_fp, "-A SECURE_BHAUL -p udp --dport 123 -j ACCEPT\n"); // Allow NTP
    // Allow ping to DNS root servers a.root-servers.net to m.root-servers.net
    for (int i = 0; i < 13; i++)
    {
        fprintf(filter_fp, "-A SECURE_BHAUL -p icmp --icmp-type echo-request -d %c.root-servers.net -j ACCEPT\n", 'a' + i);
    }
    fprintf(filter_fp, "-A SECURE_BHAUL -p icmp --icmp-type echo-request -d 192.168.250.254 -j ACCEPT\n");
    fprintf(filter_fp, "-A SECURE_BHAUL -d 96.102.0.0/15 -j ACCEPT\n"); // Allow connection to Comcast Controller IP's
    fprintf(filter_fp, "-A SECURE_BHAUL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n");
    fprintf(filter_fp, "-A SECURE_BHAUL -j DROP\n");
    FIREWALL_DEBUG("Exiting do_secure_backhaul\n");
}
#endif
#endif
/*
 *  Procedure     : prepare_subtables
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules with the table/subtable structure
 *  Parameters    :
 *    raw_fp         : An open file for raw subtables
 *    mangle_fp      : An open file for mangle subtables
 *    nat_fp         : An open file for nat subtables
 *    filter_fp      : An open file for filter subtables
 * Return Values  :
 *    0              : Success
 */
static int prepare_subtables(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering prepare_subtables \n"); 	
   int i; 
   /*
    * raw
    */
   fprintf(raw_fp, "*raw\n");
   fprintf(raw_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(raw_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   fprintf(raw_fp, ":%s - [0:0]\n", "xlog_drop_lanattack");
   fprintf(raw_fp, ":%s - [0:0]\n", "prerouting_ephemeral");
   fprintf(raw_fp, ":%s - [0:0]\n", "output_ephemeral");
   fprintf(raw_fp, ":%s - [0:0]\n", "prerouting_raw");
#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
   if (AutoConntrackHelperDisabled()) {
       fprintf(raw_fp, ":%s - [0:0]\n", "lan2wan_helpers");
   }
#endif

   fprintf(raw_fp, ":%s - [0:0]\n", "output_raw");
   fprintf(raw_fp, ":%s - [0:0]\n", "prerouting_nowan");
   fprintf(raw_fp, ":%s - [0:0]\n", "output_nowan");
 
#if !defined(_BWG_PRODUCT_REQ_)
   fprintf(raw_fp, "-A PREROUTING -j prerouting_ephemeral\n");
   fprintf(raw_fp, "-A OUTPUT -j output_ephemeral\n");
   fprintf(raw_fp, "-A PREROUTING -j prerouting_raw\n");
   fprintf(raw_fp, "-A OUTPUT -j output_raw\n");
   fprintf(raw_fp, "-A PREROUTING -j prerouting_nowan\n");
   fprintf(raw_fp, "-A OUTPUT -j output_nowan\n");
#endif

#if defined(CONFIG_KERNEL_NETFILTER_XT_TARGET_CT)
   /* On some platforms automatic connection tracking helpers are disabled for security reasons. */
   /* The firewall can enable the helpers for valid traffic patterns explicitly. */
   if (AutoConntrackHelperDisabled()) {
       /* Enable LAN to WAN helpers for primary LAN */
       fprintf(raw_fp, "-A prerouting_raw -i %s -j lan2wan_helpers\n", lan_ifname);

       /* Enable LAN to WAN helpers for multinet LANs */
       prepare_multinet_prerouting_raw(raw_fp); 
       do_lan2wan_helpers(raw_fp);
   }
#endif
   /*
    * mangle
    */
   fprintf(mangle_fp, "*mangle\n");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
#ifdef CONFIG_BUILD_TRIGGER
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(mangle_fp, ":%s - [0:0]\n", "prerouting_trigger");
#endif
#endif
   fprintf(mangle_fp, ":%s - [0:0]\n", "prerouting_qos");
   fprintf(mangle_fp, ":%s - [0:0]\n", "postrouting_qos");
   fprintf(mangle_fp, ":%s - [0:0]\n", "postrouting_lan2lan");
#if defined (_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
   char syscfg_value[64] = { 0 };
   int get_ret = 0;
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
   {
    fprintf(mangle_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
    fprintf(mangle_fp, "-I PREROUTING -j %s\n", IPOE_HEALTHCHECK);
   }
#else //Hub4
    fprintf(mangle_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
    fprintf(mangle_fp, "-I PREROUTING -j %s\n", IPOE_HEALTHCHECK);
#endif //_RDKB_GLOBAL_PRODUCT_REQ_
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED
#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
   fprintf(mangle_fp, ":%s - [0:0]\n", HTTP_HIJACK_DIVERT);
   fprintf(mangle_fp, ":%s - [0:0]\n", SELFHEAL);
   fprintf(mangle_fp, "-A PREROUTING -j %s\n", SELFHEAL);
#endif
#endif
   prepare_lld_dscp_rules(mangle_fp);
   prepare_dscp_rules_to_prioritized_clnt(mangle_fp);
   prepare_lnf_internet_rules(mangle_fp,4);
   prepare_dscp_rule_for_host_mngt_traffic(mangle_fp);
   prepare_xconf_rules(mangle_fp);


#ifdef CONFIG_BUILD_TRIGGER
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(mangle_fp, "-A PREROUTING -j prerouting_trigger\n");
#endif
#endif

   fprintf(mangle_fp, "-A PREROUTING -j prerouting_qos\n");
   fprintf(mangle_fp, "-A POSTROUTING -j postrouting_qos\n");
   fprintf(mangle_fp, "-A POSTROUTING -j postrouting_lan2lan\n");

#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",emta_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",emta_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",emta_wan_ifname);
#endif
   /*
    * nat
    */
   fprintf(nat_fp, "*nat\n");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");

#if defined(FEATURE_SUPPORT_RADIUSGREYLIST) && (defined(_COSA_INTEL_XB3_ARM_) || defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
    /*
     *RDKB-33651 :
     *    If RadiusGrayList is enabled/true, Then open port #3799 in WAN interface to pre route RADIUS disconnect
     *    request packets to ATOM side
     */
     int retPsmGet = CCSP_SUCCESS;
     char *strValue = NULL;
     retPsmGet = PSM_VALUE_GET_STRING(PSM_NAME_RADIUS_GREY_LIST_ENABLED, strValue);
     if(retPsmGet == CCSP_SUCCESS)
     {
        if(strValue != NULL && strncmp("1", strValue, 1) == 0)
        {
           FIREWALL_DEBUG("Open the port 3799 in WAN interface for RADIUS GreyList Support\n");
#if defined(_COSA_INTEL_XB3_ARM_)
           fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 3799 -j DNAT --to 192.168.251.254\n",current_wan_ifname);
#endif
#if (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
	   fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 3799 -j DNAT --to 192.168.147.100\n",current_wan_ifname);
#endif
        }
        else
           FIREWALL_DEBUG("PSM_NAME_RADIUS_GREY_LIST_ENABLED val: %s\n" COMMA strValue);
	
	if (strValue) {
	 	AnscFreeMemory(strValue);
         	strValue = NULL;
	}
     }
     else
        FIREWALL_DEBUG("PSM GET PSM_NAME_RADIUS_GREY_LIST_ENABLED FAILED\n");
#endif
#if defined(_COSA_BCM_MIPS_)
   fprintf(nat_fp, "-A PREROUTING -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
   fprintf(nat_fp, "-A PREROUTING -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
   
#endif
#if defined (_XB6_PRODUCT_REQ_)
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_noRFCP_redirect");
#endif
#if defined (SR300_FEATURE_SELFHEAL) || defined (HUB4_FEATURE_SELFHEAL)
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_selfheal_redirect");
#endif
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_ephemeral");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_fromwan");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_mgmt_override");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_plugins");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_fromwan_todmz");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_fromlan");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_devices");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_redirect");
#ifdef CONFIG_BUILD_TRIGGER
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_fromlan_trigger");
   fprintf(nat_fp, ":%s - [0:0]\n", "prerouting_fromwan_trigger");
#endif
#endif

   fprintf(nat_fp, ":%s - [0:0]\n", "postrouting_towan");
   fprintf(nat_fp, ":%s - [0:0]\n", "postrouting_tolan");
   fprintf(nat_fp, ":%s - [0:0]\n", "postrouting_plugins");
   fprintf(nat_fp, ":%s - [0:0]\n", "postrouting_ephemeral");

#if defined(_COSA_BCM_MIPS_)
   fprintf(nat_fp, "-A POSTROUTING -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
   fprintf(nat_fp, "-A POSTROUTING -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
#endif

#if WAN_FAILOVER_SUPPORTED
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
   redirect_dns_to_extender(nat_fp,AF_INET);
#endif //_PLATFORM_RASPBERRYPI_ && _PLATFORM_BANANAPI_R4_
#endif 

#if defined(_WNXL11BWL_PRODUCT_REQ_) 
   proxy_dns(nat_fp,AF_INET);
#endif

#if defined (_XB6_PRODUCT_REQ_)
   do_ipv4_norf_captiveportalrule (nat_fp);
#endif
#if defined (SR300_FEATURE_SELFHEAL) || defined (HUB4_FEATURE_SELFHEAL)
   do_ipv4_selfheal_enable_rule (nat_fp);
#endif



   fprintf(nat_fp, "-A PREROUTING -j prerouting_ephemeral\n");
   fprintf(nat_fp, "-A PREROUTING -j prerouting_mgmt_override\n");
   fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromlan\n", lan_ifname);
   fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_devices\n", lan_ifname);    

   //RDKB-25069 - Lan Admin page should able to access from connected clients.
   fprintf(nat_fp, "-A prerouting_redirect -i %s -p tcp --dport 443 -d %s -j DNAT --to-destination %s\n",lan_ifname,lan_ipaddr,lan_ipaddr);
     
   syscfg_set(NULL, "HTTP_Server_IP", lan_ipaddr);
   fprintf(nat_fp, "-A prerouting_redirect -p tcp --dport 80 -j DNAT --to-destination %s:21515\n",lan_ipaddr);

   syscfg_set(NULL, "HTTPS_Server_IP", lan_ipaddr);
   fprintf(nat_fp, "-A prerouting_redirect -p tcp --dport 443 -j DNAT --to-destination %s:21515\n",lan_ipaddr);

   syscfg_set(NULL, "Default_Server_IP", lan_ipaddr);
   fprintf(nat_fp, "-A prerouting_redirect -p tcp -j DNAT --to-destination %s:21515\n",lan_ipaddr);
   fprintf(nat_fp, "-A prerouting_redirect -p udp -m multiport ! --dports 53,67 -j DNAT --to-destination %s:21515\n",lan_ipaddr);
   
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   if(isGuestNetworkEnabled) {
       fprintf(nat_fp, ":%s - [0:0]\n", "guestnet_walled_garden");
       fprintf(nat_fp, ":%s - [0:0]\n", "guestnet_allow_list");
       fprintf(nat_fp, "-A guestnet_walled_garden -j guestnet_allow_list\n");
       fprintf(nat_fp, "-A PREROUTING -s %s/%s -j guestnet_walled_garden\n", guest_network_ipaddr, guest_network_mask);
   }
   
   fprintf(nat_fp, ":%s - [0:0]\n", "device_based_parcon");
   fprintf(nat_fp, ":%s - [0:0]\n", "parcon_allow_list");
   fprintf(nat_fp, ":%s - [0:0]\n", "parcon_walled_garden");
   fprintf(nat_fp, "-A device_based_parcon -j parcon_allow_list\n");
   fprintf(nat_fp, "-A device_based_parcon -j parcon_walled_garden\n");
   fprintf(nat_fp, "-A prerouting_fromlan -j device_based_parcon\n");
#endif
#ifdef  CONFIG_CISCO_PARCON_WALLED_GARDEN
   fprintf(nat_fp, ":%s - [0:0]\n", "managedsite_based_parcon");
//   fprintf(nat_fp, ":%s - [0:0]\n", "parcon_allow_list");
   fprintf(nat_fp, ":%s - [0:0]\n", "parcon_walled_garden");
//   fprintf(nat_fp, "-A device_based_parcon -j parcon_allow_list\n");
//   fprintf(nat_fp, "-A device_based_parcon -j parcon_walled_garden\n");
#endif

#if (defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)) || defined(FEATURE_SUPPORT_MAPT_NAT46)
   if (isMAPTReady)
   {
      fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromwan\n",NAT46_INTERFACE );
   }
   else // Add erouter0 prerouting_fromwan chain for 'Dual Stack' line only
#endif //FEATURE_MAPT
   fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromwan\n", current_wan_ifname);
   prepare_multinet_prerouting_nat(nat_fp);
#ifdef CONFIG_BUILD_TRIGGER
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(nat_fp, "-A prerouting_fromlan -j prerouting_fromlan_trigger\n");
   fprintf(nat_fp, "-A prerouting_fromwan -j prerouting_fromwan_trigger\n");
#endif
#endif
   fprintf(nat_fp, "-A PREROUTING -j prerouting_plugins\n");

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   if (isMAPTReady)
   {
       fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromwan_todmz\n", NAT46_INTERFACE);
       fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_tolan\n", NAT46_INTERFACE);
       {
           unsigned int mapt_config_ratio = 0;
           char mapt_config_ratio_str[64] = {0};

           if (sysevent_get(sysevent_fd, sysevent_token, SYSEVENT_MAPT_RATIO, mapt_config_ratio_str, sizeof(mapt_config_ratio_str)) != 0)
           {
#ifdef FEATURE_MAPT_DEBUG
               LOG_PRINT_MAIN("ERROR: Failed to get MAPT ratio value from sysevent \n");
#endif
           }
           else
           {
               mapt_config_ratio = atoi(mapt_config_ratio_str);
#ifdef FEATURE_MAPT_DEBUG
               LOG_PRINT_MAIN("mapt_config_ratio :%d \n",mapt_config_ratio);
#endif

               if (mapt_config_ratio == 1)
               {
#ifdef FEATURE_MAPT_DEBUG
                   LOG_PRINT_MAIN("CONFIGURING WAN POSTROUTING \n",mapt_config_ratio);
#endif
                   fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_towan\n", NAT46_INTERFACE);
               }
               else
               {
#ifdef FEATURE_MAPT_DEBUG
                   LOG_PRINT_MAIN("NOT CONFIGURING WAN POSTROUTING \n");
                   LOG_PRINT_MAIN("mapt_config_ratio :%d \n",mapt_config_ratio);
#endif
               }
           }
       }
   }
#endif //NAT46_KERNEL_SUPPORT
   if (!isMAPTReady)
   {   // Add erouter0 prerouting_fromwan_todmz chain for 'Dual Stack' line only
       fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromwan_todmz\n", current_wan_ifname);
       fprintf(nat_fp, "-A POSTROUTING -j postrouting_ephemeral\n");
       // This breaks emta DNS routing on XF3. We may need some special rule here.
       fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_towan\n", current_wan_ifname);
   }
#endif // FEATURE_MAPT

#if !defined(FEATURE_MAPT) || !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(nat_fp, "-A PREROUTING -i %s -j prerouting_fromwan_todmz\n", current_wan_ifname);
      fprintf(nat_fp, "-A POSTROUTING -j postrouting_ephemeral\n");
   // This breaks emta DNS routing on XF3. We may need some special rule here.
      fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_towan\n", current_wan_ifname);
   }
#endif //_HUB4_PRODUCT_REQ_ ENDS

   fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_tolan\n", lan_ifname);
   prepare_multinet_postrouting_nat(nat_fp);
   fprintf(nat_fp, "-A POSTROUTING -j postrouting_plugins\n");
#if defined (_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_) 
#if defined (HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
   {
        fprintf(nat_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
        fprintf(nat_fp, "-I PREROUTING -j %s\n", IPOE_HEALTHCHECK);
   }
#else
   fprintf(nat_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
   fprintf(nat_fp, "-I PREROUTING -j %s\n", IPOE_HEALTHCHECK);
#endif //_RDKB_GLOBAL_PRODUCT_REQ_
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED
#endif //_HUB4_PRODUCT_REQ_

   /*
    * filter
    */
   fprintf(filter_fp, "*filter\n");
   fprintf(filter_fp, ":%s DROP [0:0]\n", "INPUT");
   fprintf(filter_fp, ":%s ACCEPT [0:0]\n", "FORWARD");
   fprintf(filter_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");

#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
    prepare_rabid_rules(filter_fp, mangle_fp, IP_V4);
#else
    prepare_rabid_rules_v2020Q3B(filter_fp, mangle_fp, IP_V4);
#endif

#ifdef INTEL_PUMA7
   //Avoid blocking packets at the Intel NIL layer
   fprintf(filter_fp, "-A FORWARD -i a-mux -j ACCEPT\n");
#endif
#if defined(INTEL_PUMA7) || defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) || defined(_COSA_QCA_ARM_)
   fprintf(filter_fp, "-A INPUT -i host0 -s 192.168.147.0/255.255.255.0 -j ACCEPT\n");
   fprintf(filter_fp, "-A OUTPUT -o host0 -d 192.168.147.0/255.255.255.0 -j ACCEPT\n");
#endif
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, "-A OUTPUT -p icmp -m icmp --icmp-type 3 -j DROP\n");
#endif
   fprintf(filter_fp, "-A OUTPUT -o lo -p tcp -m tcp --sport 49152:49153 -j ACCEPT\n");
   fprintf(filter_fp, "-A OUTPUT ! -o brlan0 -p tcp -m tcp --sport 49152:49153 -j DROP\n");
   /* For EasyMesh Controller Communication */
#if defined(_PLATFORM_BANANAPI_R4_)
   fprintf(filter_fp, "-I OUTPUT -o %s -p tcp --sport 49153 -j ACCEPT\n",get_current_wan_ifname());
#endif
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   fprintf(filter_fp, ":%s - [0:0]\n", "pp_disabled");
   if(isGuestNetworkEnabled) {
       fprintf(filter_fp, "-A pp_disabled -s %s/%s -p tcp -m state --state ESTABLISHED -m connbytes --connbytes 0:5 --connbytes-dir original --connbytes-mode packets -j GWMETA --dis-pp\n", guest_network_ipaddr, guest_network_mask);
       fprintf(filter_fp, "-A pp_disabled -d %s/%s -p tcp -m state --state ESTABLISHED -m connbytes --connbytes 0:5 --connbytes-dir reply --connbytes-mode packets -j GWMETA --dis-pp\n", guest_network_ipaddr, guest_network_mask);
   }

   fprintf(filter_fp, "-A pp_disabled -p udp --dport 53 -j GWMETA --dis-pp\n");
   fprintf(filter_fp, "-A pp_disabled -p udp --sport 53 -j GWMETA --dis-pp\n");
   fprintf(filter_fp, "-A FORWARD -j pp_disabled\n");
#endif

   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan");
   
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_dnsq_intercept"); //dns query nfqueue handler rules
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_httpget_intercept"); //http nfqueue handler rules
   fprintf(filter_fp, ":%s - [0:0]\n", "parcon_allow_list");
   fprintf(filter_fp, "-A lan2wan_httpget_intercept -j parcon_allow_list\n");
   fprintf(filter_fp, "-A lan2wan -p tcp --dport 80 -j lan2wan_httpget_intercept\n");
   fprintf(filter_fp, "-A lan2wan -p udp --dport 53 -j lan2wan_dnsq_intercept\n");
#endif

   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_misc");
#ifdef CONFIG_BUILD_TRIGGER
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_triggers");
#endif
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_disable");
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_staticip");
#endif
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_forwarding_accept");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_dmz_accept");
   //fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_webfilters");
   //fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_iap");
   //fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_plugins");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_pc_device");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_pc_site");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_pc_service");
   //fprintf(filter_fp, ":%s - [0:0]\n", "lan2wan_iot_allow");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan");
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN 
//    fprintf(filterFp, ":lan2wan_dnsq_nfqueue - [0:0]\n");
//    fprintf(fp, ":lan2wan_http_nfqueue - [0:0]\n");
    fprintf(filter_fp, ":wan2lan_dnsr_nfqueue - [0:0]\n");
#endif

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_dns_intercept");
#endif

   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_disabled");
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_staticip_pm");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_staticip");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_staticip_post");
#endif
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_forwarding_accept");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_misc");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_accept");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_plugins");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_nonat");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_dmz");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_iot_allow");
#ifdef CONFIG_BUILD_TRIGGER
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2lan_trigger");
#endif
#endif
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2self_by_wanip");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2self_mgmt");
   fprintf(filter_fp, ":%s - [0:0]\n", "host_detect");
   fprintf(filter_fp, ":%s - [0:0]\n", "lanattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2self_plugins");
   fprintf(filter_fp, ":%s - [0:0]\n", "self2lan");
   fprintf(filter_fp, ":%s - [0:0]\n", "self2lan_plugins");
#if !defined (NO_MOCA_FEATURE_SUPPORT)
   fprintf(filter_fp, ":%s - [0:0]\n", "moca_isolation");
#endif
   //>>DOS
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, ":%s - [0:0]\n", "wandosattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "mtadosattack");
#endif
   //<<DOS
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2self_mgmt");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2self_ports");
   fprintf(filter_fp, ":%s - [0:0]\n", "wanattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2self_allow");
   fprintf(filter_fp, ":%s - [0:0]\n", "lanhosts");
   fprintf(filter_fp, ":%s - [0:0]\n", "general_input");
   fprintf(filter_fp, ":%s - [0:0]\n", "general_output");
   fprintf(filter_fp, ":%s - [0:0]\n", "general_forward");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_accept_lan2wan");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_accept_wan2lan");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_accept_wan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_wan2lan");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lan2wan");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_wan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_wanattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lanattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlogdrop");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlogreject");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lan2wan_misc");
#if defined (_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
   {
        fprintf(filter_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
        fprintf(filter_fp, "-I INPUT -j %s\n", IPOE_HEALTHCHECK);
   }
#else
   fprintf(filter_fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
   fprintf(filter_fp, "-I INPUT -j %s\n", IPOE_HEALTHCHECK);
#endif //_RDKB_GLOBAL_PRODUCT_REQ_
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED
#endif //_HUB4_PRODUCT_REQ_

   if(isComcastImage) {
       //tr69 chains for logging and filtering
       fprintf(filter_fp, ":%s - [0:0]\n", "LOG_TR69_DROP");
       fprintf(filter_fp, ":%s - [0:0]\n", "tr69_filter");
       fprintf(filter_fp, "-A INPUT -p tcp -m tcp --dport 7547 -j tr69_filter\n");
   }
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, "-A INPUT -p icmp -m state --state ESTABLISHED -m limit --limit 5/sec --limit-burst 10 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -p icmp -m state --state ESTABLISHED -j DROP\n");
#endif

   do_openPorts(filter_fp);

   fprintf(filter_fp, ":%s - [0:0]\n", "LOG_SSH_DROP");
   fprintf(filter_fp, ":%s - [0:0]\n", "SSH_FILTER");

   if(bEthWANEnable)
   {
           //ETH WAN is TC XB6 exclusive feature
            if (strcmp(current_wan_ifname, default_wan_ifname ) == 0)
            {
              fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", current_wan_ifname);
            }
            else
            {
              fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", default_wan_ifname);
            }
   }
   else if (erouterSSHEnable)  // Applicable only for PUMA7 platforms
   {
       fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n",current_wan_ifname);
       fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", ecm_wan_ifname);
   }
   else {
       if (isEponEnable) 
           fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j DROP\n", ecm_wan_ifname);
       else
         {
            if (strcmp(current_wan_ifname, default_wan_ifname ) == 0)
            {
               fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", ecm_wan_ifname);
               fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", current_wan_ifname);
            }
            else
            {
               fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", default_wan_ifname);
            }
         }
   }

   //SNMPv3 chains for logging and filtering
   fprintf(filter_fp, ":%s - [0:0]\n", "SNMPDROPLOG");
   fprintf(filter_fp, ":%s - [0:0]\n", "SNMP_FILTER");
   //Adding 10163 port to suport SNMPv3 SHA-256
   fprintf(filter_fp, "-A INPUT -p udp -m udp --match multiport --dports 10161,10163 -j SNMP_FILTER\n");

   //DROP incoming New NTP packets on erouter interface
   fprintf(filter_fp, "-A INPUT -i %s -m state --state ESTABLISHED,RELATED -p udp --dport 123 -j ACCEPT \n", get_current_wan_ifname());
   fprintf(filter_fp, "-A INPUT -i %s  -m state --state NEW -p udp --dport 123 -j DROP \n",get_current_wan_ifname());

   /* RDKB-57182 Blocking brlan0 ports 80,443 for interfaces other than lan */
   fprintf(filter_fp, "-A INPUT -i brlan0 -p tcp -m multiport --dports 80,443 ! -d %s -j DROP\n", lan_ipaddr);

   // Video Analytics Firewall rule to allow port 58081 only from LAN interface
   do_OpenVideoAnalyticsPort (filter_fp);

   do_webui_attack_filter(filter_fp);
   // Create iptable chain to ratelimit remote management(8080, 8181) packets
   do_webui_rate_limit(filter_fp);
       
#if !defined(_COSA_INTEL_XB3_ARM_)
   filterPortMap(filter_fp);
#endif
#if defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
   fprintf(filter_fp, "-A INPUT -s 172.31.255.40/32 -p tcp -m tcp --dport 9000 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -s 172.31.255.40/32 -p udp -m udp --dport 9000 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -p tcp -m tcp --dport 9000 -j DROP\n");
   fprintf(filter_fp, "-A INPUT -p udp -m udp --dport 9000 -j DROP\n");
#endif

   // Allow local loopback traffic 
   fprintf(filter_fp, "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT\n");
   if (isWanReady) {
       #ifdef _COSA_FOR_BCI_ 
       if (1 == isWanPingDisable)
       {
           fprintf(filter_fp, "-A INPUT -i %s -p icmp -m icmp --icmp-type 8 -j DROP\n",current_wan_ifname);
           fprintf(filter_fp, "-A INPUT -i brlan0 -d %s -p icmp -m icmp --icmp-type 8 -j DROP\n",current_wan_ipaddr);
       }
       #endif       
      fprintf(filter_fp, "-A INPUT -p tcp -i lo -s %s -d %s -j ACCEPT\n", current_wan_ipaddr, current_wan_ipaddr);
   }
   // since some protocols have a different ip address for the connection to the isp, and the wan
   // accept loopback to isp
    char isp_connection[MAX_QUERY];
    isp_connection[0] = '\0';
    sysevent_get(sysevent_fd, sysevent_token, "ipv4_wan_ipaddr", isp_connection, sizeof(isp_connection));
    if ('\0' != isp_connection[0] &&
        0 != strcmp("0.0.0.0", isp_connection) &&
        0 != strcmp(isp_connection, current_wan_ipaddr)) {
      fprintf(filter_fp, "-A INPUT -p tcp -i lo -s %s -d %s -j ACCEPT\n", isp_connection, isp_connection);
   }

   fprintf(filter_fp, "-A INPUT -i lo -m state --state NEW -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -j general_input\n");
   wan_lan_webui_attack(filter_fp,lan_ifname);
   // Rate limiting the webui-access lan side
   lan_access_set_proto(filter_fp, "80",lan_ifname);
   lan_access_set_proto(filter_fp, "443",lan_ifname);

   // Blocking webui access to unnecessary interfaces
   fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",lan_ifname);
   fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",ecm_wan_ifname);
   if (isCmDiagEnabled)
   {
       fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",cmdiag_ifname);  
   }

   #if defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
       #if !defined(_CBR_PRODUCT_REQ_) && !defined (_BWG_PRODUCT_REQ_) && !defined (_CBR2_PRODUCT_REQ_)
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",LNF_IF_NAME);
	   /* RDKB-57186 SNMP drop to XHS and LnF */
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
       #endif
       fprintf(filter_fp, "-A INPUT -p tcp -i privbr --match multiport  --dport 80,443 -j ACCEPT\n");
   #endif
   fprintf(filter_fp,"-A INPUT -p tcp --match multiport  --dport 80,443 -j DROP\n");
   fprintf(filter_fp,"-A INPUT -p tcp -i brlan1 --dport 22 -j DROP\n");
   fprintf(filter_fp,"-A INPUT -p tcp -i br106 --dport 22 -j DROP\n");
   int ret = 0;
   char tmpQuery[MAX_QUERY];
   memset(tmpQuery, 0, sizeof(tmpQuery));
   #if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
       ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
   #else
       ret = syscfg_get(NULL, "mgmt_wan_httpaccess", tmpQuery, sizeof(tmpQuery));
   #endif
   if ((ret == 0) && atoi(tmpQuery) == 1)
   {
       fprintf(filter_fp,"-A INPUT -p tcp ! -i %s --dport 8080 -j DROP\n",current_wan_ifname);
   }
   else
   {
       fprintf(filter_fp,"-A INPUT -p tcp  --dport 8080 -j DROP\n");
   }
   memset(tmpQuery, 0, sizeof(tmpQuery));
   ret =  syscfg_get(NULL, "mgmt_wan_httpsaccess", tmpQuery, sizeof(tmpQuery));
   if ((ret == 0) && atoi(tmpQuery) == 1)
   {
       fprintf(filter_fp,"-A INPUT -i  brlan0 -p tcp --dport 8181 -j ACCEPT\n");
       fprintf(filter_fp,"-A INPUT -p tcp ! -i %s --dport 8181 -j DROP\n",current_wan_ifname);
   }
   else
   {
       fprintf(filter_fp,"-A INPUT -p tcp --dport 8181 -j DROP\n");
   }

#if defined (_XB7_PRODUCT_REQ_) || defined (_XB8_PRODUCT_REQ_) || defined (XB6_PRODUCT_REQ)
    /* RDKB-57664 Blocking rx_motion port TCP 6969 for Outside access */
    fprintf(filter_fp, "-A INPUT -p tcp ! -i lo --dport 6969 -j DROP\n");
#endif

#if defined(_CBR_PRODUCT_REQ_) || defined(SKY_RDKB)
   /* RDKB-56214 Blocking CcspWifiSsp port 55010 for Outside access */
   fprintf(filter_fp, "-A INPUT -p udp ! -i lo --dport 55010 -j DROP\n");
#endif

#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(filter_fp, "-A INPUT -i %s -j wan2self_mgmt\n", ecm_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(filter_fp, "-A INPUT -i %s -j wan2self_mgmt\n", current_wan_ifname);
#if !defined(_HUB4_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(filter_fp, "-A INPUT -i %s -j wan2self_mgmt\n", emta_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(filter_fp, "-A INPUT -i %s -j lan2self\n", lan_ifname);
   fprintf(filter_fp, "-A INPUT -i %s -j wan2self\n", current_wan_ifname);
   if ('\0' != default_wan_ifname[0] && 0 != strlen(default_wan_ifname) && 0 != strcmp(default_wan_ifname, current_wan_ifname)) {
      // even if current_wan_ifname is ppp we still want to consider default wan ifname as an interface
      // but dont duplicate
      fprintf(filter_fp, "-A INPUT -i %s -j wan2self\n", default_wan_ifname);
   }
   if (FALSE == bAmenityEnabled)
   {
      #if defined (WIFI_MANAGE_SUPPORTED)
      updateManageWiFiRules(bus_handle, current_wan_ifname, filter_fp);
      #endif /*WIFI_MANAGE_SUPPORTED*/
   }
   else
   {
      #if defined (AMENITIES_NETWORK_ENABLED)
      updateAmenityNetworkRules(filter_fp,mangle_fp , AF_INET);
      #endif
   }
   //Add wan2self restrictions to other wan interfaces
   //ping is allowed to cm and mta inferfaces regardless the firewall level
#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(filter_fp, "-A INPUT -i %s -p icmp --icmp-type 8 -m limit --limit 3/second -j %s\n", ecm_wan_ifname, "xlog_accept_wan2self"); // ICMP PING
      fprintf(filter_fp, "-A INPUT -i %s -j wan2self_ports\n", ecm_wan_ifname);
      fprintf(filter_fp, "-A INPUT -i %s -p icmp --icmp-type 8 -m limit --limit 3/second -j %s\n", emta_wan_ifname, "xlog_accept_wan2self"); // ICMP PING
      fprintf(filter_fp, "-A INPUT -i %s -j wan2self_ports\n", emta_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/
   fprintf(filter_fp, "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n");

   if (isCmDiagEnabled)
   {
      fprintf(filter_fp, "-A INPUT -i %s -d 192.168.100.1 -j ACCEPT\n", cmdiag_ifname);
   }

   if(isComcastImage)
   {
      do_tr69_whitelistTable(filter_fp, AF_INET);
   }
  
   if (isContainerEnabled) {
       do_container_allow(filter_fp, mangle_fp, nat_fp, AF_INET);
   }

#ifdef _COSA_BCM_MIPS_
    // Allow all traffic to the private interface priv0
    fprintf(filter_fp, "-A INPUT -i priv0 -j ACCEPT\n");
#endif

   //Captive Portal 
   /* If both PSM and syscfg values are true then SET the DNS redirection to GW*/    
   if(isInCaptivePortal()==1 && (!rfstatus))
   {   
      fprintf(nat_fp, "-I PREROUTING -i %s -p udp --dport 53 -j DNAT --to %s\n", lan_ifname, lan_ipaddr);
      fprintf(nat_fp, "-I PREROUTING -i %s -p tcp --dport 53 -j DNAT --to %s\n", lan_ifname, lan_ipaddr);
   }

#if (defined(FEATURE_MAPT) && defined(NAT46_KERNEL_SUPPORT)) || defined(FEATURE_SUPPORT_MAPT_NAT46)
   if (isMAPTReady) {
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j lan2wan\n", lan_ifname, NAT46_INTERFACE);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j lan2wan\n", ETH_MESH_BRIDGE, NAT46_INTERFACE);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j wan2lan\n", NAT46_INTERFACE, lan_ifname);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j wan2lan\n", NAT46_INTERFACE, ETH_MESH_BRIDGE);
#ifdef FEATURE_SUPPORT_MAPT_NAT46
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j lan2wan\n", XHS_BRIDGE, NAT46_INTERFACE);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j lan2wan\n", LNF_BRIDGE, NAT46_INTERFACE);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j wan2lan\n", NAT46_INTERFACE, XHS_BRIDGE);
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j wan2lan\n", NAT46_INTERFACE, LNF_BRIDGE);
      // drop map0 loopback traffic 
      fprintf(filter_fp, "-I FORWARD -i %s -o %s -j DROP\n", NAT46_INTERFACE, NAT46_INTERFACE);
#endif
   }
#endif //FEATURE_MAPT

#if defined(_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
      //SKYH4-952: Hub4 SelfHeal support.
      //If SelfHeal_Enable syscfg value is TRUE then SET the DNS directions to GW.
      if (isInSelfHealMode() == 1)
      {
         fprintf(nat_fp, "-I PREROUTING -i %s -p udp --dport 53 -j DNAT --to %s\n", lan_ifname, lan_ipaddr);
         fprintf(nat_fp, "-I PREROUTING -i %s -p tcp --dport 53 -j DNAT --to %s\n", lan_ifname, lan_ipaddr);
      }
#endif //HUB4_SELFHEAL_FEATURE_ENABLED
   }
#endif //_HUB4_PRODUCT_REQ_
   
#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      if (ecm_wan_ifname[0])  // spare eCM wan interface from Utopia firewall
      {
         //block port 53/67/514
         fprintf(filter_fp, "-A INPUT -i %s -p udp --dport 53 -j DROP\n", ecm_wan_ifname);
         fprintf(filter_fp, "-A INPUT -i %s -p udp --dport 67 -j DROP\n", ecm_wan_ifname);
         fprintf(filter_fp, "-A INPUT -i %s -p udp --dport 514 -j DROP\n", ecm_wan_ifname);

         fprintf(filter_fp, "-A INPUT -i %s -j ACCEPT\n", ecm_wan_ifname);
      }
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
      if (emta_wan_ifname[0]) // spare eMTA wan interface from Utopia firewall
      {
         fprintf(filter_fp, "-A INPUT -i %s -p udp --dport 80 -j DROP\n", emta_wan_ifname);
         fprintf(filter_fp, "-A INPUT -i %s -p udp --dport 443 -j DROP\n", emta_wan_ifname);

         fprintf(filter_fp, "-A INPUT -i %s -j ACCEPT\n", emta_wan_ifname);
      }
#endif
   }
#endif /*_HUB4_PRODUCT_REQ_*/
   /* if(isProdImage) {
       do_ssh_IpAccessTable(filter_fp, "22", AF_INET, ecm_wan_ifname);
   } else {
       fprintf(filter_fp, "-A SSH_FILTER -j ACCEPT\n");
   } */   
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
   do_ssh_IpAccessTable(filter_fp, "22", AF_INET, ecm_wan_ifname);
#else
    fprintf(filter_fp, "-A SSH_FILTER -j ACCEPT\n");
#endif

   do_snmp_IpAccessTable(filter_fp, AF_INET);

#ifdef INTEL_PUMA7

   fprintf(filter_fp, "-A INPUT -i adp0.555 -j ACCEPT\n");

#endif
   prepare_multinet_filter_input(filter_fp);
   prepare_hotspot_gre_ipv4_rule(filter_fp);
   prepare_ipc_filter(filter_fp);

   //>>DOS
#ifdef _COSA_INTEL_XB3_ARM_
   //fprintf(filter_fp, "-I INPUT -i erouter0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j wandosattack\n");
   //fprintf(filter_fp, "-I INPUT -i erouter0 -p udp -m udp -j wandosattack\n");
   fprintf(filter_fp, "-I INPUT -i wan0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j wandosattack\n");
   fprintf(filter_fp, "-I INPUT -i wan0 -p udp -m udp -j wandosattack\n");
   fprintf(filter_fp, "-I INPUT -i mta0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j mtadosattack\n");
   fprintf(filter_fp, "-I INPUT -i mta0 -p udp -m udp -j mtadosattack\n");
   fprintf(filter_fp, "-A wandosattack -p tcp -m tcp --dport 22 -m limit --limit 25/sec --limit-burst 80 -j RETURN\n");
   fprintf(filter_fp, "-A wandosattack -m limit --limit 25/sec --limit-burst 80 -j ACCEPT\n");
   fprintf(filter_fp, "-A wandosattack -j DROP\n");
   fprintf(filter_fp, "-A mtadosattack -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n");
   fprintf(filter_fp, "-A mtadosattack -j DROP\n");
#endif
   //<<DOS

   //fprintf(filter_fp, "-A OUTPUT -m state --state INVALID -j DROP\n");

   /*
    * if the wan is currently unavailable, then drop any packets from lan to wan
    * except for DHCP (broadcast)
    */
   /*char str[MAX_QUERY];*/
   //snprintf(str, sizeof(str), "-I OUTPUT 1 -s 0.0.0.0 ! -d 255.255.255.255 -o %s -j DROP", current_wan_ifname);
   //fprintf(filter_fp, "%s\n", str);
#if defined(_COSA_BCM_MIPS_)
   fprintf(filter_fp, "-A OUTPUT -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
#endif
   fprintf(filter_fp, "-A OUTPUT -j general_output\n");
   fprintf(filter_fp, "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
   fprintf(filter_fp, "-A OUTPUT -o %s -j self2lan\n", lan_ifname);
   prepare_multinet_filter_output(filter_fp);
   fprintf(filter_fp, "-A self2lan -j self2lan_plugins\n");
   fprintf(filter_fp, "-A OUTPUT -m state --state NEW -j ACCEPT\n");

#if defined(_COSA_BCM_MIPS_)
   fprintf(filter_fp, "-A FORWARD -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
   fprintf(filter_fp, "-A FORWARD -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
   fprintf(filter_fp, "-I FORWARD 2 -i br403 -o %s -j ACCEPT\n", current_wan_ifname);
   fprintf(filter_fp, "-I FORWARD 3 -i %s -o br403 -j ACCEPT\n", current_wan_ifname);
#endif

   fprintf(filter_fp, "-A FORWARD -j general_forward\n");
   fprintf(filter_fp, "-A FORWARD -i %s -o %s -j wan2lan\n", current_wan_ifname, lan_ifname);
   fprintf(filter_fp, "-A FORWARD -i %s -o %s -j lan2wan\n", lan_ifname, current_wan_ifname);
   // need br0 to br0 for virtual services)
   fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", lan_ifname, lan_ifname);
   prepare_multinet_filter_forward(filter_fp);
   fprintf(filter_fp, "-A FORWARD -j xlog_drop_wan2lan\n");

#if !defined(_COSA_BCM_ARM_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
   fprintf(filter_fp, "-I FORWARD 3 -i %s -o l2sd0.4090 -j ACCEPT\n", current_wan_ifname);
   fprintf(filter_fp, "-I FORWARD 2 -i br403 -o %s -j ACCEPT\n", current_wan_ifname);
   fprintf(filter_fp, "-I FORWARD 3 -i %s -o br403 -j ACCEPT\n", current_wan_ifname);
#endif

#if defined (INTEL_PUMA7) || ((defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) || defined(_COSA_QCA_ARM_)) && !defined(_CBR_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_)) || defined (_CBR2_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
      fprintf(filter_fp, "-I FORWARD 2 -i br403 -o %s -j ACCEPT\n", current_wan_ifname);
      fprintf(filter_fp, "-I FORWARD 3 -i %s -o br403 -j ACCEPT\n", current_wan_ifname);
#ifdef SECURE_BHAUL
      do_secure_backhaul(filter_fp);
#endif
   }
#endif

#if defined (INTEL_PUMA7) || (_COSA_INTEL_XB3_ARM_)
   //ARRISXB6-8429
   fprintf(filter_fp, "-I FORWARD -m conntrack --ctdir original -m connbytes --connbytes 0:15 --connbytes-dir original --connbytes-mode packets -j GWMETA --dis-pp\n");
   fprintf(filter_fp, "-I FORWARD -m conntrack --ctdir reply -m connbytes --connbytes 0:15 --connbytes-dir reply --connbytes-mode packets -j GWMETA --dis-pp\n");
#endif

#if (defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_))
   fprintf(filter_fp, "-I FORWARD -d 192.168.100.1/32 -i %s -j DROP\n", lan_ifname);
   fprintf(filter_fp, "-I FORWARD -d 172.31.255.0/24 -j DROP\n");
   fprintf(filter_fp, "-I INPUT -d 172.31.255.0/24 -i %s -j DROP\n", lan_ifname);
#endif

//SKYH4-6700 - [MAP-T] To prevent Denial of service due to sufficient TCP SYN`s causing resource exhaustion.
#if defined (FEATURE_MAPT) && defined (NAT46_KERNEL_SUPPORT)
   if(isMAPTReady)
   {
       fprintf(filter_fp, "-I FORWARD -i %s -o %s -j DROP\n", NAT46_INTERFACE, NAT46_INTERFACE);
   }
#endif

   do_forwardPorts(filter_fp);

   // RDKB-4826 - IOT rules for DHCP
   char iot_enabled[20];
   memset(iot_enabled, 0, sizeof(iot_enabled));
   syscfg_get(NULL, "lost_and_found_enable", iot_enabled, sizeof(iot_enabled));
  
   if(0==strcmp("true",iot_enabled))
   {
      FIREWALL_DEBUG("IOT_LOG : Adding iptable rules for IOT\n");
      memset(iot_ifName, 0, sizeof(iot_ifName));
      syscfg_get(NULL, "iot_ifname", iot_ifName, sizeof(iot_ifName));
      if( strstr( iot_ifName, "l2sd0.106")) {
                  syscfg_get( NULL, "iot_brname", iot_ifName, sizeof(iot_ifName));
      }
      memset(iot_primaryAddress, 0, sizeof(iot_primaryAddress));
      syscfg_get(NULL, "iot_ipaddr", iot_primaryAddress, sizeof(iot_primaryAddress));
      fprintf(filter_fp,"-A INPUT -d %s/24 -i %s -j ACCEPT\n",iot_primaryAddress,iot_ifName);
      fprintf(filter_fp,"-A INPUT -i %s -m pkttype ! --pkt-type unicast -j ACCEPT\n",iot_ifName);
      //fprintf(filter_fp,"-A FORWARD -i %s -o %s -j ACCEPT\n",iot_ifName,iot_ifName);
      //fprintf(filter_fp, "-I FORWARD 2 -i %s -o %s -j lan2wan_iot_allow\n", iot_ifName,current_wan_ifname);
      fprintf(filter_fp, "-I FORWARD 2 -i %s -o %s -j ACCEPT\n", iot_ifName,current_wan_ifname);
      fprintf(filter_fp, "-I FORWARD 3 -i %s -o %s -j wan2lan_iot_allow\n", current_wan_ifname, iot_ifName);
      //zqiu: R5337
      //do_lan2wan_IoT_Allow(filter_fp);
      do_wan2lan_IoT_Allow(filter_fp);
#if defined (INTEL_PUMA7) || ((defined (_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) || defined(_COSA_QCA_ARM_)) && !defined(_CBR_PRODUCT_REQ_)) // ARRIS XB6 ATOM, TCXB6
      // Block forwarding between bridges.
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", lan_ifname, iot_ifName);
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", XHS_IF_NAME, iot_ifName);
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", iot_ifName, lan_ifname);
      fprintf(filter_fp, "-A FORWARD -i %s -o %s -j DROP\n", iot_ifName, XHS_IF_NAME);
#endif
   }


   /***********************
    * set lan to wan subrule by order 
    * *********************/
   fprintf(filter_fp, "-A lan2wan -j lan2wan_disable\n");
   //fprintf(filter_fp, "-A lan2wan -i l2sd0.106 -j lan2wan_iot_allow\n");
   for(i=0; i< IPT_PRI_MAX; i++)
   {
      switch(iptables_pri_level[i]){
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
          case IPT_PRI_STATIC_IP:
             fprintf(filter_fp, "-A lan2wan -j lan2wan_staticip\n");
             break;
#endif
#ifdef CONFIG_BUILD_TRIGGER
          case IPT_PRI_PORTTRIGGERING:
             fprintf(filter_fp, "-A lan2wan -j lan2wan_triggers\n");
             break;
#endif
        case IPT_PRI_FIREWALL:
             //   fprintf(filter_fp, "-A lan2wan -m state --state INVALID -j xlog_drop_lan2wan\n");
             fprintf(filter_fp, "-A lan2wan -j lan2wan_misc\n");
             //fprintf(filter_fp, "-A lan2wan -j lan2wan_webfilters\n");
            //fprintf(filter_fp, "-A lan2wan -j lan2wan_iap\n");
            //fprintf(filter_fp, "-A lan2wan -j lan2wan_plugins\n");
            fprintf(filter_fp, "-A lan2wan -j lan2wan_pc_device\n");
            fprintf(filter_fp, "-A lan2wan -j lan2wan_pc_site\n");
            fprintf(filter_fp, "-A lan2wan -j lan2wan_pc_service\n");
            fprintf(filter_fp, "-A lan2wan -j host_detect\n");
            fprintf(filter_fp, "-A lan2wan -m state --state NEW -j xlog_accept_lan2wan\n");
            fprintf(filter_fp, "-A lan2wan -m state --state RELATED,ESTABLISHED -j xlog_accept_lan2wan\n");
            fprintf(filter_fp, "-A lan2wan -j xlog_accept_lan2wan\n");
            break;

        case IPT_PRI_PORTMAPPING:
            fprintf(filter_fp, "-A lan2wan -j lan2wan_forwarding_accept\n");
            break;

        case IPT_PRI_DMZ:
            fprintf(filter_fp, "-A lan2wan -j lan2wan_dmz_accept\n");
            break;

        default:
            break;
      }
   }

   //fprintf(filter_fp, "-A lan2self -m state --state INVALID -j DROP\n");
   //Block traffic to lan0. 192.168.100.3 is for ATOM dbus connection.
   if(isWanServiceReady) {
       fprintf(filter_fp, "-A general_input -i lan0 ! -s 192.168.100.3 -d 192.168.100.1 -j xlog_drop_lan2self\n");
       fprintf(filter_fp, "-A general_input -i brlan0 ! -s 192.168.100.3 -d 192.168.100.1 -j xlog_drop_lan2self\n");
   }
 
#if defined(FEATURE_SUPPORT_RADIUSGREYLIST) && ( defined (_XB7_PRODUCT_REQ_) || defined (_XB8_PRODUCT_REQ_) || defined (_CBR2_PRODUCT_REQ_) )
     int RPsmGet = CCSP_SUCCESS;
     char *strvalue = NULL;
     RPsmGet = PSM_VALUE_GET_STRING(PSM_NAME_RADIUS_GREY_LIST_ENABLED, strvalue);

	if(RPsmGet == CCSP_SUCCESS) {
		if(strvalue != NULL && strncmp("1", strvalue, 1) == 0) {
    			FIREWALL_DEBUG("To Accept the das packet on xb7 RADIUS GreyList Support\n");
    			fprintf(filter_fp, "-A general_input -i %s -p udp -m udp --dport 3799 -j ACCEPT\n",current_wan_ifname);
		}
	 	else
           		FIREWALL_DEBUG("PSM_NAME_RADIUS_GREY_LIST_ENABLED val: %s\n" COMMA strvalue);

		if(strvalue) {
			AnscFreeMemory(strvalue);
                        strvalue = NULL;
		}
     	}
     	else
		FIREWALL_DEBUG("PSM GET PSM_NAME_RADIUS_GREY_LIST_ENABLED FAILED\n");
#endif

   //open port for DHCP
   if(!isBridgeMode) {
       fprintf(filter_fp, "-A general_input -i %s -p udp --dport 68 -j ACCEPT\n", current_wan_ifname);
#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif
   {
       fprintf(filter_fp, "-A general_input -i %s -p udp --dport 68 -j ACCEPT\n", ecm_wan_ifname);
       fprintf(filter_fp, "-A general_input -i %s -p udp --dport 68 -j ACCEPT\n", emta_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/
   }
   fprintf(filter_fp, "-A general_input -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", lan_ifname);
   /* RDKB-57186 SNMP drop to XHS and LnF */
   fprintf(filter_fp, "-A general_input -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", XHS_IF_NAME);
   fprintf(filter_fp, "-A general_input -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", LNF_IF_NAME);
#if defined (MULTILAN_FEATURE)
   fprintf(filter_fp, "-A lan2self -j lan2self_by_wanip\n");
#else
   fprintf(filter_fp, "-A lan2self ! -d %s -j lan2self_by_wanip\n", lan_ipaddr);
#endif
   fprintf(filter_fp, "-A lan2self -j lan2self_mgmt\n");
   fprintf(filter_fp, "-A lan2self -j lanattack\n");
   fprintf(filter_fp, "-A lan2self -j host_detect\n");
   fprintf(filter_fp, "-A lan2self -j lan2self_plugins\n");
   fprintf(filter_fp, "-A lan2self -m state --state NEW -j ACCEPT\n");
   fprintf(filter_fp, "-A lan2self -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
   fprintf(filter_fp, "-A lan2self -j ACCEPT\n");

//   fprintf(filter_fp, "-A wan2self -m state --state INVALID -j xlog_drop_wan2self\n");
   fprintf(filter_fp, "-A wan2self -j wan2self_allow\n");
   fprintf(filter_fp, "-A wan2self -j wanattack\n");
   fprintf(filter_fp, "-A wan2self -j wan2self_ports\n");
   fprintf(filter_fp, "-A wan2self -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
#ifdef INTEL_PUMA7
   // Accept Vonage packets --  ARRISXB6-3881
   fprintf(filter_fp, "-A wan2self -p udp -m udp --dport 10000:20000 -j ACCEPT\n");
   // Accept Teams packets --  INTCS-114
   fprintf(filter_fp, "-A wan2self -s 52.112.0.0/12 -m conntrack --ctstate NEW -j ACCEPT\n");
#endif
   //fprintf(filter_fp, "-A wan2self -j wan2self_mgmt\n");
   fprintf(filter_fp, "-A wan2self -j xlog_drop_wan2self\n");

//   fprintf(filter_fp, "-A wan2lan -m state --state INVALID -j xlog_drop_wan2lan\n");

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   fprintf(filter_fp, "-A wan2lan  -p udp --sport 53 -j wan2lan_dns_intercept\n");
#endif

   fprintf(filter_fp, "-A wan2lan  -j wan2lan_disabled\n");
   for(i=0; i< IPT_PRI_MAX; i++)
   {
      switch(iptables_pri_level[i]){
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
          case IPT_PRI_STATIC_IP:
             fprintf(filter_fp, "-A wan2lan -j wan2lan_staticip_pm\n");
             fprintf(filter_fp, "-A wan2lan -j wan2lan_staticip\n");
             break;
#endif
          case IPT_PRI_PORTMAPPING:
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_forwarding_accept\n");
             break;
#ifdef CONFIG_BUILD_TRIGGER
          case IPT_PRI_PORTTRIGGERING:
#ifdef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_trigger\n");
#endif
             break;
#endif
          case IPT_PRI_DMZ:
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_dmz\n");
             break;
        case IPT_PRI_FIREWALL:
#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
             fprintf(filter_fp, "-A wan2lan -p udp --sport 53 -j wan2lan_dnsr_nfqueue\n");
             fprintf(filter_fp, "-A wan2lan_dnsr_nfqueue -j GWMETA --dis-pp\n");
#endif
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_misc\n");
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_accept\n");
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_plugins\n");
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_nonat\n");
             fprintf(filter_fp, "-A wan2lan -m state --state RELATED,ESTABLISHED -j ACCEPT\n");
             fprintf(filter_fp, "-A wan2lan  -j host_detect\n");
#ifdef CISCO_CONFIG_TRUE_STATIC_IP
             /* TODO: next time change to USE IPT_PRI flag */
             fprintf(filter_fp, "-A wan2lan  -j wan2lan_staticip_post\n");
#endif
             break;
          default:
              break;
      }
   }
      FIREWALL_DEBUG("Exiting  prepare_subtables \n"); 	
   return(0);
}

/*
 *  Procedure     : prepare_subtables_ext
 *  Purpose       : Add rules to the iptables rules file based on an external file
 *                  This model is used for plugins 
 *  Parameters    :
 *    fname          : The name of the file to consult for extention rules
 *    raw_fp         : An open file for raw subtables
 *    mangle_fp      : An open file for mangle subtables
 *    nat_fp         : An open file for nat subtables
 *    filter_fp      : An open file for filter subtables
 * Return Values  :
 *    0              : Success
 */

static int prepare_subtables_ext(char *fname, FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
	FILE *ext_fp;
	char line[256];
	FILE *fp = NULL;
   FIREWALL_DEBUG("Entering prepare_subtables_ext \n"); 	
	ext_fp = fopen(fname, "r");
	if (ext_fp == NULL) {
		return -1;
	}

	while (fgets(line, sizeof(line), ext_fp) != NULL) {
		if (line[0] == '#') {	// Comment
			continue;
		}
		else if (line[0] == '*') {	// Table
			if (strncmp(line, "*raw", 4) == 0) {
				fp = raw_fp;
			}
			else if (strncmp(line, "*mangle", 7) == 0) {
				fp = mangle_fp;
			}
			else if (strncmp(line, "*nat", 4) == 0) {
				fp = nat_fp;
			}
			else if (strncmp(line, "*filter", 7) == 0) {
				fp = filter_fp;
			}
			continue;
		}
		else if (line[0] == ':') {	// Chain
			if (strncmp(line, ":PREROUTING", 11) == 0 ||
				strncmp(line, ":INPUT", 6) == 0 ||
				strncmp(line, ":OUTPUT", 7) == 0 ||
				strncmp(line, ":POSTROUTING", 12) == 0 ||
				strncmp(line, ":FORWARD", 8) == 0) {
				continue;
			}
		}
		else if (strncmp(line, "COMMIT", 6) == 0) {
			continue;
		}
			
		if (fp != NULL) {
			fprintf(fp, "%s", line);
			printf("%s", line);
		}
	}
	fclose( ext_fp ); /*RDKB-7145, CID-33371, free unused resource before exit*/
	FIREWALL_DEBUG("Exiting prepare_subtables_ext \n"); 	
	return(0);
}

/*
===========================================================================
               raw table
===========================================================================
*/

/*
 *  Procedure     : do_raw_ephemeral
 *  Purpose       : prepare the iptables-restore statements for raw statements gleaned from the sysevent
 *                  RawFirewallRule pool
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 *  Notes         : These rules will be placed into the iptables raw table, and use target
 *                     prerouting_ephemeral for PREROUTING statements, or
 *                     output_ephemeral for OUTPUT statements
 */
//unused function
#if 0
static int do_raw_ephemeral(FILE *fp)
{
   unsigned  int iterator;
   char      name[MAX_QUERY];
   char      in_rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   char      str[MAX_QUERY];
   FIREWALL_DEBUG("Entering do_raw_ephemeral \n"); 
   iterator = SYSEVENT_NULL_ITERATOR;
   do {
      name[0] = subst[0] = '\0';
      memset(in_rule, 0, sizeof(in_rule));
      sysevent_get_unique(sysevent_fd, sysevent_token,
                          "RawFirewallRule", &iterator,
                          name, sizeof(name), in_rule, sizeof(in_rule));
      if ('\0' != in_rule[0]) {
         // use the raw table
         isRawTableUsed = 1;
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
        if (NULL != make_substitutions(in_rule, subst, sizeof(subst))) {
           if (1 == substitute(subst, str, sizeof(str), "PREROUTING", "prerouting_ephemeral") ||
              (1 == substitute(subst, str, sizeof(str), "OUTPUT", "output_ephemeral")) ) {
              fprintf(fp, "%s\n", str);
           }
        }
      }
   } while (SYSEVENT_NULL_ITERATOR != iterator);

   FIREWALL_DEBUG("Exiting do_raw_ephemeral \n"); 
   return(0);
}
#endif

/*
 *  Procedure     : do_raw_table_general_rules
 *  Purpose       : prepare the iptables-restore statements for raw statements gleaned from the syscfg
 *                  RawTableFirewallRule
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 *  Notes         : These rules will be placed into the iptables raw table, and use target
 *                     prerouting_raw for PREROUTING statements, or
 *                     output_raw for OUTPUT statements
 */
//unused function
#if 0
static int do_raw_table_general_rules(FILE *fp)
{
FIREWALL_DEBUG("Entering do_raw_table_general_rules \n"); 
   int  idx;
   char rule_query[MAX_QUERY];
   int  count = 1;

   char      in_rule[MAX_QUERY];
   char      subst[MAX_QUERY];
   in_rule[0] = '\0';
   syscfg_get(NULL, "RawTableFirewallRuleCount", in_rule, sizeof(in_rule));
   if ('\0' == in_rule[0]) {
      return(0);
   } else {
      // use the raw table
      isRawTableUsed = 1;
      count = atoi(in_rule);
      if (0 == count) {
         return(0);
      }
      if (MAX_SYSCFG_ENTRIES < count) {
         count = MAX_SYSCFG_ENTRIES;
      }
   }

   memset(in_rule, 0, sizeof(in_rule));
   for (idx=1; idx<=count; idx++) {
      snprintf(rule_query, sizeof(rule_query), "RawTableFirewallRule_%d", idx);
      syscfg_get(NULL, rule_query, in_rule, sizeof(in_rule));
      if ('\0' == in_rule[0]) {
         continue;
      } else {
         /*
          * the rule we just got could contain variables that we need to substitute
          * for runtime/configuration values
          */
         char str[MAX_QUERY];
         if (NULL != make_substitutions(in_rule, subst, sizeof(subst))) {
             if ((1 == substitute(subst, str, sizeof(str), "PREROUTING", "prerouting_raw")) ||
                (1 == substitute(subst, str, sizeof(str), "OUTPUT", "output_raw")) ) {
               fprintf(fp, "%s\n", str);
            }
         }
      }
      memset(in_rule, 0, sizeof(in_rule));
   }
   FIREWALL_DEBUG("Exiting do_raw_table_general_rules \n"); 
   return(0);
}
#endif

/*
 *  Procedure     : do_raw_table_nowan
 *  Purpose       : prepare the iptables-restore statements for raw statements used only when there is
 *                  no wan connection yet
 *  Parameters    :
 *     fp              : An open file that will be used for iptables-restore
 *  Return Values :
 *     0               : done
 *    -1               : bad input parameter
 * Notes          :
 *    When there is no wan ip address we turn connection tracking off for packets to/from us
 *    because sometimes a conntrack with 0.0.0.0 is formed, and this lasts a lot time if conntrack
 */
//unused function
#if 0
static int do_raw_table_nowan(FILE *fp)
{
	FIREWALL_DEBUG("Entering do_raw_table_nowan \n"); 
   if (!isWanReady) {
      char str[MAX_QUERY];

      //use the raw table
      isRawTableUsed = 1;

      fprintf(fp, "-A prerouting_nowan -i %s -j NOTRACK\n", default_wan_ifname);

      fprintf(fp, "-A output_nowan -o %s -j NOTRACK\n",default_wan_ifname);
   }
      FIREWALL_DEBUG("Exiting do_raw_table_nowan \n"); 
   return(0);
}
#endif

#ifdef INTEL_PUMA7
static int do_raw_table_puma7(FILE *fp)
{
   FIREWALL_DEBUG("Entering do_raw_table_puma7 \n"); 
	fprintf(stderr,"******DO RAW TABLE PUMA7 ****\n");

      	//use the raw table
      	isRawTableUsed = 1;

	fprintf(fp, "-A PREROUTING -i a-mux -j NOTRACK\n");

	//For ath0 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1000 -j NOTRACK\n");

	//For ath1 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1001 -j NOTRACK\n");

	//For ath2 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1002 -j NOTRACK\n");

	//For ath3 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1003 -j NOTRACK\n");

	//For ath4 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1004 -j NOTRACK\n");

	//For ath5 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1005 -j NOTRACK\n");

	//For ath6 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1006 -j NOTRACK\n");

	//For ath7 acceleration loop
	fprintf(fp, "-A PREROUTING -i wifilbr0.1007 -j NOTRACK\n");
   FIREWALL_DEBUG("Exiting do_raw_table_puma7 \n"); 
	return(0);
}
#endif
// static int prepare_multilan_firewall(FILE *nat_fp, FILE *filter_fp)
// {
    //Allow traffic through all psm configured networks.
// }

/*
===========================================================================
              
===========================================================================
*/
int do_block_ports(FILE *filter_fp)
{
   int retPsmGet = CCSP_SUCCESS;
   char *strValue = NULL;

   /* Blocking block page ports except for brlan0 interface */
   fprintf(filter_fp, "-A INPUT -i brlan0 -p tcp -m tcp --dport 21515 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -p tcp -m tcp --dport 21515 -j DROP\n");
   /* Blocking zebra ports except for brlan0 interface */
   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p tcp -m tcp --dport 2601 -j DROP\n");
   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p udp -m udp --dport 2601 -j DROP\n");
   /* Blocking IGD ports except for brlan0 interface */
   fprintf(filter_fp, "-A INPUT -i lo  -p tcp -m tcp --dport 49152:49153 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -i lo -p udp -m udp --dport 1900 -j ACCEPT\n");

   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p tcp -m tcp --dport 49152:49153 -j DROP\n");
   /* For EasyMesh Controller Communication */
#if defined(_PLATFORM_BANANAPI_R4_)
   fprintf(filter_fp, "-I INPUT -i %s -p tcp --dport 49153 -j ACCEPT\n",get_current_wan_ifname());
#endif
   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p udp -m udp --dport 1900 -j DROP\n");
   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p tcp -m tcp --dport 21515 -j DROP\n");
   fprintf(filter_fp, "-A INPUT ! -i brlan0 -p udp -m udp --dport 21515 -j DROP\n");

   /*	RDKB-22836 :
	If Server.Capability is enabled/true, Then open port #9869 to the LAN for use by SpeedTest	*/
   retPsmGet = PSM_VALUE_GET_STRING(PSM_NAME_SPEEDTEST_SERVER_CAPABILITY, strValue);
   if(retPsmGet == CCSP_SUCCESS && strValue != NULL)
   {
      if(strcmp("1", strValue) == 0)
      {
         FIREWALL_DEBUG("Open the port 9869 to the LAN for use by SpeedTest \n");
         fprintf(filter_fp, "-A INPUT -i brlan0 -p tcp -m tcp --dport 9869 -j ACCEPT\n");
         fprintf(filter_fp, "-A INPUT -p tcp -m tcp --dport 9869 -j DROP\n");
         fprintf(filter_fp, "-A INPUT ! -i brlan0 -p tcp -m tcp --dport 9869 -j DROP\n");
         fprintf(filter_fp, "-A INPUT ! -i brlan0 -p udp -m udp --dport 9869 -j DROP\n");
         AnscFreeMemory(strValue);
         strValue = NULL;
      }
   }
#ifdef FEATURE_MATTER_ENABLED
   fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 5540 -j ACCEPT\n", lan_ifname);
   fprintf(filter_fp, "-A INPUT -i %s -p udp -m udp --dport 5540 -j ACCEPT\n", lan_ifname);
   fprintf(filter_fp, "-A INPUT -p udp -i %s --dport 5353 -j ACCEPT\n", lan_ifname);
#endif
   return 0;
}

#if defined(MOCA_HOME_ISOLATION)
static int prepare_MoCA_bridge_firewall(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   char *pVal = NULL;
   char pLan[10] = {0}, mLan[10] = {0}; // CID 119363: Uninitialized scalar variable (UNINIT), CID 119362: Uninitialized scalar variable (UNINIT)
   int   HomeIsolation_en = 0;
   int retPsm = 0;
   const char *HomeNetIsolation = "dmsb.l2net.HomeNetworkIsolation";
   const char *HomePrivateLan = "dmsb.l2net.1.Name";
   const char *HomeMoCALan = "dmsb.l2net.9.Name";
   char MoCA_AccountIsolation[8] = {0};
   int rc = 0;
   errno_t safec_rc = -1;
   if(bus_handle != NULL)
   {
       retPsm = PSM_VALUE_GET_STRING(HomeNetIsolation, pVal);
       if(retPsm == CCSP_SUCCESS && pVal != NULL)
       {
          HomeIsolation_en = atoi(pVal);
          Ansc_FreeMemory_Callback(pVal);
          pVal = NULL;
       }  
   }
   if(HomeIsolation_en == 1)
   {
       retPsm = PSM_VALUE_GET_STRING(HomePrivateLan, pVal);
       if(retPsm == CCSP_SUCCESS && pVal != NULL)
       {
          safec_rc = strcpy_s(pLan, sizeof(pLan),pVal);
          ERR_CHK(safec_rc);
          Ansc_FreeMemory_Callback(pVal);
          pVal = NULL;
       }
       retPsm = PSM_VALUE_GET_STRING(HomeMoCALan, pVal);
       if(retPsm == CCSP_SUCCESS && pVal != NULL)
       {
          safec_rc = strcpy_s(mLan, sizeof(mLan),pVal);
          ERR_CHK(safec_rc);
          Ansc_FreeMemory_Callback(pVal);
          pVal = NULL;
       }
       if((strlen(pLan) != 0)&&(strlen(mLan) != 0))
       {
          fprintf(filter_fp, "-I INPUT -i %s -j ACCEPT\n", mLan);
          fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", pLan,mLan);
          fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", mLan,pLan);
          fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n",current_wan_ifname,mLan);
          fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", mLan,current_wan_ifname);
          fprintf(filter_fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", mLan,mLan);
          fprintf(filter_fp, "-A OUTPUT -o %s -j ACCEPT\n",mLan);
          MoCA_AccountIsolation[0] = '\0';
          rc = syscfg_get(NULL, "enableMocaAccountIsolation", MoCA_AccountIsolation, sizeof(MoCA_AccountIsolation));
          if (0 != rc || '\0' == MoCA_AccountIsolation[0]) {
	  }
          else if (0 == strcmp("true", MoCA_AccountIsolation)) {
          // increment ttl if upnp discovery from brlan0
          fprintf(mangle_fp, "-A PREROUTING -i %s -d 239.255.255.250 -j TTL --ttl-inc 1\n", pLan);

          // traffic between brlan0 and brlan10, subject to moca_isolation
          fprintf(filter_fp, "-I FORWARD -i %s -o %s -j moca_isolation\n", pLan, mLan);
          fprintf(filter_fp, "-I FORWARD -i %s -o %s -j moca_isolation\n", mLan, pLan);
          fprintf(filter_fp, "-A moca_isolation -o %s -s %s/24 -d 239.255.255.250/32 -j ACCEPT\n", mLan, lan_ipaddr);
          // moca traffic, default to drop all
          fprintf(filter_fp, "-A moca_isolation -i %s -d %s/24 -j DROP\n", mLan, lan_ipaddr);
          fprintf(filter_fp, "-A moca_isolation -o %s -s %s/24 -j DROP\n", mLan, lan_ipaddr);
          // if the packet does not match the above, do we DROP it ? ACCEPT it ? or
          // send it back to the FORWARD chain ? currently send it back to FORWARD,

          // moca whitelist, allow them
          FILE *whitelist_fp;
          char line[256];
          int len;

          whitelist_fp = fopen("/tmp/moca_whitelist.txt", "r");
          if (whitelist_fp != NULL)
          {
              memset(line, 0, sizeof(line));
              while (fgets(line, sizeof(line)-1, whitelist_fp) != 0)
              {
                  if (strstr(line, "169.254."))
                  {
                      len = strlen(line);
                      line[len-2] = '\0';
                      fprintf(filter_fp, "-I moca_isolation -i %s -s %s/32 -j ACCEPT\n", mLan, line);
                      fprintf(filter_fp, "-I moca_isolation -o %s -d %s/32 -j ACCEPT\n", mLan, line);
			/* Establish point to point traffic- whitelisting */
                      fprintf(filter_fp, "-I moca_isolation -i %s -d %s/24 -s %s/32 -j ACCEPT\n", mLan, lan_ipaddr,line);
                      fprintf(filter_fp, "-I moca_isolation -o %s -s %s/24 -d %s/32 -j ACCEPT\n", mLan, lan_ipaddr,line);
                      memset(line, 0, sizeof(line));
		  }
	      }

              fclose(whitelist_fp);
	  }
	}
       }

   }
   return 0; 
}
#endif

#if defined(FEATURE_RDKB_INTER_DEVICE_MANAGER)
static void prepare_idm_firewall(FILE * filter_fp)
{
      if(idmInterface[0] != '\0' )
         fprintf(filter_fp, "-I INPUT -i %s -p udp --dport 1900 -j ACCEPT \n", idmInterface);
}
#endif

#if defined(_WNXL11BWL_PRODUCT_REQ_) 
void get_iface_ipaddr_ula(const char* ifname,char* ipaddr, int max_ip_size)
{
   char prefix[128] = {0};

   char cmd[128]= {0};
   memset(prefix,0,sizeof(prefix));
      char ipv6_ifaces[128] = {0};

   if (strcmp(ifname,"brlan0") == 0 )
   {
      sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix_ula", prefix, sizeof(prefix));
   }
   else
   {
      memset(ipv6_ifaces,0,sizeof(ipv6_ifaces));
      syscfg_get(NULL, "IPv6_Interface", ipv6_ifaces, sizeof(ipv6_ifaces));
      if(! strstr( ipv6_ifaces, ifname))
      {
         return;
      }
      memset(cmd,0,sizeof(cmd));
      snprintf(cmd, sizeof(cmd), "%s%s",ifname,"_ipaddr_v6_ula");
      sysevent_get(sysevent_fd, sysevent_token, cmd, prefix, sizeof(prefix));

   }

   if (prefix[0] != '\0')
   {
      char *token_pref =NULL;
      token_pref = strtok(prefix,"/");
      snprintf(ipaddr,max_ip_size,"%s1",token_pref);    
   }
   return ;

}

void  proxy_dns(FILE *nat_fp,int family)
{
   if  ( (Get_Device_Mode() == ROUTER ) )
   {
      char net_query[MAX_QUERY] = {0};
      char net_resp[MAX_QUERY] = {0};     
      char inst_resp[MAX_QUERY] = {0};
      char iot_enabled[20];
      char if_ipaddr[128] = {0};

      char* tok = NULL ;
      char* rest = NULL;

         snprintf(net_query, sizeof(net_query), "ipv4-instances");
         sysevent_get(sysevent_fd, sysevent_token, net_query, inst_resp, sizeof(inst_resp));
         rest = inst_resp;
         while ((tok = strtok_r(rest, " ", &rest)))
         {
                 memset(net_query,0,sizeof(net_query));
                 memset(net_resp,0,sizeof(net_resp));

                 snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
                 sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
                 if (strcmp("up", net_resp) != 0)
                     continue;

                 memset(net_query,0,sizeof(net_query));

                 memset(net_resp,0,sizeof(net_resp));
                 snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
                 sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

                  if (net_resp[0] != '\0' && strlen(net_resp) != 0 )
                  {

                        memset(if_ipaddr, 0, sizeof(if_ipaddr));
                        if(family == AF_INET )
                           snprintf(if_ipaddr,sizeof(if_ipaddr),"%s",get_iface_ipaddr(net_resp));
                        else if (family == AF_INET6)
                        {
                           get_iface_ipaddr_ula(net_resp,if_ipaddr,sizeof(if_ipaddr));
                        }
                        if(if_ipaddr[0] != '\0')
                        {
                           fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",net_resp,if_ipaddr);
                           fprintf(nat_fp, "-A PREROUTING -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",net_resp,if_ipaddr);
                        }
                  }    
            }   
         

         memset(iot_enabled, 0, sizeof(iot_enabled));

         syscfg_get(NULL, "lost_and_found_enable", iot_enabled, sizeof(iot_enabled));
     
         if(0==strcmp("true",iot_enabled))
         {
            memset(iot_ifName, 0, sizeof(iot_ifName));
            syscfg_get(NULL, "iot_ifname", iot_ifName, sizeof(iot_ifName));
            if( strstr( iot_ifName, "l2sd0.106")) {
                     syscfg_get( NULL, "iot_brname", iot_ifName, sizeof(iot_ifName));
            }

            if (iot_ifName[0] != '\0' && strlen(iot_ifName) != 0 )
            {
               memset(if_ipaddr, 0, sizeof(if_ipaddr));
               if(family == AF_INET )
                  snprintf(if_ipaddr,sizeof(if_ipaddr),"%s",get_iface_ipaddr(iot_ifName));
               else if (family == AF_INET6)
               {
                  get_iface_ipaddr_ula(iot_ifName,if_ipaddr,sizeof(if_ipaddr));
               }

               if(if_ipaddr[0] != '\0')
               {
                  fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",iot_ifName,if_ipaddr);
                  fprintf(nat_fp, "-A PREROUTING -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",iot_ifName,if_ipaddr);           
               }

            }

         }         
   }

}
#endif

#ifdef WAN_FAILOVER_SUPPORTED
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
void  redirect_dns_to_extender(FILE *nat_fp,int family)
{
   FIREWALL_DEBUG("Entering redirect_dns_to_extender,current_wan_ifname is %s , default wan is %s\n" COMMA current_wan_ifname COMMA default_wan_ifname);
   errno_t safec_rc = -1;
    char* tok = NULL;
    char net_query[MAX_QUERY] = {0};
    char net_resp[MAX_QUERY] = {0};
    char inst_resp[MAX_QUERY] = {0};
    char iot_enabled[20];
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
    if((Get_Device_Mode() != EXTENDER_MODE ) && (strcmp(current_wan_ifname, mesh_wan_ifname ) == 0))
#else 
   if  ( (Get_Device_Mode() != EXTENDER_MODE ) && strcmp(current_wan_ifname,default_wan_ifname ) != 0 ) 
#endif
   {
         FIREWALL_DEBUG("Device in wan failover state\n");
 
         char dest_ip[128] = {0};
         memset(dest_ip,0,sizeof(dest_ip));
         if(family == AF_INET)
         {
               sysevent_get(sysevent_fd, sysevent_token,REMOTEWAN_ROUTER_IP, dest_ip, sizeof(dest_ip));
               if (dest_ip[0] == '\0'  )
               {
                      memset(dest_ip,0,sizeof(dest_ip));
                      safec_rc = strcpy_s(dest_ip, sizeof(dest_ip),"192.168.246.1");
                      ERR_CHK(safec_rc);
               }
         }
         else if (family == AF_INET6)
         {
               sysevent_get(sysevent_fd, sysevent_token,REMOTEWAN_ROUTER_IPv6, dest_ip, sizeof(dest_ip));
         }
         else
            return;

      if (dest_ip[0] != '\0' && strlen(dest_ip) != 0 )
      {
        char *token =NULL ;
        token = strtok(dest_ip,"/");

         snprintf(net_query, sizeof(net_query), "ipv4-instances");
         sysevent_get(sysevent_fd, sysevent_token, net_query, inst_resp, sizeof(inst_resp));

         tok = strtok(inst_resp, " ");

         if (tok) 
         {
               do {
                 memset(net_query,0,sizeof(net_query));
                 memset(net_resp,0,sizeof(net_resp));

                 snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
                 sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));
                 if (strcmp("up", net_resp) != 0)
                     continue;

                 memset(net_query,0,sizeof(net_query));

                 memset(net_resp,0,sizeof(net_resp));
                 snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
                 sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

                  if (net_resp[0] != '\0' && strlen(net_resp) != 0 )
                  {
                        fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",net_resp,token);
                        fprintf(nat_fp, "-A PREROUTING -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",net_resp,token);
                  }

               } while ((tok = strtok(NULL, " ")) != NULL);       
         }

         memset(iot_enabled, 0, sizeof(iot_enabled));
         syscfg_get(NULL, "lost_and_found_enable", iot_enabled, sizeof(iot_enabled));
     
         if(0==strcmp("true",iot_enabled))
         {
            memset(iot_ifName, 0, sizeof(iot_ifName));
            syscfg_get(NULL, "iot_ifname", iot_ifName, sizeof(iot_ifName));
            if( strstr( iot_ifName, "l2sd0.106")) {
                     syscfg_get( NULL, "iot_brname", iot_ifName, sizeof(iot_ifName));
            }

            if (iot_ifName[0] != '\0' && strlen(iot_ifName) != 0 )
            {
               fprintf(nat_fp, "-A PREROUTING -i %s -p udp --dport 53 -j DNAT --to-destination %s\n",iot_ifName,token);
               fprintf(nat_fp, "-A PREROUTING -i %s -p tcp --dport 53 -j DNAT --to-destination %s\n",iot_ifName,token);  
            }

         }
         fprintf(nat_fp, "-A PREROUTING -i br403 -p udp --dport 53 -j DNAT --to-destination %s\n",token);
         fprintf(nat_fp, "-A PREROUTING -i br403 -p tcp --dport 53 -j DNAT --to-destination %s\n",token);  
      }

    }
   FIREWALL_DEBUG("Exiting redirect_dns_to_extender\n");
   return ;
}
#endif //_PLATFORM_RASPBERRYPI_ && _PLATFORM_BANANAPI_R4_
#endif

#ifdef LTE_USB_FEATURE_ENABLED
#define LTE_USB_IFACE_NAME "usb0"
#define LTE_USB_HTTPS_SERVER_PORT 4550
#define LTE_FIRMWARE_DOWNLOAD_SERVER_PORT 21616
static int do_lte_usb_rules_v4(FILE* fp)
{
	fprintf(fp, "-I %s -i %s -p tcp --dport %d -j ACCEPT\n", "INPUT", LTE_USB_IFACE_NAME,LTE_USB_HTTPS_SERVER_PORT);
	return 0;
}
static int do_lte_firmware_download_rules_v4(FILE* fp)
{
        fprintf(fp, "-I %s -i %s -p tcp --dport %d -j ACCEPT\n", "INPUT", LTE_USB_IFACE_NAME,LTE_FIRMWARE_DOWNLOAD_SERVER_PORT);
        return 0;
}

#endif // LTE_USB_FEATURE_ENABLED
/*
 *  Procedure     : prepare_enabled_ipv4_firewall
 *  Purpose       : prepare ipv4 firewall
 *  Parameters    :
 *   raw_fp         : An open file for raw subtables
 *   mangle_fp      : an open file for writing mangle statements
 *   nat_fp         : an open file for writing nat statements
 *   filter_fp      : an open file for writing filter statements
 */
static int prepare_enabled_ipv4_firewall(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering prepare_enabled_ipv4_firewall \n"); 
   /*
    * Add all of the tables and subtables that are required for the firewall
    */
   prepare_subtables(raw_fp, mangle_fp, nat_fp, filter_fp);

   /*
    * Add subtables created by plugins
    */
#define GUARDIAN_IPTABLES	"/tmp/guardian.ipt"
   if (access(GUARDIAN_IPTABLES, F_OK) == 0) {
      prepare_subtables_ext(GUARDIAN_IPTABLES, raw_fp, mangle_fp, nat_fp, filter_fp);
   }

   /*
    * Add firewall rules
    */
   //RAW tables is not used in USGv2
   //do_raw_ephemeral(raw_fp);
   //do_raw_table_general_rules(raw_fp);
   //do_raw_table_nowan(raw_fp);
#ifdef INTEL_PUMA7
   do_raw_table_puma7(raw_fp);
#endif
   #ifdef RDKB_EXTENDER_ENABLED
   add_if_mss_clamping(mangle_fp,AF_INET);
   #endif
   add_qos_marking_statements(mangle_fp);

   do_port_forwarding(nat_fp, filter_fp);
   do_ipv4_UIoverWAN_filter(mangle_fp);

   do_nonat(filter_fp);
   WAN_FAILOVER_SUPPORT_CHECK
   do_dmz(nat_fp, filter_fp);
   WAN_FAILOVER_SUPPORT_CHECk_END
   do_nat_ephemeral(nat_fp);
   do_wan_nat_lan_clients(nat_fp);
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   if (isMAPTReady)
   {
       do_wan_nat_lan_clients_mapt(nat_fp);
   }
#endif //FEATURE_MAPT

   do_wpad_isatap_blockv4(filter_fp);

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
   if(isGuestNetworkEnabled) {
       do_guestnet_walled_garden(nat_fp);
   }

   do_device_based_parcon(nat_fp, filter_fp);
#endif

   do_lan2self(filter_fp);
   do_wan2self(mangle_fp, nat_fp, filter_fp);
   do_lan2wan(mangle_fp, filter_fp, nat_fp); 
   do_wan2lan(filter_fp);
   do_filter_table_general_rules(filter_fp);
#if defined(SPEED_BOOST_SUPPORTED)
WAN_FAILOVER_SUPPORT_CHECK
   if(isWanServiceReady)
	do_speedboost_port_rules(mangle_fp,nat_fp , 4);
WAN_FAILOVER_SUPPORT_CHECk_END
#endif

#ifdef FEATURE_464XLAT
   do_xlat_rule(nat_fp);
#endif

#if defined(_BWG_PRODUCT_REQ_)
   do_raw_table_staticip(raw_fp);
#else
   do_raw_logs(raw_fp);
#endif

   do_logs(filter_fp);
  
/* Prepare mangle table rules for brlan1 traffic marking used to clamp mss for GRE traffic */
   prepare_ethernetbhaul_greclamp(mangle_fp);
 
   prepare_multinet_mangle(mangle_fp);
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   do_mapt_rules_v4(nat_fp, filter_fp, mangle_fp);
#endif //FEATURE_MAPT

#if defined(_HUB4_PRODUCT_REQ_) || defined(_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      do_hub4_voice_rules_v4(filter_fp);
   }
#if defined(HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
   char syscfg_value[64] = { 0 };
   int get_ret = 0;
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
        do_hub4_bfd_rules_v4(nat_fp, filter_fp, mangle_fp);
   }
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED

#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
#ifdef HUB4_QOS_MARK_ENABLED
      do_qos_output_marking_v4(mangle_fp);
#endif

#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
      do_self_heal_rules_v4(mangle_fp);
#endif
   }
#endif //_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_

#ifdef LTE_USB_FEATURE_ENABLED
   do_lte_usb_rules_v4(filter_fp);
   do_lte_firmware_download_rules_v4(filter_fp);
#endif // LTE_USB_FEATURE_ENABLED

   //do_multinet_patch(mangle_fp, nat_fp, filter_fp);
#if defined(MOCA_HOME_ISOLATION)
   prepare_MoCA_bridge_firewall(raw_fp, mangle_fp, nat_fp, filter_fp);
#endif

#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_) && !defined(_SCXF11BFL_PRODUCT_REQ_)
 /* To avoid open ssh connection to CM IP TCXB6-2879*/
   if (!isBridgeMode)
   {
       FILE *f = NULL;
       char request[256], response[256], cm_ipaddr[20];
       unsigned int a = 0, b = 0, c = 0, d = 0;

       snprintf(request, 256, "snmpget -cpub -v2c -Ov %s %s", CM_SNMP_AGENT, kOID_cmRemoteIpAddress);

       if ((f = popen(request, "r")) != NULL)
       {
           fgets(response, 255, f);
           sscanf(response, "Hex-STRING: %02x %02x %02x %02x", &a, &b, &c, &d);
           sprintf(cm_ipaddr, "%d.%d.%d.%d", a, b, c, d);

           if (!(a == 0 && b == 0 && c == 0 && d == 0))
           {
                fprintf(filter_fp, "-I FORWARD -d %s -i %s -j DROP\n", cm_ipaddr,lan_ifname);
           }

           pclose(f);
       }
   }
#endif
   
   do_blockfragippktsv4(filter_fp);
   do_portscanprotectv4(filter_fp);
   do_ipflooddetectv4(filter_fp);

   prepare_rabid_rules_for_mapt(filter_fp, IP_V4);

#if defined(FEATURE_RDKB_INTER_DEVICE_MANAGER)
   prepare_idm_firewall(filter_fp);
#endif

   #ifdef WAN_FAILOVER_SUPPORTED
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
        if(strcmp(current_wan_ifname, mesh_wan_ifname ) == 0)
#else
         if ( strcmp(current_wan_ifname,default_wan_ifname) != 0 )
#endif
         {
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -o %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -o %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
            fprintf(filter_fp, "-I OUTPUT -o %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I OUTPUT -o %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
         }
         fprintf(filter_fp, "-I FORWARD -o %s -m state --state INVALID -j DROP\n",current_wan_ifname);
   #endif
   fprintf(raw_fp, "COMMIT\n");
   fprintf(mangle_fp, "COMMIT\n");
   fprintf(nat_fp, "COMMIT\n");
   fprintf(filter_fp, "COMMIT\n");
   FIREWALL_DEBUG("Exiting prepare_enabled_ipv4_firewall \n"); 
   return(0);
}

/*
 *  Procedure     : prepare_disabled_ipv4_firewall
 *  Purpose       : prepare ipv4 firewall in the case it is disabled (qos and nat may be enabled or disabled)
 *  Parameters    :
 *   raw_fp         : an open file for writing raw statements
 *   mangle_fp      : an open file for writing mangle statements
 *   nat_fp         : an open file for writing nat statements
 *   filter_fp      : an open file for writing filter statements
 */
static int prepare_disabled_ipv4_firewall(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   /*
    * raw
    */
   FIREWALL_DEBUG("Entering prepare_disabled_ipv4_firewall \n"); 
   fprintf(raw_fp, "*raw\n");
   fprintf(raw_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(raw_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
#ifdef INTEL_PUMA7
   do_raw_table_puma7(raw_fp);
#endif

#if defined(_BWG_PRODUCT_REQ_)
   do_raw_table_staticip(raw_fp);
#endif

   fprintf(raw_fp, "COMMIT\n");

   /*
    * mangle
    */
   fprintf(mangle_fp, "*mangle\n");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(mangle_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
#ifdef CONFIG_BUILD_TRIGGER
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(mangle_fp, ":%s - [0:0]\n", "prerouting_trigger");
#endif
#endif
   fprintf(mangle_fp, ":%s - [0:0]\n", "prerouting_qos");
   fprintf(mangle_fp, ":%s - [0:0]\n", "postrouting_qos");
   fprintf(mangle_fp, ":%s - [0:0]\n", "postrouting_lan2lan");
   
   //RDKB-54847: lld dscp rules and dscp 8 rule needs to be present for pseudo bridge mode
   prepare_lld_dscp_rules(mangle_fp);
   prepare_dscp_rule_for_host_mngt_traffic(mangle_fp);

   //zqiu: RDKB-5686: xconf rule should work for pseudo bridge mode
   prepare_xconf_rules(mangle_fp);

#ifdef CONFIG_BUILD_TRIGGER
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   fprintf(mangle_fp, "-A PREROUTING -j prerouting_trigger\n");
#endif
#endif
   fprintf(mangle_fp, "-A PREROUTING -j prerouting_qos\n");
   fprintf(mangle_fp, "-A POSTROUTING -j postrouting_qos\n");
   fprintf(mangle_fp, "-A POSTROUTING -j postrouting_lan2lan\n");
   add_qos_marking_statements(mangle_fp);
#ifdef DSLITE_FEATURE_SUPPORT  
   add_dslite_mss_clamping(mangle_fp);
#endif
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -m conntrack --ctstate INVALID -j DROP\n",emta_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",emta_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",current_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",ecm_wan_ifname);
   fprintf(mangle_fp, "-A PREROUTING -i %s -p udp -m conntrack --ctstate NEW -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n",emta_wan_ifname);
#endif

   /*
    * nat
    */
   fprintf(nat_fp, "*nat\n");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(nat_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   fprintf(nat_fp, ":%s - [0:0]\n", "postrouting_towan");
#if defined (FEATURE_SUPPORT_MAPT_NAT46)
   if (isMAPTReady)
   {
       fprintf(nat_fp, "-A POSTROUTING -o %s -j %s\n", NAT46_INTERFACE, MAPT_NAT_IPV4_POST_ROUTING_TABLE);
   }
   else
   {
#endif
   fprintf(nat_fp, "-A POSTROUTING -o %s -j postrouting_towan\n", current_wan_ifname);
#if defined (FEATURE_SUPPORT_MAPT_NAT46)
   }
#endif
#if defined(_COSA_BCM_MIPS_)
   if(isBridgeMode) {       
       fprintf(nat_fp, "-A PREROUTING -d %s/32 -i %s -p tcp -j DNAT --to-destination %s\n", BRIDGE_MODE_IP_ADDRESS, current_wan_ifname, lan0_ipaddr);
   }
#endif
   do_port_forwarding(nat_fp, NULL);
   do_ipv4_UIoverWAN_filter(mangle_fp);
   do_nat_ephemeral(nat_fp);
   do_wan_nat_lan_clients(nat_fp);
#if defined (FEATURE_MAPT)
   if (isMAPTReady)
   {
       do_wan_nat_lan_clients_mapt(nat_fp);
   }
#endif  //FEATURE_MAPT
#if defined (FEATURE_SUPPORT_MAPT_NAT46)
       do_mapt_rules_v4(nat_fp, filter_fp, mangle_fp);
#endif
  
   fprintf(nat_fp, "COMMIT\n");
   fprintf(mangle_fp, "COMMIT\n");

   /*
    * filter
    */
   fprintf(filter_fp, "*filter\n");
   fprintf(filter_fp, ":%s ACCEPT [0:0]\n", "INPUT");
   fprintf(filter_fp, ":%s - [0:0]\n", "wan2self_mgmt");
   fprintf(filter_fp, ":%s - [0:0]\n", "lan2self_mgmt");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_wan2self");
   fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lan2self");
   if (FALSE == bAmenityEnabled)
   {
      #if defined (WIFI_MANAGE_SUPPORTED)
      if (true == isManageWiFiEnabled())
      {
         fprintf(filter_fp, ":%s - [0:0]\n", "lan2self");
         fprintf(filter_fp, ":%s - [0:0]\n", "lan2self_by_wanip");
         fprintf(filter_fp, ":%s - [0:0]\n", "lanattack");
         fprintf(filter_fp, ":%s - [0:0]\n", "xlog_drop_lanattack");
         do_lan2self(filter_fp);
      }
      #endif /*WIFI_MANAGE_SUPPORTED*/
   }

   //>>DOS
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, ":%s - [0:0]\n", "wandosattack");
   fprintf(filter_fp, ":%s - [0:0]\n", "mtadosattack");
#endif
   //<<DOS
 
   if (isBridgeMode)
   {
#if defined (FEATURE_SUPPORT_MAPT_NAT46)
       if (isMAPTReady)
       {
           fprintf(filter_fp, "-I INPUT -i %s -p gre -j ACCEPT\n", NAT46_INTERFACE);

           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", ETH_MESH_BRIDGE, NAT46_INTERFACE);
           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", NAT46_INTERFACE, ETH_MESH_BRIDGE);
           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", XHS_BRIDGE, NAT46_INTERFACE);
           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", NAT46_INTERFACE, XHS_BRIDGE);
           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", LNF_BRIDGE, NAT46_INTERFACE);
           fprintf(filter_fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", NAT46_INTERFACE, LNF_BRIDGE);
       }
#endif
       fprintf(filter_fp, ":%s - [0:0]\n", "general_input");
       fprintf(filter_fp, ":%s - [0:0]\n", "general_output");
       fprintf(filter_fp, ":%s - [0:0]\n", "general_forward");
       fprintf(filter_fp, "-A INPUT -j general_input\n");
       fprintf(filter_fp, "-A FORWARD -j general_forward\n");
       fprintf(filter_fp, "-A OUTPUT -j general_output\n");
       do_filter_table_general_rules(filter_fp);
   }
   fprintf(filter_fp, "-A xlog_drop_wan2self -j DROP\n");
   fprintf(filter_fp, "-A xlog_drop_lan2self -j DROP\n");
   if(isWanServiceReady || isBridgeMode) {
#if defined(_COSA_BCM_MIPS_)
       fprintf(filter_fp, "-A INPUT -p tcp -m multiport --dports 80,443 -d %s -j ACCEPT\n",lan0_ipaddr);
#endif
#if defined (MULTILAN_FEATURE)
       fprintf(filter_fp, "-A INPUT -i %s -j wan2self_mgmt\n", current_wan_ifname);
#else
       fprintf(filter_fp, "-A INPUT ! -i %s -j wan2self_mgmt\n", isBridgeMode == 0 ? lan_ifname : cmdiag_ifname);
#endif
       do_webui_attack_filter(filter_fp);
       // Create iptable chain to ratelimit remote management packets
       do_webui_rate_limit(filter_fp);
       WAN_FAILOVER_SUPPORT_CHECK
       do_remote_access_control(NULL, filter_fp, AF_INET);
       WAN_FAILOVER_SUPPORT_CHECk_END
   }

#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, "-A INPUT -p icmp -m state --state NEW,ESTABLISHED -m limit --limit 5/sec --limit-burst 10 -j ACCEPT\n");
   fprintf(filter_fp, "-A INPUT -p icmp -m state --state NEW,ESTABLISHED -j DROP\n");
#endif
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, "-I INPUT -i wan0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j wandosattack\n");
   fprintf(filter_fp, "-I INPUT -i wan0 -p udp -m udp -j wandosattack\n");
   fprintf(filter_fp, "-I INPUT -i mta0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j mtadosattack\n");
   fprintf(filter_fp, "-I INPUT -i mta0 -p udp -m udp -j mtadosattack\n");
   fprintf(filter_fp, "-A wandosattack -p tcp -m tcp --dport 22 -m limit --limit 25/sec --limit-burst 80 -j RETURN\n");
   fprintf(filter_fp, "-A wandosattack -m limit --limit 25/sec --limit-burst 80 -j ACCEPT\n");
   fprintf(filter_fp, "-A wandosattack -j DROP\n");
   fprintf(filter_fp, "-A mtadosattack -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n");
   fprintf(filter_fp, "-A mtadosattack -j DROP\n");
#endif
   //<<DOS
   /* Enabling SSH, SNMP and TR-069 firewall rules in bridge mode */
   if(isBridgeMode) {
   /* Filtering firewall rules for ssh and SNMP in bridgemode*/
   fprintf(filter_fp, ":%s - [0:0]\n", "LOG_SSH_DROP");
   fprintf(filter_fp, ":%s - [0:0]\n", "SSH_FILTER");
   fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", ecm_wan_ifname);
   //if (erouterSSHEnable || bEthWANEnable)
   fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n",current_wan_ifname);
   fprintf(filter_fp, "-A LOG_SSH_DROP -j LOG --log-prefix \"SSH Connection Blocked: \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level);
   fprintf(filter_fp, "-A LOG_SSH_DROP -j DROP\n");

   fprintf(filter_fp, "-A INPUT -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", cmdiag_ifname); //SNMP filter
   /* RDKB-57186 SNMP drop to XHS and LnF */
   fprintf(filter_fp, "-A INPUT -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", XHS_IF_NAME);
   fprintf(filter_fp, "-A INPUT -i %s -p udp -m udp --dport 161 -j xlog_drop_lan2self\n", LNF_IF_NAME);

   fprintf(filter_fp,"-A INPUT -p tcp -i brlan1 --dport 22 -j DROP\n");
   fprintf(filter_fp,"-A INPUT -p tcp -i br106 --dport 22 -j DROP\n");
   //SNMPv3 chains for logging and filtering
   fprintf(filter_fp, ":%s - [0:0]\n", "SNMPDROPLOG");
   fprintf(filter_fp, ":%s - [0:0]\n", "SNMP_FILTER");
   fprintf(filter_fp, "-A INPUT -p udp -m udp --match multiport --dports 10161,10163 -j SNMP_FILTER\n");
   fprintf(filter_fp, "-A SNMPDROPLOG -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"SNMP Connection Blocked:\"\n",syslog_level);
   fprintf(filter_fp, "-A SNMPDROPLOG -j DROP\n");

   //DROP incoming  NTP packets on erouter interface
   fprintf(filter_fp, "-A INPUT -i %s -m state --state ESTABLISHED,RELATED -p udp --dport 123 -j ACCEPT \n", get_current_wan_ifname());
   fprintf(filter_fp, "-A INPUT -i %s  -m state --state NEW -p udp --dport 123 -j DROP \n",get_current_wan_ifname());

   //DROP incoming 21515 port on erouter interface
   fprintf(filter_fp, "-A INPUT -i %s -p tcp -m tcp --dport 21515 -j DROP\n",get_current_wan_ifname());

   // Video Analytics Firewall rule to allow port 58081 only from LAN interface
   do_OpenVideoAnalyticsPort (filter_fp);

#if !defined(_COSA_INTEL_XB3_ARM_)
   filterPortMap(filter_fp);
#endif

#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_) && !defined(_PLATFORM_BANANAPI_R4_)
   do_ssh_IpAccessTable(filter_fp, "22", AF_INET, ecm_wan_ifname);
#else
   fprintf(filter_fp, "-A SSH_FILTER -j ACCEPT\n");
#endif
   do_snmp_IpAccessTable(filter_fp, AF_INET);

   }

   if(isComcastImage && isBridgeMode) {
       //tr69 chains for logging and filtering
       fprintf(filter_fp, ":%s - [0:0]\n", "LOG_TR69_DROP");
       fprintf(filter_fp, ":%s - [0:0]\n", "tr69_filter");
       fprintf(filter_fp, "-A INPUT -p tcp -m tcp --dport 7547 -j tr69_filter\n");
       fprintf(filter_fp, "-A LOG_TR69_DROP -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"TR-069 ACS Server Blocked:\"\n",syslog_level);
       fprintf(filter_fp, "-A LOG_TR69_DROP -j DROP\n");
       do_tr69_whitelistTable(filter_fp, AF_INET);
   }

   if(!isBridgeMode) {//brlan0 exists
       fprintf(filter_fp, "-A INPUT -i %s -j lan2self_mgmt\n", lan_ifname);
   }
#if defined(_CBR_PRODUCT_REQ_)
   else {
     	   //TCCBR-2674 - Technicolor CBR Telnet port exposed to Public internet
	   fprintf(filter_fp, "-A INPUT -i erouter0 -p tcp -m tcp --dport 23 -j DROP\n" );
	 }
#endif

#if defined (MULTILAN_FEATURE)
   prepare_multinet_disabled_ipv4_firewall(filter_fp);
#endif

   if (FALSE == bAmenityEnabled)
   {
      #if defined (WIFI_MANAGE_SUPPORTED)
      updateManageWiFiRules(bus_handle, current_wan_ifname, filter_fp);
      #endif /*WIFI_MANAGE_SUPPORTED*/
   }
   else
   {
      #if defined (AMENITIES_NETWORK_ENABLED)
      updateAmenityNetworkRules(filter_fp,mangle_fp , AF_INET);
      #endif
   }

   fprintf(filter_fp, "-A INPUT -i %s -j lan2self_mgmt\n", cmdiag_ifname); //lan0 always exist

   lan_telnet_ssh(filter_fp, AF_INET);

   #if defined(CONFIG_CCSP_LAN_HTTP_ACCESS)
   lan_http_access(filter_fp);
   #endif

#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_) && !defined(_SCXF11BFL_PRODUCT_REQ_)
   if (isBridgeMode)
   {
       FILE *f = NULL;
       char request[256], response[256], cm_ipaddr[20];
       unsigned int a = 0, b = 0, c = 0, d = 0;

       snprintf(request, 256, "snmpget -cpub -v2c -Ov %s %s", CM_SNMP_AGENT, kOID_cmRemoteIpAddress);

       if ((f = popen(request, "r")) != NULL)
       {
           fgets(response, 255, f);
           sscanf(response, "Hex-STRING: %02x %02x %02x %02x", &a, &b, &c, &d);
           sprintf(cm_ipaddr, "%d.%d.%d.%d", a, b, c, d);

           if (!(a == 0 && b == 0 && c == 0 && d == 0))
           {
               fprintf(filter_fp, "-I FORWARD -d %s -i %s -j DROP\n", cm_ipaddr,lan_ifname);
           }

           pclose(f);
       }
   }
#endif

#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(filter_fp, "-A OUTPUT -p icmp -m icmp --icmp-type 3 -j DROP\n");
#endif
   fprintf(filter_fp, ":%s ACCEPT [0:0]\n", "FORWARD");
   fprintf(filter_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   wan_lan_webui_attack(filter_fp,cmdiag_ifname);
   // Rate limiting the webui-access lan side
   lan_access_set_proto(filter_fp, "80",cmdiag_ifname);
   lan_access_set_proto(filter_fp, "443",cmdiag_ifname);
   // Blocking webui access to unnecessary interfaces
   fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",lan_ifname);
   fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",ecm_wan_ifname);
   if (isCmDiagEnabled)
   {
       fprintf(filter_fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",cmdiag_ifname);  
   }
   #if defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
        #if !defined(_CBR_PRODUCT_REQ_) && !defined (_BWG_PRODUCT_REQ_) && !defined (_CBR2_PRODUCT_REQ_)
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",LNF_IF_NAME);
	   /* RDKB-57186 SNMP drop to XHS and LnF */
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
	   fprintf(filter_fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(filter_fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
       #endif
       fprintf(filter_fp, "-A INPUT -p tcp -i privbr --match multiport  --dport 80,443 -j ACCEPT\n");
       fprintf(filter_fp, "-I FORWARD -d 172.31.255.0/24 -j DROP\n");
       fprintf(filter_fp, "-I INPUT -d 172.31.255.0/24 -i %s -j DROP\n", cmdiag_ifname);
   #endif
   fprintf(filter_fp,"-A INPUT -p tcp --match multiport  --dport 80,443 -j DROP\n");
   int ret = 0;
   char tmpQuery[MAX_QUERY];
   memset(tmpQuery, 0, sizeof(tmpQuery));
   #if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
       ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
   #else
       ret = syscfg_get(NULL, "mgmt_wan_httpaccess", tmpQuery, sizeof(tmpQuery));
   #endif
   if ((ret == 0) && atoi(tmpQuery) == 1)
   {
       fprintf(filter_fp,"-A INPUT -p tcp ! -i %s --dport 8080 -j DROP\n",current_wan_ifname);
   }
   else
   {
       fprintf(filter_fp,"-A INPUT -p tcp --dport 8080 -j DROP\n");
   }
   memset(tmpQuery, 0, sizeof(tmpQuery));
   ret =  syscfg_get(NULL, "mgmt_wan_httpsaccess", tmpQuery, sizeof(tmpQuery));
   if ((ret == 0) && atoi(tmpQuery) == 1)
   {
       fprintf(filter_fp,"-A INPUT -i  brlan0 -p tcp --dport 8181 -j ACCEPT\n");
       fprintf(filter_fp,"-A INPUT -p tcp ! -i %s --dport 8181 -j DROP\n",current_wan_ifname);
   }
   else
   {
       fprintf(filter_fp,"-A INPUT -p tcp --dport 8181 -j DROP\n");
   }
   
   fprintf(filter_fp, "COMMIT\n");
 FIREWALL_DEBUG("Exiting prepare_disabled_ipv4_firewall \n"); 
   return(0);
}

/*
 *  Procedure     : prepare_ipv4_firewall
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules
 *  Parameters    :
 *    fw_file        : The name of the file to which the firewall rules are written
 * Return Values  :
 *    0              : Success
 *   -1              : Bad input parameters
 *   -2              : Could not open firewall file
 * Notes          :
 *   If the fw_file does not exist, it will be created and used as the target of iptables-restore
 *   If the fw_file exists it will be overwritten, but the firewall itself will be updated using a
 *      series of iptables statements.
 *   The syscfg subsystem must be initialized prior to calling this function
 *   The sysevent subsytem must be initializaed prior to calling this function
 */
int prepare_ipv4_firewall(const char *fw_file)
{
 FIREWALL_DEBUG("Inside prepare_ipv4_firewall \n"); 
   /*
    * fw_file is the name of the file that we write firewall statement to.
    * This file is used by iptables-restore to provision the firewall.
    */
   if (NULL == fw_file) {
      return(-1);
   }

   FILE *fp = fopen(fw_file, "w"); 
   if (NULL == fp) {
      return(-2);
   }

   /*
    * We use 4 files to store the intermediary firewall statements.
    * One file is for raw, another is for mangle, another is for 
    * nat tables statements, and the other is for filter statements.
    */
   pid_t ourpid = getpid();
   char  fname[50];

   snprintf(fname, sizeof(fname), "/tmp/raw_%x", ourpid);
   FILE *raw_fp = fopen(fname, "w+");
   if (NULL == raw_fp) {
      fclose(fp);
      return(-2);
   }
   snprintf(fname, sizeof(fname), "/tmp/mangle_%x", ourpid);
   FILE *mangle_fp = fopen(fname, "w+");
   if (NULL == mangle_fp) {
      fclose(raw_fp);
      fclose(fp);
      return(-2);
   }
   snprintf(fname, sizeof(fname), "/tmp/filter_%x", ourpid);
   FILE *filter_fp = fopen(fname, "w+");
   if (NULL == filter_fp) {
      fclose(raw_fp);
      fclose(fp);
      fclose(mangle_fp);
      return(-2);
   }
   snprintf(fname, sizeof(fname), "/tmp/nat_%x", ourpid);
   FILE *nat_fp = fopen(fname, "w+");
   if (NULL == nat_fp) {
      fclose(raw_fp); /*RDKB-7145, CID-33445, free unused resource before exit */
      fclose(fp);
      fclose(mangle_fp);
      fclose(filter_fp);
      return(-2);
   }

   
   #ifdef RDKB_EXTENDER_ENABLED  
      if (isExtProfile() == 0 )
      {
         prepare_ipv4_rule_ex_mode(raw_fp, mangle_fp, nat_fp, filter_fp);
      }
      else if (isFirewallEnabled && !isBridgeMode ) { fprintf(stderr, "-- prepare_enabled_ipv4_firewall isWanServiceReady=%d\n", isWanServiceReady); //&& isWanServiceReady) {
   #else
      if (isFirewallEnabled && !isBridgeMode ) { fprintf(stderr, "-- prepare_enabled_ipv4_firewall isWanServiceReady=%d\n", isWanServiceReady); //&& isWanServiceReady) {
   #endif
      prepare_enabled_ipv4_firewall(raw_fp, mangle_fp, nat_fp, filter_fp);
   } else {
      prepare_disabled_ipv4_firewall(raw_fp, mangle_fp, nat_fp, filter_fp);
   }
   
   //prepare_multilan_firewall(nat_fp, filter_fp);
   fflush(raw_fp);
   fflush(mangle_fp);
   fflush(nat_fp);
   fflush(filter_fp);
   rewind(raw_fp);
   rewind(mangle_fp);
   rewind(nat_fp);
   rewind(filter_fp);
   char string[MAX_QUERY];
   char *strp;
   /*
    * The raw table is before conntracking and is thus expensive
    * So we dont set it up unless we actually used it
    */
   if (isRawTableUsed) {
      while (NULL != (strp = fgets(string, MAX_QUERY, raw_fp)) ) {
         fprintf(fp, "%s", string);
      }
   } else {
      fprintf(fp, "*raw\n-F\nCOMMIT\n");
   }
   while (NULL != (strp = fgets(string, MAX_QUERY, mangle_fp)) ) {
      fprintf(fp, "%s", string);
   }
   while (NULL != (strp = fgets(string, MAX_QUERY, nat_fp)) ) {
      fprintf(fp, "%s", string);
   }
   while (NULL != (strp = fgets(string, MAX_QUERY, filter_fp)) ) {
      fprintf(fp, "%s", string);
   }
   
   fflush(fp);
   fclose(fp);
   fclose(raw_fp);
   fclose(mangle_fp);
   fclose(nat_fp);
   fclose(filter_fp);

   snprintf(fname, sizeof(fname), "/tmp/raw_%x", ourpid);
   unlink(fname);
   snprintf(fname, sizeof(fname), "/tmp/mangle_%x", ourpid);
   unlink(fname);
   snprintf(fname, sizeof(fname), "/tmp/filter_%x", ourpid);
   unlink(fname);
   snprintf(fname, sizeof(fname), "/tmp/nat_%x", ourpid);
   unlink(fname);
 FIREWALL_DEBUG("Exiting prepare_ipv4_firewall \n"); 
   return(0);
}

/*
 *  Procedure     : prepare_stopped_ipv4_firewall
 *  Purpose       : prepare ipv4 firewall to stop all services (firewall, nat, qos) 
 *                  irrespective of their configuration
 *  Parameters    :
 *   file_fp         : an open file for writing iptables statements
 */
static int prepare_stopped_ipv4_firewall(FILE *file_fp)
{
 FIREWALL_DEBUG("Inside prepare_stopped_ipv4_firewall \n"); 
   /*
    * raw
    */
#ifdef NOTDEF
   fprintf(file_fp, "*raw\n");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   fprintf(file_fp, "COMMIT\n");
#endif

   /*
    * mangle
    */
   fprintf(file_fp, "*mangle\n");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   fprintf(file_fp, "COMMIT\n");

   /*
    * nat
    */
   fprintf(file_fp, "*nat\n");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "PREROUTING");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "POSTROUTING");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");
   fprintf(file_fp, "COMMIT\n");

   /*
    * filter
    */
   fprintf(file_fp, "*filter\n");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "INPUT");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "FORWARD");
   fprintf(file_fp, ":%s ACCEPT [0:0]\n", "OUTPUT");

   //Comment out to disable telnet/ssh in stopped firewall
   //fprintf(file_fp, ":lan2self_mgmt - [0:0]\n");
   //fprintf(file_fp, "-A INPUT -j lan2self_mgmt\n");
   //lan_telnet_ssh(file_fp, AF_INET);

   fprintf(file_fp, "COMMIT\n");
 FIREWALL_DEBUG("Exiting prepare_stopped_ipv4_firewall \n"); 
   return(0);
}

/*
 ********************************************************************
 *                                                                  *
 ********************************************************************
 */
static void printhelp(char *name) {
   printf ("Usage %s event_name --port sysevent_port --ip sysevent_ip --help\n", name);
   FIREWALL_DEBUG("Usage %s event_name --port sysevent_port --ip sysevent_ip --help\n" COMMA name);
}

/*
 * Procedure     : get_options
 * Purpose       : read commandline parameters and set configurable
 *                 parameters
 * Parameters    :
 *    argc       : The number of input parameters
 *    argv       : The input parameter strings
 * Return Value  :
 *   the index of the first not optional argument
 */
static int get_options(int argc, char **argv)
{
   int c;
   FIREWALL_DEBUG("Inside get_options\n");
   while (1) {
      int option_index = 0;
      static struct option long_options[] = {
         {"port", 1, 0, 'p'},
         {"ip", 1, 0, 'i'},
         {"help", 0, 0, 'h'},
         {0, 0, 0, 0}
      };

      // optstring has a leading : to stop debug output
      // p takes an argument
      // i takes an argument
      // h takes no argument
      // w takes no argument
      c = getopt_long (argc, argv, ":p:i:h", long_options, &option_index);
      if (c == -1) {
         break;
      }

      switch (c) {
         case 'p':
            sysevent_port = (0x0000FFFF & (unsigned short) atoi(optarg));
            break;

         case 'i':
            snprintf(sysevent_ip, sizeof(sysevent_ip), "%s", optarg);
            break;

         case 'h':
         case '?':
            printhelp(argv[0]);
            return -1;

         default:
            printhelp(argv[0]);
            break;
      }
   }
   FIREWALL_DEBUG("Exiting get_options\n");
   return(optind);
}

/*
 * Service Template Methods
 */

/*
 * Name           :  get_service_event
 * Purpose        :  Utility method to convert string to event id
 * Parameters     :  None
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static service_ev_t get_service_event (const char *ev)
{
	FIREWALL_DEBUG("Inside service_ev_t get_service_event\n");
    int i;
    
    for (i = 0; i < SERVICE_EV_COUNT; i++) {
        if (0 == strcmp(ev, service_ev_map[i].ev_string)) {
            return service_ev_map[i].ev;
        }
    }
	FIREWALL_DEBUG("Exiting service_ev_t get_service_event\n");
    return SERVICE_EV_UNKNOWN;
}
static BOOL isIPv6Addr(const char* ipAddr)
{
    if(strchr(ipAddr, ':') != NULL)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}
void RmConntrackEntry(char *IPaddr)
{
    if(isIPv6Addr(IPaddr))
    {
        v_secure_system("conntrack -D -f ipv6 -s %s", IPaddr);
        v_secure_system("conntrack -D -f ipv6 -d %s", IPaddr);

/*Mamidi:12042017:Fix for ARRISXB6-5237 and ARRISXB6-6256*/
#if !defined (INTEL_PUMA7)
        v_secure_system("ip6tables -I FORWARD -s %s -j DROP", IPaddr);
        v_secure_system("ip6tables -I FORWARD -s %s -m state --state ESTABLISHED -j DROP", IPaddr);
#endif
        v_secure_system("ip6tables -I FORWARD -s %s -m udp -p udp -j DROP", IPaddr);
        v_secure_system("ip6tables -I FORWARD -s %s -m udp -p udp --dport 53 -j ACCEPT", IPaddr);
        v_secure_system("ip6tables -I FORWARD -d %s -m udp -p udp --dport 53 -j ACCEPT", IPaddr);
        v_secure_system("ip6tables -I FORWARD -s %s -m tcp -p tcp -m state --state NEW -j ACCEPT", IPaddr);
    }
    else
    {
        v_secure_system("conntrack -D --orig-src %s", IPaddr);
/*Mamidi:12042017:Fix for ARRISXB6-5237 and ARRISXB6-6256*/
#if !defined (INTEL_PUMA7)
        v_secure_system("iptables -I FORWARD -s %s -j DROP", IPaddr);
        v_secure_system("iptables -I FORWARD -s %s -m state --state ESTABLISHED -j DROP", IPaddr);
#endif
        v_secure_system("iptables -I FORWARD -s %s -m udp -p udp -j DROP", IPaddr);
        v_secure_system("iptables -I FORWARD -s %s -m udp -p udp --dport 53 -j ACCEPT", IPaddr);
        v_secure_system("iptables -I FORWARD -d %s -m udp -p udp --dport 53 -j ACCEPT", IPaddr);
        v_secure_system("iptables -I FORWARD -s %s -m tcp -p tcp -m state --state NEW -j ACCEPT", IPaddr);
    }
}
int CleanIPConntrack(char *physAddress)
{
#ifdef CORE_NET_LIB
    char *mac_filter = NULL;
    char *if_filter = NULL;
    int af_filter = 0;
    char output[INET6_ADDRSTRLEN] = {0};

    if (physAddress != NULL) {
       mac_filter = strdup(physAddress);
       if (!mac_filter) {
          FIREWALL_DEBUG("CleanIPConntrack: Failed to copy MAC string\n");
          return -1;
       }
    }
    else{
       FIREWALL_DEBUG("CleanIPConntrack: Input MAC address is NULL\n");
       return -1;
    }

    struct neighbour_info *neigh_data =  init_neighbour_info();
    if (!neigh_data) {
       FIREWALL_DEBUG("CleanIPConntrack: Failed to initialize neighbor information structure\n");
       free(mac_filter);
       return -1;
    }
    libnet_status status = neighbour_get_list(neigh_data, mac_filter, if_filter, af_filter);
    if (status != CNL_STATUS_SUCCESS) {
        FIREWALL_DEBUG("Failed to list neighbours for %s\n" COMMA physAddress);
        free(mac_filter);
        neighbour_free_neigh(neigh_data);
        return -1;
    }
    FIREWALL_DEBUG("Successfully listed neighbours for %s\n" COMMA physAddress);
    for (int i = 0; i < neigh_data->neigh_count; i++) {
         snprintf(output, sizeof(output), "%s", neigh_data->neigh_arr[i].local);
         printf("Output: neighbour list %s\n",output);
            if (!strstr(output, "fe80:")) {
            RmConntrackEntry(output);
            }
    }
    neighbour_free_neigh(neigh_data);
    free(mac_filter);
#else
    FILE *fp = NULL;
    char output[50] = {0};
    memset(output,0,50);
    v_secure_system("ip nei show | grep brlan0 | grep -i %s | awk '{print $1}' ", physAddress);
      if(!(fp = v_secure_popen("r","ip nei show | grep brlan0 | grep -i %s | awk '{print $1}' ", physAddress)))
        {
            return -1;
        }
    while(fgets(output, sizeof(output), fp)!=NULL)
    {
        output[strlen(output) - 1] = '\0';
    	if(strstr(output,"fe80:"))
		{
	
		}
    	else
   		 RmConntrackEntry(output);
    }
    v_secure_pclose(fp);
#endif
    return 0;
}
int IsFileExists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}
BOOL validate_mac(char * physAddress)
{
	if(physAddress[2] == ':')
		if(physAddress[5] == ':')
			if(physAddress[8] == ':')
				if(physAddress[11] == ':')
					if(physAddress[14] == ':')
						return TRUE;
					
					
	return FALSE;
}
static int ClearEstbConnection(void)
{
char mac[20];
char buf[200] = {0};
FILE *fp = NULL;
memset(mac,0,20);
memset(buf,0,200);
    if(IsFileExists("/tmp/conn_mac"))
    {
      if(!(fp = v_secure_popen("r", "cat /tmp/conn_mac|awk '{print $1}'")))
        {
            return -1;
        }
		while(fgets(mac, sizeof(mac), fp)!=NULL)
		{
			mac[strlen(mac) - 1] = '\0';
                  if(validate_mac(mac))
                  {
                        CleanIPConntrack(mac);
                  }
		}
		  v_secure_pclose(fp);
		  v_secure_system("rm /tmp/conn_mac");  
    }
    return 0;
}

/*
 * Function to add IP Table rules regarding IPv4 Fragmented Packets
 */
int do_blockfragippktsv4(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};

    syscfg_get(NULL, V4_BLOCKFRAGIPPKT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        fprintf(fp, "-N FRAG_DROP\n");
        fprintf(fp, "-F FRAG_DROP\n");
        fprintf(fp, "-I FORWARD -m mark --mark 0x0800 -j FRAG_DROP\n");
        fprintf(fp, "-I INPUT -m mark --mark 0x0800 -j FRAG_DROP\n");
        fprintf(fp, "-A FRAG_DROP -i %s -j DROP\n", lan_ifname);
        fprintf(fp, "-A FRAG_DROP -i %s -o %s -j DROP\n",current_wan_ifname, lan_ifname);

    }
    return 0;
}

/*
 * Function to add IP Table rules against Ports scanning
 */
int do_portscanprotectv4(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};
    syscfg_get(NULL, V4_PORTSCANPROTECT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        fprintf(fp,"-N %s\n",PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-N %s\n",PORT_SCAN_DROP_CHAIN);
        fprintf(fp,"-F %s\n",PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-F %s\n",PORT_SCAN_DROP_CHAIN);
        /*Adding rules in new chain */
        fprintf(fp,"-A INPUT -j %s\n",PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-A FORWARD -j %s\n",PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-A %s -i %s -j RETURN\n", PORT_SCAN_CHECK_CHAIN,current_wan_ifname);
        fprintf(fp,"-A %s -i lo -j RETURN\n", PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-A %s -p udp -m recent --name portscan --rcheck --seconds 86400 -j %s\n", PORT_SCAN_CHECK_CHAIN, PORT_SCAN_DROP_CHAIN);
        fprintf(fp,"-A %s -p tcp -m recent --name portscan --rcheck --seconds 86400 -j %s\n", PORT_SCAN_CHECK_CHAIN, PORT_SCAN_DROP_CHAIN);
        fprintf(fp,"-A %s -j DROP\n", PORT_SCAN_DROP_CHAIN);

    }
    return 0;
}

/*
 * Function to add IP Table rules against IPV4 Flooding
 */
int do_ipflooddetectv4(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};
    syscfg_get(NULL, V4_IPFLOODDETECT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        /* Creating New Chain */
        fprintf(fp, "-N DOS\n");
        fprintf(fp, "-N DOS_FWD\n");
        fprintf(fp, "-N DOS_TCP\n");
        fprintf(fp, "-N DOS_UDP\n");
        fprintf(fp, "-N DOS_ICMP\n");
        fprintf(fp, "-N DOS_ICMP_REQUEST\n");
        fprintf(fp, "-N DOS_ICMP_REPLY\n");
        fprintf(fp, "-N DOS_ICMP_OTHER\n");
        fprintf(fp, "-N DOS_DROP\n");

        fprintf(fp, "-F DOS\n");
        fprintf(fp, "-F DOS_FWD\n");
        fprintf(fp, "-F DOS_TCP\n");
        fprintf(fp, "-F DOS_UDP\n");
        fprintf(fp, "-F DOS_ICMP\n");
        fprintf(fp, "-F DOS_ICMP_REQUEST\n");
        fprintf(fp, "-F DOS_ICMP_REPLY\n");
        fprintf(fp, "-F DOS_ICMP_OTHER\n");
        fprintf(fp, "-F DOS_DROP\n");
        /*Adding Rules in new chain */
        fprintf(fp, "-A DOS  -d 224.0.0.0/4 -j RETURN\n");
        fprintf(fp, "-A DOS -i lo -j RETURN\n");
        fprintf(fp, "-A DOS -p tcp --syn -j DOS_TCP\n");
        fprintf(fp, "-A DOS -p udp -m state --state NEW -j DOS_UDP\n");
        fprintf(fp, "-A DOS -p icmp -j DOS_ICMP\n");
        fprintf(fp, "-A DOS_TCP -p tcp --syn -m limit --limit 20/s --limit-burst 40 -j RETURN\n");
        fprintf(fp, "-A DOS_TCP -j DOS_DROP\n");
        fprintf(fp, "-A DOS_UDP -p udp -m limit --limit 20/s --limit-burst 40 -j RETURN\n");
        fprintf(fp, "-A DOS_UDP -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_REQUEST\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_REPLY\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_OTHER\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -p icmp ! --icmp-type echo-request -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -p icmp --icmp-type echo-request -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -p icmp ! --icmp-type echo-reply -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -p icmp --icmp-type echo-reply -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p icmp --icmp-type echo-request -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p icmp --icmp-type echo-reply -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p icmp -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -j DOS_DROP\n");
        fprintf(fp, "-A DOS_DROP -j DROP\n");
        fprintf(fp, "-A DOS_FWD -j DOS\n");
        fprintf(fp, "-A FORWARD -j DOS_FWD\n");
        fprintf(fp, "-A INPUT -j DOS\n");
    }
    return 0;
}

/*
 * Name           :  service_init
 * Purpose        :  Initialize resources & retrieve configurations
 *                   required for firewall service
 * Parameters     :
 *    argc        :  Count of arguments (excludes event-name)
 *    argv        :  Array of arguments 
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static int service_init (int argc, char **argv)
{
   int rc = 0;
   char* pCfg = CCSP_MSG_BUS_CFG;
   int ret = 0;

   ulog_init();
	FIREWALL_DEBUG("Inside firewall service_init()\n");
   ulogf(ULOG_FIREWALL, UL_INFO, "%s service initializing", service_name);
      	FIREWALL_DEBUG("%s service initializing\n" COMMA service_name);

   isCronRestartNeeded     = 0;

   snprintf(sysevent_ip, sizeof(sysevent_ip), "127.0.0.1");
   sysevent_port = SE_SERVER_WELL_KNOWN_PORT;

   // parse commandline for options and readjust defaults if requested
   //int next_arg = get_options(argc, argv);
   get_options(argc, argv);

   sysevent_fd =  sysevent_open(sysevent_ip, sysevent_port, SE_VERSION, sysevent_name, &sysevent_token);
   if (0 > sysevent_fd) {
      printf("Unable to register with sysevent daemon at %s %u.\n", sysevent_ip, sysevent_port);
      FIREWALL_DEBUG("Unable to register with sysevent daemon at %s %u.\n"COMMA sysevent_ip COMMA sysevent_port);
      rc = -2;
      goto ret_err;
   }
   
#ifdef DBUS_INIT_SYNC_MODE
    ret = CCSP_Message_Bus_Init_Synced(firewall_component_id, pCfg, &bus_handle, Ansc_AllocateMemory_Callback, Ansc_FreeMemory_Callback);
#else
    ret = CCSP_Message_Bus_Init((char *)firewall_component_id, pCfg, &bus_handle, (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback, Ansc_FreeMemory_Callback);
#endif
    if ( ret == -1 )
    {
        // Dbus connection error
        // Comment below
        fprintf(stderr, "%d, DBUS connection error\n", CCSP_MESSAGE_BUS_CANNOT_CONNECT);
        FIREWALL_DEBUG("%d, DBUS connection error\n" COMMA CCSP_MESSAGE_BUS_CANNOT_CONNECT);
        fprintf(stderr, "%d", CCSP_MESSAGE_BUS_CANNOT_CONNECT);
        bus_handle = NULL;
        //firewall need work before DBUS started, cannot exit
        //exit(CCSP_MESSAGE_BUS_CANNOT_CONNECT);
    }

   ulog_debugf(ULOG_FIREWALL, UL_INFO, "firewall opening sysevent_fd %d, token %d", sysevent_fd, sysevent_token);
   FIREWALL_DEBUG("firewall opening sysevent_fd %d, token %d\n"COMMA sysevent_fd COMMA sysevent_token);       
   time_t now;
   time(&now);
   if (NULL == localtime_r((&now), (&local_now))) {
      rc = -3;
      goto ret_err;
   }

   prepare_globals_from_configuration();

   firewall_lib_init(bus_handle, sysevent_fd, sysevent_token);

ret_err:
FIREWALL_DEBUG("Exiting firewall service_init()\n");
   return rc;
}

/*
 * Name           :  service_close
 * Purpose        :  Close resources initialized for firewall service
 * Parameters     :
 *    None        :
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static int service_close ()
{
   FIREWALL_DEBUG("Inside firewall service_close()\n");
   if (0 <= sysevent_fd)  {
       ulog_debugf(ULOG_FIREWALL, UL_INFO, "firewall closing sysevent_fd %d, token %d",
                   sysevent_fd, sysevent_token);
       FIREWALL_DEBUG("firewall closing sysevent_fd %d, token %d\n"COMMA
                   sysevent_fd COMMA sysevent_token);
       sysevent_close(sysevent_fd, sysevent_token);
   }
   if (bus_handle != NULL) {
       ulog_debug(ULOG_FIREWALL, UL_INFO, "firewall closing dbus connection");
       FIREWALL_DEBUG("firewall closing dbus connection\n");
        CCSP_Message_Bus_Exit(bus_handle);
   }
   ulog(ULOG_FIREWALL, UL_INFO, "firewall operation completed");
FIREWALL_DEBUG("exiting firewall service_close()\n");
   return 0;
}

/*
 * Name           :  service_start
 * Purpose        :  Start firewall service (including nat & qos)
 * Parameters     :
 *    None        :
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static int service_start ()
{
   char *filename1 = "/tmp/.ipt";
   char *filename2 = "/tmp/.ipt_v6";
   BOOL needs_flush = FALSE;
   char temp[20];
   //int res_rfcfile = -1, res_rfclock = -1;

   /* If firewall is starting for the first time, we need to flush connection tracking */
   temp[0] = '\0';
   sysevent_get(sysevent_fd, sysevent_token, "firewall-status", temp, sizeof(temp));
   if ('\0' == temp[0] || 0 == strcmp(temp, "stopped")) {
      needs_flush = TRUE;
   }

   //clear content in firewall cron file.
   char *cron_file = crontab_dir"/"crontab_filename;
   FILE *cron_fp = NULL; // the crontab file we use to set wakeups for timed firewall events
   //pthread_mutex_lock(&firewall_check);
   FIREWALL_DEBUG("Inside firewall service_start()\n");
   cron_fp = fopen(cron_file, "w");
   if(cron_fp) {
       fclose(cron_fp);
   } else {
       fprintf(stderr,"%s: ### create crontab_file error with %d!!!\n",__FUNCTION__, errno);
       FIREWALL_DEBUG("%s: ### create crontab_file error with %d!!!\n" COMMA __FUNCTION__ COMMA errno);
   } 

   sysevent_set(sysevent_fd, sysevent_token, "firewall-status", "starting", 0);
   ulogf(ULOG_FIREWALL, UL_INFO, "starting %s service", service_name);
   FIREWALL_DEBUG("starting %s service\n" COMMA service_name);
   /*  ipv4 */
   prepare_ipv4_firewall(filename1);

   FIREWALL_DEBUG("iptables-restore for ipv4 starts\n");
#ifdef _HUB4_PRODUCT_REQ_
   v_secure_system("iptables-restore -c  < /tmp/.ipt 2> /tmp/.ipv4table_error");
#else
   v_secure_system("iptables-restore -w 10 -c  < /tmp/.ipt 2> /tmp/.ipv4table_error");
#endif
   FIREWALL_DEBUG("iptables-restore for ipv4 ends\n");

   //if (!isFirewallEnabled) {
   //   unlink(filename1);
   //}

   /* ipv6 */
   prepare_ipv6_firewall(filename2);
   FIREWALL_DEBUG("iptables-restore for ipv6 starts\n");
#ifdef _HUB4_PRODUCT_REQ_
   v_secure_system("ip6tables-restore < /tmp/.ipt_v6 2> /tmp/.ipv6table_error");
#else
   v_secure_system("ip6tables-restore -w 10 < /tmp/.ipt_v6 2> /tmp/.ipv6table_error");
#endif
   FIREWALL_DEBUG("iptables-restore for ipv6 ends\n");

   #ifdef _PLATFORM_RASPBERRYPI_
       /* Apply Mac Filtering rules for RPI-Device */
       v_secure_system("/bin/sh -c /tmp/mac_filter.sh");
   #endif
   #ifdef _PLATFORM_TURRIS_
       /* Apply Mac Filtering rules */
       v_secure_system("/bin/sh -c /tmp/mac_filter.sh");
   #endif
   #ifdef _PLATFORM_BANANAPI_R4_
       /* Apply Mac Filtering rules */
       v_secure_system("/bin/sh -c /tmp/mac_filter.sh");
   #endif

  #if 0
   /* RFC REFRESH for dynamic whitelisting of IPs */
   FIREWALL_DEBUG("Before check whether RFC file for SSH present or not\n");
   res_rfcfile = access("/tmp/RFC/.RFC_SSHWhiteList.list", F_OK);
   res_rfclock = access("/tmp/.rfcLock", F_OK);
   if ( ( res_rfcfile != -1 ) && ( res_rfclock == -1 ) ) 
   {
      FIREWALL_DEBUG("RFC file for SSH present. Whitelisting IP's\n");
      system("sh /lib/rdk/rfc_refresh.sh SSH_REFRESH");
   }

   FIREWALL_DEBUG(".RFC_SSHWhiteList.list status[%d] /tmp/.rfcLock status[%d]\n" COMMA res_rfcfile COMMA res_rfclock);
   #endif

   if (isContainerEnabled && access("/tmp/container_env.sh", F_OK) != -1 && access("/tmp/.lxcIptablesLock", F_OK) == -1) {
      FIREWALL_DEBUG("LXC Support enabled. Adding rules for lighttpd container\n");
      v_secure_system("sh /lib/rdk/iptables_container.sh");
   }

   ClearEstbConnection();
   /* start the other process as needed */
#ifdef CONFIG_BUILD_TRIGGER
#ifndef CONFIG_KERNEL_NF_TRIGGER_SUPPORT
   if (isTriggerMonitorRestartNeeded) {
      sysevent_set(sysevent_fd, sysevent_token, "firewall_trigger_monitor-start", NULL, 0);
   }
#endif
#endif
   if (isLanHostTracking) {
      sysevent_set(sysevent_fd, sysevent_token, "firewall_newhost_monitor-start", NULL, 0);
   }

   if (isCronRestartNeeded) {
      sysevent_set(sysevent_fd, sysevent_token, "crond-restart", "1", 0);
   }
   else {
      unlink(cron_file);
   }

   if(ppFlushNeeded == 1) {
#if defined (INTEL_PUMA7)
       v_secure_system("conntrack -F");
#else
       v_secure_system("echo flush_all_sessions > /proc/net/ti_pp");
#endif
       sysevent_set(sysevent_fd, sysevent_token, "pp_flush", "0", 0);
   }

   /* If firewall is starting for the first time, we need to flush connection tracking */
   if (needs_flush) {
      v_secure_system("conntrack -F");
   }

   sysevent_set(sysevent_fd, sysevent_token, "firewall-status", "started", 0);
   ulogf(ULOG_FIREWALL, UL_INFO, "started %s service", service_name);
   FIREWALL_DEBUG("started %s service\n" COMMA service_name);
//   pthread_mutex_unlock(&firewall_check);
   FIREWALL_DEBUG("Exiting firewall service_start()\n");
 	return 0;
}

/*
 * Name           :  service_stop
 * Purpose        :  Stop firewall service (including nat & qos)
 * Parameters     :  None
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static int service_stop ()
{
   char *filename1 = "/tmp/.ipt";
//	pthread_mutex_lock(&firewall_check);
	FIREWALL_DEBUG("Inside firewall service_stop()\n");
   sysevent_set(sysevent_fd, sysevent_token, "firewall-status", "stopping", 0);
   ulogf(ULOG_FIREWALL, UL_INFO, "stopping %s service", service_name);
	FIREWALL_DEBUG("stopping %s service\n" COMMA service_name);
   FILE *fp = fopen(filename1, "w"); 
   if (NULL == fp) {
//   pthread_mutex_unlock(&firewall_check);
      return(-2);
   }
   prepare_stopped_ipv4_firewall(fp);
   fclose(fp);

   v_secure_system("iptables -t filter -F");
   v_secure_system("iptables -t nat -F");
   v_secure_system("iptables -t mangle -F");
   v_secure_system("iptables -t raw -F");

   FIREWALL_DEBUG("iptables-restore starts\n");
#ifdef _HUB4_PRODUCT_REQ_
   v_secure_system("iptables-restore -c  < /tmp/.ipt");
#else
   v_secure_system("iptables-restore -w 10 -c  < /tmp/.ipt");
#endif
   FIREWALL_DEBUG("iptables-restore ends\n");
  
   sysevent_set(sysevent_fd, sysevent_token, "firewall-status", "stopped", 0);
   ulogf(ULOG_FIREWALL, UL_INFO, "stopped %s service", service_name);
   	FIREWALL_DEBUG("stopped %s service\n" COMMA service_name);
 //pthread_mutex_unlock(&firewall_check);
 	FIREWALL_DEBUG("Exiting firewall service_stop()\n");
    return 0;
}

/*
 * Name           :  service_restart
 * Purpose        :  Restart the firewall service
 * Parameters     :  None
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
static int service_restart ()
{
// dont tear down firewall and put it into completly open and unnatted state
// just recalculate the rules - service start does that
//    (void) service_stop();
	FIREWALL_DEBUG("Inside Firewall service_restart () \n");
      #ifdef RDKB_EXTENDER_ENABLED  

   if (isExtProfile() == 0 )
      return service_start_ext_mode();
   else
   #endif
	return service_start();
}

fw_shm_mutex fw_shm_mutex_init(char *mutexName) {

	errno = 0;
	fw_shm_mutex firewallMutex;
	memset(&firewallMutex,0,sizeof firewallMutex);
	/* CID 135273 : BUFFER_SIZE_WARNING */
	strncpy(firewallMutex.fw_mutex, mutexName,sizeof(firewallMutex.fw_mutex)-1);
        firewallMutex.fw_mutex[sizeof(firewallMutex.fw_mutex)-1] = '\0';

	firewallMutex.fw_shm_fd= shm_open(mutexName, O_RDWR, 0660);

	 if (errno == ENOENT) 
	 {
     	    FIREWALL_DEBUG("shm open in create mode\n");
	    firewallMutex.fw_shm_fd = shm_open(mutexName, O_RDWR|O_CREAT, 0660);
	    firewallMutex.fw_shm_create = 1;
	 }


	 if (firewallMutex.fw_shm_fd == -1) 
	 {
	    FIREWALL_DEBUG("shm_open call failed\n");
	    return firewallMutex;
	  }

	  if (ftruncate(firewallMutex.fw_shm_fd, sizeof(pthread_mutex_t)) != 0) {
	    FIREWALL_DEBUG("ftruncate call failed\n");
	    return firewallMutex;
	  }

	  // Using mmap to map the pthread mutex into the shared memory.
	  void *address = mmap(
	    NULL,
	    sizeof(pthread_mutex_t),
	    PROT_READ|PROT_WRITE,
	    MAP_SHARED,
	    firewallMutex.fw_shm_fd,
	    0
	  );

	  if (address == MAP_FAILED) {
	    FIREWALL_DEBUG("mmap failed\n");
	    return firewallMutex;
	  }

	  firewallMutex.ptr  = (pthread_mutex_t *)address;

	  if (firewallMutex.fw_shm_create) 
	  {

		pthread_mutexattr_t attr;
     	        if (pthread_mutexattr_init(&attr)) 
		{
			FIREWALL_DEBUG("pthread_mutexattr_init failed\n");
		    	return firewallMutex;
		}
		int error = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		if (error) 
		{
			FIREWALL_DEBUG("pthread_mutexattr_setpshared error %d: %s\n" COMMA error COMMA strerror(error));
		      	return firewallMutex;
		}

		error = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
		if (error) 
		{
			 FIREWALL_DEBUG("pthread_mutexattr_setprotocol error %d: %s\n" COMMA error COMMA strerror(error));
		}

     	   	error = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
	    	if (error) 
		{
			FIREWALL_DEBUG("pthread_mutexattr_setrobust error %d: %s\n" COMMA error COMMA strerror(error));
	    	}


		if (pthread_mutex_init(firewallMutex.ptr, &attr)) 
		{
			FIREWALL_DEBUG("pthread_mutex_init failed\n");
			return firewallMutex;
		}
	  }
		  return firewallMutex;
}


int fw_shm_mutex_close(fw_shm_mutex fwMutex) 
{

	  if (munmap((void *)fwMutex.ptr, sizeof(pthread_mutex_t))) 
	  {
		FIREWALL_DEBUG("munmap failed\n");
	 	return -1;
	  }

	  fwMutex.ptr = NULL;

	  if (close(fwMutex.fw_shm_fd)) 
	  {
     		FIREWALL_DEBUG("closing file handler");
	    	return -1;
	  }

	  fwMutex.fw_shm_fd = 0;
  return 0;
}



/*
 * Purpose        : Instantiate ipv4 and ipv6 firewall 
 * Parameters     :
 *    argc          :
 *    argv          :
 * Return Values  :
 *    0              : Success
 *   -1              : Problem with syscfg
 *   -2              : Problem with sysevent
 *   -3              : Couldn't get local time. System error
 *   -4              : Could not open mutex file
 */
int main(int argc, char **argv)
{
   int rc = 0;
   char syslog_status[32];
   pid_t process_id;
   
   process_id = getpid();

   ulogf(ULOG_FIREWALL, UL_INFO, "%s called with %s", service_name, (argc > 1) ? argv[1] : "no arg");

   // defualt command if first argument is missing
   service_ev_t event = SERVICE_EV_RESTART;
	   if(firewallfp == NULL) {
		firewallfp = fopen ("/rdklogs/logs/FirewallDebug.txt", "a+");
	} 

   FIREWALL_DEBUG("ENTERED FIREWALL, argc = %d \n" COMMA argc);

   if (argc > 1) {
       if (SERVICE_EV_UNKNOWN == (event = get_service_event(argv[1]))) {
           event = SERVICE_EV_RESTART;
       }
       argc--;
       argv++;
   }

   if (argc > 1) {
      if (!strncmp("flush", argv[1], strlen("flush"))) {
         flush = 1;
         argc--;
         argv++;
      }
   }
//	pthread_mutex_init(&firewall_check, NULL);


  fw_shm_mutex fwmutex = fw_shm_mutex_init(SHM_MUTEX);
  if (fwmutex.ptr == NULL) {
    rc = -1;
    return rc;
  }

  if (fwmutex.fw_shm_create) {
    FIREWALL_DEBUG("Created shm mutex\n");
  }

int error;
  // Use pthread calls for locking and unlocking.
  FIREWALL_DEBUG(" Process %d is waiting for lock\n" COMMA process_id);
  error = pthread_mutex_lock(fwmutex.ptr);

  FIREWALL_DEBUG(" Process %d acquired the lock\n" COMMA process_id);
  if (error == EOWNERDEAD) 
  {
	FIREWALL_DEBUG("Owner dead, acquring the lock\n");
	error = pthread_mutex_consistent(fwmutex.ptr);
  }


   rc = service_init(argc, argv);
   if (rc < 0) {
       service_close();
       if(firewallfp)
       fclose(firewallfp);
	 pthread_mutex_unlock(fwmutex.ptr);
	  if (fw_shm_mutex_close(fwmutex)) {
	    return -1;
	  }
       return rc;
   }

   update_rabid_features_status();

   switch (event) {
   case SERVICE_EV_START:
      #ifdef RDKB_EXTENDER_ENABLED  

       if (isExtProfile() == 0 )
            service_start_ext_mode();
       else
       #endif
            service_start();
       break;
   case SERVICE_EV_STOP:
       service_stop();
       break;
   case SERVICE_EV_RESTART:
       service_restart();
       break;
   /*
    * Handle custom events below here
    */
   case SERVICE_EV_SYSLOG_STATUS:
       sysevent_get(sysevent_fd, sysevent_token, "syslog-status", syslog_status, sizeof(syslog_status));
       ulogf(ULOG_FIREWALL, UL_INFO, "%s handling syslog-status=%s", service_name, syslog_status);
       FIREWALL_DEBUG("%s handling syslog-status=%s\n" COMMA service_name COMMA syslog_status);
       if (0 == strcmp(syslog_status, "started")) {
           service_restart();
       }
       break;
   default:
       ulogf(ULOG_FIREWALL, UL_INFO, "%s received unhandled event", service_name);
        FIREWALL_DEBUG("%s received unhandled event \n" COMMA service_name);
       break;
   }

   service_close();

   if (flush)

       //ARRISXB3-1949
        v_secure_system( "conntrack_flush; expect_flush;" );

        if(firewallfp)
       fclose(firewallfp);

	 pthread_mutex_unlock(fwmutex.ptr);
	 if (fw_shm_mutex_close(fwmutex)) {
	    return -1;
	 }

   return(rc);
}
#ifdef DSLITE_FEATURE_SUPPORT
static void add_dslite_mss_clamping(FILE *fp)
{
    char val[64] = {0};
    sysevent_get(sysevent_fd, sysevent_token, "dslite_service-status", val, sizeof(val));
    if(strncmp(val, "started", strlen("started")) == 0)
    {
        syscfg_get(NULL, "dslite_mss_clamping_enable_1", val, sizeof(val));
        if(strncmp(val, "1", 1) == 0)
        {
            syscfg_get(NULL, "dslite_tcpmss_1", val, sizeof(val));
            if(atoi(val) <= 1460)
            {
                fprintf(fp, "-I FORWARD -o ipip6tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %s\n", val);
                fprintf(fp, "-I FORWARD -i ipip6tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %s\n", val);
            }
            else
            {
                fprintf(fp, "-I FORWARD -o ipip6tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n");
                fprintf(fp, "-I FORWARD -i ipip6tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n");
            }
        }
    }
    FIREWALL_DEBUG("Exiting add_dslite_mss_clamping\n");
}
#endif
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
static void wanmgr_get_wan_interface(char *wanInterface)
{
    sysevent_get(sysevent_fd, sysevent_token, "current_wan_ifname", wanInterface, BUFLEN_64);
    if(wanInterface[0] == '\0' ||  strlen(wanInterface) == 0)
    {
        strcpy(wanInterface,"erouter0"); // default wan interface
    }
}
#endif

#if defined (WIFI_MANAGE_SUPPORTED)
#define BUFF_LEN_64 64
#define BUFF_LEN_8 8
void updateManageWiFiRules(void * busHandle, char * pCurWanInterface, FILE * filterFp)
{
    if ((NULL == busHandle) || (NULL == filterFp))
    {
        FIREWALL_DEBUG("busHandle or filterFp is NULL \n");
        return;
    }

    if (true == isManageWiFiEnabled())
    {
        char aParamName[BUFF_LEN_64];
        char aParamVal[BUFF_LEN_8];
        char aV4Addr[BUFF_LEN_64];

        psmGet(bus_handle, MANAGE_WIFI_PSM_STR, aParamVal, sizeof(aParamVal));
        if ('\0' != aParamVal[0])
        {
            snprintf(aParamName, sizeof(aParamName), MANAGE_WIFI_V4_ADDR, aParamVal);
            psmGet(bus_handle, aParamName, aV4Addr, sizeof(aV4Addr));
            snprintf(aParamName, sizeof(aParamName), MANAGE_WIFI_BRIDGE_NAME, aParamVal);
            psmGet(bus_handle,aParamName, aParamVal, sizeof(aParamVal));
            if ('\0' != aParamVal[0])
            {
                fprintf(filterFp, "-A INPUT -p tcp -i %s --dport 22 -j DROP\n", aParamVal);
                fprintf(filterFp, "-A INPUT -d %s/32 -i %s -j ACCEPT\n", aV4Addr,aParamVal);
                fprintf(filterFp, "-A INPUT -i %s -j lan2self\n", aParamVal);
                fprintf(filterFp, "-A FORWARD -i %s -o %s -j ACCEPT\n", aParamVal,aParamVal);
                if (NULL != pCurWanInterface)
                {
                    fprintf(filterFp, "-A FORWARD -i %s ! -o %s -j DROP\n", aParamVal,pCurWanInterface);
                    fprintf(filterFp, "-A FORWARD ! -i %s -o %s -j DROP\n",pCurWanInterface,aParamVal);
                }
            }
        }
    }
}

bool isManageWiFiEnabled(void)
{
    char aManageWiFiEnabled[BUFF_LEN_8];

    memset(aManageWiFiEnabled, 0, sizeof(aManageWiFiEnabled));
    syscfg_get(NULL, "Manage_WiFi_Enabled", aManageWiFiEnabled, sizeof(aManageWiFiEnabled));

    if (!strncmp(aManageWiFiEnabled, "true", 4))
        return true;
    else
        return false;
}
#endif /*WIFI_MANAGE_SUPPORTED*/

int do_wpad_isatap_blockv4 (FILE *filter_fp)
{
#if defined (BLOCK_WPAD_ISATAP)

    char *tok;
    char net_query[MAX_QUERY];
    char net_resp[MAX_QUERY];
    char inst_resp[MAX_QUERY];

    fprintf(filter_fp, "-N block_wpad\n");

    sysevent_get(sysevent_fd, sysevent_token, "ipv4-instances", inst_resp, sizeof(inst_resp));

    tok = strtok(inst_resp, " ");

    if (tok)
    {
        do
        {
            snprintf(net_query, sizeof(net_query), "ipv4_%s-status", tok);
            sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

            if (strcmp(net_resp, "up") != 0)
                continue;

            snprintf(net_query, sizeof(net_query), "ipv4_%s-ifname", tok);
            sysevent_get(sysevent_fd, sysevent_token, net_query, net_resp, sizeof(net_resp));

            //Representation of hostname in NetBIOS protocol uses encoding mechanism as specified in RFC-1001, hence hostname "ISATAP", "WSPAD" and "WPAD" will get encoded as string EJFDEBFEEBFA, FHFDFAEBEE, and FHFAEBEE
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"EJFDEBFEEBFA\" --algo bm -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|06|isatap|\" --algo bm --icase -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/isatap\" --algo bm --icase -j DROP\n", net_resp);

            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"FHFDFAEBEE\" --algo bm -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|05|wspad|\" --algo bm --icase -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/wspad\" --algo bm --icase -j DROP\n", net_resp);

            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"FHFAEBEE\" --algo bm -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|04|wpad|\" --algo bm --icase -j DROP\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/wpad\" --algo bm --icase -j DROP\n", net_resp);

            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --dport 80 -m string --algo bm --string \"GET /wpad.dat\" -j REJECT --reject-with tcp-reset\n", net_resp);
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --sport 80 -m string --algo bm --string \"application/x-ns-proxy-autoconfig\" -j block_wpad\n", net_resp);
        }
        while ((tok = strtok(NULL, " ")) != NULL);
    }

    fprintf(filter_fp, "-A block_wpad -m string --algo bm --string \"FindProxyForURL\" -j DROP\n");

#endif

    return 0;
}

int do_wpad_isatap_blockv6 (FILE *filter_fp)
{
#if defined (BLOCK_WPAD_ISATAP)

    unsigned char *tok;
    unsigned char sysevent_query[MAX_QUERY];
    unsigned char inst_resp[MAX_QUERY];
    unsigned char multinet_ifname[MAX_QUERY];

    fprintf(filter_fp, "-N block_wpad\n");

    sysevent_get(sysevent_fd, sysevent_token, "ipv6_active_inst", inst_resp, sizeof(inst_resp));

    tok = strtok(inst_resp, " ");

    if (tok)
    {
        do
        {
            snprintf(sysevent_query, sizeof(sysevent_query), "multinet_%s-name", tok);
            sysevent_get(sysevent_fd, sysevent_token, sysevent_query, multinet_ifname, sizeof(multinet_ifname));

            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"EJFDEBFEEBFA\" --algo bm -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|06|isatap|\" --algo bm --icase -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/isatap\" --algo bm --icase -j DROP\n", multinet_ifname);

            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"FHFDFAEBEE\" --algo bm -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|05|wspad|\" --algo bm --icase -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/wspad\" --algo bm --icase -j DROP\n", multinet_ifname);

            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"FHFAEBEE\" --algo bm -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --hex-string \"|04|wpad|\" --algo bm --icase -j DROP\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p udp --dport 53 -m string --string \"/wpad\" --algo bm --icase -j DROP\n", multinet_ifname);

            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --dport 80 -m string --algo bm --string \"GET /wpad.dat\" -j REJECT --reject-with tcp-reset\n", multinet_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --sport 80 -m string --algo bm --string \"application/x-ns-proxy-autoconfig\" -j block_wpad\n", multinet_ifname);
        }
        while ((tok = strtok(NULL, " ")) != NULL);
    }

    fprintf(filter_fp, "-A block_wpad -m string --algo bm --string \"FindProxyForURL\" -j DROP\n");

#endif

    return 0;
}
