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

#ifndef _UTAPI_H_
#define _UTAPI_H_

#include <utctx/utctx_api.h>

#ifndef UTAPI_UNITTEST
#include <ulog/ulog.h>
#include <sysevent/sysevent.h>
#else

#define ULOG_CONFIG "config"
#define UL_UTAPI    "utapi"
#define UL_WLANCFG "wlan"
#define ulog(x,y,msg)       printf("%s.%s %s", ULOG_CONFIG, UL_UTAPI, msg);
#define ulog_debug(x,y,msg) printf("%s.%s %s", ULOG_CONFIG, UL_UTAPI, msg);
#define ulog_error(x,y,msg) printf("%s.%s ERROR:%s", ULOG_CONFIG, UL_UTAPI, msg);
#define ulogf(x,y,format,...) printf(format, __VA_ARGS__)
#define ulog_debugf(x,y,format,...) printf(format, __VA_ARGS__)
#define syscfg_getall(x,y,z) printf("Calling syscfg_getall()...\n")

typedef int token_t;
#define SE_SERVER_WELL_KNOWN_PORT 5000
#define sysevent_close(y,z)       printf("Closing sysevent...\n")
#define sysevent_open(v,w,x,y,z)  printf("Initializing sysevent...\n")
#define sysevent_get(v,w,x,y,z)   printf("Sysevent get...\n");
#define sysevent_set(w,x,y,z,c)     printf("Sysevent set...\n");
#define sysevent_set_unique(u,v,w,x,y,z)     printf("Sysevent set unique...\n");
#endif

/*
 * General
 */

typedef char* String;
typedef int boolean_t;

#define FALSE 0
#define TRUE  1

/*
 * Administration Settings
 */
#define LANG_SZ 8
#define IPADDR_SZ 40       // IPv4 or IPv6 address
#define MACADDR_SZ 18      // MAC address aa:bb:cc:dd:ee:ff
#define IPHOSTNAME_SZ 128  // hostname foo.domain.com or IP address
#define PORT_SZ    6       // port number 0 - 65535
#define URL_SZ   512       // http://foo.domain.com/blahblah
#define IFNAME_SZ 16       // size of interface names like br0, vlan2, eth3
#define TOKEN_SZ 128       // generic token
#define USERNAME_SZ 64
#define PASSWORD_SZ 64
#define WAN_SERVICE_NAME_SZ 64
#define NAME_SZ 64      // generic friendly name size
#define IAP_KEYWORD_SZ    64
#define TR_ALIAS_SZ 65


/*
 * Platform specific settings
 */
#define CONFIG_MTD_DEVICE   "/dev/mtd3"
#define IMAGE_WRITER        "/usr/sbin/image_writer"
#define IMAGE_WRITER_OUTPUT "/tmp/image_writer.out"

#define CFG_MAGIC            0xFEEDDADE
#define CFG_VERSION          0x00000001
#define CFG_RESTORE_TMP_FILE "/tmp/.cfg_restore_tmp"

#define DEFAULT_HTTP_ADMIN_PASSWORD "admin"

#define INCOMING_LOG_TMP_FILE      "/tmp/.incoming_log_tmp"
#define OUTGOING_LOG_TMP_FILE      "/tmp/.outgoing_log_tmp"
#define SECURITY_LOG_TMP_FILE      "/tmp/.security_log_tmp"
#define DHCP_LOG_TMP_FILE          "/tmp/.dhcp_log_tmp"

// Log dumps that can be accessed through the web interface
// If any of these values change, then Makefile.nfsroot needs
// to be updated to reflect the changes
#define INCOMING_LOG_SAVE_FILE     "/tmp/incoming_log.txt"
#define OUTGOING_LOG_SAVE_FILE     "/tmp/outgoing_log.txt"
#define SECURITY_LOG_SAVE_FILE     "/tmp/security_log.txt"
#define DHCP_LOG_SAVE_FILE         "/tmp/dhcp_log.txt"
#define INCOMING_LOG_SAVE_FILE_URL "incoming_log.txt"
#define OUTGOING_LOG_SAVE_FILE_URL "outgoing_log.txt"
#define SECURITY_LOG_SAVE_FILE_URL "security_log.txt"
#define DHCP_LOG_SAVE_FILE_URL     "dhcp_log.txt"

#define PING_LOG_TMP_FILE          "/tmp/.ping_log_tmp"
#define TRACEROUTE_LOG_TMP_FILE    "/tmp/.traceroute_log_tmp"

#define ROUTE_TABLE_TMP_FILE       "/tmp/.route_table_tmp"

typedef struct {
    unsigned int magic;
    unsigned int len;
    unsigned int version;
    unsigned int crc32;
} config_hdr_t;


/*
 * Error code
 */
typedef enum {
    SUCCESS                       =  0,
    UT_SUCCESS                    =  0,
    ERR_UTCTX_OP                  = -1,
    ERR_INSUFFICIENT_MEM          = -2,
    ERR_ITEM_NOT_FOUND            = -3,
    ERR_INVALID_VALUE             = -4,
    ERR_INVALID_INT_VALUE         = -5,
    ERR_INVALID_BOOL_VALUE        = -6,
    ERR_INVALID_IP                = -7,
    ERR_INVALID_NETMASK           = -8,
    ERR_INVALID_MAC               = -9,
    ERR_INVALID_WAN_TYPE          = -10,
    ERR_INVALID_DDNS_TYPE         = -11,
    ERR_SYSEVENT_CONN             = -12,
    ERR_INVALID_ARGS              = -13,
    ERR_INVALID_PORT_RANGE        = -14,
    ERR_WIFI_INVALID_MODE         = -15,
    ERR_REBOOT_FAILED             = -16,
    ERR_NOT_YET_IMPLEMENTED       = -17,
    ERR_FILE_NOT_FOUND            = -18,
    ERR_UTCTX_INIT                = -19,
    ERR_SYSCFG_FAILED             = -20,
    ERR_INVALID_SYSCFG_FILE       = -21,
    ERR_CFGRESTORE_BAD_MAGIC      = -22,
    ERR_CFGRESTORE_BAD_SIZE       = -23,
    ERR_CFGRESTORE_BAD_VERSION    = -24,
    ERR_CFGRESTORE_BAD_CRC32      = -25,
    ERR_FILE_READ_FAILED          = -26,
    ERR_FILE_WRITE_FAILED         = -27,
    ERR_FW_UPGRADE_LOCK_CONFLICT  = -28,
    ERR_INVALID_BRIDGE_MODE       = -29,
    ERR_WIFI_INVALID_CONFIG_MODE  = -30,
    ERR_WIFI_NO_FREE_SSID         = -31,
    ERR_WIFI_CAN_NOT_DELETE       = -32
} utret_t;

typedef enum {
    INTERFACE_LAN,
    INTERFACE_WAN,
} interface_t;


/*
 * WAN settings
 */
typedef enum {
    DHCP,
    STATIC,
    PPPOE,
    PPTP,
    L2TP,
    TELSTRA
} wanProto_t;

typedef enum {
    WAN_UNKNOWN,
    WAN_DISCONNECTED,
    WAN_CONNECTING,
    WAN_CONNECTED,
    WAN_DISCONNECTING,
} wanConnStatus_t;

typedef enum {
    WAN_PHY_STATUS_UNKNOWN,
    WAN_PHY_STATUS_DISCONNECTED,
    WAN_PHY_STATUS_CONNECTED,
} wanPhyConnStatus_t;


typedef enum {
    KEEP_ALIVE,
    CONNECT_ON_DEMAND,
} wanConnectMethod_t;


typedef struct wan_static {
    char ip_addr[IPADDR_SZ];
    char subnet_mask[IPADDR_SZ];
    char default_gw[IPADDR_SZ];
    char dns_ipaddr1[IPADDR_SZ];
    char dns_ipaddr2[IPADDR_SZ];
    char dns_ipaddr3[IPADDR_SZ];
}__attribute__ ((__packed__)) wan_static_t;


typedef struct wan_ppp {
    char username[USERNAME_SZ];
    char password[PASSWORD_SZ];
    char service_name[WAN_SERVICE_NAME_SZ];   // for pppoe
    char server_ipaddr[IPADDR_SZ];            // for pptp, l2tp
    wanConnectMethod_t conn_method;
    int max_idle_time;
    int redial_period;
    boolean_t ipAddrStatic;   // for pptp/l2tp: true - use wan_static, false - use dhcp
}__attribute__ ((__packed__)) wan_ppp_t;


typedef struct wanInfo {
    wanProto_t    wan_proto;
    wan_static_t  wstatic;
    wan_ppp_t     ppp;
    char          domainname[IPHOSTNAME_SZ];
    boolean_t     auto_mtu;    // true - automatically picked, false - set it to size specified
    int           mtu_size;
}__attribute__ ((__packed__)) wanInfo_t;

/*
 * Router/Bridge settings
 */
typedef enum {
    BRIDGE_MODE_OFF    = 0,
    BRIDGE_MODE_DHCP   = 1,
    BRIDGE_MODE_STATIC = 2,
    BRIDGE_MODE_FULL_STATIC = 3,
} bridgeMode_t;

typedef struct bridge_static {
    char ip_addr[IPADDR_SZ];
    char subnet_mask[IPADDR_SZ];
    char default_gw[IPADDR_SZ];
    char domainname[IPHOSTNAME_SZ];
    char dns_ipaddr1[IPADDR_SZ];
    char dns_ipaddr2[IPADDR_SZ];
    char dns_ipaddr3[IPADDR_SZ];
} bridge_static_t;

typedef struct bridgeInfo {
    bridgeMode_t  mode;
    bridge_static_t  bstatic;
} bridgeInfo_t;

typedef enum{
    NAPT_MODE_DISABLE_DHCP = 0,
    NAPT_MODE_DHCP,
    NAPT_MODE_STATICIP,
    NAPT_MODE_DISABLE_STATIC
}napt_mode_t;

/*
 * DDNS Settings
 */
#if !defined(DDNS_BROADBANDFORUM)
typedef enum ddnsProvider {
    DDNS_EZIP,
    DDNS_PGPOW,
    DDNS_DHS,
    DDNS_DYNDNS,
    DDNS_DYNDNS_STATIC,
    DDNS_DYNDNS_CUSTOM,
    DDNS_ODS,
    DDNS_TZO,
    DDNS_EASYDNS,
    DDNS_EASYDNS_PARTNER,
    DDNS_GNUDIP,
    DDNS_JUSTLINUX,
    DDNS_DYNS,
    DDNS_HN,
    DDNS_ZONEEDIT,
    DDNS_HEIPV6TB
} ddnsProvider_t;

typedef struct ddnsService {
    boolean_t      enabled;
    ddnsProvider_t provider;
    char           username[USERNAME_SZ];
    char           password[PASSWORD_SZ];
    char           hostname[IPHOSTNAME_SZ];
    char           mail_exch[IPHOSTNAME_SZ];
    boolean_t      backup_mx;
    boolean_t      wildcard;
} ddnsService_t;

typedef enum {
    DDNS_STATUS_UNKNOWN,
    DDNS_STATUS_FAILED,
    DDNS_STATUS_FAILED_CONNECT,
    DDNS_STATUS_FAILED_AUTH,
    DDNS_STATUS_SUCCESS,
} ddnsStatus_t;
#endif
/*
 * Route Settings
 */

typedef struct routeRIP {
    boolean_t enabled;
    boolean_t no_split_horizon;
    boolean_t lan_interface;
    boolean_t wan_interface;
    char      wan_md5_password[PASSWORD_SZ];
    char      wan_text_password[PASSWORD_SZ];
} routeRIP_t;

typedef struct routeStatic {
    char         name[NAME_SZ];
    char         dest_lan_ip[IPADDR_SZ];
    char         netmask[IPADDR_SZ];
    char         gateway[IPADDR_SZ];
    interface_t  dest_intf;
} routeStatic_t;

typedef struct routeEntry {
    char destlanip[IPADDR_SZ];
    char netmask[IPADDR_SZ];
    char gateway[IPADDR_SZ];
    int  hopcount;
    char interface[TOKEN_SZ];
} routeEntry_t;

/*
 * Port Forwarding
 */

typedef enum protocol {
    TCP,
    UDP,
    BOTH_TCP_UDP,
} protocol_t;

typedef struct portFwdSingle {
    char       name[NAME_SZ];
    boolean_t  enabled;
    boolean_t  prevRuleEnabledState;
    int        rule_id;
    protocol_t protocol;
    int        external_port;
    int        internal_port;
    char       dest_ip[IPADDR_SZ];
    char       dest_ipv6[64];
} portFwdSingle_t;

typedef struct portMapDyn {
    char       name[NAME_SZ];
    boolean_t  enabled;
    protocol_t protocol;
    char       external_host[IPADDR_SZ];   // empty for all external hosts
    int        external_port;
    char       internal_host[IPADDR_SZ];   // empty for all internal hosts
    int        internal_port;
    int        lease;
    time_t     last_updated;
} portMapDyn_t;

typedef struct portFwdRange {
    char       name[NAME_SZ];
    boolean_t  enabled;
    boolean_t  prevRuleEnabledState;
    int        rule_id;
    protocol_t protocol;
    int        start_port;
    int        end_port;
    int        internal_port;
    int        internal_port_range_size;
    char       dest_ip[IPADDR_SZ];
    char       dest_ipv6[64];
	char       public_ip[IPADDR_SZ];
} portFwdRange_t;

typedef struct portRangeTrig {
    char       name[TOKEN_SZ];
    boolean_t  enabled;
    boolean_t  prevRuleEnabledState;
    int        rule_id;
    protocol_t trigger_proto;
    protocol_t forward_proto;
    int        trigger_start;
    int        trigger_end;
    int        fwd_range_start;
    int        fwd_range_end;
} portRangeTrig_t;

/*
 * Internet Access Policy Settings
 */

#define NUM_IAP_POLICY            5
#define NUM_IAP_BLOCKED_URL       4
#define NUM_IAP_BLOCKED_KEYWORD   4
#define NUM_IAP_BLOCKED_APPS     32
#define NUM_IAP_MACHOSTS         10
#define NUM_IAP_IPHOSTS           6
#define NUM_IAP_IPRANGEHOSTS      4

#define DAY_SUN 0x01
#define DAY_MON 0x02
#define DAY_TUE 0x04
#define DAY_WED 0x08
#define DAY_THU 0x10
#define DAY_FRI 0x20
#define DAY_SAT 0x40
#define DAY_ALL (DAY_SUN | DAY_MON | DAY_TUE | DAY_WED | DAY_THU | DAY_FRI | DAY_SAT)

#define HH_MM_SZ 6

typedef struct iprange {
    int start_ip;   // last octet
    int end_ip;     // last octet
}__attribute__ ((__packed__)) iprange_t;

typedef struct portrange {
    int start;
    int end;
}__attribute__ ((__packed__)) portrange_t;

typedef struct lanHosts {
    int        mac_count;
    char      *maclist;          //  MACADDR_SZ * mac_count buffer
    int        ip_count;
    char      *iplist;           //  IPADDR_SZ * ip_count buffer
    int        iprange_count;
    iprange_t *iprangelist;      //  sizeof(iprange_t) * _count buffer
}__attribute__ ((__packed__)) lanHosts_t;

typedef struct {
    unsigned char day;                     // bitmask of DAY_xyz
    boolean_t     all_day;                 // true if the policy is active
                                           // for the full 24 hours
    char          start_time[HH_MM_SZ];    // 24hr format
    char          stop_time[HH_MM_SZ];
}__attribute__ ((__packed__)) timeofday_t;


typedef struct appentry {
    char        name[NAME_SZ];
    boolean_t   wellknown;
    portrange_t port;
    protocol_t  proto;
}__attribute__ ((__packed__)) appentry_t;

typedef struct {
    int              url_count;
    char            *url_list;          // each of URL_SZ
    unsigned int    *url_tr_inst_num;   // size of url_count
    char            *url_tr_alias;      // each of TR_ALIAS_SZ
    int              keyword_count;
    char            *keyword_list;       // each of IAP_KEYWORD_SZ
    unsigned int    *keyword_tr_inst_num;// size of keyword_count
    char            *keyword_tr_alias;   // each of TR_ALIAS_SZ
    int              app_count;
    appentry_t      *app_list;
    unsigned int    *app_tr_inst_num;   // size of app_count
    char            *app_tr_alias;      // each of TR_ALIAS_SZ
}__attribute__ ((__packed__)) blockentry_t;

typedef struct iap_entry {
    char             policyname[NAME_SZ];
    boolean_t        enabled;
    boolean_t        allow_access;      // allow/deny access during TOD
    timeofday_t      tod;
    boolean_t        lanhosts_set;      // indicates if lanhosts is set
    lanHosts_t       lanhosts;
    blockentry_t     block;
    unsigned int     tr_inst_num;
}__attribute__ ((__packed__)) iap_entry_t;


/*
 * QoS Settings
 */
typedef enum {
    QOS_PRIORITY_DEFAULT,
    QOS_PRIORITY_MEDIUM = QOS_PRIORITY_DEFAULT,
    QOS_PRIORITY_NORMAL,
    QOS_PRIORITY_HIGH,
    QOS_PRIORITY_LOW
} priority_t;

typedef enum {
    QOS_APPLICATION,
    QOS_GAME,
    QOS_MACADDR,
    QOS_VOICE_DEVICE,
    QOS_ETHERNET_PORT,
    QOS_CUSTOM
} qostype_t;

typedef enum {
    QOS_CUSTOM_APP,
    QOS_CUSTOM_GAME
} qoscustomtype_t;

#define MAX_CUSTOM_PORT_ENTRIES 3

typedef struct qosPolicy {
    char            name[NAME_SZ];
    qostype_t       type;
    char            mac[MACADDR_SZ];
    int             hwport;         // 1 to max lan ports (eg 4)
    protocol_t      custom_proto[MAX_CUSTOM_PORT_ENTRIES];
    portrange_t     custom_port[MAX_CUSTOM_PORT_ENTRIES];
    qoscustomtype_t custom_type;
    priority_t      priority;
} qosPolicy_t;

typedef struct qosDefinedPolicy {
    char        name[TOKEN_SZ];
    char        friendly_name[TOKEN_SZ];
    qostype_t   type;
    priority_t  default_priority;
} qosDefinedPolicy_t;

typedef struct qosInfo {
    boolean_t   enable;
    int         policy_count;
    qosPolicy_t *policy_list;
    int         download_speed;
    int         upload_speed;
} qosInfo_t;


/*
typedef struct qosPolicy {
    int  app_count;
    qosAppEntry_t *app;
    int  onlinegame_count;
    qosGameEntry_t *game;
    int  macaddr_count;
    qosMacEntry_t *mac;
    int  etherport_count;
    qosEthPortEntry_t *ethport;
} qosPolicy_t;
*/

/**
* @brief Get QoS defined policy list.
*
* Returns a list of predefined QoS policies with their default priorities.
*
* @param[out] out_count - Pointer to store count of policies.
* @param[out] out_qoslist - Pointer to receive const array of predefined policies.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_FILE_NOT_FOUND error on file not found
* @retval Error code on failure.
*/
int Utopia_GetQoSDefinedPolicyList (int *out_count, qosDefinedPolicy_t const **out_qoslist);

/**
* @brief Set QoS settings.
*
* Configures Quality of Service settings including enable status, policy list, and bandwidth speeds.
*
* @param[in] ctx - Utopia context.
* @param[in] qos - Pointer to qosInfo_t structure containing QoS settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetQoSSettings (UtopiaContext *ctx, qosInfo_t *qos);

/**
* @brief Get QoS settings.
*
* @param[in] ctx - Utopia context.
* @param[out] qos - Pointer to qosInfo_t structure to store QoS settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetQoSSettings (UtopiaContext *ctx, qosInfo_t *qos);

/**
* @brief Get LAN host comments by MAC address.
*
* Retrieves the comments/description associated with a LAN host identified by MAC address.
*
* @param[in] ctx - Utopia context.
* @param[in] pMac - MAC address of the LAN host.
* @param[out] pComments - Buffer to store comments.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_get_lan_host_comments(UtopiaContext *ctx, unsigned char *pMac, unsigned char *pComments);

/**
* @brief Set LAN host comments by MAC address.
*
* Associates comments/description with a LAN host identified by MAC address.
*
* @param[in] ctx - Utopia context.
* @param[in] pMac - MAC address of the LAN host.
* @param[in] pComments - Comments to associate with the host.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_set_lan_host_comments(UtopiaContext *ctx, unsigned char *pMac, unsigned char *pComments);

/*
 * Log Settings
 */
typedef enum logType {
    INCOMING_LOG,
    OUTGOING_LOG,
    SECURITY_LOG,
    DHCP_CLIENT_LOG
} logtype_t;

typedef enum dhcp_msg_type {
    DHCPDISCOVER,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPACK,
    DHCPNAK,
    DHCPDECLINE,
    DHCPRELEASE,
    DHCPINFORM
} dhcp_msg_type_t;

typedef struct logentry {
    char src[URL_SZ];   // ip address or URL
    char dst[URL_SZ];   // ip address or URL
    char service_port[TOKEN_SZ];  // port or service name
} logentry_t;

typedef struct dhcpclientlog {
    char timestamp[TOKEN_SZ];
    dhcp_msg_type_t msg_type;
    char ipaddr[IPADDR_SZ];
    char macaddr[MACADDR_SZ];
} dhcpclientlog_t;


/*
 * Status Settings
 */

#define NUM_DNS_ENTRIES 3

typedef struct wanConnectionInfo {
    char ip_address[IPADDR_SZ];
    char subnet_mask[IPADDR_SZ];
    char default_gw[IPADDR_SZ];
    char dns[NUM_DNS_ENTRIES][IPHOSTNAME_SZ];
    int  dhcp_lease_time;      // in seconds
    char ifname[IFNAME_SZ];
} wanConnectionInfo_t;

typedef struct wanConnectionStatus {
    wanConnStatus_t   status;
    unsigned int      phylink_up;
    long int          uptime;               // current connection's uptime in seconds (NOT system uptime)
    char              ip_address[IPADDR_SZ];
} wanConnectionStatus_t;

typedef struct wanTrafficInfo {
    unsigned long int          pkts_sent;
    unsigned long int          pkts_rcvd;
    unsigned long int          bytes_sent;
    unsigned long int          bytes_rcvd;
} wanTrafficInfo_t;

typedef struct {
    char ipaddr[IPADDR_SZ];
    char netmask[IPADDR_SZ];
    char domain[IPHOSTNAME_SZ];
    char macaddr[MACADDR_SZ];    // ONLY get-able, not-applicable in set operation
    char ifname[IFNAME_SZ];  // ONLY get-able, not-applicable in set operation
} lanSetting_t;


typedef struct bridgeConnectionInfo {
    char ip_address[IPADDR_SZ];
    char subnet_mask[IPADDR_SZ];
    char default_gw[IPADDR_SZ];
    char dns[NUM_DNS_ENTRIES][IPHOSTNAME_SZ];
    int  dhcp_lease_time;      // in seconds
} bridgeConnectionInfo_t;

/*
 * Lang -
 *     ISO Language Code (ISO-639) - ISO Country Code (ISO-3166)
 *     eg: en-us
 */

typedef struct {
    float gmt_offset;          // GMT offset in hours
    boolean_t is_dst_observed;
    char *dst_on;              // TZ string when DST is on
    char *dst_off;             // TZ string when DST is off
                               // Note: dst_on and dst_off are the same
                               //       when DST is not observed
} timezone_info_t;

typedef enum {
    AUTO_DST_OFF = 0,
    AUTO_DST_ON,
    AUTO_DST_NA,     // not-applicable, for countries that don't have DST
} auto_dst_t;

typedef struct {
    char       hostname[IPHOSTNAME_SZ];
    char       lang[LANG_SZ];
    float      tz_gmt_offset;
    auto_dst_t auto_dst;
} deviceSetting_t;

typedef enum {
    LAN_INTERFACE_WIRED,
    LAN_INTERFACE_WIFI,
} lan_interface_t;

/*
 * LAN setting
 */
typedef struct DHCPMap {
    char client_name[TOKEN_SZ];
    //int host_ip;                  // just the last octet
    char host_ip[IPADDR_SZ];
    char macaddr[MACADDR_SZ];
} DHCPMap_t;

typedef struct arpHost {
    char ipaddr[IPADDR_SZ];
    char macaddr[MACADDR_SZ];
    char interface[IFNAME_SZ];
    boolean_t is_static;
} arpHost_t;

typedef struct dhcpLANHost {
    char hostname[TOKEN_SZ];
    char ipaddr[IPADDR_SZ];
    char macaddr[MACADDR_SZ];
    char client_id[TOKEN_SZ];
    long leasetime;
    lan_interface_t lan_interface;
} dhcpLANHost_t;

typedef struct dhcpServerInfo {
    boolean_t enabled;
    char DHCPIPAddressStart[IPADDR_SZ];
    char DHCPIPAddressEnd[IPADDR_SZ];
    int  DHCPMaxUsers;
    char DHCPClientLeaseTime[TOKEN_SZ];
    boolean_t StaticNameServerEnabled;
    char StaticNameServer1[IPHOSTNAME_SZ];
    char StaticNameServer2[IPHOSTNAME_SZ];
    char StaticNameServer3[IPHOSTNAME_SZ];
    char WINSServer[IPHOSTNAME_SZ];
} dhcpServerInfo_t;

typedef struct dmz {
    boolean_t enabled;
    char      source_ip_start[IPADDR_SZ]; // empty string means "any ip address"
    char      source_ip_end[IPADDR_SZ];
    //int       dest_ip;                    // last octet
    char      dest_ip[IPADDR_SZ];           // full ip
    char      dest_mac[MACADDR_SZ];
    char      dest_ipv6[64];
} dmz_t;


/*
 * Public APIs
 */

/*
 * Device Settings
 */

/**
* @brief Get device settings.
*
* Retrieves device configuration like hostname, language, timezone, and auto DST settings.
*
* @param[in] ctx - Utopia context.
* @param[out] device - Pointer to deviceSetting_t structure to store device settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetDeviceSettings (UtopiaContext *ctx, deviceSetting_t *device);

/**
* @brief Set device settings.
*
* Configures device settings like hostname, language, timezone, and auto DST settings.
*
* @param[in] ctx - Utopia context.
* @param[in] device - Pointer to deviceSetting_t structure containing device settings to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetDeviceSettings (UtopiaContext *ctx, deviceSetting_t *device);

/*
 * LAN Settings
 */

/**
* @brief Get LAN settings.
*
* Retrieves LAN configuration like IP address, netmask, domain, MAC address, and interface name.
*
* @param[in] ctx - Utopia context.
* @param[out] lan - Pointer to lanSetting_t structure to store LAN settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetLanSettings (UtopiaContext *ctx, lanSetting_t *lan);

/**
* @brief Set LAN settings.
*
* Configures LAN settings like IP address, netmask, domain.
*
* @param[in] ctx - Utopia context.
* @param[in] lan - Pointer to lanSetting_t structure containing LAN settings to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetLanSettings(UtopiaContext *ctx, lanSetting_t *lan);

/**
* @brief Set DHCP server settings.
*
* Configures DHCP server parameters like IP address range, lease time, and DNS servers.
*
* @param[in] ctx - Utopia context.
* @param[in] dhcps - Pointer to dhcpServerInfo_t structure containing DHCP server settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetDHCPServerSettings (UtopiaContext *ctx, dhcpServerInfo_t *dhcps);

/**
* @brief Get DHCP server settings.
*
* Retrieves DHCP server configuration like IP address range, lease time, and DNS servers.
*
* @param[in] ctx - Utopia context.
* @param[out] out_dhcps - Pointer to dhcpServerInfo_t structure to store DHCP server settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetDHCPServerSettings (UtopiaContext *ctx, dhcpServerInfo_t *out_dhcps);

/**
* @brief Set DHCP server static host mappings.
*
* Configures static IP address assignments for specific MAC addresses.
*
* @param[in] ctx - Utopia context.
* @param[in] count - Number of static host entries in the dhcpMap array.
* @param[in] dhcpMap - Array of DHCPMap_t structures containing static host mappings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetDHCPServerStaticHosts (UtopiaContext *ctx, int count, DHCPMap_t *dhcpMap);

/**
* @brief Get DHCP server static host mappings.
*
* Retrieves configured static IP address assignments.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of static host entries retrieved.
* @param[out] dhcpMap - Pointer to store address of allocated DHCPMap_t array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDHCPServerStaticHosts (UtopiaContext *ctx, int *count, DHCPMap_t **dhcpMap);

/**
* @brief Get count of DHCP server static host mappings.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of static host entries.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDHCPServerStaticHostsCount (UtopiaContext *ctx, int *count);

/**
* @brief Unset/clear all DHCP server static host mappings.
*
* @param[in] ctx - Utopia context.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_UnsetDHCPServerStaticHosts (UtopiaContext *ctx);

/**
* @brief Get ARP cache entries.
*
* Retrieves current ARP (Address Resolution Protocol) cache entries.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of ARP entries retrieved.
* @param[out] out_hosts - Pointer to store address of allocated arpHost_t array.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetARPCacheEntries (UtopiaContext *ctx, int *count, arpHost_t **out_hosts);

/**
* @brief Get WLAN client MAC addresses.
*
* Retrieves list of MAC addresses for currently connected WLAN clients.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of WLAN clients.
* @param[out] out_maclist - Pointer to store address of allocated MAC address list.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetWLANClients (UtopiaContext *ctx, int *count, char **out_maclist);

// Used for status and display current DHCP leases
/**
* @brief Get DHCP server LAN host information.
*
* This function used to retrieve DHCP server LAN host information that used for status and displaying current DHCP leases.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of DHCP clients.
* @param[out] client_info - Pointer to store address of allocated dhcpLANHost_t array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetDHCPServerLANHosts (UtopiaContext *ctx, int *count, dhcpLANHost_t **client_info);

/**
* @brief Delete a DHCP server LAN host entry by IP address.
*
* @param[in] ipaddr - IP address of the host to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval Error code on failure.
*/
int Utopia_DeleteDHCPServerLANHost (char *ipaddr);


/*
 * WAN Settings
 */

/**
* @brief Set WAN settings.
*
* This function configures WAN connection.
*
* @param[in] ctx - Utopia context.
* @param[in] wan_info - Pointer to wanInfo_t structure containing WAN settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INVALID_WAN_TYPE if wan_proto is invalid.
* @retval Error code on failure.
*/
int Utopia_SetWANSettings (UtopiaContext *ctx, wanInfo_t *wan_info);

/**
* @brief Get WAN settings.
*
* Retrieves WAN connection configuration.
*
* @param[in] ctx - Utopia context.
* @param[out] wan_info - Pointer to wanInfo_t structure to store WAN settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INVALID_WAN_TYPE if wan_proto is invalid.
* @retval Error code on failure.
*/
int Utopia_GetWANSettings (UtopiaContext *ctx, wanInfo_t *wan_info);
#if !defined(DDNS_BROADBANDFORUM)

/**
* @brief Set Dynamic DNS service configuration.
*
* This function configures DDNS provider, credentials, and hostname settings.
*
* @param[in] ctx - Utopia context.
* @param[in] ddns - Pointer to ddnsService_t structure containing DDNS settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_DDNS_TYPE if ddns provider is invalid.
* @retval Error code on failure.
*/
int Utopia_SetDDNSService (UtopiaContext *ctx, ddnsService_t *ddns);

/**
* @brief Update Dynamic DNS service.
*
* This function triggers an update to the DDNS service.
*
* @param[in] ctx - Utopia context.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_UpdateDDNSService (UtopiaContext *ctx);

/**
* @brief Get Dynamic DNS service configuration.
*
* Retrieves DDNS provider, credentials, and hostname settings.
*
* @param[in] ctx - Utopia context.
* @param[out] ddns - Pointer to ddnsService_t structure to store DDNS settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDDNSService (UtopiaContext *ctx, ddnsService_t *ddns);

/**
* @brief Get Dynamic DNS service status.
*
* Retrieves current status of DDNS update.
*
* @param[in] ctx - Utopia context.
* @param[out] ddnsStatus - Pointer to ddnsStatus_t to store DDNS status.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval Error code on failure.
*/
int Utopia_GetDDNSServiceStatus (UtopiaContext *ctx, ddnsStatus_t *ddnsStatus);
#endif
/**
* @brief Set MAC address cloning.
*
* Configures WAN interface MAC address cloning.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - TRUE to enable MAC cloning, FALSE to disable.
* @param[in] macaddr - MAC address to clone.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetMACAddressClone (UtopiaContext *ctx, boolean_t enable, char macaddr[MACADDR_SZ]);

/**
* @brief Get MAC address cloning configuration.
*
* Retrieves MAC cloning enable status and cloned MAC address.
*
* @param[in] ctx - Utopia context.
* @param[out] enable - Pointer to store enable status.
* @param[out] macaddr - Buffer to store cloned MAC address.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetMACAddressClone (UtopiaContext *ctx, boolean_t *enable, char macaddr[MACADDR_SZ]);

/**
* @brief Release WAN DHCP client lease.
*
* Sends DHCP release message to release current IP address lease.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_WANDHCPClient_Release (void);

/**
* @brief Renew WAN DHCP client lease.
*
* Sends DHCP renew request to renew current IP address lease.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_WANDHCPClient_Renew (void);

/**
* @brief Terminate WAN connection.
*
* This function disconnects active WAN connection.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval Error code on failure.
*/
int Utopia_WANConnectionTerminate (void);

/**
* @brief Get WAN connection information.
*
* Retrieves WAN IP address, subnet mask, default gateway, DNS servers, and lease time.
*
* @param[in] ctx - Utopia context.
* @param[out] info - Pointer to wanConnectionInfo_t structure to store connection info.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval Error code on failure.
*/
int Utopia_GetWANConnectionInfo (UtopiaContext *ctx, wanConnectionInfo_t *info);

/**
* @brief Get WAN connection status.
*
* Retrieves WAN connection status like state, physical link, uptime, and IP address.
*
* @param[in] ctx - Utopia context.
* @param[out] wan - Pointer to wanConnectionStatus_t structure to store status.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval Error code on failure.
*/
int Utopia_GetWANConnectionStatus (UtopiaContext *ctx, wanConnectionStatus_t *wan);

/**
* @brief Get WAN traffic information.
*
* Retrieves WAN traffic statistics including packets and bytes sent/received.
*
* @param[out] wan - Pointer to wanTrafficInfo_t structure to store traffic info.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval ERR_FILE_READ_FAILED if unable to read traffic data.
* @retval Error code on failure.
*/
int Utopia_GetWANTrafficInfo (wanTrafficInfo_t *wan);

/*
 * Router/Bridge settings
 */

/**
* @brief Set bridge mode settings.
*
* This function configures bridge mode and related IP configuration.
*
* @param[in] ctx - Utopia context.
* @param[in] bridge_info - Pointer to bridgeInfo_t structure containing bridge settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INVALID_BRIDGE_TYPE if bridge_mode is invalid.
* @retval Error code on failure.
*/
int Utopia_SetBridgeSettings (UtopiaContext *ctx, bridgeInfo_t *bridge_info);

/**
* @brief Get bridge mode settings.
*
* Retrieves current bridge mode configuration.
*
* @param[in] ctx - Utopia context.
* @param[out] bridge_info - Pointer to bridgeInfo_t structure to store bridge settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INVALID_BRIDGE_TYPE if bridge_mode is invalid.
* @retval Error code on failure.
*/
int Utopia_GetBridgeSettings (UtopiaContext *ctx, bridgeInfo_t *bridge_info);

/**
* @brief Get bridge connection information.
*
* This function retrieves bridge connection information.
*
* @param[in] ctx - Utopia context.
* @param[out] bridge - Pointer to bridgeConnectionInfo_t structure to store connection info.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
* @retval ERR_INVALID_BRIDGE_TYPE if bridge_mode is invalid.
* @retval Error code on failure.
*/
int Utopia_GetBridgeConnectionInfo (UtopiaContext *ctx, bridgeConnectionInfo_t *bridge);

/*
 * Route Settings
 */

/**
* @brief Set NAT (Network Address Port Translation) mode.
*
* Configures NAPT mode for routing.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - NAPT mode to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetRouteNAT (UtopiaContext *ctx, napt_mode_t enable);

/**
* @brief Get NAT (Network Address Port Translation) mode.
*
* Retrieves current NAPT mode configuration.
*
* @param[in] ctx - Utopia context.
* @param[out] enable - Pointer to store NAPT mode.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetRouteNAT (UtopiaContext *ctx, napt_mode_t *enable);

/**
* @brief Set RIP (Routing Information Protocol) configuration.
*
* Configures RIP settings like enable status, split horizon, interface selection, and passwords.
*
* @param[in] ctx - Utopia context.
* @param[in] rip - Pointer to routeRIP_t structure containing RIP settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetRouteRIP (UtopiaContext *ctx, routeRIP_t *rip); //CID 67860: Big parameter passed by value

/**
* @brief Get RIP (Routing Information Protocol) configuration.
*
* Retrieves RIP settings.
*
* @param[in] ctx - Utopia context.
* @param[out] rip - Pointer to routeRIP_t structure to store RIP settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetRouteRIP (UtopiaContext *ctx, routeRIP_t *rip);

/**
* @brief Find static route by name.
*
* Searches for a static route entry by route name.
*
* @param[in] count - Number of routes in sroutes array.
* @param[in] sroutes - Array of routeStatic_t structures to search.
* @param[in] route_name - Name of the route to find.
*
* @return Index of the found route.
* @retval >=0 Index of the route in array if found.
* @retval -1 if route not found.
*/
int Utopia_FindStaticRoute (int count, routeStatic_t *sroutes, const char *route_name);

/**
* @brief Delete static route by index.
*
* Removes a static route entry at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of the route to delete.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_DeleteStaticRoute (UtopiaContext *ctx, int index);

/**
* @brief Delete static route by name.
*
* Removes a static route entry with specified name.
*
* @param[in] ctx - Utopia context.
* @param[in] route_name - Name of the route to delete.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if route name does not exist.
* @retval Error code on failure.
*/
int Utopia_DeleteStaticRouteName (UtopiaContext *ctx, const char *route_name);

/**
* @brief Add new static route.
*
* Adds a new static route entry.
*
* @param[in] ctx - Utopia context.
* @param[in] sroute - Pointer to routeStatic_t structure containing route to add.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_AddStaticRoute (UtopiaContext *ctx, routeStatic_t *sroute);

/**
* @brief Edit existing static route by index.
*
* Modifies a static route entry at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of the route to edit.
* @param[in] sroute - Pointer to routeStatic_t structure containing new route data.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_EditStaticRoute (UtopiaContext *ctx, int index, routeStatic_t *sroute);

/**
* @brief Get count of static routes.
*
* Retrieves the number of configured static routes.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of static routes.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetStaticRouteCount (UtopiaContext *ctx, int *count);

/**
* @brief Get static routes configuration.
*
* Retrieves all configured static routes.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of routes retrieved.
* @param[out] out_sroute - Pointer to store address of allocated routeStatic_t array.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetStaticRoutes (UtopiaContext *ctx, int *count, routeStatic_t **out_sroute);

/**
* @brief Get static route table.
*
* Retrieves the static route table.
*
* @param[out] count - Pointer to store the number of route entries.
* @param[out] out_sroute - Pointer to store address of allocated routeStatic_t array.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetStaticRouteTable (int *count, routeStatic_t **out_sroute);

/*
 * Firewall Settings
 */

/*
 * Port Mapping
 */

/**
* @brief Check port trigger range for conflicts.
*
* Validates port trigger range against existing rules to detect conflicts.
*
* @param[in] ctx - Utopia context.
* @param[in] new_rule_id - Rule ID of the new/modified rule.
* @param[in] new_start - Start port of the range.
* @param[in] new_end - End port of the range.
* @param[in] new_protocol - Protocol.
* @param[in] is_trigger - TRUE if checking trigger range, FALSE if checking forward range.
*
* @return Status of the operation.
* @retval TRUE if no conflict.
* @retval FALSE if conflict detected.
*/
int Utopia_CheckPortTriggerRange(UtopiaContext *ctx, int new_rule_id, int new_start, int new_end, int new_protocol, int is_trigger);

/**
* @brief Check port range for conflicts.
*
* Validates port range against existing rules to detect conflicts.
*
* @param[in] ctx - Utopia context.
* @param[in] new_rule_id - Rule ID of the new/modified rule.
* @param[in] new_start - Start port of the range.
* @param[in] new_end - End port of the range.
* @param[in] new_protocol - Protocol.
* @param[in] is_trigger - TRUE if checking trigger range, FALSE if checking forward range.
*
* @return Status of the operation.
* @retval TRUE if no conflict.
* @retval FALSE if conflict detected.
*/
int Utopia_CheckPortRange(UtopiaContext *ctx, int new_rule_id, int new_start, int new_end, int new_protocol, int is_trigger);

/**
* @brief Set port forwarding rules for single port mappings.
*
* Configures multiple single port forwarding rules.
*
* @param[in] ctx - Utopia context.
* @param[in] count - Number of port forwarding entries in fwdinfo array.
* @param[in] fwdinfo - Array of portFwdSingle_t structures containing forwarding rules.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_INVALID_IPADDR if IP address is invalid.
* @retval Error code on failure.
*/
int Utopia_SetPortForwarding (UtopiaContext *ctx, int count, portFwdSingle_t *fwdinfo);

/**
* @brief Get port forwarding rules for single port mappings.
*
* Retrieves all configured single port forwarding rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of port forwarding entries.
* @param[out] fwdinfo - Pointer to store address of allocated portFwdSingle_t array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetPortForwarding (UtopiaContext *ctx, int *count, portFwdSingle_t **fwdinfo);

/**
* @brief Get count of port forwarding rules.
*
* Retrieves the number of configured single port forwarding rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store the number of port forwarding entries.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingCount (UtopiaContext *ctx, int *count);

/**
* @brief Find port forwarding rule by external port and protocol.
*
* Searches for a port forwarding entry matching external port and protocol.
*
* @param[in] count - Number of port mappings in portmap array.
* @param[in] portmap - Array of portFwdSingle_t structures to search.
* @param[in] external_port - External port number to find.
* @param[in] proto - Protocol.
*
* @return Index of the found port mapping.
* @retval >=0 Index in array if found.
* @retval -1 if not found.
*/
int Utopia_FindPortForwarding (int count, portFwdSingle_t *portmap, int external_port, protocol_t proto);

/**
* @brief Add new port forwarding rule.
*
* This function adds a new single port forwarding rule.
*
* @param[in] ctx - Utopia context.
* @param[in] portmap - Pointer to portFwdSingle_t structure containing rule to add.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_INVALID_IP if IP address is invalid.
* @retval Error code on failure.
*/
int Utopia_AddPortForwarding (UtopiaContext *ctx, portFwdSingle_t *portmap);

/**
* @brief Get port forwarding rule by index.
*
* Retrieves a specific port forwarding rule by array index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of the rule to retrieve.
* @param[out] fwdinfo - Pointer to portFwdSingle_t structure to store forwarding rule.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingByIndex (UtopiaContext *ctx, int index, portFwdSingle_t *fwdinfo);

/**
* @brief Set port forwarding rule by index.
*
* Modifies a specific port forwarding rule by array index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of the rule to modify.
* @param[in] fwdinfo - Pointer to portFwdSingle_t structure containing new rule data.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_SetPortForwardingByIndex (UtopiaContext *ctx, int index, portFwdSingle_t *fwdinfo);

/**
* @brief Delete port forwarding rule by index.
*
* Removes a port forwarding rule by array index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of the rule to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_DelPortForwardingByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get port forwarding rule by rule ID.
*
* Retrieves a specific port forwarding rule by its rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in,out] fwdinfo - Pointer to portFwdSingle_t structure with rule_id set on input,
*                          filled with rule data on output.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingByRuleId (UtopiaContext *ctx, portFwdSingle_t *fwdinfo);

/**
* @brief Set port forwarding rule by rule ID.
*
* Modifies a specific port forwarding rule by its rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] fwdinfo - Pointer to portFwdSingle_t structure with rule_id and new data.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_SetPortForwardingByRuleId (UtopiaContext *ctx, portFwdSingle_t *fwdinfo);

/**
* @brief Delete port forwarding rule by rule ID.
*
* Removes a port forwarding rule by its rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] rule_id - Rule ID of the forwarding rule to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_DelPortForwardingByRuleId (UtopiaContext *ctx, int rule_id);

/**
* @brief Add dynamic port mapping.
*
* Adds a dynamic port mapping entry.
*
* @param[in] portmap - Pointer to portMapDyn_t structure containing mapping to add.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_AddDynPortMapping (portMapDyn_t *portmap);

/**
* @brief Update dynamic port mapping.
*
* Updates an existing dynamic port mapping entry.
*
* @param[in] index - Index of the mapping to update.
* @param[in] pmap - Pointer to portMapDyn_t structure containing updated mapping data.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_UpdateDynPortMapping (int index, portMapDyn_t *pmap);

/**
* @brief Delete dynamic port mapping.
*
* Removes a dynamic port mapping entry.
*
* @param[in] portmap - Pointer to portMapDyn_t structure identifying mapping to delete.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_DeleteDynPortMapping (portMapDyn_t *portmap);

/**
* @brief Delete dynamic port mapping by index.
*
* Removes a dynamic port mapping entry by index.
*
* @param[in] index - Index of the mapping to delete.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_DeleteDynPortMappingIndex (int index);

/**
* @brief Invalidate all dynamic port mappings.
*
* Marks all dynamic port mappings as invalid/expired. Remove entries whose lease time expired
* this check is valid only on entries that have leasetime > 0. if leastime = 0, the entry is left
* indefinitely until it is explicitly deleted or system reboots.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_InvalidateDynPortMappings (void);

/**
* @brief Validate dynamic port mapping.
*
* Marks a dynamic port mapping as valid/active.
*
* @param[in] index - Index of the mapping to validate.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_ValidateDynPortMapping (int index);

/**
* @brief Get count of dynamic port mappings.
*
* Retrieves the number of dynamic port mappings.
*
* @param[out] count - Pointer to store the number of mappings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDynPortMappingCount (int *count);

/**
* @brief Get dynamic port mapping by index.
*
* Retrieves a specific dynamic port mapping entry.
*
* @param[in] index - Index of the mapping to retrieve.
* @param[out] portmap - Pointer to portMapDyn_t structure to store mapping data.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDynPortMapping (int index, portMapDyn_t *portmap);

/**
* @brief Find dynamic port mapping.
*
* Searches for a dynamic port mapping by external host, port, and protocol.
*
* @param[in] external_host - External host IP address.
* @param[in] external_port - External port number.
* @param[in] proto - Protocol.
* @param[out] pmap - Pointer to portMapDyn_t structure to store found mapping.
* @param[out] index - Pointer to store the index of found mapping.
*
* @return Status of the operation.
* @retval UT_SUCCESS if found.
* @retval ERR_ITEM_NOT_FOUND if not found.
* @retval Error code if not found or on failure.
*/
int Utopia_FindDynPortMapping(const char *external_host, int external_port, protocol_t proto, portMapDyn_t *pmap, int *index);

/**
* @brief Check if IGD configuration is allowed.
*
* Determines if UPnP IGD configuration is permitted.
*
* @param[in] ctx - Utopia context.
*
* @return Configuration allowed status.
* @retval 1 if IGD user configuration is allowed.
* @retval 0 if IGD configuration is not allowed.
*/
int Utopia_IGDConfigAllowed (UtopiaContext *ctx);

/**
* @brief Check if IGD internet disable is allowed.
*
* Determines if UPnP IGD can disable internet access.
*
* @param[in] ctx - Utopia context.
*
* @return Internet disable allowed status.
* @retval 1 if IGD can disable internet.
* @retval 0 if IGD cannot disable internet.
*/
int Utopia_IGDInternetDisbleAllowed (UtopiaContext *ctx);

/**
* @brief Set port forwarding range rules.
*
* Configures multiple port forwarding rules for port ranges.
*
* @param[in] ctx - Utopia context.
* @param[in] count - Number of port forwarding range entries.
* @param[in] fwdinfo - Array of portFwdRange_t structures containing forwarding rules.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetPortForwardingRange (UtopiaContext *ctx, int count, portFwdRange_t *fwdinfo);

/**
* @brief Get port forwarding range rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store number of entries.
* @param[out] fwdinfo - Pointer to store allocated array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_INVALID_IP if IP address is invalid.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingRange (UtopiaContext *ctx, int *count, portFwdRange_t **fwdinfo);

/**
* @brief Get count of port forwarding range rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingRangeCount (UtopiaContext *ctx, int *count);

/**
* @brief Add port forwarding range rule.
*
* @param[in] ctx - Utopia context.
* @param[in] portmap - Port forwarding range rule to add.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_INVALID_IP if IP address is invalid.
* @retval Error code on failure.
*/
int Utopia_AddPortForwardingRange (UtopiaContext *ctx, portFwdRange_t *portmap);

/**
* @brief Get port forwarding range rule by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule.
* @param[out] fwdinfo - Pointer to store rule data.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingRangeByIndex (UtopiaContext *ctx, int index, portFwdRange_t *fwdinfo);

/**
* @brief Set port forwarding range rule by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule.
* @param[in] fwdinfo - Rule data to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_SetPortForwardingRangeByIndex (UtopiaContext *ctx, int index, portFwdRange_t *fwdinfo);

/**
* @brief Delete port forwarding range rule by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_DelPortForwardingRangeByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get port forwarding range rule by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in,out] fwdinfo - Rule ID on input, rule data on output.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_GetPortForwardingRangeByRuleId (UtopiaContext *ctx, portFwdRange_t *fwdinfo);

/**
* @brief Set port forwarding range rule by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] fwdinfo - Rule data with rule_id.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_SetPortForwardingRangeByRuleId (UtopiaContext *ctx, portFwdRange_t *fwdinfo);

/**
* @brief Delete port forwarding range rule by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] rule_id - Rule ID to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_DelPortForwardingRangeByRuleId (UtopiaContext *ctx, int rule_id);

/**
* @brief Set port trigger rules.
*
* @param[in] ctx - Utopia context.
* @param[in] count - Number of port trigger entries.
* @param[in] portinfo - Array of portRangeTrig_t structures.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetPortTrigger (UtopiaContext *ctx, int count, portRangeTrig_t *portinfo);

/**
* @brief Get port trigger rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count.
* @param[out] portinfo - Pointer to store allocated array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetPortTrigger (UtopiaContext *ctx, int *count, portRangeTrig_t **portinfo);

/**
* @brief Get count of port trigger rules.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetPortTriggerCount (UtopiaContext *ctx, int *count);

/**
* @brief Add port trigger rule.
*
* @param[in] ctx - Utopia context.
* @param[in] portmap - Port trigger rule to add.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_AddPortTrigger (UtopiaContext *ctx, portRangeTrig_t *portmap);

/**
* @brief Get port trigger by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule.
* @param[out] fwdinfo - Pointer to store rule data.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_GetPortTriggerByIndex (UtopiaContext *ctx, int index, portRangeTrig_t *fwdinfo);

/**
* @brief Set port trigger by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule.
* @param[in] fwdinfo - Rule data to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_SetPortTriggerByIndex (UtopiaContext *ctx, int index, portRangeTrig_t *fwdinfo);

/**
* @brief Delete port trigger by index.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of rule to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval Error code on failure.
*/
int Utopia_DelPortTriggerByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get port trigger by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in,out] portinfo - Rule ID on input, rule data on output.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_GetPortTriggerByRuleId (UtopiaContext *ctx, portRangeTrig_t *portinfo);

/**
* @brief Set port trigger by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] portinfo - Rule data with rule_id.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_SetPortTriggerByRuleId (UtopiaContext *ctx, portRangeTrig_t *portinfo);

/**
* @brief Delete port trigger by rule ID.
*
* @param[in] ctx - Utopia context.
* @param[in] trigger_id - Trigger ID to delete.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_ITEM_NOT_FOUND if rule_id does not exist.
* @retval Error code on failure.
*/
int Utopia_DelPortTriggerByRuleId (UtopiaContext *ctx, int trigger_id);

/**
* @brief Set DMZ settings.
*
* Configures Demilitarized Zone settings like enable status and destination IP/MAC.
*
* @param[in] ctx - Utopia context.
* @param[in] dmz - Pointer to dmz_t structure containing DMZ settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetDMZSettings (UtopiaContext *ctx, dmz_t *dmz);

/**
* @brief Get DMZ settings.
*
* @param[in] ctx - Utopia context.
* @param[out] out_dmz - Pointer to dmz_t structure to store DMZ settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetDMZSettings (UtopiaContext *ctx, dmz_t *out_dmz);

/**
* @brief Add Internet Access Policy.
*
* @param[in] ctx - Utopia context.
* @param[in] iap - Pointer to iap_entry_t structure containing policy.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_AddInternetAccessPolicy (UtopiaContext *ctx, iap_entry_t *iap);

/**
* @brief Edit Internet Access Policy.
*
* @param[in] ctx - Utopia context.
* @param[in] index - Index of policy to edit.
* @param[in] iap - Pointer to iap_entry_t structure with new policy data.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_EditInternetAccessPolicy (UtopiaContext *ctx, int index, iap_entry_t *iap);

/**
* @brief Add LAN hosts to Internet Access Policy.
*
* @param[in] ctx - Utopia context.
* @param[in] policyname - Name of policy.
* @param[in] lanhosts - Pointer to lanHosts_t structure containing LAN hosts.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_AddInternetAccessPolicyLanHosts (UtopiaContext *ctx, const char *policyname, lanHosts_t *lanhosts);

/**
* @brief Delete Internet Access Policy.
*
* @param[in] ctx - Utopia context.
* @param[in] policyname - Name of policy to delete.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INVALID_VALUE if policy does not exist.
* @retval Error code on failure.
*/
int Utopia_DeleteInternetAccessPolicy (UtopiaContext *ctx, const char *policyname);

/**
* @brief Get Internet Access Policies.
*
* @param[in] ctx - Utopia context.
* @param[out] out_count - Pointer to store count.
* @param[out] out_iap - Pointer to store allocated array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval Error code on failure.
*/
int Utopia_GetInternetAccessPolicy (UtopiaContext *ctx, int *out_count, iap_entry_t **out_iap);

/**
* @brief Find Internet Access Policy by name.
*
* @param[in] ctx - Utopia context.
* @param[in] policyname - Policy name to find.
* @param[out] out_iap - Pointer to store policy data.
* @param[out] out_index - Pointer to store policy index.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_ITEM_NOT_FOUND if policy not found.
* @retval Error code on failure.
*/
int Utopia_FindInternetAccessPolicy (UtopiaContext *ctx, const char *policyname, iap_entry_t *out_iap, int *out_index);

/**
* @brief Free Internet Access Policy memory.
*
* @param[in] iap - Pointer to iap_entry_t to free.
*
* @return None.
*/
void Utopia_FreeInternetAccessPolicy (iap_entry_t *iap);

/**
* @brief Get network services list.
*
* Returns a null terminated array of strings with network service names like ftp, telnet, dns, etc.
*
* @param[out] out_list - Pointer to receive service list.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetNetworkServicesList (const char **out_list);

typedef struct firewall {
    boolean_t spi_protection;
    boolean_t filter_anon_req;
    boolean_t filter_anon_req_v6;
    boolean_t filter_multicast;
    boolean_t filter_multicast_v6;
    boolean_t filter_nat_redirect;
    boolean_t filter_ident;
    boolean_t filter_ident_v6;
    boolean_t filter_web_proxy;
    boolean_t filter_web_java;
    boolean_t filter_web_activex;
    boolean_t filter_web_cookies;
    boolean_t allow_ipsec_passthru;
    boolean_t allow_pptp_passthru;
    boolean_t allow_l2tp_passthru;
    boolean_t allow_ssl_passthru;
    boolean_t filter_http_from_wan;
    boolean_t filter_http_from_wan_v6;
    boolean_t filter_p2p_from_wan;
    boolean_t filter_p2p_from_wan_v6;
    boolean_t true_static_ip_enable;
    boolean_t true_static_ip_enable_v6;
    boolean_t smart_pkt_dection_enable;
    boolean_t smart_pkt_dection_enable_v6;
    boolean_t wan_ping_enable;
    boolean_t wan_ping_enable_v6;
} firewall_t;

/**
* @brief Set firewall settings.
*
* Configures general firewall settings like SPI protection, packet filtering options.
*
* @param[in] ctx - Utopia context.
* @param[in] fw - Firewall settings structure.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetFirewallSettings (UtopiaContext *ctx, firewall_t fw);

/**
* @brief Get firewall settings.
*
* @param[in] ctx - Utopia context.
* @param[out] fw - Pointer to firewall_t structure to store settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetFirewallSettings (UtopiaContext *ctx, firewall_t *fw);

typedef struct ipv6Prefix {
	char prefix[IPADDR_SZ];
	int size;
}ipv6Prefix_t;

/*
 * IPv6 Settings and Status
 */

typedef struct ipv6Info {
    /* Dynamic information from sysevent mainly */
    char ipv6_connection_state[NAME_SZ];
    char current_lan_ipv6address[IPADDR_SZ];
    char current_lan_ipv6address_ll[IPADDR_SZ];
    char current_wan_ipv6_interface[IFNAME_SZ];
    char current_wan_ipv6address[IPADDR_SZ];
    char current_wan_ipv6address_ll[IPADDR_SZ];
    char ipv6_domain[TOKEN_SZ] ;
    char ipv6_nameserver[TOKEN_SZ] ;
    char ipv6_ntp_server[TOKEN_SZ] ;
    char ipv6_prefix[IPADDR_SZ] ;
    /* Configuration from syscfg mainly */
    int sixrd_enable;
            int sixrd_common_prefix4;
            char sixrd_relay[IPADDR_SZ];
            char sixrd_zone[IPADDR_SZ];
            int sixrd_zone_length;
    int sixtofour_enable;
    int aiccu_enable;
            char aiccu_password[PASSWORD_SZ];
            char aiccu_prefix[IPADDR_SZ];
            char aiccu_tunnel[TOKEN_SZ];
            char aiccu_user[USERNAME_SZ];
    int he_enable;
            char he_client_ipv6[IPADDR_SZ];
            char he_password[PASSWORD_SZ];
            char he_prefix[IPADDR_SZ];
            char he_server_ipv4[IPADDR_SZ];
            char he_tunnel[TOKEN_SZ];
            char he_user[USERNAME_SZ];
    int ipv6_bridging_enable;
    int ipv6_ndp_proxy_enable;
    int dhcpv6c_enable ;
            char dhcpv6c_duid[TOKEN_SZ] ;
    int dhcpv6s_enable ;
            char dhcpv6s_duid[TOKEN_SZ] ;
    int ipv6_static_enable ;
            char ipv6_default_gateway[IPADDR_SZ] ;
            char ipv6_lan_address[IPADDR_SZ] ;
            char ipv6_wan_address[IPADDR_SZ] ;
    int ra_enable ; /* Whether to start Zebra to transmit RA on the LAN side */
    int ra_provisioning_enable ; /* Whether to listen to RA on the WAN side */
} ipv6Info_t ;

/**
* @brief Set IPv6 settings.
*
* Configures IPv6 settings such as tunnel modes (6rd, 6to4, AICCU, HE), DHCPv6 client/server.
*
* @param[in] ctx - Utopia context.
* @param[in] ipv6_info - Pointer to ipv6Info_t structure containing IPv6 settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetIPv6Settings (UtopiaContext *ctx, ipv6Info_t *ipv6_info);

/**
* @brief Get IPv6 settings.
*
* Retrieves current IPv6 configuration and status information such as connection state.
*
* @param[in] ctx - Utopia context.
* @param[out] ipv6_info - Pointer to ipv6Info_t structure to store IPv6 settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetIPv6Settings (UtopiaContext *ctx, ipv6Info_t *ipv6_info);

/*
 * Administration
 */

typedef struct {
    char      admin_user[NAME_SZ];
    boolean_t http_access;
    boolean_t https_access;
    boolean_t wifi_mgmt_access;
    boolean_t wan_mgmt_access;
    boolean_t wan_http_access;
    boolean_t wan_https_access;
    int       wan_http_port;        // default is 8080
    boolean_t wan_firmware_upgrade;
    boolean_t wan_src_anyip;
    char      wan_src_startip[IPADDR_SZ];
    char      wan_src_endip[IPADDR_SZ];
} webui_t;

typedef struct {
    boolean_t enable;
    boolean_t allow_userconfig;
    boolean_t allow_wandisable;
} igdconf_t;

/**
* @brief Restore factory defaults.
*
* Resets the device configuration to factory default settings.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_RestoreFactoryDefaults (void);

/**
* @brief Restore configuration from file.
*
* Restores device configuration from a previously saved backup file.
*
* @param[in] config_fname - Path to configuration backup file.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval ERR_INVALID_SYSCFG_FILE if the config file is invalid.
* @retval Error code on failure.
*/
int Utopia_RestoreConfiguration (char *config_fname);

/**
* @brief Backup configuration to file.
*
* Saves current device configuration to a backup file.
*
* @param[in] out_config_fname - Path where backup file will be created.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_INSUFFICIENT_MEM for memory allocation failure.
* @retval ERR_FILE_WRITE_FAILED if unable to write to file.
* @retval Error code on failure.
*/
int Utopia_BackupConfiguration (char *out_config_fname);

/**
* @brief Perform firmware upgrade.
*
* Upgrades device firmware from specified firmware file.
*
* @param[in] ctx - Utopia context.
* @param[in] firmware_file - Path to firmware image file.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if another upgrade is in progress.
* @retval ERR_FILE_WRITE_FAILED if unable to read firmware file.
* @retval Error code on failure.
*/
int Utopia_FirmwareUpgrade (UtopiaContext *ctx, char *firmware_file);

/**
* @brief Check if firmware upgrade is allowed.
*
* Validates if firmware upgrade is permitted based on current configuration and access port.
*
* @param[in] ctx - Utopia context.
* @param[in] http_port - HTTP port being used for upgrade request.
*
* @return Status of the operation.
* @retval 1 if upgrade is allowed.
* @retval 0 if upgrade is not allowed.
*/
int Utopia_IsFirmwareUpgradeAllowed (UtopiaContext *ctx, int http_port);

/**
* @brief Acquire firmware upgrade lock.
*
* Obtains exclusive lock for firmware upgrade operation to prevent concurrent upgrades.
*
* @param[out] lock_fd - Pointer to store lock file descriptor.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_FILE_NOT_FOUND if  failed to open file.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if lock is already held.
* @retval Error code on failure.
*/
int Utopia_AcquireFirmwareUpgradeLock (int *lock_fd);

/**
* @brief Release firmware upgrade lock.
*
* Releases previously acquired firmware upgrade lock.
*
* @param[in] lock_fd - Lock file descriptor to release.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if lock is not held.
* @retval Error code on failure.
*/
int Utopia_ReleaseFirmwareUpgradeLock (int lock_fd);

/**
* @brief Check if system changes are allowed.
*
* Determines if configuration changes are permitted in current system state.
*
* @return Status of the operation.
* @retval 1 if system changes are allowed.
* @retval 0 if system changes are not allowed.
*/
int Utopia_SystemChangesAllowed (void);

/**
* @brief Reboot the device.
*
* Initiates a system reboot.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_REBOOT_FAILED on failure.
*/
int Utopia_Reboot (void);

/**
* @brief Set WebUI admin password.
*
* Sets or changes the administrator password for WebUI access.
*
* @param[in] ctx - Utopia context.
* @param[in] username - Admin username.
* @param[in] cleartext_password - New password in cleartext.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_FILE_NOT_FOUND if file failed to open.
* @retval ERR_INVALID_VALUE if username does not exist.
* @retval Error code on failure.
*/
int Utopia_SetWebUIAdminPasswd (UtopiaContext *ctx, char *username, char *cleartext_password);

/**
* @brief Check if Admin configuration is default.
*
* Determines if the current Admin configuration is still set to the factory default value.
*
* @param[in] ctx - Utopia context.
* @param[out] is_admin_default - Pointer to boolean indicating if password is default.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_IsAdminDefault (UtopiaContext *ctx, boolean_t *is_admin_default);

/**
* @brief Set WebUI settings.
*
* Configures WebUI access settings such as HTTP/HTTPS access, WiFi management,
* WAN access controls, and source IP restrictions.
*
* @param[in] ctx - Utopia context.
* @param[in] ui - Pointer to webui_t structure containing WebUI settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetWebUISettings (UtopiaContext *ctx, webui_t *ui);

/**
* @brief Get WebUI settings.
*
* @param[in] ctx - Utopia context.
* @param[out] ui - Pointer to webui_t structure to store WebUI settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetWebUISettings (UtopiaContext *ctx, webui_t *ui);

/**
* @brief Set IGD (Internet Gateway Device) settings.
*
* Configures UPnP IGD settings like enable status and user configuration permissions.
*
* @param[in] ctx - Utopia context.
* @param[in] igd - Pointer to igdconf_t structure containing IGD settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_SetIGDSettings (UtopiaContext *ctx, igdconf_t *igd);

/**
* @brief Get IGD (Internet Gateway Device) settings.
*
* @param[in] ctx - Utopia context.
* @param[out] igd - Pointer to igdconf_t structure to store IGD settings.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_GetIGDSettings (UtopiaContext *ctx, igdconf_t *igd);

/*
 * Logging and Diagnostics
 */
/**
* @brief Get incoming traffic log entries.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count of log entries.
* @param[out] ilog - Pointer to receive allocated log array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*
* @note caller need to free log array.
*/
int Utopia_GetIncomingTrafficLog (UtopiaContext *ctx, int *count, logentry_t **ilog);

/**
* @brief Get outgoing traffic log entries.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count of log entries.
* @param[out] olog - Pointer to receive allocated log array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*
* @note caller need to free log array.
*/
int Utopia_GetOutgoingTrafficLog (UtopiaContext *ctx, int *count, logentry_t **olog);

/**
* @brief Get security log entries.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store count of log entries.
* @param[out] slog - Pointer to receive allocated log array.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetSecurityLog (UtopiaContext *ctx, int *count, logentry_t **slog);

/**
* @brief Get DHCP client log.
*
* @param[in] ctx - Utopia context.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDHCPClientLog (UtopiaContext *ctx);

/**
* @brief Set log settings.
*
* Configures logging enable status and log viewer path.
*
* @param[in] ctx - Utopia context.
* @param[in] log_enabled - Boolean to enable/disable logging.
* @param[in] log_viewer - Path to log viewer application.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetLogSettings (UtopiaContext *ctx, boolean_t log_enabled, char *log_viewer);

/**
* @brief Get log settings.
*
* @param[in] ctx - Utopia context.
* @param[out] log_enabled - Pointer to store logging enable status.
* @param[out] log_viewer - Buffer to store log viewer path.
* @param[in] sz - Size of log_viewer buffer.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetLogSettings (UtopiaContext *ctx, boolean_t *log_enabled, char *log_viewer, int sz);

/**
* @brief Start diagnostic ping test.
*
* Initiates a ping test to specified destination with given packet size and count.
*
* @param[in] dest - Destination IP address or hostname.
* @param[in] packet_size - Size of ping packets in bytes.
* @param[in] num_ping - Number of ping packets to send.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_DiagPingTestStart (char *dest, int packet_size, int num_ping);

/**
* @brief Stop diagnostic ping test.
*
* Terminates currently running ping test.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_DiagPingTestStop (void);

/**
* @brief Check if diagnostic ping test is running.
*
* @return Test status.
* @retval Non-zero if test is running.
* @retval 0 if test is not running.
*/
int Utopia_DiagPingTestIsRunning (void);

/**
* @brief Start diagnostic traceroute test.
*
* Initiates a traceroute test to specified destination.
*
* @param[in] dest - Destination IP address or hostname.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval ERR_FILE_NOT_FOUND if failed to open
* @retval Error code on failure.
*/
int Utopia_DiagTracerouteTestStart (char *dest);

/**
* @brief Stop diagnostic traceroute test.
*
* Terminates currently running traceroute test.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_DiagTracerouteTestStop (void);

/**
* @brief Check if diagnostic traceroute test is running.
*
* @return Test status.
* @retval Non-zero if test is running.
* @retval 0 if test is not running.
*/
int Utopia_DiagTracerouteTestIsRunning (void);

/**
* @brief Execute diagnostic ping test.
*
* Performs a ping test to destination and returns results.
*
* @param[in] ctx - Utopia context.
* @param[in] dest - Destination IP address or hostname.
* @param[in] packet_size - Size of ping packets in bytes.
* @param[in] num_ping - Number of ping packets to send.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int diagPingTest (UtopiaContext *ctx, String dest, int packet_size, int num_ping);

/**
* @brief Execute diagnostic traceroute test.
*
* Performs a traceroute test to destination and returns results.
*
* @param[in] ctx - Utopia context.
* @param[in] dest - Destination IP address or hostname.
* @param[out] results_buffer - Pointer to buffer for storing results.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int diagTraceroute (UtopiaContext *ctx, String dest, char **results_buffer);

/**
* @brief Connect PPP session.
*
* Initiates a PPP (Point-to-Point Protocol) connection for WAN.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to set sysevent for connection.
* @retval Error code on failure.
*/
int Utopia_PPPConnect (void);

/**
* @brief Disconnect PPP session.
*
* Terminates the active PPP connection.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to set sysevent for disconnection.
* @retval Error code on failure.
*/
int Utopia_PPPDisconnect (void);


/* BYOI */
#if 0
typedef struct byoi_wan_ppp {
    char username[USERNAME_SZ];
    char password[PASSWORD_SZ];
    char service_name[WAN_SERVICE_NAME_SZ];   // for pppoe
    wanConnectMethod_t conn_method;
    int max_idle_time;
    int redial_period;
} byoi_wan_ppp_t;

typedef enum {
    BYOI_DHCP,
    BYOI_PPPOE
} byoi_wanProto_t;



typedef struct byoi {
    boolean_t          primary_hsd_allowed;
    byoi_wanProto_t    wan_proto;
    byoi_wan_ppp_t     ppp;
    hsd_type_t         byoi_mode;
    boolean_t          byoi_bridge_mode;
}byoi_t;
int Utopia_Get_BYOI(UtopiaContext *ctx, byoi_t *byoi);
int Utopia_Set_BYOI(UtopiaContext *ctx, byoi_t *byoi);
*/
#endif

typedef enum hsd_type {
    PRIMARY_PROVIDER_HSD,
    PRIMARY_PROVIDER_RESTRICTED,
    USER_SELECTABLE
} hsd_type_t;


typedef enum {
    CABLE_PROVIDER_HSD,
    BYOI_PROVIDER_HSD,
    NONE
} hsdStatus_t;

/**
* @brief Get BYOI allowed status.
*
* Determines if BYOI mode is permitted on the device.
*
* @param[in] ctx - Utopia context.
* @param[out] value - Pointer to store BYOI allowed status.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to get sysevent value.
* @retval Error code on failure.
*/
int Utopia_Get_BYOI_allowed(UtopiaContext *ctx,  int *value);

/**
* @brief Get current BYOI provider status.
*
* Returns the currently active High-Speed Data provider.
*
* @param[in] ctx - Utopia context.
* @param[out] hsdStatus - Pointer to store current provider status.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval ERR_SYSEVENT_CONN if unable to get sysevent value.
* @retval Error code on failure.
*/
int Utopia_Get_BYOI_Current_Provider(UtopiaContext *ctx,  hsdStatus_t *hsdStatus);

/**
* @brief Set desired BYOI provider.
*
* Configures the desired High-Speed Data provider selection.
*
* @param[in] ctx - Utopia context.
* @param[in] hsdStatus - Desired provider status to set.
*
* @return Status of the operation.
* @retval UT_SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval ERR_SYSEVENT_CONN if unable to set sysevent value.
* @retval Error code on failure.
*/
int Utopia_Set_BYOI_Desired_Provider(UtopiaContext *ctx,  hsdStatus_t hsdStatus);

/**
* @brief Get web session timeout value.
*
* Retrieves the inactivity timeout for WebUI sessions in minutes.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store timeout value in minutes.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetWebTimeout(UtopiaContext *ctx, int *count);

/**
* @brief Set web session timeout value.
*
* Configures the inactivity timeout for WebUI sessions in minutes.
*
* @param[in] ctx - Utopia context.
* @param[in] count - Timeout value in minutes.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetWebTimeout(UtopiaContext *ctx, int count);

/*typedef enum {
    ADMIN,
    HOME_USER,
} userType_t;
*/
typedef struct http_user {
    char username[USERNAME_SZ];
    char password[PASSWORD_SZ];
    //userType_t usertype;
} http_user_t;

/**
* @brief Get HTTP user credentials.
*
* Retrieves home user account credentials for HTTP access.
*
* @param[in] ctx - Utopia context.
* @param[out] httpuser - Pointer to http_user_t structure to store user credentials.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Get_Http_User(UtopiaContext *ctx,  http_user_t *httpuser);

/**
* @brief Set HTTP user credentials.
*
* Configures home user account credentials for HTTP access.
*
* @param[in] ctx - Utopia context.
* @param[in] httpuser - Pointer to http_user_t structure containing user credentials.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_Set_Http_User(UtopiaContext *ctx, http_user_t *httpuser);

/**
* @brief Get HTTP admin credentials.
*
* Retrieves administrator account credentials for HTTP access.
*
* @param[in] ctx - Utopia context.
* @param[out] httpuser - Pointer to http_user_t structure to store admin credentials.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Get_Http_Admin(UtopiaContext *ctx, http_user_t *httpuser);

/**
* @brief Set HTTP admin credentials.
*
* Configures administrator account credentials for HTTP access.
*
* @param[in] ctx - Utopia context.
* @param[in] httpuser - Pointer to http_user_t structure containing admin credentials.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_Set_Http_Admin(UtopiaContext *ctx, http_user_t *httpuser);
/**
* @brief Set provisioning code.
*
* Stores the device provisioning code.
*
* @param[in] ctx - Utopia context.
* @param[in] val - Provisioning code string.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_Set_Prov_Code(UtopiaContext *ctx, char *val);

/**
* @brief Get provisioning code.
*
* Retrieves the device provisioning code.
*
* @param[in] ctx - Utopia context.
* @param[out] val - Buffer to store provisioning code.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_Get_Prov_Code(UtopiaContext *ctx, char *val);

/**
* @brief Get first use date.
*
* Retrieves the date when the device was first used.
*
* @param[in] ctx - Utopia context.
* @param[out] val - Buffer to store first use date.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_Get_First_Use_Date(UtopiaContext *ctx,  char *val);

/* NTP Functions */
/**
* @brief Set NTP server address.
*
* Configures an NTP (Network Time Protocol) server at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] server - NTP server address (hostname or IP).
* @param[in] index - Server index.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Set_DeviceTime_NTPServer(UtopiaContext *ctx, char *server, int index);

/**
* @brief Get NTP server address.
*
* Retrieves the NTP server configured at specified index.
*
* @param[in] ctx - Utopia context.
* @param[out] server - Buffer to store NTP server address.
* @param[in] index - Server index.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval ERR_SYSCFG_FAILED if unable to get syscfg value.
* @retval Error code on failure.
*/
int Utopia_Get_DeviceTime_NTPServer(UtopiaContext *ctx, char *server,int index);

/**
* @brief Set local timezone.
*
* Configures the device timezone setting.
*
* @param[in] ctx - Utopia context.
* @param[in] tz - Timezone string.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Set_DeviceTime_LocalTZ(UtopiaContext *ctx, char *tz);

/**
* @brief Get local timezone.
*
* Retrieves the device timezone setting.
*
* @param[in] ctx - Utopia context.
* @param[out] tz - Buffer to store timezone string.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval ERR_SYSCFG_FAILED if unable to get syscfg value.
* @retval Error code on failure.
*/
int Utopia_Get_DeviceTime_LocalTZ(UtopiaContext *ctx, char *tz);

/**
* @brief Set device time enable status.
*
* Enables or disables automatic time synchronization via NTP.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - Enable status (1=enable, 0=disable).
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Set_DeviceTime_Enable(UtopiaContext *ctx, unsigned char enable);

/**
* @brief Get device time enable status.
*
* Retrieves whether automatic time synchronization is enabled.
*
* @param[in] ctx - Utopia context.
*
* @return Enable status.
* @retval 1 if enabled.
* @retval 0 if disabled.
*/
unsigned char Utopia_Get_DeviceTime_Enable(UtopiaContext *ctx);

/**
* @brief Get device time synchronization status.
*
* Checks if device time is currently synchronized with NTP server.
*
* @param[in] ctx - Utopia context.
*
* @return Synchronization status.
* @retval Non-zero if synchronized.
* @retval 0 if not synchronized.
*/
int Utopia_Get_DeviceTime_Status(UtopiaContext *ctx);

/**
* @brief Set daylight saving time enable status.
*
* Enables or disables automatic daylight saving time adjustment.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - Enable status (1=enable, 0=disable).
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_UTCTX_INIT if Utopia context is not initialized.
* @retval Error code on failure.
*/
int Utopia_Set_DeviceTime_DaylightEnable(UtopiaContext *ctx, unsigned char enable);

/**
* @brief Get daylight saving time enable status.
*
* Retrieves whether automatic daylight saving time adjustment is enabled.
*
* @param[in] ctx - Utopia context.
*
* @return Enable status.
* @retval 1 if enabled.
* @retval 0 if disabled.
*/
unsigned char Utopia_Get_DeviceTime_DaylightEnable(UtopiaContext *ctx);

/**
* @brief Get daylight saving time offset.
*
* Retrieves the DST offset in minutes.
*
* @param[in] ctx - Utopia context.
* @param[out] count - Pointer to store DST offset in minutes.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_Get_DeviceTime_DaylightOffset(UtopiaContext *ctx, int *count);

/**
* @brief Set daylight saving time offset.
*
* Configures the DST offset in minutes.
*
* @param[in] ctx - Utopia context.
* @param[in] count - DST offset in minutes.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_Set_DeviceTime_DaylightOffset(UtopiaContext *ctx, int count);

/**
* @brief Get MAC address of MG WAN interface.
*
* Retrieves the MAC address of the Management WAN interface.
*
* @param[in] ctx - Utopia context.
* @param[out] val - Buffer to store MAC address.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_ARGS if parameters are NULL or invalid.
* @retval Error code on failure.
*/
int Utopia_Get_Mac_MgWan(UtopiaContext *ctx,  char *val);

/**
* @brief Get Ethernet associated devices.
*
* Retrieves MAC addresses of devices associated with specified Ethernet port.
*
* @param[in] unitId - Unit identifier.
* @param[in] portId - Port identifier.
* @param[out] macAddrList - Buffer to store MAC address list.
* @param[out] numMacAddr - Pointer to store number of MAC addresses.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_FILE_OPEN_FAIL if failed to open file.
* @retval ERR_FILE_CLOSE_FAIL if failed to close file
* @retval Error code on failure.
*/
int Utopia_GetEthAssocDevices(int unitId, int portId, unsigned char *macAddrList,int *numMacAddr);

/**
* @brief Get LAN management count.
*
* Retrieves the count of LAN management instances.
*
* @param[in] ctx - Utopia context.
* @param[out] val - Pointer to store count.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetLanMngmCount(UtopiaContext *ctx, int *val);

/**
* @brief Set LAN management instance number.
*
* Configures the LAN management instance number.
*
* @param[in] ctx - Utopia context.
* @param[in] val - Instance number value.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if the value is invalid.
* @retval Error code on failure.
*/
int Utopia_SetLanMngmInsNum(UtopiaContext *ctx, unsigned long int val);

/**
* @brief Get LAN management instance number.
*
* Retrieves the LAN management instance number.
*
* @param[in] ctx - Utopia context.
* @param[out] val - Pointer to store instance number.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetLanMngmInsNum(UtopiaContext *ctx, unsigned long int *val);

/**
* @brief Get LAN management alias.
*
* Retrieves the alias for LAN management.
*
* @param[in] ctx - Utopia context.
* @param[out] buf - Buffer to store alias.
* @param[in] b_len - Buffer length.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if the value is invalid.
* @retval Error code on failure.
*/
int Utopia_GetLanMngmAlias(UtopiaContext *ctx, char *buf, size_t b_len );

/**
* @brief Set LAN management alias.
*
* Configures the alias for LAN management.
*
* @param[in] ctx - Utopia context.
* @param[in] val - Alias string.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if the value is invalid.
* @retval Error code on failure.
*/
int Utopia_SetLanMngmAlias(UtopiaContext *ctx, const char *val);
//int Utopia_GetLanMngmLanMode(UtopiaContext *ctx, lanMngm_LanMode_t *LanMode);
//int Utopia_SetLanMngmLanMode(UtopiaContext *ctx, lanMngm_LanMode_t LanMode);

/**
* @brief Get LAN networks allow status.
*
* Retrieves whether LAN networks are allowed.
*
* @param[in] ctx - Utopia context.
* @param[out] allow - Pointer to store allow status.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetLanMngmLanNetworksAllow(UtopiaContext *ctx, int* allow);

/**
* @brief Set LAN networks allow status.
*
* Configures whether LAN networks are allowed.
*
* @param[in] ctx - Utopia context.
* @param[in] allow - Allow status.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if the value is invalid.
* @retval Error code on failure.
*/
int Utopia_SetLanMngmLanNetworksAllow(UtopiaContext *ctx, int allow);

/**
* @brief Get LAN NAPT mode.
*
* Retrieves the Network Address Port Translation mode for LAN.
*
* @param[in] ctx - Utopia context.
* @param[out] enable - Pointer to store NAPT mode.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetLanMngmLanNapt(UtopiaContext *ctx, napt_mode_t *enable);

/**
* @brief Set LAN NAPT mode.
*
* Configures the Network Address Port Translation mode for LAN.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - NAPT mode to set.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_SetLanMngmLanNapt(UtopiaContext *ctx, napt_mode_t enable);

#define DNS_CLIENT_NAMESERVER_CNT 10

typedef struct dns_client{
    char dns_server[DNS_CLIENT_NAMESERVER_CNT][IPADDR_SZ];
}DNS_Client_t;

/**
* @brief Set DNS enable status.
*
* This function enables or disables DNS functionality.
*
* @param[in] ctx - Utopia context.
* @param[in] enable - Enable status.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if invalid value.
* @retval Error code on failure.
*/
int Utopia_SetDNSEnable(UtopiaContext *ctx, boolean_t enable);

/**
* @brief Get DNS enable status.
*
* Retrieves whether DNS functionality is enabled.
*
* @param[in] ctx - Utopia context.
* @param[out] enable - Pointer to store enable status.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDNSEnable(UtopiaContext *ctx, boolean_t* enable);

/**
* @brief Get DNS servers.
*
* Retrieves configured DNS server addresses.
*
* @param[in] ctx - Utopia context.
* @param[out] dns - Pointer to DNS_Client_t structure to store DNS servers.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_INVALID_VALUE if invalid value.
* @retval ERR_FILE_NOT_FOUND if failed to open file.
* @retval Error code on failure.
*/
int Utopia_GetDNSServer(UtopiaContext *ctx, DNS_Client_t * dns);

/**
* @brief Configure ephemeral port forwarding rule.
*
* Adds or removes an ephemeral (temporary) port forwarding rule via IP tables.
*
* @param[in] pmap - Pointer to portMapDyn_t structure containing mapping details.
* @param[in] isCallForAdd - Boolean indicating add (TRUE) or remove (FALSE) operation.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval ERR_SYSEVENT_CONN if unable to set sysevent value.
* @retval ERR_INVALID_VALUE if invalid value.
* @retval Error code on failure.
*/
int Utopia_IPRule_ephemeral_port_forwarding( portMapDyn_t *pmap, boolean_t isCallForAdd );

/**
* @brief Check if IP address is private.
*
* Validates whether the specified IP address is in a private address range.
*
* @param[in] ip_to_check - IP address string to check.
*
* @return Check result.
* @retval Non-zero if IP is private.
* @retval 0 if IP is public.
*/
int Utopia_privateIpCheck(char *ip_to_check);

#if defined(DDNS_BROADBANDFORUM)
typedef struct DynamicDnsClient
{
   unsigned long  InstanceNumber;
   char           Alias[64];
   int            Status;
   int            LastError;
   char           Server[256];
   char           Interface[256];
   char           Username[256];
   char           Password[256];
   boolean_t      Enable;
}DynamicDnsClient_t;

/**
* @brief Get dynamic DNS client instance number by index.
*
* Retrieves the instance number for a dynamic DNS client at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] uIndex - Client index.
* @param[out] ins - Pointer to store instance number.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetDynamicDnsClientInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get number of dynamic DNS clients.
*
* Retrieves the count of configured dynamic DNS clients.
*
* @param[in] ctx - Utopia context.
* @param[out] num - Pointer to store client count.
*
* @return Status of the operation.
* @retval SUCCESS on success.
* @retval Error code on failure.
*/
int Utopia_GetNumberOfDynamicDnsClient(UtopiaContext *ctx, int *num);

/**
* @brief Get dynamic DNS client by index.
*
* Retrieves dynamic DNS client configuration at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] ulIndex - Client index.
* @param[out] DynamicDnsClient - Pointer to DynamicDnsClient_t structure to store configuration.
*
* @return Status of the operation.
* @retval 0 on success.
*/
int Utopia_GetDynamicDnsClientByIndex(UtopiaContext *ctx, unsigned long ulIndex, DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Set dynamic DNS client by index.
*
* Updates dynamic DNS client configuration at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] ulIndex - Client index.
* @param[in] DynamicDnsClient - Pointer to DynamicDnsClient_t structure containing new configuration.
*
* @return Status of the operation.
* @retval 0 on success.
*/
int Utopia_SetDynamicDnsClientByIndex(UtopiaContext *ctx, unsigned long ulIndex, const DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Set dynamic DNS client instance and alias by index.
*
* Configures instance number and alias for dynamic DNS client at specified index.
*
* @param[in] ctx - Utopia context.
* @param[in] ulIndex - Client index.
* @param[in] ins - Instance number.
* @param[in] alias - Alias string.
*
* @return Status of the operation.
* @retval 0 on success.
*/
int Utopia_SetDynamicDnsClientInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ins, const char *alias);

/**
* @brief Add dynamic DNS client.
*
* Adds a new dynamic DNS client configuration.
*
* @param[in] ctx - Utopia context.
* @param[in] DynamicDnsClient - Pointer to DynamicDnsClient_t structure containing client configuration.
*
* @return Status of the operation.
* @retval 0 on success.
*/
int Utopia_AddDynamicDnsClient(UtopiaContext *ctx, const DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Delete dynamic DNS client.
*
* Removes dynamic DNS client by instance number.
*
* @param[in] ctx - Utopia context.
* @param[in] ins - Instance number of client to delete.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval -1 if the client with the specified instance number is not found.
*/
int Utopia_DelDynamicDnsClient(UtopiaContext *ctx, unsigned long ins);
#endif

#endif // _UTAPI_H_