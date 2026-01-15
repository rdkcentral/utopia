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
* @brief Get the list of predefined QoS (Quality of Service) policies.
*
* @param[out] out_count   - Pointer to an integer where the count of QoS policies will be returned.
* @param[out] out_qoslist - Pointer to a qosDefinedPolicy_t const pointer where the list of QoS policies will be returned.
*                           \n Policies are read from /etc/qos_classification_rules file.
*                           \n Maximum policies: 256.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_FILE_NOT_FOUND if the QoS classification rules file cannot be opened.
*
*/
int Utopia_GetQoSDefinedPolicyList (int *out_count, qosDefinedPolicy_t const **out_qoslist);

/**
* @brief Set the QoS (Quality of Service) settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] qos - Pointer to a qosInfo_t structure containing the QoS settings to be set.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, qos is NULL, or if enable is TRUE with policy count > 0 but policy list is NULL.
*
*/
int Utopia_SetQoSSettings (UtopiaContext *ctx, qosInfo_t *qos);

/**
* @brief Get the QoS (Quality of Service) settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] qos - Pointer to a qosInfo_t structure where the QoS settings will be returned.
*                   \n Caller must free policy_list after use.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or qos is NULL.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetQoSSettings (UtopiaContext *ctx, qosInfo_t *qos);

/**
* @brief Get comments/description for a LAN host identified by MAC address.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[in]  pMac      - Pointer to the MAC address buffer.
* @param[out] pComments - Pointer to the buffer where comments will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pMac, or pComments is NULL.
*
*/
int Utopia_get_lan_host_comments(UtopiaContext *ctx, unsigned char *pMac, unsigned char *pComments);

/**
* @brief Set comments/description for a LAN host identified by MAC address.
*
* @param[in] ctx       - Pointer to the Utopia context.
* @param[in] pMac      - Pointer to the MAC address buffer.
* @param[in] pComments - Pointer to the comments buffer to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pMac, or pComments is NULL.
*
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
* @brief Get device settings including hostname, language, and timezone.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] device - Pointer to a deviceSetting_t structure where the device settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or device is NULL.
*
*/
int Utopia_GetDeviceSettings (UtopiaContext *ctx, deviceSetting_t *device);

/**
* @brief Set device settings including hostname, language, and timezone.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] device - Pointer to a deviceSetting_t structure containing the device settings to be set.
*                     \n Timezone is determined by matching GMT offset and DST settings with internal timezone list.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or device is NULL.
*
*/
int Utopia_SetDeviceSettings (UtopiaContext *ctx, deviceSetting_t *device);

/*
 * LAN Settings
 */

/**
* @brief Get LAN (Local Area Network) settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] lan - Pointer to a lanSetting_t structure where the LAN settings will be returned.
*                   \n Domain is retrieved from sysevent or syscfg.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or lan is NULL.
*
*/
int Utopia_GetLanSettings (UtopiaContext *ctx, lanSetting_t *lan);

/**
* @brief Set LAN (Local Area Network) settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] lan - Pointer to a lanSetting_t structure containing the LAN settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or lan is NULL.
* @retval ERR_INVALID_NETMASK if the netmask is invalid.
*
*/
int Utopia_SetLanSettings(UtopiaContext *ctx, lanSetting_t *lan);


/**
* @brief Set the DHCP server settings.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] dhcps - Pointer to a dhcpServerInfo_t structure containing the DHCP server settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or dhcps is NULL.
*
*/
int Utopia_SetDHCPServerSettings (UtopiaContext *ctx, dhcpServerInfo_t *dhcps);

/**
* @brief Get the DHCP server settings.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] dhcps - Pointer to a dhcpServerInfo_t structure where the DHCP server settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or out_dhcps is NULL.
*
*/
int Utopia_GetDHCPServerSettings (UtopiaContext *ctx, dhcpServerInfo_t *out_dhcps);


/**
* @brief Set DHCP server static host mappings.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] count   - Number of static host entries to set.
* @param[in] dhcpMap - Pointer to an array of DHCPMap_t structures containing static host mappings.
*                      \n MAC address and IP address are validated before setting.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
* @retval ERR_INVALID_VALUE if MAC address or IP address is invalid.
*
*/
int Utopia_SetDHCPServerStaticHosts (UtopiaContext *ctx, int count, DHCPMap_t *dhcpMap);

/**
* @brief Get DHCP server static host mappings.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[out] count   - Pointer to an integer where the count of static hosts will be returned.
* @param[out] dhcpMap - Pointer to a DHCPMap_t pointer where the static host mappings will be returned.
*                       \n Format: "macaddr,last octet of host_ip,client_name" or None
*                       \n Caller must free dhcpMap after use.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, count, or dhcpMap is NULL.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetDHCPServerStaticHosts (UtopiaContext *ctx, int *count, DHCPMap_t **dhcpMap);

/**
* @brief Get the count of DHCP server static host entries.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the count of static hosts will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetDHCPServerStaticHostsCount (UtopiaContext *ctx, int *count);

/**
* @brief Remove all DHCP server static host entries.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_UnsetDHCPServerStaticHosts (UtopiaContext *ctx);

/**
* @brief Get ARP (Address Resolution Protocol) cache entries.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[out] count     - Pointer to an integer where the count of ARP entries will be returned.
* @param[out] out_hosts - Pointer to an arpHost_t pointer where the ARP cache entries will be returned.
*                         \n Caller must free out_hosts after use.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetARPCacheEntries (UtopiaContext *ctx, int *count, arpHost_t **out_hosts);

/**
* @brief Get the list of WLAN (WiFi) clients connected to the access point.
*
* @param[in]  ctx        - Pointer to the Utopia context.
* @param[out] count      - Pointer to an integer where the count of WLAN clients will be returned.
* @param[out] out_maclist - Pointer to a char pointer where the MAC address list will be returned.
*                          \n MAC addresses are stored contiguously, each 18 bytes.
*                          \n Caller must free out_maclist after use.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetWLANClients (UtopiaContext *ctx, int *count, char **out_maclist);

/**
* @brief Get the list of active DHCP leases and  on the LAN.
*
* @param[in]  ctx         - Pointer to the Utopia context.
* @param[out] count       - Pointer to an integer where the count of DHCP leases will be returned.
* @param[out] client_info - Pointer to a dhcpLANHost_t pointer where the lease information will be returned.
*                           \n Lease information is read from /tmp/dnsmasq.leases file.
*                           \n Caller must free client_info after use.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetDHCPServerLANHosts (UtopiaContext *ctx, int *count, dhcpLANHost_t **client_info);

/**
* @brief Delete a DHCP lease for a specific IP address.
*
* @param[in] ipaddr - Pointer to the IP address string of the lease to delete.
*                     \n Triggers dhcp_server-restart sysevent.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_DeleteDHCPServerLANHost (char *ipaddr);


/*
 * WAN Settings
 */

/**
* @brief Set WAN (Wide Area Network) settings.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] wan_info - Pointer to a wanInfo_t structure containing the WAN settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or wan_info is NULL.
* @retval ERR_INVALID_WAN_TYPE if the WAN protocol is invalid.
*
*/
int Utopia_SetWANSettings (UtopiaContext *ctx, wanInfo_t *wan_info);

/**
* @brief Get WAN (Wide Area Network) settings.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[out] wan_info - Pointer to a wanInfo_t structure where the WAN settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or wan_info is NULL.
* @retval ERR_INVALID_WAN_TYPE if the WAN protocol is invalid.
*
*/
int Utopia_GetWANSettings (UtopiaContext *ctx, wanInfo_t *wan_info);
#if !defined(DDNS_BROADBANDFORUM)
/**
* @brief Set DDNS (Dynamic DNS) service settings.
*
* @param[in] ctx  - Pointer to the Utopia context.
* @param[in] ddns - Pointer to a ddnsService_t structure containing the DDNS settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_DDNS_TYPE if the DDNS provider type is invalid.
*
*/
int Utopia_SetDDNSService (UtopiaContext *ctx, ddnsService_t *ddns);

/**
* @brief Trigger an update of the DDNS service.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_UpdateDDNSService (UtopiaContext *ctx);

/**
* @brief Get DDNS (Dynamic DNS) service settings.
*
* @param[in]  ctx  - Pointer to the Utopia context.
* @param[out] ddns - Pointer to a ddnsService_t structure where the DDNS settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetDDNSService (UtopiaContext *ctx, ddnsService_t *ddns);

/**
* @brief Get the current DDNS service status.
*
* @param[in]  ctx        - Pointer to the Utopia context.
* @param[out] ddnsStatus - Pointer to a ddnsStatus_t where the DDNS status will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
* @retval ERR_INVALID_ARGS if ctx or ddnsStatus is NULL.
*
*/
int Utopia_GetDDNSServiceStatus (UtopiaContext *ctx, ddnsStatus_t *ddnsStatus);
#endif
/**
* @brief Set MAC address cloning for the WAN interface.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] enable  - Boolean flag to enable or disable MAC cloning.
* @param[in] macaddr - MAC address string to clone (18 bytes).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_MAC if the provided MAC address is invalid.
*
*/
int Utopia_SetMACAddressClone (UtopiaContext *ctx, boolean_t enable, char macaddr[MACADDR_SZ]);

/**
* @brief Get MAC address cloning settings for the WAN interface.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[out] enable  - Pointer to a boolean_t where the MAC cloning enable status will be returned.
* @param[out] macaddr - Buffer where the cloned MAC address will be returned (18 bytes).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, enable, or macaddr is NULL.
*
*/
int Utopia_GetMACAddressClone (UtopiaContext *ctx, boolean_t *enable, char macaddr[MACADDR_SZ]);

/**
* @brief Release the current DHCP lease on the WAN interface.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if Utopia context initialization fails.
* @retval ERR_INVALID_WAN_TYPE if the WAN protocol is not DHCP.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_WANDHCPClient_Release (void);

/**
* @brief Renew the DHCP lease on the WAN interface.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if Utopia context initialization fails.
* @retval ERR_INVALID_WAN_TYPE if the WAN protocol is not DHCP.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_WANDHCPClient_Renew (void);

/**
* @brief Terminate the WAN connection.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_WANConnectionTerminate (void);

/**
* @brief Get WAN connection information.
*
* @param[in]  ctx  - Pointer to the Utopia context.
* @param[out] info - Pointer to a wanConnectionInfo_t structure where the connection information will be returned.
*                    \n Information source depends on WAN protocol (DHCP/PPP/STATIC).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or info is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_GetWANConnectionInfo (UtopiaContext *ctx, wanConnectionInfo_t *info);

/**
* @brief Get WAN connection status.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] wan - Pointer to a wanConnectionStatus_t structure where the connection status will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or wan is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_GetWANConnectionStatus (UtopiaContext *ctx, wanConnectionStatus_t *wan);

/**
* @brief Get WAN traffic statistics.
*
* @param[out] wan - Pointer to a wanTrafficInfo_t structure where the traffic statistics will be returned.
*                   \n Statistics are read from /proc/net/dev.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if wan is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
* @retval ERR_FILE_READ_FAILED if /proc/net/dev cannot be opened.
*
*/
int Utopia_GetWANTrafficInfo (wanTrafficInfo_t *wan);

/*
 * Router/Bridge settings
 */
/**
* @brief Set bridge mode settings.
*
* @param[in] ctx         - Pointer to the Utopia context.
* @param[in] bridge_info - Pointer to a bridgeInfo_t structure containing the bridge settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or bridge_info is NULL.
* @retval ERR_INVALID_BRIDGE_MODE if the bridge mode is invalid.
*
*/
int Utopia_SetBridgeSettings (UtopiaContext *ctx, bridgeInfo_t *bridge_info);

/**
* @brief Get bridge mode settings.
*
* @param[in]  ctx         - Pointer to the Utopia context.
* @param[out] bridge_info - Pointer to a bridgeInfo_t structure where the bridge settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or bridge_info is NULL.
* @retval ERR_INVALID_BRIDGE_MODE if the bridge mode is invalid.
*
*/
int Utopia_GetBridgeSettings (UtopiaContext *ctx, bridgeInfo_t *bridge_info);

/**
* @brief Get bridge connection information.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] bridge - Pointer to a bridgeConnectionInfo_t structure where the connection information will be returned.
*                      \n Returns zeroed struct if bridge mode is OFF.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or bridge is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon (DHCP mode).
* @retval ERR_INVALID_BRIDGE_MODE if the bridge mode is invalid.
*
*/
int Utopia_GetBridgeConnectionInfo (UtopiaContext *ctx, bridgeConnectionInfo_t *bridge);

/*
 * Route Settings
 */
/**
* @brief Set NAT (Network Address Translation) mode.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - NAT mode to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetRouteNAT (UtopiaContext *ctx, napt_mode_t enable);

/**
* @brief Get NAT (Network Address Translation) mode.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] enable - Pointer to a napt_mode_t where the NAT mode will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetRouteNAT (UtopiaContext *ctx, napt_mode_t *enable);

/**
* @brief Set RIP (Routing Information Protocol) settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] rip - Pointer to a routeRIP_t structure containing the RIP settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetRouteRIP (UtopiaContext *ctx, routeRIP_t *rip); //CID 67860: Big parameter passed by value

/**
* @brief Get RIP (Routing Information Protocol) settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] rip - Pointer to a routeRIP_t structure where the RIP settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetRouteRIP (UtopiaContext *ctx, routeRIP_t *rip);

/**
* @brief Find a static route entry by name from an array of static routes.
*
* @param[in] count       - The number of static route entries in the sroutes array.
* @param[in] sroutes     - Pointer to an array of routeStatic_t structures containing the static routes to search.
* @param[in] route_name  - Pointer to a null-terminated string containing the route name to search for.
*
* @return The index of the matched route (1-based), or -1 if not found.
* @retval 1 to count - Index of the matched static route entry (1-based).
* @retval -1 - Route not found.
*
*/
int Utopia_FindStaticRoute (int count, routeStatic_t *sroutes, const char *route_name);

/**
* @brief Delete a static route entry by index.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] index - The 1-based index of the static route to delete.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_DeleteStaticRoute (UtopiaContext *ctx, int index);

/**
* @brief Delete a static route entry by its friendly name.
*
* @param[in] ctx        - Pointer to the Utopia context.
* @param[in] route_name - Pointer to a null-terminated string containing the name of the route to delete.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or route_name is NULL.
* @retval ERR_ITEM_NOT_FOUND if no route with the specified name is found.
*
*/
int Utopia_DeleteStaticRouteName (UtopiaContext *ctx, const char *route_name);

/**
* @brief Add a new static route entry to the system configuration.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] sroute - Pointer to a routeStatic_t structure containing the static route information to add.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or sroute is NULL.
* @retval SUCCESS if the route is successfully added and count incremented.
*
*/
int Utopia_AddStaticRoute (UtopiaContext *ctx, routeStatic_t *sroute);

/**
* @brief Edit an existing static route entry at the specified index.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] index  - The 1-based index of the static route to modify.
* @param[in] sroute - Pointer to a routeStatic_t structure containing the updated static route information.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL, index is less than 1, sroute is NULL, or index exceeds the route count.
* @retval SUCCESS if the route is successfully updated.
*
*/
int Utopia_EditStaticRoute (UtopiaContext *ctx, int index, routeStatic_t *sroute);

/**
* @brief Get the number of configured static routes.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the static route count will be returned.
*                     \n Initialized to 0 before retrieval.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or count is NULL.
*
*/
int Utopia_GetStaticRouteCount (UtopiaContext *ctx, int *count);

/**
* @brief Get all configured static routes from the system configuration.
*
* This function allocates memory for the route array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx         - Pointer to the Utopia context.
* @param[out] count       - Pointer to an integer where the number of static routes will be returned.
* @param[out] out_sroute  - Pointer to a routeStatic_t pointer where the allocated array of static routes will be returned.
*                           \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INVALID_ARGS if ctx, count, or out_sroute is NULL.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
* @retval SUCCESS if all routes are successfully retrieved.
*
*/
int Utopia_GetStaticRoutes (UtopiaContext *ctx, int *count, routeStatic_t **out_sroute);

/**
* @brief Get the current active routing table from the system kernel.
* \n
* Retrieves the actual routing table by executing 'route -en' command and parsing the output.
* \n This function allocates memory for the route array. Caller is responsible for freeing the memory.
*
* @param[out] count       - Pointer to an integer where the number of route entries will be returned.
* @param[out] out_sroute  - Pointer to a routeStatic_t pointer where the allocated array of route entries will be returned.
*                           \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if count or out_sroute is NULL.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
* @retval ERR_FILE_NOT_FOUND if the temporary route table file cannot be opened.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetStaticRouteTable (int *count, routeStatic_t **out_sroute);

/*
 * Firewall Settings
 */

/*
 * Port Mapping
 */

/**
* @brief Check if a port trigger range conflicts with existing port trigger rules.
*
* Validates that the specified trigger port range does not overlap with existing port trigger configurations.
*
* @param[in] ctx          - Pointer to the Utopia context.
* @param[in] new_rule_id  - The rule ID of the new/edited rule (existing rules with this ID are skipped in validation).
* @param[in] new_start    - The starting port number of the range to validate.
* @param[in] new_end      - The ending port number of the range to validate.
* @param[in] new_protocol - The protocol type (TCP, UDP, BOTH_TCP_UDP).
* @param[in] is_trigger   - Flag indicating if this is a trigger port check (1) or forwarding port check (0).
*
* @return Validation result.
* @retval TRUE if the port range is valid (no conflicts).
* @retval FALSE if the port range conflicts with an existing trigger rule.
*
*/
int Utopia_CheckPortTriggerRange(UtopiaContext *ctx, int new_rule_id, int new_start, int new_end, int new_protocol, int is_trigger);

/**
* @brief Check if a port range conflicts with existing port forwarding and port trigger rules.
*
* Validates that the specified port range does not overlap with existing single port forwarding,
* port range forwarding, or port triggering forwarding port configurations.
*
* @param[in] ctx          - Pointer to the Utopia context.
* @param[in] new_rule_id  - The rule ID of the new/edited rule (existing rules with this ID are skipped in validation).
* @param[in] new_start    - The starting port number of the range to validate.
* @param[in] new_end      - The ending port number of the range to validate.
* @param[in] new_protocol - The protocol type (TCP, UDP, BOTH_TCP_UDP).
* @param[in] is_trigger   - Flag indicating if this is a trigger port check (1) or forwarding port check (0).
*
* @return Validation result.
* @retval TRUE if the port range is valid (no conflicts).
* @retval FALSE if the port range conflicts with an existing rule.
*
*/
int Utopia_CheckPortRange(UtopiaContext *ctx, int new_rule_id, int new_start, int new_end, int new_protocol, int is_trigger);

/**
* @brief Set the complete list of single port forwarding rules, replacing all existing rules.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] count   - The number of port forwarding rules in the fwdinfo array.
* @param[in] fwdinfo - Pointer to an array of portFwdSingle_t structures containing the port forwarding rules.
*                      \n If rule_id is 0, it will be auto-assigned based on array position for backward compatibility.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if any rule_id is negative.
* @retval ERR_INVALID_IP if any destination IP address is invalid.
*
*/
int Utopia_SetPortForwarding (UtopiaContext *ctx, int count, portFwdSingle_t *fwdinfo);

/**
* @brief Get all configured single port forwarding rules.
* \n
* This function allocates memory for the forwarding rules array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[out] count   - Pointer to an integer where the number of port forwarding rules will be returned.
* @param[out] fwdinfo - Pointer to a portFwdSingle_t pointer where the allocated array of forwarding rules will be returned.
*                       \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetPortForwarding (UtopiaContext *ctx, int *count, portFwdSingle_t **fwdinfo);

/**
* @brief Get the number of configured single port forwarding rules.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the port forwarding rule count will be returned.
*                     \n Initialized to 0 before retrieval.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetPortForwardingCount (UtopiaContext *ctx, int *count);

/**
* @brief Find a port forwarding entry by external port and protocol from an array of port mappings.
*
* @param[in] count         - The number of port forwarding entries in the portmap array.
* @param[in] portmap       - Pointer to an array of portFwdSingle_t structures containing the port mappings to search.
* @param[in] external_port - The external port number to search for.
* @param[in] proto         - The protocol type (TCP, UDP, BOTH_TCP_UDP) to match.
*
* @return The index of the matched entry
* @retval 0 to count-1 - Index of the matched port forwarding entry (0-based) on success.
* @retval -1 - Entry not found.
*
*/
int Utopia_FindPortForwarding (int count, portFwdSingle_t *portmap, int external_port, protocol_t proto);

/**
* @brief Add a new single port forwarding rule to the configuration.
* \n
* If rule_id is 0, appends the rule at the end. If rule_id is specified, inserts the rule
* \n in order by rule_id, ensuring uniqueness.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] portmap - Pointer to a portFwdSingle_t structure containing the port forwarding rule to add.
*                      \n Must have valid destination IP address.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative or if rule_id already exists.
* @retval ERR_INVALID_IP if destination IP address is invalid.
*
*/
int Utopia_AddPortForwarding (UtopiaContext *ctx, portFwdSingle_t *portmap);

/**
* @brief Get a single port forwarding rule by its 0-based index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  index   - The 0-based index of the port forwarding rule to retrieve.
* @param[out] fwdinfo - Pointer to a portFwdSingle_t structure where the forwarding rule will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_GetPortForwardingByIndex (UtopiaContext *ctx, int index, portFwdSingle_t *fwdinfo);

/**
* @brief Update a single port forwarding rule at the specified 0-based index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] index   - The 0-based index of the port forwarding rule to update.
* @param[in] fwdinfo - Pointer to a portFwdSingle_t structure containing the updated forwarding rule.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_SetPortForwardingByIndex (UtopiaContext *ctx, int index, portFwdSingle_t *fwdinfo);

/**
* @brief Delete a single port forwarding rule at the specified 0-based index.
* \n
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] index - The 0-based index of the port forwarding rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_DelPortForwardingByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get a single port forwarding rule by its rule ID.
*
* @param[in]     ctx     - Pointer to the Utopia context.
* @param[in,out] fwdinfo - Pointer to a portFwdSingle_t structure.
*                          \n [in] fwdinfo->rule_id contains the rule ID to search for.
*                          \n [out] Structure is filled with the matching rule's complete information.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative or if no rule with the specified ID is found.
*
*/
int Utopia_GetPortForwardingByRuleId (UtopiaContext *ctx, portFwdSingle_t *fwdinfo);

/**
* @brief Update a single port forwarding rule identified by its rule ID.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] fwdinfo - Pointer to a portFwdSingle_t structure containing the updated rule.
*                      \n fwdinfo->rule_id is used to locate the rule to update.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative.
* @retval ERR_ITEM_NOT_FOUND if no rule with the specified rule_id is found.
*
*/
int Utopia_SetPortForwardingByRuleId (UtopiaContext *ctx, portFwdSingle_t *fwdinfo);

/**
* @brief Delete a single port forwarding rule identified by its rule ID.
*
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] rule_id - The rule ID of the port forwarding rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if rule_id is negative or if no rule with the specified ID is found.
*
*/
int Utopia_DelPortForwardingByRuleId (UtopiaContext *ctx, int rule_id);

/**
* @brief Add a dynamic port mapping entry.
*
* Dynamic port mappings do not persist across reboots and are aged out by lease time.
* Automatically updates the last_updated timestamp and firewall rules.
*
* @param[in] portmap - Pointer to a portMapDyn_t structure containing the dynamic port mapping to add.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if portmap is NULL.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_AddDynPortMapping (portMapDyn_t *portmap);

/**
* @brief Update an existing dynamic port mapping entry at the specified index.
* \n
* Updates the mapping and refreshes firewall rules.
*
* @param[in] index - The 1-based index of the dynamic port mapping to update.
* @param[in] pmap  - Pointer to a portMapDyn_t structure containing the updated mapping information.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if index is out of range.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_UpdateDynPortMapping (int index, portMapDyn_t *pmap);

/**
* @brief Delete a dynamic port mapping by searching for a matching entry.
*
* Searches for a mapping matching external host, external port, and protocol, then deletes it.
*
* @param[in] portmap - Pointer to a portMapDyn_t structure containing the mapping to delete.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if no matching entry is found.
* @retval ERR_INVALID_ARGS if deletion by index fails.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_DeleteDynPortMapping (portMapDyn_t *portmap);

/**
* @brief Delete a dynamic port mapping at the specified index.
*
* Removes the entry and shifts subsequent entries to fill the gap. Updates firewall rules.
*
* @param[in] index - The 1-based index of the dynamic port mapping to delete.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if index is out of range.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_DeleteDynPortMappingIndex (int index);

/**
* @brief Remove expired dynamic port mapping entries.
*
* Decrements lease time for all entries by 3600 seconds and removes entries with expired leases.
* This check applies to all entries, and firewall is restarted upon removal.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_InvalidateDynPortMappings (void);

/**
* @brief Validate a dynamic port mapping by updating its last_updated timestamp.
* \n
* Refreshes the timestamp to extend the lease time of the mapping.
*
* @param[in] index - The 1-based index of the dynamic port mapping to validate.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails during retrieval.
*
*/
int Utopia_ValidateDynPortMapping (int index);

/**
* @brief Get the number of dynamic port mapping entries.
*
* @param[out] count - Pointer to an integer where the dynamic port mapping count will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_GetDynPortMappingCount (int *count);

/**
* @brief Get a dynamic port mapping entry at the specified index.
*
* @param[in]  index   - The 1-based index of the dynamic port mapping to retrieve.
* @param[out] portmap - Pointer to a portMapDyn_t structure where the mapping information will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
* @retval ERR_INVALID_VALUE if parsing the mapping entry fails.
*
*/
int Utopia_GetDynPortMapping (int index, portMapDyn_t *portmap);

/**
* @brief Find a dynamic port mapping entry by external host, port, and protocol.
*
* @param[in]  external_host - Pointer to a null-terminated string containing the external host IP address.
* @param[in]  external_port - The external port number to search for.
* @param[in]  proto         - The protocol type (TCP, UDP) to match.
* @param[out] pmap          - Pointer to a portMapDyn_t structure where the matching mapping will be returned.
* @param[out] index         - Pointer to an integer where the 1-based index of the found entry will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if a matching entry is found.
* @retval ERR_ITEM_NOT_FOUND if no matching entry is found.
* @retval ERR_SYSEVENT_CONN if sysevent connection fails.
*
*/
int Utopia_FindDynPortMapping(const char *external_host, int external_port, protocol_t proto, portMapDyn_t *pmap, int *index);

/**
* @brief Check if IGD (Internet Gateway Device) user configuration is allowed.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return Configuration permission status.
* @retval 1 if IGD user configuration is allowed.
* @retval 0 if disallowed or if ctx is NULL.
*
*/
int Utopia_IGDConfigAllowed (UtopiaContext *ctx);

/**
* @brief Check if IGD internet disable (using force-termination) is allowed.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return Internet disable permission status.
* @retval 1 if IGD internet disable is allowed.
* @retval 0 if disallowed or if ctx is NULL.
*
*/
int Utopia_IGDInternetDisbleAllowed (UtopiaContext *ctx);

/**
* @brief Set the complete list of port forwarding range rules, replacing all existing range rules.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] count   - The number of port forwarding range rules in the fwdinfo array.
* @param[in] fwdinfo - Pointer to an array of portFwdRange_t structures containing the range forwarding rules.
*                      \n If rule_id is 0, it will be auto-assigned based on array position for backward compatibility.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if any rule_id is negative.
* @retval ERR_INVALID_IP if any destination IP or public IP address is invalid.
*
*/
int Utopia_SetPortForwardingRange (UtopiaContext *ctx, int count, portFwdRange_t *fwdinfo);

/**
* @brief Get all configured port forwarding range rules.
* \n
* This function allocates memory for the forwarding range rules array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[out] count   - Pointer to an integer where the number of range forwarding rules will be returned.
* @param[out] fwdinfo - Pointer to a portFwdRange_t pointer where the allocated array of range forwarding rules will be returned.
*                       \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
* @retval ERR_INVALID_PORT_RANGE if parsing a port range fails.
*
*/
int Utopia_GetPortForwardingRange (UtopiaContext *ctx, int *count, portFwdRange_t **fwdinfo);

/**
* @brief Get the number of configured port forwarding range rules.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the range forwarding rule count will be returned.
*                     \n Initialized to 0 before retrieval.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP_FAILED if Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if count is not valid integer.
*
*/
int Utopia_GetPortForwardingRangeCount (UtopiaContext *ctx, int *count);

/**
* @brief Add a new port forwarding range rule to the configuration.
*
* If rule_id is 0, appends the rule at the end. If rule_id is specified, inserts the rule
* in order by rule_id, ensuring uniqueness.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] portmap - Pointer to a portFwdRange_t structure containing the range forwarding rule to add.
*                      \n Must have valid destination IP and public IP (if specified) addresses.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative or if rule_id already exists.
* @retval ERR_INVALID_IP if destination IP or public IP address is invalid.
*
*/
int Utopia_AddPortForwardingRange (UtopiaContext *ctx, portFwdRange_t *portmap);

/**
* @brief Get a port forwarding range rule by its 0-based index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  index   - The 0-based index of the range forwarding rule to retrieve.
* @param[out] fwdinfo - Pointer to a portFwdRange_t structure where the forwarding range rule will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval ERR_INVALID_PORT_RANGE if parsing the port range fails.
*
*/
int Utopia_GetPortForwardingRangeByIndex (UtopiaContext *ctx, int index, portFwdRange_t *fwdinfo);

/**
* @brief Update a port forwarding range rule at the specified 0-based index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] index   - The 0-based index of the range forwarding rule to update.
* @param[in] fwdinfo - Pointer to a portFwdRange_t structure containing the updated range forwarding rule.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_SetPortForwardingRangeByIndex (UtopiaContext *ctx, int index, portFwdRange_t *fwdinfo);

/**
* @brief Delete a port forwarding range rule at the specified 0-based index.
*
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] index - The 0-based index of the range forwarding rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_DelPortForwardingRangeByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get a port forwarding range rule by its rule ID.
*
* @param[in]     ctx     - Pointer to the Utopia context.
* @param[in,out] fwdinfo - Pointer to a portFwdRange_t structure.
*                          \n [in] fwdinfo->rule_id contains the rule ID to search for.
*                          \n [out] Structure is filled with the matching rule's complete information.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative.
* @retval ERR_ITEM_NOT_FOUND if no rule with the specified ID is found.
* @retval ERR_INVALID_PORT_RANGE if parsing the port range fails.
*
*/
int Utopia_GetPortForwardingRangeByRuleId (UtopiaContext *ctx, portFwdRange_t *fwdinfo);

/**
* @brief Update a port forwarding range rule identified by its rule ID.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] fwdinfo - Pointer to a portFwdRange_t structure containing the updated rule.
*                      \n fwdinfo->rule_id is used to locate the rule to update.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative.
* @retval ERR_ITEM_NOT_FOUND if no rule with the specified rule_id is found.
*
*/
int Utopia_SetPortForwardingRangeByRuleId (UtopiaContext *ctx, portFwdRange_t *fwdinfo);

/**
* @brief Delete a port forwarding range rule identified by its rule ID.
*
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] rule_id - The rule ID of the range forwarding rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if rule_id is negative or if no rule with the specified ID is found.
*
*/
int Utopia_DelPortForwardingRangeByRuleId (UtopiaContext *ctx, int rule_id);

/**
* @brief Set the complete list of port trigger rules, replacing all existing trigger rules.
*
* @param[in] ctx         - Pointer to the Utopia context.
* @param[in] count       - The number of port trigger rules in the portinfo array.
* @param[in] portinfo    - Pointer to an array of portRangeTrig_t structures containing the port trigger rules.
*                          \n If rule_id is 0, it will be auto-assigned based on array position for backward compatibility.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if any rule_id is negative.
*
*/
int Utopia_SetPortTrigger (UtopiaContext *ctx, int count, portRangeTrig_t *portinfo);

/**
* @brief Get all configured port trigger rules.
*
* This function allocates memory for the port trigger rules array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[out] count    - Pointer to an integer where the number of port trigger rules will be returned.
* @param[out] portinfo - Pointer to a portRangeTrig_t pointer where the allocated array of trigger rules will be returned.
*                        \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
* @retval ERR_INVALID_PORT_RANGE if parsing a port range fails.
*
*/
int Utopia_GetPortTrigger (UtopiaContext *ctx, int *count, portRangeTrig_t **portinfo);

/**
* @brief Get the number of configured port trigger rules.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the port trigger rule count will be returned.
*                     \n Initialized to 0 before retrieval.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if utopia get fails
* @retval ERR_INVALID_INT_VALUE if count is not a valid integer
*
*/
int Utopia_GetPortTriggerCount (UtopiaContext *ctx, int *count);

/**
* @brief Add a new port trigger rule to the configuration.
* \n
* If rule_id is 0, appends the rule at the end. If rule_id is specified, inserts the rule
* \n in order by rule_id, ensuring uniqueness.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] portmap - Pointer to a portRangeTrig_t structure containing the port trigger rule to add.
*                      \n Includes trigger and forward port ranges with their respective protocols.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative or if rule_id already exists.
*
*/
int Utopia_AddPortTrigger (UtopiaContext *ctx, portRangeTrig_t *portmap);

/**
* @brief Get a port trigger rule by its 0-based index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  index   - The 0-based index of the port trigger rule to retrieve.
* @param[out] fwdinfo - Pointer to a portRangeTrig_t structure where the trigger rule will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
* @retval ERR_INVALID_PORT_RANGE if parsing a port range fails.
*
*/
int Utopia_GetPortTriggerByIndex (UtopiaContext *ctx, int index, portRangeTrig_t *fwdinfo);

/**
* @brief Update a port trigger rule at the specified 0-based index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] index   - The 0-based index of the port trigger rule to update.
* @param[in] fwdinfo - Pointer to a portRangeTrig_t structure containing the updated trigger rule.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range .
*
*/
int Utopia_SetPortTriggerByIndex (UtopiaContext *ctx, int index, portRangeTrig_t *fwdinfo);

/**
* @brief Delete a port trigger rule at the specified 0-based index.
* \n
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] index - The 0-based index of the port trigger rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if index is out of range.
*
*/
int Utopia_DelPortTriggerByIndex (UtopiaContext *ctx, int index);

/**
* @brief Get a port trigger rule by its rule ID.
*
* @param[in]     ctx        - Pointer to the Utopia context.
* @param[in,out] portinfo   - Pointer to a portRangeTrig_t structure.
*                             \n [in] portinfo->rule_id contains the rule ID to search for.
*                             \n [out] Structure is filled with the matching rule's complete information.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative.
* @retval ERR_ITEM_NOT_FOUND if no rule with the specified ID is found.
* @retval ERR_INVALID_PORT_RANGE if parsing a port range fails.
*
*/
int Utopia_GetPortTriggerByRuleId (UtopiaContext *ctx, portRangeTrig_t *portinfo);

/**
* @brief Update a port trigger rule identified by its rule ID.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] portinfo - Pointer to a portRangeTrig_t structure containing the updated rule.
*                       \n portinfo->rule_id is used to locate the rule to update.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if rule_id is negative.
* @retval ERR_ITEM_NOT_FOUND if no rule with the specified rule_id is found.
*
*/
int Utopia_SetPortTriggerByRuleId (UtopiaContext *ctx, portRangeTrig_t *portinfo);

/**
* @brief Delete a port trigger rule identified by its rule ID.
*
* Removes the rule and shifts subsequent rules to fill the gap.
*
* @param[in] ctx        - Pointer to the Utopia context.
* @param[in] trigger_id - The rule ID of the port trigger rule to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_ITEM_NOT_FOUND if trigger_id is negative or if no rule with the specified ID is found.
*
*/
int Utopia_DelPortTriggerByRuleId (UtopiaContext *ctx, int trigger_id);

/**
* @brief Set DMZ (Demilitarized Zone) settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] dmz - Pointer to a dmz_t structure containing the DMZ settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or dmz is NULL.
*
*/
int Utopia_SetDMZSettings (UtopiaContext *ctx, dmz_t *dmz);

/**
* @brief Get DMZ (Demilitarized Zone) settings.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[out] out_dmz - Pointer to a dmz_t structure where the DMZ settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or out_dmz is NULL.
*
*/
int Utopia_GetDMZSettings (UtopiaContext *ctx, dmz_t *out_dmz);

/**
* @brief Add a new Internet Access Policy or update an existing one by policy name.
*
* If a policy with the same name exists, it will be updated. Otherwise, a new policy is appended.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] iap - Pointer to an iap_entry_t structure containing the Internet Access Policy.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or iap is NULL.
* @retval UT_SUCCESS if the policy is successfully added or updated.
*
*/
int Utopia_AddInternetAccessPolicy (UtopiaContext *ctx, iap_entry_t *iap);

/**
* @brief Edit an existing Internet Access Policy at the specified 1-based index.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] index - The 1-based index of the IAP entry to edit.
* @param[in] iap   - Pointer to an iap_entry_t structure containing the updated policy information.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL, iap is NULL, index is less than 1, or index exceeds the policy count.
*
*/
int Utopia_EditInternetAccessPolicy (UtopiaContext *ctx, int index, iap_entry_t *iap);

/**
* @brief Add or update LAN hosts for an Internet Access Policy identified by policy name.
* \n
* If the policy exists, only the LAN hosts portion is updated. Otherwise, a new policy is created with the specified LAN hosts.
*
* @param[in] ctx        - Pointer to the Utopia context.
* @param[in] policyname - Pointer to a null-terminated string containing the policy name.
* @param[in] lanhosts   - Pointer to a lanHosts_t structure containing the LAN hosts to associate with the policy.
*                         \n Includes: IP address list, MAC address list, IP range list.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, policyname, or lanhosts is NULL.
*
*/
int Utopia_AddInternetAccessPolicyLanHosts (UtopiaContext *ctx, const char *policyname, lanHosts_t *lanhosts);

/**
* @brief Delete an Internet Access Policy by policy name.
* \n
* Removes the policy and shifts subsequent entries to fill the gap.
*
* @param[in] ctx        - Pointer to the Utopia context.
* @param[in] policyname - Pointer to a null-terminated string containing the policy name to delete.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or policyname is NULL.
* @retval ERR_INVALID_VALUE if no policy with the specified name is found.
*
*/
int Utopia_DeleteInternetAccessPolicy (UtopiaContext *ctx, const char *policyname);

/**
* @brief Get all configured Internet Access Policies.
*
* This function allocates memory for the IAP array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[out] out_count - Pointer to an integer where the number of policies will be returned.
* @param[out] out_iap   - Pointer to an iap_entry_t pointer where the allocated array of policies will be returned.
*                         \n Caller must free this memory using Utopia_FreeInternetAccessPolicy when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INVALID_ARGS if ctx, out_count, or out_iap is NULL.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_GetInternetAccessPolicy (UtopiaContext *ctx, int *out_count, iap_entry_t **out_iap);

/**
* @brief Find an Internet Access Policy by policy name.
*
* @param[in]  ctx        - Pointer to the Utopia context.
* @param[in]  policyname - Pointer to a null-terminated string containing the policy name to search for.
* @param[out] out_iap    - Pointer to an iap_entry_t structure where the matching policy will be returned.
* @param[out] out_index  - Optional pointer to an integer where the 1-based index of the found policy will be returned (can be NULL).
*
* @return The status of the operation.
* @retval UT_SUCCESS if a matching policy is found.
* @retval ERR_INVALID_ARGS if ctx, policyname, or out_iap is NULL.
* @retval ERR_ITEM_NOT_FOUND if no policy with the specified name is found.
*
*/
int Utopia_FindInternetAccessPolicy (UtopiaContext *ctx, const char *policyname, iap_entry_t *out_iap, int *out_index);

/**
* @brief Free memory allocated for an Internet Access Policy entry.
*
* Frees all dynamically allocated memory within the iap_entry_t structure including
* LAN host lists, blocked URL/keyword/application lists, and their associated metadata.
*
* @param[in] iap - Pointer to an iap_entry_t structure to free.
*
* @return void
*
*/
void Utopia_FreeInternetAccessPolicy (iap_entry_t *iap);

/**
* @brief Get the list of network service names.
*
* @param[out] out_list - Pointer to a const char pointer where the null-terminated array of service names will be returned.
*                        \n Includes common services: ftp, telnet, ssh, http, https, smtp, dns, etc.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
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
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] fw  - firewall_t structure containing the firewall settings to be set.
*                  \n Includes: SPI protection, content filtering, protocol passthrough, WAN access controls.
*                  \n Supports both IPv4 and IPv6 filtering options.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_SetFirewallSettings (UtopiaContext *ctx, firewall_t fw);

/**
* @brief Get firewall settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] fw  - Pointer to a firewall_t structure where the firewall settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or fw is NULL.
*
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
* @param[in] ctx       - Pointer to the Utopia context.
* @param[in] ipv6_info - Pointer to an ipv6Info_t structure containing the IPv6 settings to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or ipv6_info is NULL.
*
*/
int Utopia_SetIPv6Settings (UtopiaContext *ctx, ipv6Info_t *ipv6_info);

/**
* @brief Get IPv6 settings.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[out] ipv6_info - Pointer to an ipv6Info_t structure where the IPv6 settings will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or ipv6_info is NULL.
*
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
* @brief Restore factory default settings.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSCFG_FAILED if syscfg destroy operation fails.
*
*/
int Utopia_RestoreFactoryDefaults (void);

/**
* @brief Restore configuration from a backup file.
*
* @param[in] config_fname - Pointer to the configuration filename string.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if config_fname is NULL.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
* @retval ERR_FILE_NOT_FOUND if the configuration file cannot be opened.
* @retval ERR_CFGRESTORE_BAD_MAGIC if the configuration file has invalid magic number.
* @retval ERR_CFGRESTORE_BAD_SIZE if the configuration file size is invalid.
* @retval ERR_CFGRESTORE_BAD_VERSION if the configuration file version is invalid.
* @retval ERR_CFGRESTORE_BAD_CRC32 if the configuration file CRC32 check fails.
*
*/
int Utopia_RestoreConfiguration (char *config_fname);

/**
* @brief Backup current configuration to a file.
*
* @param[out] out_config_fname - Pointer to a buffer where the output configuration filename will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_FILE_WRITE_FAILED if the configuration file cannot be written.
* @retval ERR_INSUFFICIENT_MEM if memory allocation fails.
*
*/
int Utopia_BackupConfiguration (char *out_config_fname);

/**
* @brief Upgrade the device firmware.
*
* @param[in] ctx            - Pointer to the Utopia context.
* @param[in] firmware_file  - Pointer to the firmware filename string.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or firmware_file is NULL.
* @retval ERR_FILE_WRITE_FAILED if the firmware file cannot be written.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if firmware upgrade lock cannot be acquired.
*
*/
int Utopia_FirmwareUpgrade (UtopiaContext *ctx, char *firmware_file);

/**
* @brief Check if remote management user is allowed to do firmware upgrades
*
* @param[in] ctx       - Pointer to the Utopia context.
* @param[in] http_port - HTTP port number to check.
*
* @return The status of the operation.
* @retval 1 if firmware upgrade is allowed.
* @retval 0 if firmware upgrade is not allowed.

* @note Checks if the http request is coming from Remote Management (WAN) side by looking at http-port.
*/
int Utopia_IsFirmwareUpgradeAllowed (UtopiaContext *ctx, int http_port);

/**
* @brief Acquire the firmware upgrade lock.
*
* @param[out] lock_fd - Pointer to an integer where the lock file descriptor will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the lock is acquired successfully.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if the lock cannot be acquired.
* @retval ERR_INVALID_ARGS if lock_fd is NULL.
* @retval ERR_FILE_NOT_FOUND if the lock file cannot be opened.
*
*/
int Utopia_AcquireFirmwareUpgradeLock (int *lock_fd);

/**
* @brief Release the firmware upgrade lock.
*
* @param[in] lock_fd - Lock file descriptor to release.
*
* @return The status of the operation.
* @retval SUCCESS if the lock is released successfully.
* @retval ERR_INVALID_ARGS if lock_fd is invalid.
* @retval ERR_FW_UPGRADE_LOCK_CONFLICT if the lock cannot be acquired.
*
*/
int Utopia_ReleaseFirmwareUpgradeLock (int lock_fd);

/**
* @brief Check if system changes are allowed.
*
* @return The status of the operation.
* @retval 1 if system changes are allowed.
* @retval 0 if system changes are disallowed.
*
*/
int Utopia_SystemChangesAllowed (void);

/**
* @brief Reboot the device.
*
* @return The status of the operation.
* @retval SUCCESS if the reboot is initiated successfully.
* @retval ERR_REBOOT_FAILED if the reboot fails.
*
*/
int Utopia_Reboot (void);

/**
* @brief Set the Web UI admin password.
*
* @param[in] ctx                 - Pointer to the Utopia context.
* @param[in] username            - Pointer to the username string.
* @param[in] cleartext_password  - Pointer to the cleartext password string.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the password is set successfully.
* @retval ERR_INVALID_ARGS if ctx, username, or cleartext_password is NULL.
* @retval ERR_FILE_NOT_FOUND if the password file cannot be opened.
* @retval ERR_INVALID_VALUE if the username or password is invalid.
*
*/
int Utopia_SetWebUIAdminPasswd (UtopiaContext *ctx, char *username, char *cleartext_password);

/**
* @brief Check if the admin password is set to the default value.
*
* @param[in]  ctx              - Pointer to the Utopia context.
* @param[out] is_admin_default - Pointer to a boolean_t where the default status will be returned.
*                                \n TRUE if admin password is the default value, FALSE otherwise.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or is_admin_default is NULL.
*
*/
int Utopia_IsAdminDefault (UtopiaContext *ctx, boolean_t *is_admin_default);

/**
* @brief Set Web UI access settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ui  - Pointer to a webui_t structure containing the Web UI settings to be set.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or ui is NULL.
*
*/
int Utopia_SetWebUISettings (UtopiaContext *ctx, webui_t *ui);

/**
* @brief Get Web UI access settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] ui  - Pointer to a webui_t structure where the Web UI settings will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or ui is NULL.
*
*/
int Utopia_GetWebUISettings (UtopiaContext *ctx, webui_t *ui);

/**
* @brief Set IGD (Internet Gateway Device) configuration settings.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] igd - Pointer to an igdconf_t structure containing the IGD settings to be set.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or igd is NULL.
*
*/
int Utopia_SetIGDSettings (UtopiaContext *ctx, igdconf_t *igd);

/**
* @brief Get IGD (Internet Gateway Device) configuration settings.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] igd - Pointer to an igdconf_t structure where the IGD settings will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or igd is NULL.
*
*/
int Utopia_GetIGDSettings (UtopiaContext *ctx, igdconf_t *igd);

/*
 * Logging and Diagnostics
 */

/**
* @brief Get the incoming traffic log entries.
*
* Retrieves firewall log entries for incoming traffic (WAN to LAN/SELF ACCEPT).
* This function allocates memory for the log array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the number of log entries will be returned.
*                     \n Maximum entries: 128.
* @param[out] ilog  - Pointer to a logentry_t pointer where the allocated array of log entries will be returned.
*                     \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INVALID_ARGS if count or ilog is NULL.
* @retval ERR_FILE_NOT_FOUND if the log file cannot be opened.
* @retval other error codes otherwise.
*
*/
int Utopia_GetIncomingTrafficLog (UtopiaContext *ctx, int *count, logentry_t **ilog);

/**
* @brief Get the outgoing traffic log entries.
*
* Retrieves firewall log entries for outgoing traffic (LAN to WAN ACCEPT).
* This function allocates memory for the log array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the number of log entries will be returned.
*                     \n Maximum entries: 64.
* @param[out] olog  - Pointer to a logentry_t pointer where the allocated array of log entries will be returned.
*                     \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_INVALID_ARGS if count or olog is NULL.
* @retval ERR_FILE_NOT_FOUND if the log file cannot be opened.
* @retval other error codes otherwise.
*
*/
int Utopia_GetOutgoingTrafficLog (UtopiaContext *ctx, int *count, logentry_t **olog);

/**
* @brief Get the security log entries.
* \n
* Retrieves firewall log entries for dropped packets (WAN to SELF/ATTACK DROP).
* \n This function allocates memory for the log array. Caller is responsible for freeing the memory.
*
* @param[in]  ctx   - Pointer to the Utopia context (unused, can be NULL).
* @param[out] count - Pointer to an integer where the number of log entries will be returned.
*                     \n Maximum entries: 64.
* @param[out] slog  - Pointer to a logentry_t pointer where the allocated array of log entries will be returned.
*                     \n Caller must free this memory when done.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_FILE_NOT_FOUND if the log file cannot be opened.
* @retval other error codes otherwise.
*
*/
int Utopia_GetSecurityLog (UtopiaContext *ctx, int *count, logentry_t **slog);

/**
* @brief Get the DHCP client log and save it to a file.
*
* Retrieves DHCP log entries (DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM) and saves to /tmp/dhcp_log.txt.
*
* @param[in] ctx - Pointer to the Utopia context (unused, can be NULL).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (including when count is 0).
* @retval ERR_FILE_NOT_FOUND if the log file cannot be opened.
* @retval other error codes otherwise.
*
*/
int Utopia_GetDHCPClientLog (UtopiaContext *ctx);

/**
* @brief Set logging settings.
*
* @param[in] ctx         - Pointer to the Utopia context.
* @param[in] log_enabled - Boolean flag to enable or disable logging.
* @param[in] log_viewer  - Pointer to log viewer IP address string (can be empty).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetLogSettings (UtopiaContext *ctx, boolean_t log_enabled, char *log_viewer);

/**
* @brief Get logging settings.
*
* @param[in]  ctx         - Pointer to the Utopia context.
* @param[out] log_enabled - Pointer to a boolean_t where the logging enabled status will be returned.
* @param[out] log_viewer  - Buffer where the log viewer IP address will be returned.
* @param[in]  sz          - Size of the log_viewer buffer (should be IPHOSTNAME_SZ).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetLogSettings (UtopiaContext *ctx, boolean_t *log_enabled, char *log_viewer, int sz);

/**
* @brief Start a diagnostic ping test.
*
* @param[in] dest        - Pointer to the destination IP address or hostname string.
* @param[in] packet_size - Size of the ping packet in bytes (must be > 0).
* @param[in] num_ping    - Number of pings to send (0 = indefinite, >= 0).
*                          \n Results are written to /tmp/.ping_log_tmp.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if dest is NULL, packet_size <= 0, or num_ping < 0.
*
*/
int Utopia_DiagPingTestStart (char *dest, int packet_size, int num_ping);

/**
* @brief Stop the currently running diagnostic ping test.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_DiagPingTestStop (void);

/**
* @brief Check if a diagnostic ping test is currently running.
*
* @return Running status.
* @retval 1 if a ping test is running.
* @retval 0 if no ping test is running.
*
*/
int Utopia_DiagPingTestIsRunning (void);

/**
* @brief Start a diagnostic traceroute test.
*
* @param[in] dest - Pointer to the destination IP address or hostname string.
*                   \n Results are written to /tmp/.traceroute_log_tmp.
*                   \n Special handling for 0.0.0.0 and 255.255.255.255 (writes error message).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if dest is NULL.
* @retval ERR_FILE_NOT_FOUND if the log file cannot be opened for special cases.
*
*/
int Utopia_DiagTracerouteTestStart (char *dest);

/**
* @brief Stop the currently running diagnostic traceroute test.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_DiagTracerouteTestStop (void);

/**
* @brief Check if a diagnostic traceroute test is currently running.
*
* @return Running status.
* @retval 1 if a traceroute test is running.
* @retval 0 if no traceroute test is running.
*
*/
int Utopia_DiagTracerouteTestIsRunning (void);

/**
* @brief Execute a diagnostic ping test to a destination host.
*
* This function performs a network connectivity diagnostic test by sending ICMP echo requests (ping) to the specified destination.
*
* @param[in] ctx         - Pointer to the Utopia context.
* @param[in] dest        - Pointer to the destination IP address or hostname string.
* @param[in] packet_size - Size of the ICMP data payload in bytes.
.
* @param[in] num_ping    - Number of ping packets to send.
*
* @return The status of the operation.
* @retval SUCCESS if the ping test is successfully started.
* @retval ERR_INVALID_ARGS if dest is NULL, packet_size <= 0, or num_ping < 0.
*
*/
int diagPingTest (UtopiaContext *ctx, String dest, int packet_size, int num_ping);

/**
* @brief Execute a diagnostic traceroute test to trace the network path to a destination host.
*
* This function performs a network path diagnostic test by tracing the route packets take to reach the specified destination.
*
* @param[in] ctx            - Pointer to the Utopia context.
* @param[in] dest           - Pointer to the destination IP address or hostname string.

* @param[out] results_buffer - Pointer to a char pointer where the traceroute results will be returned.
*                              \n Caller is responsible for freeing the allocated buffer.
*
* @return The status of the operation.
* @retval SUCCESS if the traceroute test is successfully started.
* @retval ERR_INVALID_ARGS if dest is NULL.
*
*/
int diagTraceroute (UtopiaContext *ctx, String dest, char **results_buffer);

/**
* @brief Initiate a PPP connection.
*
* Triggers the wan-start sysevent to start the WAN PPP connection.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_PPPConnect (void);

/**
* @brief Disconnect a PPP connection.
*
* Triggers the wan-stop sysevent to stop the WAN PPP connection.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
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
* @brief Get BYOI (Bring Your Own Internet) allowed status.
*
* This API is used to control to UI pages display
*\n if the status is docsis - no UI page for internet setting.
*\n if the status is non-docsis- UI page with WAN option(byoi) and None( no internet).
*\n if the status is user - UI page with Cable(primary provider), WAN(byoi) and None(no internet) will be provided.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] value - Pointer to an integer where the BYOI allowed state will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_Get_BYOI_allowed(UtopiaContext *ctx,  int *value);

/**
* @brief Get the current BYOI provider status.
* \n
* Returns the current HSD mode the user is operating in.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[out] hsdStatus - Pointer to an hsdStatus_t where the current provider status will be returned.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or hsdStatus is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_Get_BYOI_Current_Provider(UtopiaContext *ctx,  hsdStatus_t *hsdStatus);

/**
* @brief Set the desired BYOI provider.
*
* Sets the desired HSD mode and triggers sysevent for mode change.
*
* @param[in] ctx       - Pointer to the Utopia context.
* @param[in] hsdStatus - The desired provider status to set.
*
* @return The status of the operation.
* @retval UT_SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
*
*/
int Utopia_Set_BYOI_Desired_Provider(UtopiaContext *ctx,  hsdStatus_t hsdStatus);

/**
* @brief Get the Web UI timeout value in minutes.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the timeout value (in minutes) will be returned.
*                     \n Initialized to 0 before retrieval.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetWebTimeout(UtopiaContext *ctx, int *count);

/**
* @brief Set the Web UI timeout value in minutes.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] count - The timeout value (in minutes) to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
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
* @brief Get HTTP home user credentials.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[out] httpuser - Pointer to an http_user_t structure where the user credentials will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or httpuser is NULL.
*
*/
int Utopia_Get_Http_User(UtopiaContext *ctx,  http_user_t *httpuser);

/**
* @brief Set HTTP home user credentials.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] httpuser - Pointer to an http_user_t structure containing the user credentials to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_Set_Http_User(UtopiaContext *ctx, http_user_t *httpuser);

/**
* @brief Get HTTP admin credentials.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[out] httpuser - Pointer to an http_user_t structure where the admin credentials will be returned.

*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or httpuser is NULL.
*
*/
int Utopia_Get_Http_Admin(UtopiaContext *ctx, http_user_t *httpuser);

/**
* @brief Set HTTP admin credentials.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] httpuser - Pointer to an http_user_t structure containing the admin credentials to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_Set_Http_Admin(UtopiaContext *ctx, http_user_t *httpuser);

/**
* @brief Set the provisioning code.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] val - Pointer to the provisioning code string to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_Set_Prov_Code(UtopiaContext *ctx, char *val);

/**
* @brief Get the provisioning code.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] val - Buffer where the provisioning code will be returned (NAME_SZ bytes).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or val is NULL.
*
*/
int Utopia_Get_Prov_Code(UtopiaContext *ctx, char *val);

/**
* @brief Get the device first use date.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] val - Buffer where the first use date will be returned (NAME_SZ bytes).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or val is NULL.
*
*/
int Utopia_Get_First_Use_Date(UtopiaContext *ctx,  char *val);

/* NTP Functions */

/**
* @brief Set the NTP server address for a specific index.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] server - Pointer to the NTP server address string (empty string sets to "no_ntp_address").
* @param[in] index  - NTP server index (1-5).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or server is NULL.
*
*/
int Utopia_Set_DeviceTime_NTPServer(UtopiaContext *ctx, char *server, int index);

/**
* @brief Get the NTP server address for a specific index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] server - Buffer where the NTP server address will be returned (UTOPIA_TR181_PARAM_SIZE bytes).
*                      \n Returns empty string if value is "no_ntp_address".
* @param[in]  index  - NTP server index (1-5).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or server is NULL.
* @retval ERR_SYSCFG_FAILED if syscfg get operation fails.
*
*/
int Utopia_Get_DeviceTime_NTPServer(UtopiaContext *ctx, char *server,int index);

/**
* @brief Set the local timezone.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] tz  - Pointer to the timezone string.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or tz is NULL.
*
*/
int Utopia_Set_DeviceTime_LocalTZ(UtopiaContext *ctx, char *tz);

/**
* @brief Get the local timezone.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] tz  - Buffer where the timezone will be returned (UTOPIA_TR181_PARAM_SIZE1 bytes).
*                   \n Buffer is zeroed before retrieval.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx or tz is NULL.
* @retval ERR_SYSCFG_FAILED if syscfg get operation fails.
*
*/
int Utopia_Get_DeviceTime_LocalTZ(UtopiaContext *ctx, char *tz);

/**
* @brief Enable or disable NTP time synchronization.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - Enable flag (TRUE/FALSE).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx is NULL.
*
*/
int Utopia_Set_DeviceTime_Enable(UtopiaContext *ctx, unsigned char enable);

/**
* @brief Get NTP time synchronization enabled status.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return NTP enabled status.
* @retval TRUE if NTP is enabled.
* @retval FALSE if NTP is disabled or ctx is NULL.
*
*/
unsigned char Utopia_Get_DeviceTime_Enable(UtopiaContext *ctx);

/**
* @brief Get the NTP synchronization status.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return NTP synchronization status.
* @retval 0 or positive integer representing the status.
*
*/
int Utopia_Get_DeviceTime_Status(UtopiaContext *ctx);

/**
* @brief Enable or disable daylight saving time.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - Enable flag (TRUE/FALSE).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_INIT if ctx is NULL.
*
*/
int Utopia_Set_DeviceTime_DaylightEnable(UtopiaContext *ctx, unsigned char enable);

/**
* @brief Get daylight saving time enabled status.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return Daylight saving time enabled status.
* @retval TRUE if daylight saving time is enabled.
* @retval FALSE if daylight saving time is disabled or ctx is NULL.
*
*/
unsigned char Utopia_Get_DeviceTime_DaylightEnable(UtopiaContext *ctx);

/**
* @brief Get the daylight saving time offset in minutes.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] count - Pointer to an integer where the daylight offset (in minutes) will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_Get_DeviceTime_DaylightOffset(UtopiaContext *ctx, int *count);

/**
* @brief Set the daylight saving time offset in minutes.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] count - The daylight offset value (in minutes) to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_Set_DeviceTime_DaylightOffset(UtopiaContext *ctx, int count);

/**
* @brief Get the management WAN MAC address.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] val - Buffer where the MAC address will be returned (MACADDR_SZ bytes).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or val is NULL.
*
*/
int Utopia_Get_Mac_MgWan(UtopiaContext *ctx,  char *val);

/**
* @brief Get the list of MAC addresses of devices associated with an Ethernet port.
* \n
* Queries the switch for learned MAC addresses on the specified port.
*
* @param[in]  unitId     - Switch unit ID.
* @param[in]  portId     - Switch port ID.
* @param[out] macAddrList - Buffer where MAC addresses will be returned (6 bytes per address).
*                          \n Multicast MAC addresses are excluded.
* @param[out] numMacAddr  - Pointer to an integer where the number of associated devices will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_FILE_OPEN_FAIL if the temporary file cannot be opened.
* @retval ERR_FILE_CLOSE_FAIL if the temporary file cannot be closed.
* @retval ERR_NO_NODES if macAddrList is NULL.
*
*/
int Utopia_GetEthAssocDevices(int unitId, int portId, unsigned char *macAddrList,int *numMacAddr);

/**
* @brief Get the count of LAN management interfaces.
*
* @param[in]  ctx - Pointer to the Utopia context (unused).
* @param[out] val - Pointer to an integer where the LAN interface count will be returned.
*                   \n Currently always returns 1 (single LAN interface supported).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetLanMngmCount(UtopiaContext *ctx, int *val);

/**
* @brief Set the LAN management instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] val - Instance number to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if the value cannot be set.
*
*/
int Utopia_SetLanMngmInsNum(UtopiaContext *ctx, unsigned long int val);

/**
* @brief Get the LAN management instance number.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] val - Pointer to an unsigned long int where the instance number will be returned.
*                   \n Returns 0 if not configured.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetLanMngmInsNum(UtopiaContext *ctx, unsigned long int *val);

/**
* @brief Get the LAN management alias.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[out] buf   - Buffer where the alias will be returned.
* @param[in]  b_len - Size of the buffer.
*                     \n If alias doesn't exist, returns the LAN interface name and sets it as the alias.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if buf is NULL.
*
*/
int Utopia_GetLanMngmAlias(UtopiaContext *ctx, char *buf, size_t b_len );

/**
* @brief Set the LAN management alias.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] val - Pointer to the alias string to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if val is NULL or value cannot be set.
*
*/
int Utopia_SetLanMngmAlias(UtopiaContext *ctx, const char *val);
//int Utopia_GetLanMngmLanMode(UtopiaContext *ctx, lanMngm_LanMode_t *LanMode);
//int Utopia_SetLanMngmLanMode(UtopiaContext *ctx, lanMngm_LanMode_t LanMode);

/**
* @brief Get LAN networks allow setting.
*
* USGv2 platform does not support this feature.
*
* @param[in]  ctx   - Pointer to the Utopia context .
* @param[out] allow - Pointer to an integer where the allow setting will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetLanMngmLanNetworksAllow(UtopiaContext *ctx, int* allow);

/**
* @brief Set LAN networks allow setting.
* \n
* USGv2 platform does not support this feature.
*
* @param[in] ctx   - Pointer to the Utopia context .
* @param[in] allow - Allow setting (must be 0, other values are invalid).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful (allow == 0).
* @retval ERR_INVALID_VALUE if allow != 0.
*
*/
int Utopia_SetLanMngmLanNetworksAllow(UtopiaContext *ctx, int allow);

/**
* @brief Get LAN NAPT (Network Address Port Translation) mode.
*
* Retrieves the current NAT mode for the LAN interface.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] enable - Pointer to a napt_mode_t where the NAPT mode will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or enable is NULL.
*
*/
int Utopia_GetLanMngmLanNapt(UtopiaContext *ctx, napt_mode_t *enable);

/**
* @brief Set LAN NAPT (Network Address Port Translation) mode.
*
* Sets the NAT mode for the LAN interface.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - NAPT mode to set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_SetLanMngmLanNapt(UtopiaContext *ctx, napt_mode_t enable);

#define DNS_CLIENT_NAMESERVER_CNT 10

typedef struct dns_client{
    char dns_server[DNS_CLIENT_NAMESERVER_CNT][IPADDR_SZ];
}DNS_Client_t;

/**
* @brief Set DNS client enable status.
*
* DNS client cannot be disabled on this platform.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - Enable flag (must be TRUE, FALSE is invalid).
*
* @return The status of the operation.
* @retval SUCCESS if enable is TRUE.
* @retval ERR_INVALID_VALUE if enable is FALSE.
*
*/
int Utopia_SetDNSEnable(UtopiaContext *ctx, boolean_t enable);

/**
* @brief Get DNS client enable status.
*
* DNS client is always enabled on this platform.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] enable - Pointer to a boolean_t where the enable status will be returned.
*                      \n Always returns TRUE.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetDNSEnable(UtopiaContext *ctx, boolean_t* enable);

/**
* @brief Get the list of DNS servers from /etc/resolv.conf.
* \n
* Parses the resolv.conf file to retrieve configured DNS servers.
*
* @param[in]  ctx - Pointer to the Utopia context (unused).
* @param[out] dns - Pointer to a DNS_Client_t structure where the DNS servers will be returned.
*                   \n Maximum 10 DNS servers (DNS_CLIENT_NAMESERVER_CNT).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_VALUE if dns is NULL.
* @retval ERR_FILE_NOT_FOUND if /etc/resolv.conf cannot be opened.
*
*/
int Utopia_GetDNSServer(UtopiaContext *ctx, DNS_Client_t * dns);

/**
* @brief Add or remove iptables rules for ephemeral (dynamic) port forwarding.
*
* Manages iptables NAT and filter rules for dynamic port mappings based on system state.
*
* @param[in] pmap        - Pointer to a portMapDyn_t structure containing the port mapping information.
* @param[in] isCallForAdd - Boolean flag indicating operation type.
*                          \n TRUE: Add iptables rules (operation code 'A').
*                          \n FALSE: Delete iptables rules (operation code 'D').
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent daemon.
* @retval ERR_INVALID_VALUE if pmap->enabled is FALSE.
*
*/
int Utopia_IPRule_ephemeral_port_forwarding( portMapDyn_t *pmap, boolean_t isCallForAdd );

/**
* @brief Check if an IP address is within the DHCP address range.
*
* @param[in] ip_to_check - Pointer to the IP address string to check.
*                          \n Compared against dhcp_start and dhcp_end values from syscfg.
*
* @return Check result.
* @retval 1 if IP is within DHCP range, IP is NULL/empty, or parsing fails.
* @retval 0 if IP is outside DHCP range.
*
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
* @brief Get the instance number of a Dynamic DNS client by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - 0-based index of the Dynamic DNS client.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetDynamicDnsClientInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of Dynamic DNS clients.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the client count will be returned.
*                   \n Value is cached in static variable g_DynamicDnsClientCount.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetNumberOfDynamicDnsClient(UtopiaContext *ctx, int *num);

/**
* @brief Get a Dynamic DNS client entry by 0-based index.
*
* @param[in]  ctx               - Pointer to the Utopia context.
* @param[in]  ulIndex           - 0-based index of the Dynamic DNS client.
* @param[out] DynamicDnsClient  - Pointer to a DynamicDnsClient_t structure where the client information will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetDynamicDnsClientByIndex(UtopiaContext *ctx, unsigned long ulIndex, DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Update a Dynamic DNS client entry at the specified 0-based index.
*
* @param[in] ctx              - Pointer to the Utopia context.
* @param[in] ulIndex          - 0-based index of the Dynamic DNS client to update.
* @param[in] DynamicDnsClient - Pointer to a DynamicDnsClient_t structure containing the updated client information.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetDynamicDnsClientByIndex(UtopiaContext *ctx, unsigned long ulIndex, const DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Set the instance number and alias for a Dynamic DNS client at the specified 0-based index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - 0-based index of the Dynamic DNS client.
* @param[in] ins     - Instance number to set.
* @param[in] alias   - Pointer to the alias string to set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetDynamicDnsClientInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ins, const char *alias);

/**
* @brief Add a new Dynamic DNS client entry.
*
* Increments the client count and adds the entry at the next available index.
*
* @param[in] ctx              - Pointer to the Utopia context.
* @param[in] DynamicDnsClient - Pointer to a DynamicDnsClient_t structure containing the client information to add.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddDynamicDnsClient(UtopiaContext *ctx, const DynamicDnsClient_t *DynamicDnsClient);

/**
* @brief Delete a Dynamic DNS client entry by instance number.
*
* Searches for the client by instance number, removes it, and shifts subsequent entries.
* Decrements the client count.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the Dynamic DNS client to delete.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
* @retval -1 if no client with the specified instance number is found.
*
*/
int Utopia_DelDynamicDnsClient(UtopiaContext *ctx, unsigned long ins);
#endif

#endif // _UTAPI_H_
