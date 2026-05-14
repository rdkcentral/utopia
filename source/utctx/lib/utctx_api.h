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
 * utctx_api.h - Utopia system api
 */

#ifndef __UTCTX_API_H__
#define __UTCTX_API_H__

#include "autoconf.h"
#include <utctx/utctx.h>

/* Utopia defines  */
#define UTOPIA_STATE_SIZE           (32 * (1024))
#define UTOPIA_BUF_SIZE             2048
#define UTOPIA_KEY_NS_SIZE          64
#define UTOPIA_MAX_PASSWD_LENGTH    64
#define UTOPIA_MIN_PASSWD_LENGTH    1
#define UTOPIA_MAX_USERNAME_LENGTH  63
#define UTOPIA_DEFAULT_ADMIN_PASSWD "admin"
#define UTOPIA_DEFAULT_ADMIN_USER   "admin"

/*
 * Utopia value enum
 */
typedef enum _UtopiaValue
{
    UtopiaValue__UNKNOWN__ = 0,

    /* UtopiaValues used by the unittest framework */
#ifdef UTCTX_UNITTEST
    UtopiaValue__TEST_BEGIN__,
    UtopiaValue_Static_TestOne,
    UtopiaValue_Config_TestTwo,
    UtopiaValue_Indexed_TestOne,
    UtopiaValue_Indexed_TestTwo,
    UtopiaValue_Indexed2_TestOne,
    UtopiaValue_Indexed2_TestTwo,
    UtopiaValue_Indexed2_TestThree,
    UtopiaValue_Named_TestOne,
    UtopiaValue_Named_TestTwo,
    UtopiaValue_Named2_TestOne,
    UtopiaValue_Named2_TestTwo,
    UtopiaValue_Named2_TestThree,
    UtopiaValue_Event_TestOne,
    UtopiaValue_Event_TestTwo,
    UtopiaValue__TEST_LAST__,
#endif

    UtopiaValue_DeviceType,
    UtopiaValue_ModelDescription,
    UtopiaValue_ModelName,
    UtopiaValue_ModelRevision,
    UtopiaValue_PresentationURL,
    UtopiaValue_VendorName,
    UtopiaValue_AutoDST,
    UtopiaValue_DefHwAddr,
    UtopiaValue_HostName,
    UtopiaValue_Locale,
    UtopiaValue_LogLevel,
    UtopiaValue_LogRemote,
    UtopiaValue_NATEnabled,
    UtopiaValue_SambaServerEnabled,
    UtopiaValue_TZ,
    UtopiaValue_DDNS_Enable,
    UtopiaValue_DDNS_Service,
    UtopiaValue_DDNS_UpdateDays,
    UtopiaValue_DDNS_LastUpdate,
    UtopiaValue_DDNS_Hostname,
    UtopiaValue_DDNS_Username,
    UtopiaValue_DDNS_Password,
    UtopiaValue_DDNS_Mx,
    UtopiaValue_DDNS_MxBackup,
    UtopiaValue_DDNS_Wildcard,
    UtopiaValue_DDNS_Server,
    UtopiaValue_DHCP_ServerEnabled,
    UtopiaValue_DHCP_Start,
    UtopiaValue_DHCP_End,
    UtopiaValue_DHCP_Num,
    UtopiaValue_DHCP_LeaseTime,
    UtopiaValue_DHCP_Nameserver_Enabled,
    UtopiaValue_DHCP_Nameserver1,
    UtopiaValue_DHCP_Nameserver2,
    UtopiaValue_DHCP_Nameserver3,
    UtopiaValue_DHCP_WinsServer,
    UtopiaValue_DHCP_NumStaticHosts,
    UtopiaValue_DMZ_Enabled,
    UtopiaValue_DMZ_SrcAddrRange,
    UtopiaValue_DMZ_DstIpAddr,
    UtopiaValue_DMZ_DstIpAddrV6,
    UtopiaValue_DMZ_DstMacAddr,
    UtopiaValue_User_AdminPassword,
    UtopiaValue_User_RootPassword,
    UtopiaValue_HTTP_AdminPassword,
    UtopiaValue_HTTP_AdminPort,
    UtopiaValue_HTTP_AdminUser,
    UtopiaValue_HTTP_AdminIsDefault,
    UtopiaValue_Mgmt_HTTPAccess,
    UtopiaValue_Mgmt_HTTPSAccess,
    UtopiaValue_Mgmt_WIFIAccess,
    UtopiaValue_Mgmt_WANAccess,
    UtopiaValue_Mgmt_WANHTTPAccess,
    UtopiaValue_Mgmt_WANHTTPSAccess,
    UtopiaValue_Mgmt_WANHTTPPort,
    UtopiaValue_Mgmt_WANHTTPSPort,
    UtopiaValue_Mgmt_WANFWUpgrade,
    UtopiaValue_Mgmt_WANSrcAny,
    UtopiaValue_Mgmt_WANSrcStartIP,
    UtopiaValue_Mgmt_WANSrcStartIPV6,
    UtopiaValue_Mgmt_WANSrcEndIP,
    UtopiaValue_Mgmt_WANSrcEndIPV6,
    UtopiaValue_Mgmt_WANIPrangeCount,
    UtopiaValue_Mgmt_WANIPrange,
    UtopiaValue_Mgmt_WANIPrange_SrcEndIP,
    UtopiaValue_Mgmt_WANIPRange_SrcStartIP,
    UtopiaValue_Mgmt_WANIPrange_Desp,
    UtopiaValue_Mgmt_WANIPrange_InsNum,
    UtopiaValue_Mgmt_IGDEnabled,
    UtopiaValue_Mgmt_IGDUserConfig,
    UtopiaValue_Mgmt_IGDWANDisable,
    UtopiaValue_Mgmt_MsoAccess,
    UtopiaValue_Mgmt_CusadminAccess,
    UtopiaValue_LAN_Domain,
    UtopiaValue_LAN_EthernetPhysicalIfNames,
    UtopiaValue_LAN_EthernetVirtualIfNum,
    UtopiaValue_LAN_IPAddr,
    UtopiaValue_LAN_IfName,
    UtopiaValue_LAN_Netmask,
    UtopiaValue_NTP_Server1,
    UtopiaValue_NTP_Server2,
    UtopiaValue_NTP_Server3,
    UtopiaValue_NTP_Server4,
    UtopiaValue_NTP_Server5,
    UtopiaValue_NTP_DaylightEnable,
    UtopiaValue_NTP_DaylightOffset,
    UtopiaValue_RIP_Enabled,
    UtopiaValue_RIP_NoSplitHorizon,
    UtopiaValue_RIP_InterfaceLAN,
    UtopiaValue_RIP_InterfaceWAN,
    UtopiaValue_RIP_MD5Passwd,
    UtopiaValue_RIP_TextPasswd,
    UtopiaValue_StaticRoute_Count,
    UtopiaValue_WAN_Proto,
    UtopiaValue_WAN_IPAddr,
    UtopiaValue_WAN_Netmask,
    UtopiaValue_WAN_DefaultGateway,
    UtopiaValue_WAN_EnableStaticNameServer,
    UtopiaValue_WAN_NameServer1,
    UtopiaValue_WAN_NameServer2,
    UtopiaValue_WAN_NameServer3,
    UtopiaValue_WAN_ProtoUsername,
    UtopiaValue_WAN_ProtoPassword,
    UtopiaValue_WAN_PPPConnMethod,
    UtopiaValue_WAN_PPPKeepAliveInterval,
    UtopiaValue_WAN_PPPIdleTime,
    UtopiaValue_WAN_ProtoRemoteName,
    UtopiaValue_WAN_ProtoAuthDomain,
    UtopiaValue_WAN_PPPoEServiceName,
    UtopiaValue_WAN_PPPoEAccessConcentratorName,
    UtopiaValue_WAN_ProtoServerAddress,
    UtopiaValue_WAN_PPTPAddressStatic,
    UtopiaValue_WAN_L2TPAddressStatic,
    UtopiaValue_WAN_TelstraServer,
    UtopiaValue_WAN_MTU,
    UtopiaValue_WAN_PhysicalIfName,
    UtopiaValue_WAN_VirtualIfNum,
    UtopiaValue_LAN_DHCPClient,
    UtopiaValue_Bridge_Mode,
    UtopiaValue_Bridge_IPAddress,
    UtopiaValue_Bridge_Netmask,
    UtopiaValue_Bridge_DefaultGateway,
    UtopiaValue_Bridge_Domain,
    UtopiaValue_Bridge_NameServer1,
    UtopiaValue_Bridge_NameServer2,
    UtopiaValue_Bridge_NameServer3,
    UtopiaValue_WLAN_ConfigMode,
    UtopiaValue_WLAN_MACFilter,
    UtopiaValue_WLAN_AccessRestriction,
    UtopiaValue_WLAN_ClientList,
    UtopiaValue_WLAN_PhysicalIfNames,
    UtopiaValue_WLAN_WMMSupport,
    UtopiaValue_WLAN_NoAcknowledgement,
    UtopiaValue_WLAN_BridgeMode,
    UtopiaValue_WLAN_BridgeSSID,
    UtopiaValue_QoS_Enable,
    UtopiaValue_QoS_DefPolicyCount,
    UtopiaValue_QoS_UserDefPolicyCount,
    UtopiaValue_QoS_PolicyCount,
    UtopiaValue_QoS_MacAddrCount,
    UtopiaValue_QoS_EthernetPortCount,
    UtopiaValue_QoS_VoiceDeviceCount,
    UtopiaValue_QoS_EthernetPort1,
    UtopiaValue_QoS_EthernetPort2,
    UtopiaValue_QoS_EthernetPort3,
    UtopiaValue_QoS_EthernetPort4,
    UtopiaValue_QoS_WanDownloadSpeed,
    UtopiaValue_QoS_WanUploadSpeed,
    UtopiaValue_Firewall_Enabled,
    UtopiaValue_Firewall_BlockPing,
    UtopiaValue_Firewall_BlockPingV6,
    UtopiaValue_Firewall_BlockMulticast,
    UtopiaValue_Firewall_BlockMulticastV6,
    UtopiaValue_Firewall_BlockNatRedir,
    UtopiaValue_Firewall_BlockIdent,
    UtopiaValue_Firewall_BlockIdentV6,
    UtopiaValue_Firewall_BlockWebProxy,
    UtopiaValue_Firewall_BlockJava,
    UtopiaValue_Firewall_BlockActiveX,
    UtopiaValue_Firewall_BlockCookies,
    UtopiaValue_Firewall_BlockHttp,
    UtopiaValue_Firewall_BlockHttpV6,
    UtopiaValue_Firewall_BlockP2p,
    UtopiaValue_Firewall_BlockP2pV6,
    UtopiaValue_Firewall_Level,
    UtopiaValue_Firewall_LevelV6,
    UtopiaValue_Firewall_TrueStaticIpEnable,
    UtopiaValue_Firewall_TrueStaticIpEnableV6,
    UtopiaValue_Firewall_SmartEnable,
    UtopiaValue_Firewall_SmartEnableV6,
    UtopiaValue_Firewall_WanPingEnable,
    UtopiaValue_Firewall_WanPingEnableV6,
    UtopiaValue_Firewall_SPFCount,
    UtopiaValue_Firewall_PFRCount,
    UtopiaValue_Firewall_PRTCount,
    UtopiaValue_Firewall_IAPCount,
    UtopiaValue_Firewall_W2LWKRuleCount,
    UtopiaValue_NAS_SFCount,
    UtopiaValue_WPS_DeviceName,
    UtopiaValue_WPS_DevicePin,
    UtopiaValue_WPS_Manufacturer,
    UtopiaValue_WPS_Method,
    UtopiaValue_WPS_Mode,
    UtopiaValue_WPS_ModelName,
    UtopiaValue_WPS_ModelNumber,
    UtopiaValue_WPS_StationPin,
    UtopiaValue_WPS_UUID,
    UtopiaValue_DHCP_StaticHost,
    UtopiaValue_StaticRoute,
    UtopiaValue_SR_Name,
    UtopiaValue_SR_Dest,
    UtopiaValue_SR_Netmask,
    UtopiaValue_SR_Gateway,
    UtopiaValue_SR_Interface,
    UtopiaValue_FirewallRule,
    UtopiaValue_FW_W2LWellKnown,
    UtopiaValue_FW_W2LWK_Name,
    UtopiaValue_FW_W2LWK_Result,
    UtopiaValue_InternetAccessPolicy,
    UtopiaValue_IAP_Enabled,
    UtopiaValue_IAP_Name,
    UtopiaValue_IAP_EnforcementSchedule,
    UtopiaValue_IAP_Access,
    UtopiaValue_IAP_TR_INST_NUM,
    UtopiaValue_IAP_BlockUrlCount,
    UtopiaValue_IAP_BlockKeywordCount,
    UtopiaValue_IAP_BlockApplicationCount,
    UtopiaValue_IAP_BlockWellknownApplicationCount,
    UtopiaValue_IAP_BlockApplicationRuleCount,
    UtopiaValue_IAP_BlockPing,
    UtopiaValue_IAP_LocalHostList,
    UtopiaValue_IAP_IPHostCount,
    UtopiaValue_IAP_IPRangeCount,
    UtopiaValue_IAP_MACCount,
    UtopiaValue_SinglePortForward,
    UtopiaValue_SPF_Enabled,
    UtopiaValue_SPF_Name,
    UtopiaValue_SPF_Protocol,
    UtopiaValue_SPF_ExternalPort,
    UtopiaValue_SPF_InternalPort,
    UtopiaValue_SPF_ToIp,
    UtopiaValue_SPF_ToIpV6,
    UtopiaValue_PortRangeForward,
    UtopiaValue_PFR_Enabled,
    UtopiaValue_PFR_Name,
    UtopiaValue_PFR_Protocol,
    UtopiaValue_PFR_ExternalPortRange,
    UtopiaValue_PFR_InternalPort,
    UtopiaValue_PFR_InternalPortRangeSize,
    UtopiaValue_PFR_ToIp,
    UtopiaValue_PFR_PublicIp,
	UtopiaValue_PFR_ToIpV6,
    UtopiaValue_QoSPolicy,
    UtopiaValue_QoSDefinedPolicy,
    UtopiaValue_QDP_Name,
    UtopiaValue_QDP_Class,
    UtopiaValue_QoSUserDefinedPolicy,
    UtopiaValue_QUP_Name,
    UtopiaValue_QUP_PortRangeCount,
    UtopiaValue_QUP_Type,
    UtopiaValue_QoSMacAddr,
    UtopiaValue_QMA_Mac,
    UtopiaValue_QMA_Name,
    UtopiaValue_QMA_Class,
    UtopiaValue_QoSVoiceDevice,
    UtopiaValue_QVD_Mac,
    UtopiaValue_QVD_Name,
    UtopiaValue_QVD_Class,
    UtopiaValue_PortRangeTrigger,
    UtopiaValue_PRT_Enabled,
    UtopiaValue_PRT_Name,
    UtopiaValue_PRT_TriggerID,
    UtopiaValue_PRT_TriggerProtocol,
    UtopiaValue_PRT_TriggerRange,
    UtopiaValue_PRT_ForwardProtocol,
    UtopiaValue_PRT_ForwardRange,
    UtopiaValue_PRT_Lifetime,
    UtopiaValue_NAS_SharedFolder,
    UtopiaValue_NSF_Name,
    UtopiaValue_NSF_Folder,
    UtopiaValue_NSF_Drive,
    UtopiaValue_NSF_ReadOnly,
    UtopiaValue_IAP_BlockURL,
    UtopiaValue_IAP_BlockURL_TR_INST_NUM,
    UtopiaValue_IAP_BlockURL_TR_ALIAS,
    UtopiaValue_IAP_BlockKeyword,
    UtopiaValue_IAP_BlockKeyword_TR_INST_NUM,
    UtopiaValue_IAP_BlockKeyword_TR_ALIAS,
    UtopiaValue_IAP_BlockApplication,
    UtopiaValue_IAP_BlockApplication_TR_INST_NUM,
    UtopiaValue_IAP_BlockWKApplication,
    UtopiaValue_IAP_BlockWKApplication_TR_INST_NUM,
    UtopiaValue_IAP_BlockApplicationRule,
    UtopiaValue_IAP_IP,
    UtopiaValue_IAP_IPRange,
    UtopiaValue_IAP_MAC,
    UtopiaValue_QSP_Rule,
    UtopiaValue_QUP_Protocol,
    UtopiaValue_QUP_PortRange,
    UtopiaValue_QUP_Class,
    UtopiaValue_IAP_BlockName,
    UtopiaValue_IAP_BlockProto,
    UtopiaValue_IAP_BlockPortRange,
    UtopiaValue_WLAN_Description,
    UtopiaValue_WLAN_NetworkMode,
    UtopiaValue_WLAN_SSID,
    UtopiaValue_WLAN_SSIDBroadcast,
    UtopiaValue_WLAN_RadioBand,
    UtopiaValue_WLAN_WideChannel,
    UtopiaValue_WLAN_StandardChannel,
    UtopiaValue_WLAN_Channel,
    UtopiaValue_WLAN_SideBand,
    UtopiaValue_WLAN_State,
    UtopiaValue_WLAN_SecurityMode,
    UtopiaValue_WLAN_Passphrase,
    UtopiaValue_WLAN_Key0,
    UtopiaValue_WLAN_Key1,
    UtopiaValue_WLAN_Key2,
    UtopiaValue_WLAN_Key3,
    UtopiaValue_WLAN_TxKey,
    UtopiaValue_WLAN_RadiusServer,
    UtopiaValue_WLAN_RadiusPort,
    UtopiaValue_WLAN_Shared,
    UtopiaValue_WLAN_Encryption,
    UtopiaValue_WLAN_KeyRenewal,
    UtopiaValue_WLAN_ApIsolation,
    UtopiaValue_WLAN_FrameBurst,
    UtopiaValue_WLAN_AuthenticationType,
    UtopiaValue_WLAN_BasicRate,
    UtopiaValue_WLAN_TransmissionRate,
    UtopiaValue_WLAN_N_TransmissionRate,
    UtopiaValue_WLAN_TransmissionPower,
    UtopiaValue_WLAN_CTSProtectionMode,
    UtopiaValue_WLAN_BeaconInterval,
    UtopiaValue_WLAN_DTIMInterval,
    UtopiaValue_WLAN_FragmentationThreshold,
    UtopiaValue_WLAN_RTSThreshold,
    UtopiaValue_WLAN_WPSMode,
    UtopiaValue_FirmwareVersion,
    UtopiaValue_NTP_DhcpServer1,
    UtopiaValue_NTP_DhcpServer2,
    UtopiaValue_NTP_DhcpServer3,
    UtopiaValue_LAN_CurrentState,
    UtopiaValue_USB_DeviceState,
    UtopiaValue_USB_DeviceMountPt,
    UtopiaValue_VLan2Mac,
    UtopiaValue_WAN_CurrentIPAddr,
    UtopiaValue_WAN_CurrentState,
    UtopiaValue_WAN_DefaultRouter,
    UtopiaValue_LAN_Restarting,
    UtopiaValue_WLAN_Restarting,
    UtopiaValue_WAN_Restarting,
    UtopiaValue_SerialNumber,
    UtopiaValue_LAN_CurrentIPAddr,
    /* All IPv6 related SYSEVENT */
    UtopiaValue_IPv6_Connection_State,
    UtopiaValue_IPv6_Current_Lan_IPv6_Address,
    UtopiaValue_IPv6_Current_Lan_IPv6_Address_Ll,
    UtopiaValue_IPv6_Current_Wan_IPv6_Address,
    UtopiaValue_IPv6_Current_Wan_IPv6_Address_Ll,
    UtopiaValue_IPv6_Current_Wan_IPv6_Interface,
    UtopiaValue_IPv6_Domain,
    UtopiaValue_IPv6_Nameserver,
    UtopiaValue_IPv6_Ntp_Server,
    UtopiaValue_IPv6_Prefix,
    /* All IPv6 related SYSCFG */
    UtopiaValue_IPv6_6rd_Common_Prefix4,
    UtopiaValue_IPv6_6rd_Enable,
    UtopiaValue_IPv6_6rd_Relay,
    UtopiaValue_IPv6_6rd_Zone,
    UtopiaValue_IPv6_6rd_Zone_Length,
    UtopiaValue_IPv6_6to4_Enable,
    UtopiaValue_IPv6_Aiccu_Enable,
    UtopiaValue_IPv6_Aiccu_Password,
    UtopiaValue_IPv6_Aiccu_Prefix,
    UtopiaValue_IPv6_Aiccu_Tunnel,
    UtopiaValue_IPv6_Aiccu_User,
    UtopiaValue_IPv6_DHCPv6c_DUID,
    UtopiaValue_IPv6_DHCPv6c_Enable,
    UtopiaValue_IPv6_DHCPv6s_DUID,
    UtopiaValue_IPv6_DHCPv6s_Enable,
    UtopiaValue_IPv6_HE_Client_IPv6,
    UtopiaValue_IPv6_HE_Enable,
    UtopiaValue_IPv6_HE_Password,
    UtopiaValue_IPv6_HE_Prefix,
    UtopiaValue_IPv6_HE_Server_IPv4,
    UtopiaValue_IPv6_HE_Tunnel,
    UtopiaValue_IPv6_HE_User,
    UtopiaValue_IPv6_Bridging_Enable,
    UtopiaValue_IPv6_Ndp_Proxy_Enable,
    UtopiaValue_IPv6_Static_Enable,
    UtopiaValue_IPv6_Lan_Address,
    UtopiaValue_IPv6_RA_Enable,
    UtopiaValue_IPv6_RA_Provisioning_Enable,
    UtopiaValue_IPv6_Default_Gateway,
    UtopiaValue_IPv6_Wan_Address,
    /* End of all IPv6 related */
    UtopiaValue_Primary_HSD_Allowed,
    UtopiaValue_Desired_HSD_Mode,
    UtopiaValue_Current_HSD_Mode,
    UtopiaValue_Last_Configured_HSD_Mode,
    UtopiaValue_BYOI_Bridge_Mode,
    UtopiaValue_Web_Timeout,
    UtopiaValue_Web_Username,
    UtopiaValue_Web_Password,
    UtopiaValue_TR_Prov_Code,
    UtopiaValue_NTP_Enabled,
    UtopiaValue_NTP_Status,
    UtopiaValue_Device_FirstuseDate,
    /*MoCA Intf*/
    UtopiaValue_Moca_Enable,
    UtopiaValue_Moca_Alias,
    UtopiaValue_Moca_PreferredNC,
    UtopiaValue_Moca_PrivEnabledSet,
    UtopiaValue_Moca_FreqCurMaskSet,
    UtopiaValue_Moca_KeyPassPhrase,
    UtopiaValue_Moca_TxPowerLimit,
    UtopiaValue_Moca_PwrCntlPhyTarget,
    UtopiaValue_Moca_BeaconPwrLimit,
    UtopiaValue_WLAN_Alias,
    UtopiaValue_WLAN_Network_Mode,
    UtopiaValue_WLAN_AutoChannelCycle,
    UtopiaValue_WLAN_GuardInterval,
    UtopiaValue_WLAN_Regulatory_Mode,
    UtopiaValue_WLAN_Regulatory_Domain,
    UtopiaValue_WLAN_SSID_Alias,
    UtopiaValue_WLAN_SSID_Instance_Num,
    UtopiaValue_WLAN_AP_Alias,
    UtopiaValue_WLAN_AP_Instance_Num,
    UtopiaValue_WLAN_AP_WMM,
    UtopiaValue_WLAN_AP_WMM_UAPSD,
    UtopiaValue_WLAN_AP_WMM_No_Ack,
    UtopiaValue_WLAN_AP_Retry_Limit,
    UtopiaValue_MAC_MgWan,
    UtopiaValue_WLAN_Radio_Instance_Num,
    UtopiaValue_WLAN_WPS_Enabled,
    UtopiaValue_WLAN_WPS_PIN_Method,
    UtopiaValue_WLAN_WPS_PBC_Method,
    UtopiaValue_DHCP_ServerPool_InsNum,
    UtopiaValue_DHCP_ServerPool_Alias,
    UtopiaValue_DHCP_StaticHost_InsNum,
    UtopiaValue_DHCP_StaticHost_Alias,
    UtopiaValue_User_Count,
    UtopiaValue_UserIndx_InsNum,
    UtopiaValue_UserName,
    UtopiaValue_Password,
    UtopiaValue_User_Enabled,
    UtopiaValue_User_RemoteAccess,
    UtopiaValue_User_Language,
    UtopiaValue_User_Access_Permissions,
    UtopiaValue_WLAN_Enable_MACFilter,
    UtopiaValue_WLAN_NUM_MACFilter,
    UtopiaValue_WLAN_SSID_Num,
    UtopiaValue_WLAN_SSID_Radio,
    UtopiaValue_WLAN_AP_State,
    UtopiaValue_Security_EmailEnabled,
    UtopiaValue_Security_EmailSendTo,
    UtopiaValue_Security_EmailServer,
    UtopiaValue_Security_EmailUsername,
    UtopiaValue_Security_EmailPassword,
    UtopiaValue_Security_EmailFromAddr,
    UtopiaValue_Security_SendLogs,
    UtopiaValue_Security_FirewallBreach,
    UtopiaValue_Security_ParentalControlBreach,
    UtopiaValue_Security_AlertsWarnings,
    UtopiaValue_ParentalControl_ManagedSites_Enabled,
    UtopiaValue_ParentalControl_ManagedSiteBlockedCount,
    UtopiaValue_ParentalControl_ManagedSiteBlocked,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_InsNum,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_Alias,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_Method,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_Site,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_Always,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_StartTime,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_EndTime,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_Days,
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
    UtopiaValue_ParentalControl_ManagedSiteBlocked_MAC,
    UtopiaValue_ParentalControl_ManagedSiteBlocked_DeviceName,
#endif
    UtopiaValue_ParentalControl_ManagedSiteTrustedCount,
    UtopiaValue_ParentalControl_ManagedSiteTrusted,
    UtopiaValue_ParentalControl_ManagedSiteTrusted_InsNum,
    UtopiaValue_ParentalControl_ManagedSiteTrusted_Alias,
    UtopiaValue_ParentalControl_ManagedSiteTrusted_Desc,
    UtopiaValue_ParentalControl_ManagedSiteTrusted_IpType,
    UtopiaValue_ParentalControl_ManagedSiteTrusted_IpAddr,
#ifdef _HUB4_PRODUCT_REQ_
    UtopiaValue_ParentalControl_ManagedSiteTrusted_MacAddr,
#endif
    UtopiaValue_ParentalControl_ManagedSiteTrusted_Trusted,
    UtopiaValue_ParentalControl_ManagedServices_Enabled,
    UtopiaValue_ParentalControl_ManagedServiceBlockedCount,
    UtopiaValue_ParentalControl_ManagedServiceBlocked,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_InsNum,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_Alias,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_Desc,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_Proto,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_StartPort,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_EndPort,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_Always,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_StartTime,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_EndTime,
    UtopiaValue_ParentalControl_ManagedServiceBlocked_Days,
    UtopiaValue_ParentalControl_ManagedServiceTrustedCount,
    UtopiaValue_ParentalControl_ManagedServiceTrusted,
    UtopiaValue_ParentalControl_ManagedServiceTrusted_InsNum,
    UtopiaValue_ParentalControl_ManagedServiceTrusted_Alias,
    UtopiaValue_ParentalControl_ManagedServiceTrusted_Desc,
    UtopiaValue_ParentalControl_ManagedServiceTrusted_IpType,
    UtopiaValue_ParentalControl_ManagedServiceTrusted_IpAddr,
#ifdef _HUB4_PRODUCT_REQ_
    UtopiaValue_ParentalControl_ManagedServiceTrusted_MacAddr,
#endif
    UtopiaValue_ParentalControl_ManagedServiceTrusted_Trusted,
    UtopiaValue_ParentalControl_ManagedDevices_Enabled,
    UtopiaValue_ParentalControl_ManagedDevices_AllowAll,
    UtopiaValue_ParentalControl_ManagedDeviceCount,
    UtopiaValue_ParentalControl_ManagedDevice,
    UtopiaValue_ParentalControl_ManagedDevice_InsNum,
    UtopiaValue_ParentalControl_ManagedDevice_Alias,
    UtopiaValue_ParentalControl_ManagedDevice_Block,
    UtopiaValue_ParentalControl_ManagedDevice_Desc,
    UtopiaValue_ParentalControl_ManagedDevice_MacAddr,
    UtopiaValue_ParentalControl_ManagedDevice_Always,
    UtopiaValue_ParentalControl_ManagedDevice_StartTime,
    UtopiaValue_ParentalControl_ManagedDevice_EndTime,
    UtopiaValue_ParentalControl_ManagedDevice_Days,
    #if defined(DDNS_BROADBANDFORUM)
    UtopiaValue_DynamicDnsClientCount,
    UtopiaValue_DynamicDnsClient,
    UtopiaValue_DynamicDnsClient_InsNum,
    UtopiaValue_DynamicDnsClient_Alias,
    UtopiaValue_DynamicDnsClient_Enable,
    UtopiaValue_DynamicDnsClient_Username,
    UtopiaValue_DynamicDnsClient_Password,
    UtopiaValue_DynamicDnsClient_Server,
    #endif

    /*Added for USGv2 Project*/
    UtopiaValue_USGv2_Lan_Clients_Count,
    UtopiaValue_USGv2_Lan_Clients,
    UtopiaValue_USGv2_Lan_Clients_Mac,
	UtopiaValue_PNM_Status,
	UtopiaValue_SPF_PrevRuleEnabledState,
	UtopiaValue_PFR_PrevRuleEnabledState,
	UtopiaValue_PRT_PrevRuleEnabledState,
    UtopiaValue_HashPassword,
    #if defined(_WAN_MANAGER_ENABLED_)
      UtopiaValue_WanMode,
      UtopiaValue_WanConnEnabled,
    #endif /*_WAN_MANAGER_ENABLED_*/
    #if defined(DSLITE_FEATURE_SUPPORT)
    UtopiaValue_Dslite_Enable,
    UtopiaValue_Dslite_Count,
    UtopiaValue_Dslite_InsNum,
    UtopiaValue_Dslite_Active,
    UtopiaValue_Dslite_Status,
    UtopiaValue_Dslite_Alias,
    UtopiaValue_Dslite_Mode,
    UtopiaValue_Dslite_Addr_Type,
    UtopiaValue_Dslite_Addr_Inuse,
    UtopiaValue_Dslite_Addr_Fqdn,
    UtopiaValue_Dslite_Addr_IPv6,
    UtopiaValue_Dslite_Origin,
    UtopiaValue_Dslite_Tunnel_Interface,
    UtopiaValue_Dslite_Tunneled_Interface,
    UtopiaValue_Dslite_Mss_Clamping_Enable,
    UtopiaValue_Dslite_Tcpmss,
    UtopiaValue_Dslite_IPv6_Frag_Enable,
    UtopiaValue_Dslite_Tunnel_V4Addr,
    #endif /* DSLITE_FEATURE_SUPPORT */
    UtopiaValue__LAST__
} UtopiaValue;

/**
* @brief Retrieve a Utopia key string for a given UtopiaValue index.
*
* This function retrieves the key string associated with a UtopiaValue index.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying which key to retrieve.
* @param[out] pszBuffer - Pointer to a buffer where the key string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the key was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetKey(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia key string with a numerically indexed key.
*
* This function retrieves the key string for a UtopiaValue that uses numeric indexing.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex - The numeric index to append to the key.
* @param[out] pszBuffer - Pointer to a buffer where the indexed key string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the indexed key was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetIndexedKey(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia key string with a two-dimensionally indexed key.
*
* This function retrieves the key string for a UtopiaValue that uses two-dimensional numeric indexing.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex1 - The first numeric index dimension.
* @param[in] iIndex2 - The second numeric index dimension.
* @param[out] pszBuffer - Pointer to a buffer where the indexed key string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally indexed key was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetIndexed2Key(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex1, int iIndex2, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia key string that is indexed with a string name.
*
* This function retrieves the key string for a UtopiaValue that uses string-based indexing.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName - Null-terminated string used as the name index.
* @param[out] pszBuffer - Pointer to a buffer where the named key string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the named key was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetNamedKey(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve Utopia key that is two-dimensionally indexed by string names.
*
* This function retrieves the key string for a UtopiaValue that uses two-dimensional string-based indexing.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName1 - Null-terminated string for the first name index dimension.
* @param[in] pszName2 - Null-terminated string for the second name index dimension.
* @param[out] pszBuffer - Pointer to a buffer where the two-dimensionally named key string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally named key was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetNamed2Key(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName1, char* pszName2, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia value for a given UtopiaValue index.
*
* This function retrieves the value associated with a UtopiaValue index from either the configuration system,
* event system, or static value table depending on the UtopiaValue type.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying which value to retrieve.
* @param[out] pszBuffer - Pointer to a buffer where the value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_Get(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Returns all set Utopia values in a formatted string.
*
* This function retrieves all currently set configuration and event values from the Utopia system
* and returns them in a formatted string with the format '<namespace>::<key>=<value>\n' for each entry.

*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[out] pszBuffer - Pointer to a null-terminated buffer where all values will be stored in the format
*                    \n '<namespace>::<key>=<value>\n' for each entry.
*                    \n Must be allocated by the caller with sufficient size.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*                    \n Should be at least UTOPIA_STATE_SIZE (32KB) for complete retrieval.
*
* @return The status of the operation.
* @retval 1 if all values were successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetAll(UtopiaContext* pUtopiaCtx, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia value with a numerically indexed key.
*
* This function retrieves the value for a UtopiaValue that uses numeric indexing from the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex - The numeric index to identify the specific value.
* @param[out] pszBuffer - Pointer to a buffer where the indexed value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the indexed value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetIndexed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia value with a two-dimensionally indexed key.
*
* This function retrieves the value for a UtopiaValue that uses two-dimensional numeric indexing
* from the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex1 - The first numeric index dimension.
* @param[in] iIndex2 - The second numeric index dimension.
* @param[out] pszBuffer - Pointer to a buffer where the two-dimensionally indexed value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally indexed value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetIndexed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex1, int iIndex2, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia value with a key that is indexed with a string name.
*
* This function retrieves the value for a UtopiaValue that uses string-based indexing from the
* configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName - Null-terminated string used as the name index.
* @param[out] pszBuffer - Pointer to a buffer where the named value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the named value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetNamed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a Utopia value with a key that is two-dimensionally indexed by string names.
*
* This function retrieves the value for a UtopiaValue that uses two-dimensional string-based indexing
* from the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName1 - Null-terminated string for the first name index dimension.
* @param[in] pszName2 - Null-terminated string for the second name index dimension.
* @param[out] pszBuffer - Pointer to a buffer where the two-dimensionally named value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally named value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_GetNamed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName1, char* pszName2, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Retrieve a raw non-Utopia value directly by namespace and key.
*
* This function retrieves a value directly from the underlying configuration system using explicit
* namespace and key parameters, bypassing the UtopiaValue enumeration.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] pszNamespace - Null-terminated string specifying the namespace of the value to retrieve.
* @param[in] pszKey - Null-terminated string specifying the key of the value being retrieved.
* @param[out] pszBuffer - Pointer to a buffer where the value string will be stored.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the raw value was successfully retrieved.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_RawGet(UtopiaContext* pUtopiaCtx, char* pszNamespace, char* pszKey, char* pszBuffer, unsigned int ccbBuf);

/**
* @brief Set a raw non-Utopia value directly by namespace and key.
*
* This function sets a value directly in the underlying configuration system using explicit
* namespace and key parameters, bypassing the UtopiaValue enumeration.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] pszNamespace - Null-terminated string specifying the namespace of the value being set.
* @param[in] pszKey - Null-terminated string specifying the key of the value being set.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the raw value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_RawSet(UtopiaContext* pUtopiaCtx, char* pszNamespace, char* pszKey, char* pszValue);

/**
* @brief Set a Utopia value for a given UtopiaValue index.
*
* This function sets the value associated with a UtopiaValue index in the configuration or event system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying which value to set.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_Set(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszValue);

/**
* @brief Sets all Utopia values from a formatted input buffer or resets to factory defaults.
*
* This function sets all configuration and event values in the Utopia system from a formatted input buffer
* with the format '<namespace>::<key>=<value>\n' for each entry. If a null buffer is passed, all values
* are reset to factory defaults.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] pszBuffer - Pointer to a null-terminated input buffer containing values in the format
*                    \n '<namespace>::<key>=<value>\n' for each entry.
*                    \n Pass NULL to reset all values to factory defaults.
*
* @return The status of the operation.
* @retval 1 if all values were successfully set or reset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetAll(UtopiaContext* pUtopiaCtx, char* pszBuffer);

/**
* @brief Set a Utopia value with a numerically indexed key.
*
* This function sets the value for a UtopiaValue that uses numeric indexing in the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex - The numeric index to identify the specific value.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the indexed value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetIndexed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex, char* pszValue);

/**
* @brief Set a Utopia value with a two-dimensionally indexed key.
*
* This function sets the value for a UtopiaValue that uses two-dimensional numeric indexing in the
* configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex1 - The first numeric index dimension.
* @param[in] iIndex2 - The second numeric index dimension.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally indexed value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetIndexed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex1, int iIndex2, char* pszValue);

/**
* @brief Set a Utopia value with a key that is indexed with a string name.
*
* This function sets the value for a UtopiaValue that uses string-based indexing in the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName - Null-terminated string used as the name index.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the named value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetNamed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName, char* pszValue);

/**
* @brief Set a Utopia value with a key that is two-dimensionally indexed by string names.
*
* This function sets the value for a UtopiaValue that uses two-dimensional string-based indexing in the
* configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName1 - Null-terminated string for the first name index dimension.
* @param[in] pszName2 - Null-terminated string for the second name index dimension.
* @param[in] pszValue - Null-terminated string containing the value to set.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally named value was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetNamed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName1, char* pszName2, char* pszValue);

/**
* @brief Unset a Utopia value for a given UtopiaValue index.
*
* This function removes/clears the value associated with a UtopiaValue index from the configuration or
* event system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying which value to unset.
*
* @return The status of the operation.
* @retval 1 if the value was successfully unset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_Unset(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia);

/**
* @brief Unset a Utopia value with a numerically indexed key.
*
* This function removes/clears the value for a UtopiaValue that uses numeric indexing from the
* configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex - The numeric index to identify the specific value to unset.
*
* @return The status of the operation.
* @retval 1 if the indexed value was successfully unset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_UnsetIndexed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex);

/**
* @brief Unset a Utopia value with a two-dimensionally indexed key.
*
* This function removes/clears the value for a UtopiaValue that uses two-dimensional numeric indexing
* from the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] iIndex1 - The first numeric index dimension.
* @param[in] iIndex2 - The second numeric index dimension.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally indexed value was successfully unset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_UnsetIndexed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, int iIndex1, int iIndex2);

/**
* @brief Unset a Utopia value with a key that is indexed with a string name.
*
* This function removes/clears the value for a UtopiaValue that uses string-based indexing from the
* configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName - Null-terminated string used as the name index.
*
* @return The status of the operation.
* @retval 1 if the named value was successfully unset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_UnsetNamed(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName);

/**
* @brief Unset a Utopia value with a key that is two-dimensionally indexed by string names.
*
* This function removes/clears the value for a UtopiaValue that uses two-dimensional string-based indexing
* from the configuration system.
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext containing the system state.
* @param[in] ixUtopia - UtopiaValue enumeration index specifying the base key.
* @param[in] pszName1 - Null-terminated string for the first name index dimension.
* @param[in] pszName2 - Null-terminated string for the second name index dimension.
*
* @return The status of the operation.
* @retval 1 if the two-dimensionally named value was successfully unset.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_UnsetNamed2(UtopiaContext* pUtopiaCtx, UtopiaValue ixUtopia, char* pszName1, char* pszName2);

/*
 * Utopia_Events are infered from UtopiaValue sets, so you shouldn't need to use
 * these unless you need to trigger an event without setting an UtopiaValue value.
 */
typedef enum _Utopia_Event
{
    Utopia_Event__NONE__ = 0x00,
    Utopia_Event_Cron_Restart = 0x01,
    Utopia_Event_DHCPClient_Restart = 0x02,
    Utopia_Event_DHCPServer_Restart = 0x04,
    Utopia_Event_DNS_Restart = 0x08,
    Utopia_Event_Firewall_Restart = 0x10,
    Utopia_Event_HTTPServer_Restart = 0x20,
    Utopia_Event_LAN_Restart = 0x40,
    Utopia_Event_MACFilter_Restart = 0x80,
    Utopia_Event_NTPClient_Restart = 0x100,
    Utopia_Event_Reboot = 0x200,
    Utopia_Event_WAN_Restart = 0x400,
    Utopia_Event_WLAN_Restart = 0x800,
    Utopia_Event_DDNS_Update = 0x1000,
    Utopia_Event_StaticRoute_Restart = 0x2000,
    Utopia_Event_SmbServer_Restart = 0x4000,
    Utopia_Event_IGD_Restart = 0x8000,
    Utopia_Event_RIP_Restart = 0x10000,
    Utopia_Event_Syslog_Restart = 0x20000,
    Utopia_Event_QoS_Restart = 0x40000,
    Utopia_Event_MoCA_Restart = 0x80000,
    Utopia_Event_DSLite_Restart = 0x100000,
    Utopia_Event__LAST__ = 0x200000
} Utopia_Event;

/**
* @brief Set a Utopia event to be triggered on context free.
*
* This function marks a Utopia event to be triggered when the context is freed using Utopia_Free().
*
* @param[in] pUtopiaCtx - Pointer to the UtopiaContext where the event will be registered.
* @param[in] event - Utopia_Event enumeration value specifying which event to trigger.
*
* @return The status of the operation.
* @retval 1 if the event was successfully set.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_SetEvent(UtopiaContext* pUtopiaCtx, Utopia_Event event);

#endif /* __UTCTX_API_H__ */
