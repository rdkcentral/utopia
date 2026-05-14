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

#ifndef __UTAPI_TR_WLAN_H__
#define __UTAPI_TR_WLAN_H__

#define WLANCFG_RADIO_FULL_FILE "/tmp/wifi.txt"
#define WLANCFG_RADIO_EXTN_FILE "/tmp/wifi_extn.txt"
#define WLANCFG_RADIO_STATS_FILE "/tmp/wifi_stat.txt"
#define WLANCFG_RADIO_FILE "/tmp/wifi_radio.txt"
#define WLANCFG_SSID_FILE "/tmp/wifi_ssid.txt"
#define WLANCFG_SSID_STATS_FILE "/tmp/wifi_ssid_stats.txt"
#define WLANCFG_AP_FILE "/tmp/wifi_ap.txt"
#define WLANCFG_AP_SEC_FILE "/tmp/wifi_ap_sec.txt"
#define WLANCFG_AP_WPS_FILE "/tmp/wifi_ap_wps.txt"
#define WLANCFG_AP_ASSOC_DEV_FILE "/tmp/wifi_ap_assocDev.txt"
#define WIFI_MACFILTER_FILE "/tmp/wifi_mac_filter.txt"

#define WIFI_RADIO_NUM_INSTANCES 2 /* Change this if num of Radios changes */
#define WIFI_SSID_NUM_INSTANCES 8 /* Change this once we implement multi-SSID */
#define WIFI_AP_NUM_INSTANCES 8 /* Change this once we implement multi-SSID */

#define START_SECONDARY_SSID 1 /* Starting of Secondary SSIDs */
#define MAX_SSID_PER_RADIO 8 /* For the time being we allow only 4 per radio */
#define PRIMARY_SSID_COUNT 2 /* Number of non-deletable primary SSID */

#define START_DYNAMIC_SSID 4 /* We configure 3 secondary SSIDs per radio statically */
#define STATIC_SSID_COUNT  8 /* Number of statically configured SSIDs */

#define STR_SZ 32

#define ERR_SSID_NOT_FOUND -100

#define MAX_NUM_INSTANCES 255

#define  IPV4_ADDRESS                                                        \
         union                                                               \
         {                                                                   \
            unsigned char           Dot[4];                                  \
            unsigned long           Value;                                   \
         }

typedef enum wifiInterface {
    FREQ_UNKNOWN = -1,
    FREQ_2_4_GHZ = 0,
    FREQ_5_GHZ
} wifiInterface_t;

typedef struct wifiTRPlatformSetup {
    wifiInterface_t interface;
    char *syscfg_namespace_prefix;
    char *ifconfig_interface;
    char *ssid_name;
    char *ap_name;
} wifiTRPlatformSetup_t;

typedef  enum wifiStandards {
    WIFI_STD_a             = 1,
    WIFI_STD_b             = 2,
    WIFI_STD_g             = 4,
    WIFI_STD_n             = 8
}
wifiStandards_t;

typedef enum wifiTXPower {
   TX_POWER_HIGH = 100,
   TX_POWER_MEDIUM = 50,
   TX_POWER_LOW = 25
} wifiTXPower_t;

typedef enum wifiBasicRate {
   WIFI_BASICRATE_DEFAULT,
   WIFI_BASICRATE_1_2MBPS,
   WIFI_BASICRATE_ALL,
} wifiBasicRate_t;

typedef enum wifiTXRate {
   WIFI_TX_RATE_AUTO = 0,
   WIFI_TX_RATE_6,
   WIFI_TX_RATE_9,
   WIFI_TX_RATE_12,
   WIFI_TX_RATE_18,
   WIFI_TX_RATE_24,
   WIFI_TX_RATE_36,
   WIFI_TX_RATE_48,
   WIFI_TX_RATE_54,
} wifiTxRate_t;

typedef enum wifiSideband {
    SIDEBAND_LOWER = 1,
    SIDEBAND_UPPER
} wifiSideband_t;

typedef enum wifiGuardInterval {
   GI_LONG,
   GI_SHORT,
   GI_AUTO
} wifiGuardInterval_t;

typedef enum wifiBand {
    BAND_AUTO,
    STD_20MHZ,
    WIDE_40MHZ
} wifiBand_t;

typedef enum wifiSecurity {
    WIFI_SECURITY_None                 = 0x00000001,
    WIFI_SECURITY_WEP_64               = 0x00000002,
    WIFI_SECURITY_WEP_128              = 0x00000004,
    WIFI_SECURITY_WPA_Personal         = 0x00000008,
    WIFI_SECURITY_WPA2_Personal        = 0x00000010,
    WIFI_SECURITY_WPA_WPA2_Personal    = 0x00000020,
    WIFI_SECURITY_WPA_Enterprise       = 0x00000040,
    WIFI_SECURITY_WPA2_Enterprise      = 0x00000080,
    WIFI_SECURITY_WPA_WPA2_Enterprise  = 0x00000100
}wifiSecurity_t;

typedef  enum wifiSecurityEncrption {
    WIFI_SECURITY_TKIP    = 1,
    WIFI_SECURITY_AES,
    WIFI_SECURITY_AES_TKIP
}wifiSecurityEncryption_t;

typedef enum wifiWPSMethod {
    WIFI_WPS_METHOD_UsbFlashDrive      = 0x00000001,
    WIFI_WPS_METHOD_Ethernet           = 0x00000002,
    WIFI_WPS_METHOD_ExternalNFCToken   = 0x00000004,
    WIFI_WPS_METHOD_IntgratedNFCToken  = 0x00000008,
    WIFI_WPS_METHOD_NFCInterface       = 0x00000010,
    WIFI_WPS_METHOD_PushButton         = 0x00000020,
    WIFI_WPS_METHOD_Pin                = 0x00000040
}wifiWPSMethod_t;


/*
 *  Config portion of WiFi radio info
 */

typedef  struct
wifiRadioCfg
{
    unsigned long                   InstanceNumber;
    char                            Alias[64];
    unsigned char                   bEnabled;
    wifiInterface_t                 OperatingFrequencyBand;
    unsigned long                   OperatingStandards;
    unsigned long                   Channel;
    unsigned char                   AutoChannelEnable;
    unsigned long                   AutoChannelRefreshPeriod;
    wifiBand_t                      OperatingChannelBandwidth;
    wifiSideband_t                  ExtensionChannel;
    wifiGuardInterval_t             GuardInterval;
    int                             MCS;
    int                             TransmitPower;
    unsigned char                   IEEE80211hEnabled;
    char                            RegulatoryDomain[4];
    /* Below is Cisco Extensions */
    wifiBasicRate_t                 BasicRate;
    wifiTxRate_t                    TxRate;
    unsigned char                   APIsolation;
    unsigned char                   FrameBurst;
    unsigned char                   CTSProtectionMode;
    unsigned long                   BeaconInterval;
    unsigned long                   DTIMInterval;
    unsigned long                   FragmentationThreshold;
    unsigned long                   RTSThreshold;
}wifiRadioCfg_t;

/*
 * Static portion of WiFi radio info
 */

typedef  struct
wifiRadioSinfo
{
    char                            Name[64];
    unsigned char                   bUpstream;
    unsigned long                   MaxBitRate;
    unsigned long                   SupportedFrequencyBands;
    unsigned long                   SupportedStandards;
    char                            PossibleChannels[512];
    unsigned char                   AutoChannelSupported;
    char                            TransmitPowerSupported[64];
    unsigned char                   IEEE80211hSupported;
}wifiRadioSinfo_t;

/*
 * Dynamic portion of WiFi radio info
 */

typedef  struct
wifiRadioDinfo
{
    int                             Status;
    unsigned long                   LastChange;
    char                            ChannelsInUse[512];
}wifiRadioDinfo_t;

/*
 * WiFi Radio Entry
 */

typedef struct
wifiRadioEntry
{
     wifiRadioCfg_t                  Cfg;
     wifiRadioSinfo_t                StaticInfo;
     wifiRadioDinfo_t                DynamicInfo;

}wifiRadioEntry_t;

/*
 * WiFi Radio Stats
 */

typedef  struct
wifiRadioStats
{
    unsigned long                   BytesSent;
    unsigned long                   BytesReceived;
    unsigned long                   PacketsSent;
    unsigned long                   PacketsReceived;
    unsigned long                   ErrorsSent;
    unsigned long                   ErrorsReceived;
    unsigned long                   DiscardPacketsSent;
    unsigned long                   DiscardPacketsReceived;

}wifiRadioStats_t;

/*
 * Structure definitions for WiFi SSID
 */

typedef struct
wifiSSIDCfg
{
    unsigned long                   InstanceNumber;
    char                            Alias[64];
    unsigned char                   bEnabled;
    char                            WiFiRadioName[64];
    char                            SSID[32];
}wifiSSIDCfg_t;


/*
 * Static portion of WiFi SSID info
 */

typedef  struct
wifiSSIDSInfo
{
    char                            Name[64];
    unsigned char                   BSSID[6];
    unsigned char                   MacAddress[6];
}wifiSSIDSInfo_t;

/*
 *  *  Dynamic portion of WiFi SSID info
 *   */

typedef  struct
wifiSSIDDInfo
{
    int 			    Status;
    unsigned long                   LastChange;
}wifiSSIDDInfo_t;

/*
 *  *  WiFi SSID Entry
 *   */

typedef struct
wifiSSIDEntry
{
     wifiSSIDCfg_t		    Cfg;
     wifiSSIDSInfo_t                StaticInfo;
     wifiSSIDDInfo_t                DynamicInfo;

}wifiSSIDEntry_t;

typedef struct
wifiSSIDStats
{
    unsigned long                   BytesSent;
    unsigned long                   BytesReceived;
    unsigned long                   PacketsSent;
    unsigned long                   PacketsReceived;
    unsigned long                   ErrorsSent;
    unsigned long                   ErrorsReceived;
    unsigned long                   UnicastPacketsSent;
    unsigned long                   UnicastPacketsReceived;
    unsigned long                   DiscardPacketsSent;
    unsigned long                   DiscardPacketsReceived;
    unsigned long                   MulticastPacketsSent;
    unsigned long                   MulticastPacketsReceived;
    unsigned long                   BroadcastPacketsSent;
    unsigned long                   BroadcastPacketsReceived;
    unsigned long                   UnknownProtoPacketsReceived;
}wifiSSIDStats_t;

typedef struct
wifiAPCfg
{
    unsigned long                   InstanceNumber;
    char                            Alias[64];
    char                            SSID[32];           /* Reference to SSID name */

    unsigned char                   bEnabled;
    unsigned char		    SSIDAdvertisementEnabled;
    unsigned long                   RetryLimit;
    unsigned char                   WMMEnable;
    unsigned char                   UAPSDEnable;
}wifiAPCfg_t;

typedef struct
wifiAPInfo
{
    int				    Status;
    unsigned char                   WMMCapability;
    unsigned char                   UAPSDCapability;
}wifiAPInfo_t;

typedef struct
wifiAPEntry
{
     wifiAPCfg_t                  Cfg;
     wifiAPInfo_t                 Info;

}wifiAPEntry_t;

typedef struct
wifiAPSecCfg
{
    wifiSecurity_t                  ModeEnabled;
    unsigned char                   WEPKeyp[13];
    unsigned char                   PreSharedKey[32];
    unsigned char                   KeyPassphrase[64];
    unsigned long                   RekeyingInterval;
    wifiSecurityEncryption_t        EncryptionMethod;
    IPV4_ADDRESS                    RadiusServerIPAddr;
    unsigned long                   RadiusServerPort;
    char                            RadiusSecret[64];
}wifiAPSecCfg_t;

typedef struct
wifiAPSecInfo
{
    unsigned long                   ModesSupported;     /* Bitmask of wifiSecurity_t*/
}wifiAPSecInfo_t;

typedef struct
wifiAPSecEntry
{
    wifiAPSecCfg_t                  Cfg;
    wifiAPSecInfo_t                 Info;
}wifiAPSecEntry_t;

typedef struct
wifiAPWPSCfg
{
    unsigned char                   bEnabled;
    unsigned long                   ConfigMethodsEnabled;
}wifiAPWPSCfg_t;

typedef struct
wifiAPWPSInfo
{
    unsigned long                   ConfigMethodsSupported;   /* Bitmask of wifiWPSMethod_t */
}wifiAPWPSInfo_t;

typedef struct
wifiAPWPSEntry
{
    wifiAPWPSCfg_t                  Cfg;
    wifiAPWPSInfo_t                 Info;
}wifiAPWPSEntry_t;

typedef struct
wifiAPAssocDevice
{
    unsigned char                   MacAddress[6];
    unsigned char                   AuthenticationState;
    unsigned long                   LastDataDownlinkRate;
    unsigned long                   LastDataUplinkRate;
    int                             SignalStrength;
    unsigned long                   Retransmissions;
    unsigned char                   Active;
}wifiAPAssocDevice_t;

/*
 *  * Mac Filter Cfg
 *   */

typedef struct
wifiMacFilterCfg
{
    unsigned char macFilterEnabled;
    unsigned char macFilterMode;
    unsigned long NumberMacAddrList;
    unsigned char macAddress[6*50];
}wifiMacFilterCfg_t;


/* Function Definitions */
/**
* @brief Get the total number of WiFi radio instances.
*
* @return The number of WiFi radio instances.
* @retval WIFI_RADIO_NUM_INSTANCES The fixed number of radio instances supported.
*
*/
int Utopia_GetWifiRadioInstances();

/**
* @brief Get a WiFi radio entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi radio entry (0-based).
*                       \n Valid range: 0 to (WIFI_RADIO_NUM_INSTANCES - 1).
* @param[out] pEntry - Pointer to a wifiRadioEntry_t structure where the radio entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pEntry is NULL.
*
*/
int Utopia_GetWifiRadioEntry(UtopiaContext *ctx, unsigned long ulIndex, void *pEntry);

/**
* @brief Get the WiFi radio configuration by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi radio (0-based).
*                       \n Valid range: 0 to (WIFI_RADIO_NUM_INSTANCES - 1).
* @param[out] cfg     - Pointer to a wifiRadioCfg_t structure where the radio configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL, or if ulIndex is out of range.
*
*/
int Utopia_GetIndexedWifiRadioCfg(UtopiaContext *ctx, unsigned long ulIndex, void *cfg);

/**
* @brief Get the WiFi radio configuration by instance number.
*
* @param[in]     ctx              - Pointer to the Utopia context.
* @param[in]     dummyInstanceNum - If non-zero, sets InstanceNumber to 0 in the output structure.
* @param[in,out] cfg              - Pointer to a wifiRadioCfg_t structure.
*                                   \n [in] The InstanceNumber field must be set.
*                                   \n [out] The structure will be populated with the radio configuration.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL, or if the mapped index is out of range.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no configuration nodes are found.
*
*/
int Utopia_GetWifiRadioCfg(UtopiaContext *ctx,int dummyInstanceNum, void *cfg);

/**
* @brief Get the WiFi radio static information by index.
*
* @param[in]  ulIndex - Index of the WiFi radio (0-based).
*                       \n Valid range: 0 to (WIFI_RADIO_NUM_INSTANCES - 1).
* @param[out] sInfo   - Pointer to a wifiRadioSinfo_t structure where the static information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if sInfo is NULL or if ulIndex is out of range.
*
*/
int Utopia_GetWifiRadioSinfo(unsigned long ulIndex, void *sInfo);

/**
* @brief Get the WiFi radio dynamic information by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi radio (0-based).
*                       \n Valid range: 0 to (WIFI_RADIO_NUM_INSTANCES - 1).
* @param[out] dInfo   - Pointer to a wifiRadioDinfo_t structure where the dynamic information will be returned.
*                       \n The information includes status, last change timestamp, and channels in use.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or dInfo is NULL, or if ulIndex is out of range.
*
*/
int Utopia_GetIndexedWifiRadioDinfo(UtopiaContext *ctx, unsigned long ulIndex, void *dInfo);

/**
* @brief Get the WiFi radio dynamic information by instance number.
*
* @param[in]  ulInstanceNum - Instance number of the WiFi radio.
* @param[out] dInfo         - Pointer to a wifiRadioDinfo_t structure where the dynamic information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if dInfo is NULL or if the mapped index is out of range.
* @retval ERR_NO_NODES if no information nodes are found.
*
*/
int Utopia_GetWifiRadioDinfo(unsigned long ulInstanceNum, void *dInfo);

/**
* @brief Set the WiFi radio configuration.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] cfg - Pointer to a wifiRadioCfg_t structure containing the radio configuration to be set.
*                  \n The InstanceNumber field must be valid.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL, or if the mapped index is out of range.
*
*/
int Utopia_SetWifiRadioCfg(UtopiaContext *ctx, void *cfg);

/**
* @brief Set the instance number and alias for a WiFi radio.
*
* @param[in] ctx           - Pointer to the Utopia context.
* @param[in] ulIndex       - Index of the WiFi radio (0-based).
*                            \n Valid range: 0 to (WIFI_RADIO_NUM_INSTANCES - 1).
* @param[in] ulInstanceNum - Instance number to be set.
* @param[in] pAlias        - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pAlias is NULL, or if ulIndex is out of range.
*
*/
int Utopia_WifiRadioSetValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNum, char *pAlias);

/**
* @brief Get the WiFi radio statistics by instance number.
*
* @param[in]  ulInstanceNum - Instance number of the WiFi radio.
* @param[out] stats         - Pointer to a wifiRadioStats_t structure where the statistics will be returned.
*                             \n Statistics include bytes sent/received, packets sent/received,
*                             \n errors sent/received, and discarded packets sent/received.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if stats is NULL or if the mapped index is out of range.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no statistics nodes are found.
*
*/
int Utopia_GetWifiRadioStats(unsigned long ulInstanceNum, void *stats);

/**
* @brief Get the total number of WiFi SSID instances.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return The number of WiFi SSID instances.
* @retval The number of WiFi SSID instances on success.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_GetWifiSSIDInstances(UtopiaContext *ctx);

/**
* @brief Get a WiFi SSID entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi SSID entry (0-based).
* @param[out] pEntry - Pointer to a wifiSSIDEntry_t structure where the SSID entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pEntry is NULL.
*
*/
int Utopia_GetWifiSSIDEntry(UtopiaContext *ctx, unsigned long ulIndex, void *pEntry);

/**
* @brief Get the WiFi SSID configuration by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi SSID (0-based).
* @param[out] cfg     - Pointer to a wifiSSIDCfg_t structure where the SSID configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL.
*
*/
int Utopia_GetIndexedWifiSSIDCfg(UtopiaContext *ctx, unsigned long ulIndex, void *cfg);

/**
* @brief Get the WiFi SSID configuration by instance number.
*
* @param[in]     ctx              - Pointer to the Utopia context.
* @param[in]     dummyInstanceNum - If non-zero, sets InstanceNumber to 0 in the output structure.
* @param[in,out] cfg              - Pointer to a wifiSSIDCfg_t structure.
*                                   \n [in] The InstanceNumber field must be set.
*                                   \n [out] The structure will be populated with the SSID configuration.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no configuration nodes are found.
*
*/
int Utopia_GetWifiSSIDCfg(UtopiaContext *ctx, int dummyInstanceNum, void *cfg);

/**
* @brief Get the WiFi SSID static information by index.
*
* @param[in]  ulIndex - Index of the WiFi SSID (0-based).
* @param[out] sInfo   - Pointer to a wifiSSIDSInfo_t structure where the static information will be returned.
*                       \n The information includes name, BSSID, and MAC address.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if sInfo is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no information nodes are found.
*
*/
int Utopia_GetWifiSSIDSInfo(unsigned long ulIndex, void *sInfo);

/**
* @brief Get the WiFi SSID dynamic information by instance number.
*
* @param[in]  ulInstanceNum - Instance number of the WiFi SSID.
* @param[out] dInfo         - Pointer to a wifiSSIDDInfo_t structure where the dynamic information will be returned.
*                             \n The information includes status and last change timestamp.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if dInfo is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no information nodes are found.
*
*/
int Utopia_GetWifiSSIDDInfo(unsigned long ulInstanceNum, void *dInfo);

/**
* @brief Get the WiFi SSID dynamic information by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi SSID (0-based).
* @param[out] dInfo   - Pointer to a wifiSSIDDInfo_t structure where the dynamic information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or dInfo is NULL.
*
*/
int Utopia_GetIndexedWifiSSIDDInfo(UtopiaContext *ctx, unsigned long ulIndex, void *dInfo);

/**
* @brief Get the WiFi SSID dynamic information by instance number.
*
* @param[in]  ulInstanceNum - Instance number of the WiFi SSID.
* @param[out] dInfo         - Pointer to a wifiSSIDDInfo_t structure where the dynamic information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if dInfo is NULL.
*
*/
int Utopia_GetWifiSSIDDinfo(unsigned long ulInstanceNum, void *dInfo);

/**
* @brief Set the WiFi SSID configuration.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] cfg - Pointer to a wifiSSIDCfg_t structure containing the SSID configuration to be set.
*                  \n The InstanceNumber field must be valid.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL.
*
*/
int Utopia_SetWifiSSIDCfg(UtopiaContext *ctx, void *cfg);

/**
* @brief Set the instance number and alias for a WiFi SSID.
*
* @param[in] ctx           - Pointer to the Utopia context.
* @param[in] ulIndex       - Index of the WiFi SSID (0-based).
* @param[in] ulInstanceNum - Instance number to be set.
* @param[in] pAlias        - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pAlias is NULL.
*
*/
int Utopia_WifiSSIDSetValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNum, char *pAlias);

/**
* @brief Get the WiFi SSID statistics by instance number.
*
* @param[in]  ulInstanceNum - Instance number of the WiFi SSID.
* @param[out] stats         - Pointer to a wifiSSIDStats_t structure where the statistics will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if stats is NULL.
*
*/
int Utopia_GetWifiSSIDStats(unsigned long ulInstanceNum, void *stats);

/**
* @brief Get the total number of WiFi access point instances.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return The number of WiFi access point instances.
* @retval The number of WiFi access point instances on success.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_GetWifiAPInstances(UtopiaContext *ctx);

/**
* @brief Get a WiFi access point entry by SSID name.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  pSSID  - Pointer to the SSID name string.
* @param[out] pEntry - Pointer to a wifiAPEntry_t structure where the access point entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or pEntry is NULL.
*
*/
int Utopia_GetWifiAPEntry(UtopiaContext *ctx, char*pSSID, void *pEntry);

/**
* @brief Get the WiFi access point configuration by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the WiFi access point (0-based).
* @param[out] pCfg    - Pointer to a wifiAPCfg_t structure where the access point configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pCfg is NULL.
*
*/
int Utopia_GetIndexedWifiAPCfg(UtopiaContext *ctx, unsigned long ulIndex, void *pCfg);

/**
* @brief Get the WiFi access point configuration by instance number.
*
* @param[in]     ctx              - Pointer to the Utopia context.
* @param[in]     dummyInstanceNum - If non-zero, sets InstanceNumber to 0 in the output structure.
* @param[in,out] cfg              - Pointer to a wifiAPCfg_t structure.
*                                   \n [in] The InstanceNumber field must be set.
*                                   \n [out] The structure will be populated with the access point configuration.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no configuration nodes are found.
*
*/
int Utopia_GetWifiAPCfg(UtopiaContext *ctx, int dummyInstanceNum, void *cfg);

/**
* @brief Get the WiFi access point information by SSID name.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[in]  pSSID - Pointer to the SSID name string.
* @param[out] info  - Pointer to a wifiAPInfo_t structure where the access point information will be returned.
*                     \n The information includes status, WMM capability, and UAPSD capability.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or info is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no information nodes are found.
*
*/
int Utopia_GetWifiAPInfo(UtopiaContext *ctx, char *pSSID, void *info);

/**
* @brief Set the WiFi access point configuration.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] cfg - Pointer to a wifiAPCfg_t structure containing the access point configuration to be set.
*                  \n The InstanceNumber field must be valid.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or cfg is NULL.
*
*/
int Utopia_SetWifiAPCfg(UtopiaContext *ctx, void *cfg);

/**
* @brief Set the instance number and alias for a WiFi access point.
*
* @param[in] ctx           - Pointer to the Utopia context.
* @param[in] ulIndex       - Index of the WiFi access point (0-based).
* @param[in] ulInstanceNum - Instance number to be set.
* @param[in] pAlias        - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pAlias is NULL.
*
*/
int Utopia_WifiAPSetValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNum, char *pAlias);

/**
* @brief Get the WiFi access point security entry by SSID name.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  pSSID  - Pointer to the SSID name string.
* @param[out] pEntry - Pointer to a wifiAPSecEntry_t structure where the security entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or pEntry is NULL.
*
*/
int Utopia_GetWifiAPSecEntry(UtopiaContext *ctx, char*pSSID, void *pEntry);

/**
* @brief Get the WiFi access point security configuration by SSID name.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[in]  pSSID - Pointer to the SSID name string.
* @param[out] cfg   - Pointer to a wifiAPSecCfg_t structure where the security configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no configuration nodes are found.
*
*/
int Utopia_GetWifiAPSecCfg(UtopiaContext *ctx, char*pSSID, void *cfg);

/**
* @brief Get the WiFi access point security information by SSID name.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[in]  pSSID - Pointer to the SSID name string.
* @param[out] info  - Pointer to a wifiAPSecInfo_t structure where the security information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or info is NULL.

*
*/
int Utopia_GetWifiAPSecInfo(UtopiaContext *ctx, char *pSSID, void *info);

/**
* @brief Set the WiFi access point security configuration by SSID name.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] pSSID - Pointer to the SSID name string.
* @param[in] cfg   - Pointer to a wifiAPSecCfg_t structure containing the security configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.

*
*/
int Utopia_SetWifiAPSecCfg(UtopiaContext *ctx,char *pSSID, void *cfg);

/**
* @brief Get the WiFi access point WPS entry by SSID name.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  pSSID  - Pointer to the SSID name string.
* @param[out] pEntry - Pointer to a wifiAPWPSEntry_t structure where the WPS entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or pEntry is NULL.
*
*/
int Utopia_GetWifiAPWPSEntry(UtopiaContext *ctx, char*pSSID, void *pEntry);

/**
* @brief Get the WiFi access point WPS configuration by SSID name.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[in]  pSSID - Pointer to the SSID name string.
* @param[out] cfg   - Pointer to a wifiAPWPSCfg_t structure where the WPS configuration will be returned.
*                     \n The configuration includes enable status and config methods enabled (bitmask of wifiWPSMethod_t).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.
*
*/
int Utopia_GetWifiAPWPSCfg(UtopiaContext *ctx, char*pSSID, void *cfg);

/**
* @brief Set the WiFi access point WPS configuration by SSID name.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] pSSID - Pointer to the SSID name string.
* @param[in] cfg   - Pointer to a wifiAPWPSCfg_t structure containing the WPS configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.
*
*/
int Utopia_SetWifiAPWPSCfg(UtopiaContext *ctx,char *pSSID, void *cfg);

/**
* @brief Get the count of associated devices for a WiFi access point by SSID name.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] pSSID - Pointer to the SSID name string.
*
* @return The number of associated devices.
* @retval The count of associated devices on success.
* @retval ERR_INVALID_ARGS if ctx or pSSID is NULL.
* @retval ERR_NO_NODES if no device nodes are found.
* @retval ERR_GENERAL if generic error.
*
*/
unsigned long Utopia_GetAssociatedDevicesCount(UtopiaContext *ctx, char *pSSID);

/**
* @brief Get an associated device information by index for a WiFi access point.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  pSSID    - Pointer to the SSID name string.
* @param[in]  ulIndex  - Index of the associated device (0-based).
* @param[out] assocDev - Pointer to a wifiAPAssocDevice_t structure where the device information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or assocDev is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no device nodes are found.
*
*/
int Utopia_GetAssocDevice(UtopiaContext *ctx, char *pSSID, unsigned long ulIndex, void *assocDev);

/**
* @brief Get the WiFi access point index by SSID name.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] pSSID - Pointer to the SSID name string.
*
* @return The access point index.
* @retval The access point index on success.
* @retval ERR_INVALID_ARGS if ctx or pSSID is NULL.
* @retval ERR_SSID_NOT_FOUND if the SSID is not found.
*
*/
unsigned long Utopia_GetWifiAPIndex(UtopiaContext *ctx, char *pSSID);

/*MF */
/**
* @brief Get the WiFi access point MAC filter configuration by SSID name.
*
* @param[in]  ctx   - Pointer to the Utopia context.
* @param[in]  pSSID - Pointer to the SSID name string.
* @param[out] cfg   - Pointer to a wifiMacFilterCfg_t structure where the MAC filter configuration will be returned.
*                     \n The configuration includes enable status, filter mode, number of MAC addresses,
*                     \n and the MAC address list (up to 50 addresses).
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.
* @retval ERR_GENERAL if generic error.
* @retval ERR_NO_NODES if no configuration nodes are found.
*
*/
int Utopia_GetWifiAPMFCfg(UtopiaContext *ctx, char *pSSID, void *cfg);

/**
* @brief Set the WiFi access point MAC filter configuration by SSID name.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] pSSID - Pointer to the SSID name string.
* @param[in] cfg   - Pointer to a wifiMacFilterCfg_t structure containing the MAC filter configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx, pSSID, or cfg is NULL.
*
*/
int Utopia_SetWifiAPMFCfg(UtopiaContext *ctx, char *pSSID, void *cfg);

/* Utility functions */
/**
* @brief Find the instance number corresponding to an index.
*
* @param[in] ulIndex      - Index to search for.
* @param[in] numArray     - Pointer to the number array to search in.
* @param[in] numArrayLen  - Length of the number array.
*
* @return The instance number found at the given index.
* @retval The instance number on success.
* @retval 0 if instance number not found.
*
*/
unsigned long instanceNum_find(unsigned long ulIndex, int *numArray, int numArrayLen);

/**
* @brief Parse /proc/net/dev file for a specific interface field.
*
* @param[in] if_name        - Pointer to the interface name string.
* @param[in] field_to_parse - Field number to parse from the /proc/net/dev entry.
*
* @return The parsed field value.
* @retval The parsed field value on success.
* @retval 0 if interface not found or error occurs.
*
*/
unsigned long parse_proc_net_dev(char *if_name, int field_to_parse);

/**
* @brief Get MAC address list from a comma-separated string (utility function).
*
* @param[in]  macList - Pointer to the comma-separated MAC address list string.
* @param[out] macAddr - Pointer to the buffer where MAC addresses will be stored.
* @param[in]  tok     - Delimiter character string.
* @param[out] numlist - Pointer to unsigned long where the count of MAC addresses will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if macList, macAddr, tok, or numlist is NULL.
*
*/
int getMacList(char *macList, unsigned char *macAddr, char *tok, unsigned long *numlist);

/**
* @brief Set MAC address list to a comma-separated string.
*
* @param[in]  macAddr - Pointer to the buffer containing MAC addresses.
* @param[out] macList - Pointer to the buffer where the comma-separated MAC address list will be stored.
* @param[in]  numMac  - Number of MAC addresses to process.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if macAddr or macList is NULL.
*
*/
int setMacList(unsigned char *macAddr, char *macList, unsigned long numMac);

/**
* @brief Allocate memory for multi-SSID structure.
*
* @param[in] i - Index for the multi-SSID structure allocation.
*
* @return None.
*
*/
void allocateMultiSSID_Struct(int i);

/**
* @brief Free memory for multi-SSID structure.
*
* @param[in] i - Index for the multi-SSID structure deallocation.
*
* @return None.
*
*/
void freeMultiSSID_Struct(int i);

#endif // __UTAPI_TR_WLAN_H__
