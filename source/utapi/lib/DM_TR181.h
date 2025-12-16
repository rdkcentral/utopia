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
 * DM_TR181_h - TR-181 data model structures
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include "utapi.h"
#include "utapi_util.h"

#define UTOPIA_TR181_PARAM_SIZE		64
#define NAME_LENGTH	1024
#define MAC_SZ		6
#define MIN_MAC_LEN	12
#define MAX_MAC_LEN	17
#define MAX_HEX_LEN	16
#define VERSION_SZ	16
#define SSID_SZ		32
#define BUF_SZ		256
#define LINE_SZ		1024
#define HEX_SZ		8
#define KEYPASS_SZ	18
#define INST_SIZE	18

#define ERR_INSUFFICIENT_MEM 1
#undef ERR_INVALID_PARAM
#define ERR_INVALID_PARAM 2
#define ERR_FILE_OPEN_FAIL 3
#define ERR_NO_NODES 4
#define ERR_FILE_CLOSE_FAIL 5
#define ERR_GENERAL 100

#define MOCACFG_FILE_NAME_1  	"/mnt/appdata0/moca_cfg.txt"
#define MOCACFG_FILE_NAME 	"/tmp/moca_cfg.txt"
#define MOCA_SUM_FILE		"/tmp/moca0.txt"
#define MOCA_MAC_FILE		"/tmp/mocaMac.txt"
#define MOCA_PHY_FILE		"/tmp/mocaPhy.txt"
#define MOCA_STATS_FILE		"/tmp/mocaStats.txt"
#define MOCA_STATS_FILE_1       "/tmp/mocaStats1.txt"
#define MOCA_STATS_FILE_TEMP    "/tmp/mocaStatsTmp.txt"
#define MOCA_MAC_FILE_1		"/tmp/mocaMac1.txt"
#define MOCA_ASSOC_DEV		"/tmp/mocaAssDev.txt"
#define MOCA_ASS_INST		"/tmp/mocaAssDevInst.txt"
#define MOCA_TEMP_ASSOC_DEV	"/tmp/mocaAssDevTemp.txt"
#define MOCA_MAC_NODE		"/tmp/mocaNode.txt"
#define ETHERNET_ASSOC_DEVICE_FILE "/tmp/ethernet_AssocDevice.txt"

typedef unsigned char bool_t;

typedef struct param_node_{
        char param_name[NAME_LENGTH];
        char param_val[NAME_LENGTH];
        struct param_node_ *next;
}param_node;


typedef struct _Obj_Device_MoCA_{
	int InterfaceNumberOfEntries;
}Obj_Device_MoCA;

typedef struct _Obj_Device_MoCA_Interface_i_static{
	char Name[UTOPIA_TR181_PARAM_SIZE];
        bool_t Upstream;
        unsigned char MACAddress[MAC_SZ];
        char FirmwareVersion[UTOPIA_TR181_PARAM_SIZE];
        unsigned long MaxBitRate;
        char HighestVersion[UTOPIA_TR181_PARAM_SIZE];
        unsigned char FreqCapabilityMask[HEX_SZ];
        unsigned char NetworkTabooMask[HEX_SZ];
        unsigned char NodeTabooMask[HEX_SZ];
        unsigned long TxBcastPowerReduction;
        bool_t QAM256Capable;
        unsigned long PacketAggregationCapability;
}Obj_Device_MoCA_Interface_i_static;

typedef struct _Obj_Device_MoCA_Interface_i_dyn{
	int Status;
        unsigned long LastChange;
        unsigned long MaxIngressBW;
        unsigned long MaxEgressBW;
        char CurrentVersion[UTOPIA_TR181_PARAM_SIZE];
        unsigned long NetworkCoordinator;
        unsigned long NodeID;
        bool_t MaxNodes;
        unsigned long BackupNC;
        bool_t PrivacyEnabled;
        unsigned char FreqCurrentMask[HEX_SZ];
        unsigned long CurrentOperFreq;
        unsigned long LastOperFreq;
        unsigned long TxBcastRate;
        /*
	 * Extensions
	 */
        bool_t MaxIngressBWThresholdReached;
        bool_t MaxEgressBWThresholdReached;
}Obj_Device_MoCA_Interface_i_dyn;

typedef struct _Obj_Device_MoCA_Interface_i_cfg{
	unsigned long InstanceNumber;
	char Alias[UTOPIA_TR181_PARAM_SIZE];

	bool_t Enable;
	bool_t PreferredNC;
	bool_t PrivacyEnabledSetting;
	unsigned char FreqCurrentMaskSetting[HEX_SZ];
	char KeyPassphrase[KEYPASS_SZ];
	unsigned long TxPowerLimit;
	unsigned long PowerCntlPhyTarget;
	unsigned long BeaconPowerLimit;
	/*
	 * Extensions
	 */
        unsigned long MaxIngressBWThreshold;
        unsigned long MaxEgressBWThreshold;
}Obj_Device_MoCA_Interface_i_cfg;

typedef struct _Obj_Device_MoCA_Interface_i_Stats_{
        unsigned long BytesSent;
        unsigned long BytesReceived;
        unsigned long PacketsSent;
        unsigned long PacketsReceived;
        unsigned int  ErrorsSent;
        unsigned int  ErrorsReceived;
        unsigned int  UnicastPacketsSent;
        unsigned int  UnicastPacketsReceived;
        unsigned int  DiscardPacketsSent;
        unsigned int  DiscardPacketsReceived;
        unsigned long MulticastPacketsSent;
        unsigned long MulticastPacketsReceived;
        unsigned long BroadcastPacketsSent;
        unsigned long BroadcastPacketsReceived;
        unsigned int  UnknownProtoPacketsReceived;
}Obj_Device_MoCA_Interface_i_Stats;

typedef struct _Obj_Device_MoCA_Interface_i_QoS_{
        unsigned int  EgressNumFlows;
        unsigned int  IngressNumFlows;
        unsigned int  FlowStatsNumberOfEntries;
}Obj_Device_MoCA_Interface_i_QoS;

typedef struct _Obj_Device_MoCA_Interface_i_QoS_FlowStats_i_{
        unsigned int  FlowID;
        unsigned int  MaxRate;
        unsigned int  MaxBurstSize;
        unsigned int  LeaseTime;
        unsigned int  LeaseTimeLeft;
        unsigned int  FlowPackets;
	char PacketDA[UTOPIA_BUF_SIZE];
}Obj_Device_MoCA_Interface_i_QoS_FlowStats_i;

typedef struct _Obj_Device_MoCA_Interface_i_AssociatedDevice_i_{
	unsigned char MACAddress[MAC_SZ];
	unsigned int  NodeID;
	bool_t PreferredNC;
	char HighestVersion[UTOPIA_TR181_PARAM_SIZE];
	unsigned long PHYTxRate;
	unsigned long PHYRxRate;
	unsigned long TxPowerControlReduction;
	unsigned long RxPowerLevel;
	unsigned long TxBcastRate;
	unsigned long RxBcastPowerLevel;
	unsigned long TxPackets;
	unsigned long RxPackets;
	unsigned long RxErroredAndMissedPackets;
	bool_t QAM256Capable;
	unsigned long PacketAggregationCapability;
	unsigned long RxSNR;
	bool_t Active;
}Obj_Device_MoCA_Interface_i_AssociatedDevice_i;


#define  TR181_IPV4_ADDRESS             \
         union                          \
         {                              \
                unsigned char Dot[4];   \
                unsigned long Value;    \
         }
typedef struct _Obj_Device_DNS_Relay_{
        unsigned long InstanceNumber;
        char Alias[UTOPIA_TR181_PARAM_SIZE];

        bool_t Enable;
        int    Status;
        TR181_IPV4_ADDRESS DNSServer;
        char   Interface[UTOPIA_TR181_PARAM_SIZE]; /* IP interface name */
        int Type;
}Obj_Device_DNS_Relay;

/**
 * @brief Get TR-181 Device.MoCA.Interface.{i}. static parameters.
 *
 * Retrieves static (read-only) parameters for a MoCA interface by parsing mocacfg output.
 * Populates the Obj_Device_MoCA_Interface_i_static structure with interface properties.
 *
 * @param[out] deviceMocaIntfStatic - Pointer to structure to receive static MoCA interface parameters
 *
 * @return The status of the operation.
 * @retval SUCCESS - Parameters retrieved successfully
 * @retval ERR_INVALID_ARGS - Input parameter is NULL
 * @retval ERR_GENERAL - General error during file parsing
 *
 */
int Utopia_Get_TR181_Device_MoCA_Interface_i_Static(Obj_Device_MoCA_Interface_i_static *deviceMocaIntfStatic);

/**
 * @brief Get TR-181 Device.MoCA.Interface.{i}. dynamic parameters.
 *
 * Retrieves dynamic (runtime) parameters for a MoCA interface by parsing mocacfg output.
 * Populates the Obj_Device_MoCA_Interface_i_dyn structure with current interface state.
 *
 * @param[out] deviceMocaIntfDyn - Pointer to structure to receive dynamic MoCA interface parameters
 *
 * @return The status of the operation.
 * @retval SUCCESS - Parameters retrieved successfully
 * @retval ERR_INVALID_ARGS - Input parameter is NULL
 * @retval ERR_GENERAL - General error during file parsing
 *
 */
int Utopia_Get_TR181_Device_MoCA_Interface_i_Dyn(Obj_Device_MoCA_Interface_i_dyn *deviceMocaIntfDyn);

/**
 * @brief Get MoCA interface static parameters (wrapper function).
 *
 * Wrapper function that executes mocacfg commands to generate configuration files,
 * then calls Utopia_Get_TR181_Device_MoCA_Interface_i_Static() to retrieve static parameters.
 *
 * @param[in,out] str_handle - Pointer to Obj_Device_MoCA_Interface_i_static structure
 *                             \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Static parameters retrieved successfully
 * @retval ERR_INVALID_ARGS - Input parameter is NULL
 * @retval ERR_ITEM_NOT_FOUND - Failed to retrieve MoCA interface data
 *
 */
int Utopia_GetMocaIntf_Static(void *str_handle);

/**
 * @brief Get MoCA interface dynamic parameters (wrapper function).
 *
 * Wrapper function that executes mocacfg commands to generate configuration files,
 * then calls Utopia_Get_TR181_Device_MoCA_Interface_i_Dyn() to retrieve dynamic parameters.
 *
 * @param[in,out] str_handle - Pointer to Obj_Device_MoCA_Interface_i_dyn structure
 *                             \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Dynamic parameters retrieved successfully
 * @retval ERR_INVALID_ARGS - Input parameter is NULL
 * @retval ERR_ITEM_NOT_FOUND - Failed to retrieve MoCA interface data
 *
 */
int Utopia_GetMocaIntf_Dyn(void *str_handle);

/**
 * @brief Get MoCA interface configuration parameters.
 *
 * Retrieves configurable MoCA interface parameters from Utopia context (syscfg).
 * Populates the Obj_Device_MoCA_Interface_i_cfg structure with current settings.
 *
 * @param[in] pCtx - Pointer to Utopia context
 * @param[in,out] str_handle - Pointer to Obj_Device_MoCA_Interface_i_cfg structure
 *                             \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Configuration parameters retrieved successfully
 * @retval ERR_INVALID_ARGS - pCtx or str_handle is NULL
 *
 */
int Utopia_GetMocaIntf_Cfg(UtopiaContext *pCtx, void *str_handle);

/**
 * @brief Set MoCA interface configuration parameters.
 *
 * Applies MoCA interface configuration by updating Utopia context (syscfg) and
 * executing mocacfg commands to configure the MoCA interface.
 *
 * @param[in] pCtx - Pointer to Utopia context
 * @param[in] str_handle - Pointer to Obj_Device_MoCA_Interface_i_cfg structure with new settings
 *                         \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Configuration applied successfully
 * @retval ERR_INVALID_ARGS - pCtx or str_handle is NULL
 *
 */
int Utopia_SetMocaIntf_Cfg(UtopiaContext *pCtx, void *str_handle);

/**
 * @brief Count MoCA associated device entries.
 *
 * Counts the number of devices currently associated with the MoCA network by parsing
 * the associated devices file.
 *
 * @param[out] devCount - Pointer to integer to receive device count
 *
 * @return The status of the operation.
 * @retval SUCCESS - Device count retrieved successfully
 * @retval ERR_GENERAL - General error.
 *
 */
int Utopia_Count_AssociateDeviceEntry(int *devCount);

/**
 * @brief Get MoCA associated device information.
 *
 * Retrieves information about a specific associated device on the MoCA network.
 * Populates the Obj_Device_MoCA_Interface_i_AssociatedDevice_i structure.
 *
 * @param[out] mocaIntfAssociatedevice - Pointer to structure to receive associated device information
 * @param[in] count - Index of the associated device to retrieve (0-based)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Device information retrieved successfully
 * @retval ERR_INVALID_ARGS - mocaIntfAssociatedevice parameter is NULL
 * @retval ERR_GENERAL - General error during file parsing
 *
 */
int Utopia_Get_TR181_Device_MoCA_Interface_i_AssociateDevice(Obj_Device_MoCA_Interface_i_AssociatedDevice_i *mocaIntfAssociatedevice, int count);

/**
 * @brief Get DNS relay forwarding configuration.
 *
 * Retrieves DNS relay forwarding entry configuration from Utopia context for the specified index.
 * Populates the Obj_Device_DNS_Relay structure with Enable, DNSServer, and Interface parameters.
 *
 * @param[in] pCtx - Pointer to Utopia context
 * @param[in] index - Index of the DNS forwarding entry to retrieve
 * @param[in,out] str_handle - Pointer to Obj_Device_DNS_Relay structure
 *                             \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Configuration retrieved successfully
 * @retval ERR_INVALID_ARGS - str_handle parameter is NULL
 *
 */
int Utopia_Get_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle);

/**
 * @brief Set DNS relay forwarding configuration.
 *
 * Stores DNS relay forwarding entry configuration to Utopia context for the specified index.
 * Updates Enable, DNSServer, and Interface parameters from Obj_Device_DNS_Relay structure.
 *
 * @param[in] pCtx - Pointer to Utopia context
 * @param[in] index - Index of the DNS forwarding entry to configure
 * @param[in] str_handle - Pointer to Obj_Device_DNS_Relay structure with new settings
 *                         \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval UT_SUCCESS - Configuration stored successfully
 * @retval ERR_INVALID_ARGS - pCtx or str_handle parameter is NULL
 *
 */
int Utopia_Set_DeviceDnsRelayForwarding(UtopiaContext *pCtx, int index, void *str_handle);

/**
 * @brief Parse configuration file into parameter list.
 *
 * Parses a configuration file line by line, extracting parameter name-value pairs separated by
 * colons. Builds a linked list of param_node structures containing the parsed parameters.
 *
 * @param[in] file_name - Path to configuration file to parse
 * @param[out] head - Pointer to head pointer of parameter list
 *                    \n Will be populated with linked list of param_node structures
 *
 * @return The status of the operation.
 * @retval SUCCESS - File parsed successfully
 * @retval ERR_INVALID_PARAM - file_name or head parameter is NULL
 * @retval ERR_FILE_OPEN_FAIL - Failed to open file
 * @retval ERR_FILE_CLOSE_FAIL - Failed to close file
 * @retval ERR_INSUFFICIENT_MEM - Memory allocation failed
 *
 */
int file_parse(char* file_name, param_node **head);

/**
 * @brief Free parameter list.
 *
 * Frees all nodes in a parameter linked list and sets head pointer to NULL.
 *
 * @param[in,out] head - Head pointer of parameter list to free
 *                       \n All nodes in list will be freed
 *
 * @return None.
 *
 */
void free_paramList(param_node *head);

/**
 * @brief Convert MAC address string to byte array.
 *
 * Parses a MAC address string in various formats (with colons, dashes, or underscores)
 * and converts it to a 6-byte array representation.
 *
 * @param[in] macAddress - MAC address string to parse
 *                         \n Supports formats: "AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF",
 *                         "AA-BB-CC-DD-EE-FF", "AA_BB_CC_DD_EE_FF"
 * @param[in] len - If non-zero, validates MAC length is exactly MAC_SZ (6) bytes
 *                  \n If zero, allows MAC length up to MAC_SZ bytes
 * @param[out] mac - Pointer to 6-byte array to receive MAC address
 *                   \n Buffer must be at least MAC_SZ (6) bytes
 *
 * @return The status of the operation.
 * @retval SUCCESS - MAC address converted successfully
 * @retval ERR_INVALID_PARAM - macAddress is NULL, length < MIN_MAC_LEN (12), invalid hex format, or incorrect byte count
 *
 */
int getMac(char * macAddress, int len, unsigned char * mac);

/**
 * @brief Convert hexadecimal string to byte array.
 *
 * Parses a hexadecimal string (with optional "0x" prefix) and converts it to a byte array.
 * Pads with leading zeros if input string is shorter than expected length.
 *
 * @param[in] hex_val - Hexadecimal string to parse
 *                      \n Supports format: "0x1234ABCD" or "1234ABCD"
 *                      \n Separators (colon, dash, underscore) supported between bytes
 * @param[out] hexVal - Pointer to byte array to receive hex value
 *                      \n Buffer must be at least hexLen bytes
 * @param[in] hexLen - Expected length of output in bytes
 *                     \n For hexLen=8, input padded to MAX_HEX_LEN (16) hex digits
 *
 * @return The status of the operation.
 * @retval SUCCESS - Hex string converted successfully
 * @retval ERR_INVALID_PARAM - hex_val is NULL or converted length doesn't match hexLen
 *
 */
int getHex(char *hex_val, unsigned char *hexVal, int hexLen);

/**
 * @brief Convert hexadecimal string to byte array (generic version).
 *
 * Parses a hexadecimal string and converts it to a byte array without special formatting.
 * Similar to getHex() but without automatic padding for hexLen=8.
 *
 * @param[in] hex_val - Hexadecimal string to parse
 *                      \n Format: hex digits with optional separators (colon, dash, underscore)
 * @param[out] hexVal - Pointer to byte array to receive hex value
 *                      \n Buffer must be at least hexLen bytes
 * @param[in] hexLen - Expected length of output in bytes
 *
 * @return The status of the operation.
 * @retval SUCCESS - Hex string converted successfully
 * @retval ERR_INVALID_PARAM - hex_val is NULL or converted length doesn't match hexLen
 *
 */
int getHexGeneric(char *hex_val, unsigned char *hexVal, int hexLen);

