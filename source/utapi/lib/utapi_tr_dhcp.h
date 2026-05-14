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

#ifndef __UTAPI_TR_DHCP_H__
#define __UTAPI_TR_DHCP_H__

#include  <stdint.h>
#define STR_SZ 64
#define MAX_NUM_INSTANCES 255
#define DHCPV4_NUM_SERVER_POOLS 1

#define  IPV4_ADDRESS                                                        \
         union                                                               \
         {                                                                   \
            unsigned char           Dot[4];                                  \
            uint32_t                Value;                                   \
         }

#define DELIM_CHAR ','

typedef  enum
_DHCP_SERVER_POOL_STATUS
{
    DHCP_SERVER_POOL_STATUS_Disabled = 1,
    DHCP_SERVER_POOL_STATUS_Enabled,
    DHCP_SERVER_POOL_STATUS_Error_Misconfigured,
    DHCP_SERVER_POOL_STATUS_Error
}DHCP_SERVER_POOL_STATUS;


/* Config portion of DHCPv4 Server */

typedef struct
dhcpV4ServerCfg
{
    unsigned char                   bEnabled;

}dhcpv4ServerCfg_t;

/* Config portion of DHCPv4 Server Pool */

typedef struct
dhcpV4ServerPoolCfg
{
    unsigned long                   InstanceNumber;
    char                            Alias[64];
    unsigned char                   bEnabled;
    unsigned long                   Order;
    char                            Interface[64];
    char                            VendorClassID[256];
    unsigned char                   VendorClassIDExclude;
    unsigned int                    VendorClassIDMode;
    unsigned char                   ClientID[256];
    unsigned char                   ClientIDExclude;
    unsigned char                   UserClassID[256];
    unsigned char                   UserClassIDExclude;
    unsigned char                   Chaddr[6];
    unsigned char                   ChaddrMask[6];
    unsigned char                   ChaddrExclude;
    unsigned char                   DNSServersEnabled;
    IPV4_ADDRESS                    MinAddress;
    char                            MinAddressUpdateSource[16];
    IPV4_ADDRESS                    MaxAddress;
    char                            MaxAddressUpdateSource[16];
    IPV4_ADDRESS                    ReservedAddresses[8];
    IPV4_ADDRESS                    SubnetMask;
    IPV4_ADDRESS                    DNSServers[4];
    char                            DomainName[64];
    IPV4_ADDRESS                    IPRouters[4];
    int                             LeaseTime;
    int                             X_CISCO_COM_TimeOffset;
    unsigned char                   bAllowDelete;
}dhcpV4ServerPoolCfg_t;

/* Info portion of DHCPv4 Server Pool */

typedef struct
dhcpV4ServerPoolInfo
{
    DHCP_SERVER_POOL_STATUS         Status;
    unsigned long                   activeClientNumber;
}dhcpV4ServerPoolInfo_t;

/* DHCPv4 Server Pool Entry */

typedef struct
dhcpV4ServerPoolEntry
{
    dhcpV4ServerPoolCfg_t      Cfg;
    dhcpV4ServerPoolInfo_t     Info;
}dhcpV4ServerPoolEntry_t;

typedef struct
dhcpV4ServerPoolStaticAddress
{
    unsigned long                   InstanceNumber;
    char                            Alias[64];
    unsigned char                   bEnabled;
    unsigned char                   Chaddr[6];
    IPV4_ADDRESS                    Yiaddr;
    char                            DeviceName[64];
    char                            comments[256];
    unsigned char                   ActiveFlag;
}dhcpV4ServerPoolStaticAddress_t;

/* Function prototypes */

/**
* @brief Get the DHCPv4 server enable status.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[out] bEnabled - Pointer to an unsigned char where the enable status will be returned.
*                        \n FALSE (0) if disabled, TRUE (non-zero) if enabled.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetDhcpServerEnable(UtopiaContext *ctx, unsigned char *bEnabled);

/**
* @brief Set the DHCPv4 server enable status.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] bEnabled - Enable status to be set.
*                       \n FALSE (0) to disable, TRUE (non-zero) to enable.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetDhcpServerEnable(UtopiaContext *ctx, unsigned char bEnabled);

/**
* @brief Get the total number of DHCPv4 server pools.
*
* @return The number of DHCPv4 server pools.
* @retval DHCPV4_NUM_SERVER_POOLS The fixed number of server pools supported.
*
*/
int Utopia_GetNumberOfDhcpV4ServerPools();

/**
* @brief Get a DHCPv4 server pool entry by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the DHCPv4 server pool entry.
* @param[out] pEntry  - Pointer to a dhcpV4ServerPoolEntry_t structure where the pool entry data will be returned.
*                       \n The structure includes both configuration and information components.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pEntry is NULL.
*
*/
int Utopia_GetDhcpV4ServerPoolEntry(UtopiaContext *ctx,unsigned long ulIndex, void *pEntry);

/**
* @brief Get the DHCPv4 server pool configuration.
*
* @param[in]  ctx  - Pointer to the Utopia context.
* @param[out] pCfg - Pointer to a dhcpV4ServerPoolCfg_t structure where the pool configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pCfg is NULL.
*
*/
int Utopia_GetDhcpV4ServerPoolCfg(UtopiaContext *ctx,void *pCfg);

/**
* @brief Get the DHCPv4 server pool information.
*
* @param[in]  ctx              - Pointer to the Utopia context.
* @param[in]  ulInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[out] pInfo            - Pointer to a dhcpV4ServerPoolInfo_t structure where the pool information will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pInfo is NULL.
* @retval ERR_SYSEVENT_CONN if unable to connect to sysevent.
*
*/
int Utopia_GetDhcpV4ServerPoolInfo(UtopiaContext *ctx, unsigned long ulInstanceNumber, void *pInfo);

/**
* @brief Set the DHCPv4 server pool configuration.
*
* @param[in] ctx  - Pointer to the Utopia context.
* @param[in] pCfg - Pointer to a dhcpV4ServerPoolCfg_t structure containing the pool configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pCfg is NULL.
*
*/
int Utopia_SetDhcpV4ServerPoolCfg(UtopiaContext *ctx, void *pCfg);

/**
* @brief Set the instance number and alias for a DHCPv4 server pool.
*
* @param[in] ctx              - Pointer to the Utopia context.
* @param[in] ulIndex          - Index of the DHCPv4 server pool.
* @param[in] ulInstanceNumber - Instance number to be set.
* @param[in] pAlias           - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pAlias is NULL.
*
*/
int Utopia_SetDhcpV4ServerPoolValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNumber, char *pAlias);

/**
* @brief Get the number of static address entries in a DHCPv4 server pool.
*
* @param[in] ctx                  - Pointer to the Utopia context.
* @param[in] ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
*
* @return The number of static address entries in the pool.
*
*/
int Utopia_GetDhcpV4SPool_NumOfStaticAddress(UtopiaContext *ctx,unsigned long ulPoolInstanceNumber);

/**
* @brief Get a static address entry from a DHCPv4 server pool by index.
*
* @param[in]  ctx                  - Pointer to the Utopia context.
* @param[in]  ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[in]  ulIndex              - Index of the static address entry.
* @param[out] pSAddr               - Pointer to a dhcpV4ServerPoolStaticAddress_t structure where the static address data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pSAddr is NULL, or if instance number exceeds MAX_NUM_INSTANCES.
*
*/
int Utopia_GetDhcpV4SPool_SAddress(UtopiaContext *ctx, unsigned long ulPoolInstanceNumber,unsigned long ulIndex, void *pSAddr);

/**
* @brief Get a static address entry from a DHCPv4 server pool by instance number.
*
* @param[in]     ctx                    - Pointer to the Utopia context.
* @param[in]     ulClientInstanceNumber - Instance number of the client.
* @param[in,out] pSAddr                 - Pointer to a dhcpV4ServerPoolStaticAddress_t structure.
*                                         \n [in] The InstanceNumber field must be set to the instance number to retrieve.
*                                         \n [out] The structure will be populated with the static address data.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pSAddr is NULL, or if InstanceNumber is 0.
*
*/
int Utopia_GetDhcpV4SPool_SAddressByInsNum(UtopiaContext *ctx, unsigned long ulClientInstanceNumber, void *pSAddr);

/**
* @brief Add a new static address entry to a DHCPv4 server pool.
*
* @param[in] ctx                  - Pointer to the Utopia context.
* @param[in] ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[in] pSAddr               - Pointer to a dhcpV4ServerPoolStaticAddress_t structure containing the static address data to be added.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pSAddr is NULL, instance number is 0, MAC address is invalid,
*                          IP address is invalid, or IP/MAC already exists in the list.
*
*/
int Utopia_AddDhcpV4SPool_SAddress(UtopiaContext *ctx, unsigned long ulPoolInstanceNumber, void *pSAddr);

/**
* @brief Delete a static address entry from a DHCPv4 server pool.
*
* @param[in] ctx                  - Pointer to the Utopia context.
* @param[in] ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[in] ulInstanceNumber     - Instance number of the static address entry to be deleted.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL or instance number is 0.
*
*/
int Utopia_DelDhcp4SPool_SAddress(UtopiaContext *ctx, unsigned long ulPoolInstanceNumber, unsigned long ulInstanceNumber);

/**
* @brief Set a static address entry in a DHCPv4 server pool.
*
* @param[in] ctx                  - Pointer to the Utopia context.
* @param[in] ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[in] pSAddr               - Pointer to a dhcpV4ServerPoolStaticAddress_t structure containing the static address data to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL or instance number is 0.
*
*/
int Utopia_SetDhcpV4SPool_SAddress(UtopiaContext *ctx, unsigned long ulPoolInstanceNumber, void *pSAddr);

/**
* @brief Set the instance number and alias for a static address entry in a DHCPv4 server pool.
*
* @param[in] ctx                  - Pointer to the Utopia context.
* @param[in] ulPoolInstanceNumber - Instance number of the DHCPv4 server pool.
* @param[in] ulIndex              - Index of the static address entry.
* @param[in] ulInstanceNumber     - Instance number to be set.
* @param[in] pAlias               - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pAlias is NULL.
*
*/
int Utopia_SetDhcpV4SPool_SAddress_Values(UtopiaContext *ctx, unsigned long ulPoolInstanceNumber, unsigned long ulIndex, unsigned long ulInstanceNumber, char *pAlias);

/* Utility Functions */
/**
* @brief Get a static address entry from a DHCPv4 server pool by index (utility function).
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ulIndex  - Index of the static address entry.
* @param[out] pSAddr_t - Pointer to a dhcpV4ServerPoolStaticAddress_t structure where the static address data will be returned.
*                        \n The structure includes instance number, alias, enable status, MAC address,
*                        \n IP address, device name, comments, and active flag.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval 1 if error occurs.
*
*/
int Utopia_GetDhcpV4SPool_SAddressByIndex(UtopiaContext *ctx, unsigned long ulIndex, dhcpV4ServerPoolStaticAddress_t *pSAddr_t);
#endif // __UTAPI_TR_DHCP_H__
