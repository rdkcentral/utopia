/*#####################################################################
# Copyright 2017-2019 ARRIS Enterprises, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
######################################################################*/

#ifndef __UTAPI_TR_DSLITE_H__
#define __UTAPI_TR_DSLITE_H__

#define STR_SZ 257

#define MAX_NUM_INSTANCES 255

typedef struct
DsLiteCfg
{
    unsigned long  InstanceNumber;
    int            active;
    int            status;
    char           alias[64+1];
    int            mode;
    int            addr_type;
    char           addr_inuse[256+1];
    char           addr_fqdn[256+1];
    char           addr_ipv6[256+1];
    int            origin;
    char           tunnel_interface[256+1];
    char           tunneled_interface[256+1];
    int            mss_clamping_enable;
    unsigned long  tcpmss;
    int            ipv6_frag_enable;
    char           tunnel_v4addr[64+1];
}DsLiteCfg_t;

/**
 * @brief Get DS-Lite global enable status.
 *
 * Retrieves the global enable/disable state for DS-Lite functionality from Utopia context.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[out] bEnabled - Pointer to boolean to receive enable status
 *                        \n TRUE if DS-Lite is enabled
 *                        \n FALSE if DS-Lite is disabled
 *
 * @return The status of the operation.
 * @retval SUCCESS - Enable status retrieved successfully
 *
 */
int Utopia_GetDsliteEnable(UtopiaContext *ctx, boolean_t *bEnabled);

/**
 * @brief Set DS-Lite global enable status.
 *
 * Configures the global enable/disable state for DS-Lite functionality in Utopia context.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] bEnabled - Enable flag to set
 *                       \n TRUE to enable DS-Lite
 *                       \n FALSE to disable DS-Lite
 *
 * @return The status of the operation.
 * @retval SUCCESS - Enable status set successfully
 *
 */
int Utopia_SetDsliteEnable(UtopiaContext *ctx, boolean_t bEnabled);

/**
 * @brief Get number of DS-Lite tunnel entries.
 *
 * Retrieves the count of configured DS-Lite tunnel entries from Utopia context.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[out] cnt - Pointer to unsigned long to receive entry count
 *                   \n Valid range: 0 to MAX_NUM_INSTANCES (255)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Entry count retrieved successfully
 *
 */
int Utopia_GetNumOfDsliteEntries(UtopiaContext *ctx,unsigned long *cnt);

/**
 * @brief Set number of DS-Lite tunnel entries.
 *
 * Updates the count of configured DS-Lite tunnel entries in Utopia context.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] cnt - Number of DS-Lite entries
 *                  \n Valid range: 0 to MAX_NUM_INSTANCES (255)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Entry count set successfully
 *
 */
int Utopia_SetNumOfDsliteEntries(UtopiaContext *ctx,unsigned long cnt);

/**
 * @brief Get DS-Lite tunnel configuration by instance number.
 *
 * Retrieves configuration for a specific DS-Lite tunnel entry identified by instance number.
 * Uses g_IndexMapDslite[] to map instance number to index, then calls Utopia_GetDsliteByIndex().
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in,out] pDsliteCfg - Pointer to DsLiteCfg_t structure
 *                             \n Input: InstanceNumber field must be set (non-zero)
 *                             \n Output: All configuration fields populated
 *
 * @return The status of the operation.
 * @retval SUCCESS - Configuration retrieved successfully
 * @retval ERR_INVALID_ARGS - ctx or pDsliteCfg is NULL, or InstanceNumber is 0
 *
 */
int Utopia_GetDsliteCfg(UtopiaContext *ctx,DsLiteCfg_t *pDsliteCfg);

/**
 * @brief Set DS-Lite tunnel configuration by instance number.
 *
 * Stores configuration for a specific DS-Lite tunnel entry identified by instance number.
 * Uses g_IndexMapDslite[] to map instance number to index, then calls Utopia_SetDsliteByIndex().
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] pDsliteCfg - Pointer to DsLiteCfg_t structure with configuration to set
 *                         \n InstanceNumber field must be set (non-zero)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Configuration stored successfully
 * @retval ERR_INVALID_ARGS - ctx or pDsliteCfg is NULL, or InstanceNumber is 0
 *
 */
int Utopia_SetDsliteCfg(UtopiaContext *ctx,DsLiteCfg_t *pDsliteCfg);

/**
 * @brief Add a new DS-Lite tunnel entry.
 *
 * Creates a new DS-Lite tunnel configuration entry with the specified parameters.
 * Assigns the next available index, updates the entry count, and stores the configuration.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] pDsliteCfg - Pointer to DsLiteCfg_t structure with new entry configuration
 *                         \n InstanceNumber field must be set (non-zero)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Entry added successfully
 * @retval ERR_INVALID_ARGS - ctx or pDsliteCfg is NULL, or InstanceNumber is 0
 *
 */
int Utopia_AddDsliteEntry(UtopiaContext *ctx, DsLiteCfg_t *pDsliteCfg);

/**
 * @brief Delete a DS-Lite tunnel entry by instance number.
 *
 * Removes a DS-Lite tunnel configuration entry and compacts the entry list.
 * All entries after the deleted entry are shifted down by one index.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] ulInstanceNumber - Instance number of entry to delete
 *                               \n Valid range: 1 to MAX_NUM_INSTANCES (255)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Entry deleted successfully
 * @retval ERR_INVALID_ARGS - ctx is NULL or ulInstanceNumber is 0
 *
 */
int Utopia_DelDsliteEntry(UtopiaContext *ctx, unsigned long ulInstanceNumber);

/**
 * @brief Get DS-Lite entry by zero-based index.
 *
 * Retrieves DS-Lite configuration for the entry at the specified index position.
 * If instance number exists at this index, updates g_IndexMapDslite[] mapping.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] ulIndex - Zero-based index of entry to retrieve
 *                      \n Valid range: 0 to (entry_count - 1)
 * @param[out] pDsliteEntry - Pointer to DsLiteCfg_t structure to receive configuration
 *                            \n Cast from void* for generic interface
 *
 * @return The status of the operation.
 * @retval SUCCESS - Entry retrieved successfully
 * @retval ERR_INVALID_ARGS - ctx or pDsliteEntry is NULL
 *
 */
int Utopia_GetDsliteEntry(UtopiaContext *ctx,unsigned long ulIndex, void *pDsliteEntry);

/**
 * @brief Set DS-Lite instance number for a specific index.
 *
 * Associates an instance number with a zero-based index position and updates
 * the g_IndexMapDslite[] mapping.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] ulIndex - Zero-based index position
 *                      \n Valid range: 0 to (MAX_NUM_INSTANCES - 1)
 * @param[in] ulInstanceNumber - Instance number to assign
 *                               \n Valid range: 1 to MAX_NUM_INSTANCES (255)
 *
 * @return The status of the operation.
 * @retval SUCCESS - Instance number set successfully
 * @retval ERR_INVALID_ARGS - ctx is NULL
 *
 */
int Utopia_SetDsliteInsNum(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNumber);

/* Utility functions */

/**
 * @brief Get DS-Lite configuration by zero-based index (utility function).
 *
 * Low-level utility function that retrieves all DS-Lite configuration parameters
 * from Utopia context for the entry at the specified index. Reads both configurable
 * and read-only parameters.
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] ulIndex - Zero-based index of entry to retrieve
 *                      \n Valid range: 0 to (entry_count - 1)
 * @param[out] pDsLiteCfg_t - Pointer to DsLiteCfg_t structure to receive all configuration fields
 *
 * @return The status of the operation.
 * @retval SUCCESS - Configuration retrieved successfully
 *
 */
int Utopia_GetDsliteByIndex(UtopiaContext *ctx, unsigned long ulIndex, DsLiteCfg_t *pDsLiteCfg_t);

/**
 * @brief Set DS-Lite configuration by zero-based index (utility function).
 *
 * Low-level utility function that stores DS-Lite configuration parameters to Utopia context
 * for the entry at the specified index. Writes only configurable parameters (not read-only).
 *
 * @param[in] ctx - Pointer to Utopia context
 * @param[in] ulIndex - Zero-based index of entry to update
 *                      \n Valid range: 0 to (entry_count - 1)
 * @param[in] pDsLiteCfg_t - Pointer to DsLiteCfg_t structure with configuration to store
 *
 * @return The status of the operation.
 * @retval SUCCESS - Configuration stored successfully
 *
 */
int Utopia_SetDsliteByIndex(UtopiaContext *ctx, unsigned long ulIndex, DsLiteCfg_t *pDsLiteCfg_t);

#endif // __UTAPI_TR_DSLITE_H__
