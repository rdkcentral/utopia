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

#ifndef _UTAPI_PARENTAL_CONTROL_H_
#define _UTAPI_PARENTAL_CONTROL_H_

#include "autoconf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mng_devs
{
    boolean_t enable;
    boolean_t allow_all; //If true, all the devices is allowed to connect to the network except for those devices with md_dev.is_block set to true. Vice versa.
} mng_devs_t;

/**
* @brief Get the managed devices configuration.
*
* @param[in]  ctx       - Pointer to the Utopia context.
* @param[out] mng_devs  - Pointer to a mng_devs_t structure where the managed devices configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetMngDevsCfg(UtopiaContext *ctx, mng_devs_t *mng_devs);

/**
* @brief Set the managed devices configuration.
*
* @param[in] ctx       - Pointer to the Utopia context.
* @param[in] mng_devs  - Pointer to a mng_devs_t structure containing the managed devices configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetMngDevsCfg(UtopiaContext *ctx, const mng_devs_t *mng_devs);

//----------------------------------------------------------------
typedef struct blkurl
{
    boolean_t always_block; //If set to false, always block. Other only block by start_time ~ end_time in time of day and block_days in day of week.
    unsigned long ins_num;
    char alias[256];
    char block_method[8]; //must be "URL" or "KEYWD". "URL" prevents access to specific website URLS. "KEYWD" restricts access to websites names that contain specific words.
    char site[1024]; //The url or the keyword, e.g. "www.google.com" or "google" or "www.google.com,www.aol.com,www.twitter.com"
    char start_time[64]; //e.g. "20:00"
    char end_time[64];
    char block_days[64]; //e.g. "Mon,Wed,Fri"
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
    char mac[32]; //e.g. "00:11:22:33:44:55"
    char device_name[128]; //e.g. "Jack's PC"
#endif
}blkurl_t;

/**
* @brief Get the blocked URL configuration status.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] enable - Pointer to an integer where the enable status will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetBlkURLCfg(UtopiaContext *ctx, int *enable);

/**
* @brief Set the blocked URL configuration status.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - Enable status to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetBlkURLCfg(UtopiaContext *ctx, const int enable);

/**
* @brief Get the instance number of a blocked URL entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - Index of the blocked URL entry.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
*
*/
int Utopia_GetBlkURLInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of blocked URL entries.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the count will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetNumberOfBlkURL(UtopiaContext *ctx, int *num);

/**
* @brief Get a blocked URL entry by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the blocked URL entry.
* @param[out] blkurl  - Pointer to a blkurl_t structure where the blocked URL data will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetBlkURLByIndex(UtopiaContext *ctx, unsigned long ulIndex, blkurl_t *blkurl);

/**
* @brief Set a blocked URL entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the blocked URL entry.
* @param[in] blkurl  - Pointer to a blkurl_t structure containing the blocked URL data to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetBlkURLByIndex(UtopiaContext *ctx, unsigned long ulIndex, const blkurl_t *blkurl);

/**
* @brief Set instance number and alias for a blocked URL entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the blocked URL entry.
* @param[in] ins     - Instance number to be set.
* @param[in] alias   - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetBlkURLInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ins, const char *alias);

/**
* @brief Add a new blocked URL entry.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] blkurl - Pointer to a blkurl_t structure containing the blocked URL data to be added.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddBlkURL(UtopiaContext *ctx, const blkurl_t *blkurl);

/**
* @brief Delete a blocked URL entry by instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the blocked URL entry to be deleted.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
* @retval -1 if the entry is out of range.
*
*/
int Utopia_DelBlkURL(UtopiaContext *ctx, unsigned long ins);

//--------------------------------------------------------------------
typedef struct trusted_user
{
    boolean_t trusted;
    unsigned long ins_num;
    char alias[256];

    char host_descp[64]; //e.g. "Bob's computer"
    unsigned char ipaddrtype; // 4 or 6
    char ipaddr[64];
}trusted_user_t;

/**
* @brief Get the instance number of a trusted user entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - Index of the trusted user entry.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetTrustedUserInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of trusted user entries.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the count will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetNumberOfTrustedUser(UtopiaContext *ctx, int *num);

/**
* @brief Get a trusted user entry by index.
*
* @param[in]  ctx          - Pointer to the Utopia context.
* @param[in]  ulIndex      - Index of the trusted user entry.
* @param[out] trusted_user - Pointer to a trusted_user_t structure where the trusted user data will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetTrustedUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, trusted_user_t *trusted_user);

/**
* @brief Set a trusted user entry by index.
*
* @param[in] ctx          - Pointer to the Utopia context.
* @param[in] ulIndex      - Index of the trusted user entry.
* @param[in] trusted_user - Pointer to a trusted_user_t structure containing the trusted user data to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetTrustedUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, const trusted_user_t *trusted_user);

/**
* @brief Set instance number and alias for a trusted user entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the trusted user entry.
* @param[in] ins     - Instance number to be set.
* @param[in] alias   - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetTrustedUserInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, int ins, const char *alias);

/**
* @brief Add a new trusted user entry.
*
* @param[in] ctx          - Pointer to the Utopia context.
* @param[in] trusted_user - Pointer to a trusted_user_t structure containing the trusted user data to be added.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddTrustedUser(UtopiaContext *ctx, const trusted_user_t *trusted_user);

/**
* @brief Delete a trusted user entry by instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the trusted user entry to be deleted.
*
* @return The status of the operation.
* @retval -1 if the entry is out of range.
* @retval 0 if the operation is successful.
*
*/
int Utopia_DelTrustedUser(UtopiaContext *ctx, unsigned long ins);

//----------------------------------------------------------------------
typedef struct ms_serv
{
    boolean_t always_block;
    unsigned long ins_num;
    char alias[256];

    char descp[64]; //e.g. "FTP download"
    char protocol[8]; // must be one of "TCP" / "UDP" / "BOTH"
    unsigned long start_port;
    unsigned long end_port;
    char start_time[64]; //e.g. 20:00
    char end_time[64];
    char block_days[64];
}ms_serv_t;


/**
* @brief Get the managed services configuration status.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[out] enable - Pointer to an integer where the enable status will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetMngServsCfg(UtopiaContext *ctx, int *enable);

/**
* @brief Set the managed services configuration status.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] enable - Enable status to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetMngServsCfg(UtopiaContext *ctx, const int enable);

/**
* @brief Get the instance number of a managed service entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - Index of the managed service entry.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMSServInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of managed service entries.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the count will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetNumberOfMSServ(UtopiaContext *ctx, int *num);

/**
* @brief Get a managed service entry by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the managed service entry.
* @param[out] ms_serv - Pointer to a ms_serv_t structure where the managed service data will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMSServByIndex(UtopiaContext *ctx, unsigned long ulIndex, ms_serv_t *ms_serv);

/**
* @brief Set a managed service entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the managed service entry.
* @param[in] ms_serv - Pointer to a ms_serv_t structure containing the managed service data to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMSServByIndex(UtopiaContext *ctx, unsigned long ulIndex, const ms_serv_t *ms_serv);

/**
* @brief Set instance number and alias for a managed service entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the managed service entry.
* @param[in] ins     - Instance number to be set.
* @param[in] alias   - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMSServInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, int ins, const char *alias);

/**
* @brief Add a new managed service entry.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ms_serv - Pointer to a ms_serv_t structure containing the managed service data to be added.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddMSServ(UtopiaContext *ctx, const ms_serv_t *ms_serv);

/**
* @brief Delete a managed service entry by instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the managed service entry to be deleted.
*
* @return The status of the operation.
* @retval -1 if the entry is out of range.
* @retval 0 if the operation is successful.
*
*/
int Utopia_DelMSServ(UtopiaContext *ctx, unsigned long ins);

//----------------------------------------------------------------------
typedef struct ms_trusteduser
{
    boolean_t trusted;
    unsigned long ins_num;
    char alias[256];

    char host_descp[64];
    unsigned char ipaddrtype; // 4 or 6
    char ipaddr[64];
}ms_trusteduser_t;

/**
* @brief Get the instance number of a managed services trusted user entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - Index of the managed services trusted user entry.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMSTrustedUserInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of managed services trusted user entries.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the count will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetNumberOfMSTrustedUser(UtopiaContext *ctx, int *num);

/**
* @brief Get a managed services trusted user entry by index.
*
* @param[in]  ctx             - Pointer to the Utopia context.
* @param[in]  ulIndex         - Index of the managed services trusted user entry.
* @param[out] ms_trusteduser  - Pointer to a ms_trusteduser_t structure where the managed services trusted user data will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMSTrustedUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, ms_trusteduser_t *ms_trusteduser);

/**
* @brief Set a managed services trusted user entry by index.
*
* @param[in] ctx            - Pointer to the Utopia context.
* @param[in] ulIndex        - Index of the managed services trusted user entry.
* @param[in] ms_trusteduser - Pointer to a ms_trusteduser_t structure containing the managed services trusted user data to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMSTrustedUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, const ms_trusteduser_t *ms_trusteduser);

/**
* @brief Set instance number and alias for a managed services trusted user entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the managed services trusted user entry.
* @param[in] ins     - Instance number to be set.
* @param[in] alias   - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMSTrustedUserInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, int ins, const char *alias);

/**
* @brief Add a new managed services trusted user entry.
*
* @param[in] ctx            - Pointer to the Utopia context.
* @param[in] ms_trusteduser - Pointer to a ms_trusteduser_t structure containing the managed services trusted user data to be added.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddMSTrustedUser(UtopiaContext *ctx, const ms_trusteduser_t *ms_trusteduser);

/**
* @brief Delete a managed services trusted user entry by instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the managed services trusted user entry to be deleted.
*
* @return The status of the operation.
* @retval -1 if the entry is out of range.
* @retval 0 if the operation is successful.
*
*/
int Utopia_DelMSTrustedUser(UtopiaContext *ctx, unsigned long ins);

//-------------------------------------------------------------------
typedef struct md_dev
{
    unsigned long ins_num;
    char alias[256];

    boolean_t is_block; //If set to true, this device is prevented from connecting this network. Other, it is allowed.
    boolean_t always; //Always blocked or allowed based on the value of is_block.
    char descp[64]; //e.g. "Bob's computer"
    char macaddr[64];
    char start_time[64]; //e.g. 20:00
    char end_time[64];
    char block_days[64];
}md_dev_t;

/**
* @brief Get the instance number of a managed device entry by index.
*
* @param[in]  ctx    - Pointer to the Utopia context.
* @param[in]  uIndex - Index of the managed device entry.
* @param[out] ins    - Pointer to an integer where the instance number will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMDDevInsNumByIndex(UtopiaContext *ctx, unsigned long uIndex, int *ins);

/**
* @brief Get the total number of managed device entries.
*
* @param[in]  ctx - Pointer to the Utopia context.
* @param[out] num - Pointer to an integer where the count will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetNumberOfMDDev(UtopiaContext *ctx, int *num);

/**
* @brief Get a managed device entry by index.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ulIndex - Index of the managed device entry.
* @param[out] md_dev  - Pointer to a md_dev_t structure where the managed device data will be returned.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_GetMDDevByIndex(UtopiaContext *ctx, unsigned long ulIndex, md_dev_t *md_dev);

/**
* @brief Set a managed device entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the managed device entry.
* @param[in] md_dev  - Pointer to a md_dev_t structure containing the managed device data to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMDDevByIndex(UtopiaContext *ctx, unsigned long ulIndex, const md_dev_t *md_dev);

/**
* @brief Set instance number and alias for a managed device entry by index.
*
* @param[in] ctx     - Pointer to the Utopia context.
* @param[in] ulIndex - Index of the managed device entry.
* @param[in] ins     - Instance number to be set.
* @param[in] alias   - Pointer to the alias string to be set.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_SetMDDevInsAndAliasByIndex(UtopiaContext *ctx, unsigned long ulIndex, int ins, const char *alias);

/**
* @brief Add a new managed device entry.
*
* @param[in] ctx    - Pointer to the Utopia context.
* @param[in] md_dev - Pointer to a md_dev_t structure containing the managed device data to be added.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int Utopia_AddMDDev(UtopiaContext *ctx, const md_dev_t *md_dev);

/**
* @brief Delete a managed device entry by instance number.
*
* @param[in] ctx - Pointer to the Utopia context.
* @param[in] ins - Instance number of the managed device entry to be deleted.
*
* @return The status of the operation.
* @retval -1 if the entry is out of range.
* @retval 0 if the operation is successful.
*
*/
int Utopia_DelMDDev(UtopiaContext *ctx, unsigned long ins);

#ifdef __cplusplus
}
#endif

#endif
