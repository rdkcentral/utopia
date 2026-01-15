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

#ifndef __UTAPI_TR_USER_H__
#define __UTAPI_TR_USER_H__

#define STR_SZ 64
#define PWD_SZ 128
#define MAX_NUM_INSTANCES 255

#define DELIM_CHAR ','

#define TMP_FILE "/tmp/tr_user"

typedef  enum
_USER_ACCESS_PERMISSIONS
{
    USER_ADMIN = 1,
    USER_HOMEUSER,
    USER_RESTRICTED,
    USER_DENIED
}USER_ACCESS_PERMISSIONS;


/* Config portion of User */

typedef struct
userCfg
{
    unsigned long                   InstanceNumber;

    unsigned char                   bEnabled;
    unsigned char                   RemoteAccessCapable;
    char                            Username[STR_SZ];
    char                            Password[PWD_SZ];
    char                            Language[16];
    char 	                    NumOfFailedAttempts;
    char                            X_RDKCENTRAL_COM_ComparePassword[32];
    char 			    HashedPassword[128];
    int			     	    RemainingAttempts;
    int			       	    LoginCounts;
    int				    LockOutRemainingTime;
#if defined(_COSA_FOR_BCI_)
    int                             NumOfRestoreFailedAttempt;
#endif
    USER_ACCESS_PERMISSIONS         AccessPermissions;
}userCfg_t;

/* Function prototypes */

/**
* @brief Get the total number of user accounts.
*
* @param[in] ctx - Pointer to the Utopia context.
*
* @return The number of user accounts.
* @retval The number of user accounts on success.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_GetNumOfUsers(UtopiaContext *ctx);

/**
* @brief Set the total number of user accounts.
*
* @param[in] ctx   - Pointer to the Utopia context.
* @param[in] count - The number of user accounts to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_SetNumOfUsers(UtopiaContext *ctx, int count);

/**
* @brief Get a user entry by index.
*
* @param[in]  ctx        - Pointer to the Utopia context.
* @param[in]  ulIndex    - Index of the user entry (0-based).
* @param[out] pUserEntry - Pointer to a userCfg_t structure where the user entry data will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pUserEntry is NULL.
*
*/
int Utopia_GetUserEntry(UtopiaContext *ctx,unsigned long ulIndex, void *pUserEntry);

/**
* @brief Get a user configuration by instance number.
*
* @param[in,out] ctx      - Pointer to the Utopia context.
* @param[in,out] pUserCfg - Pointer to a userCfg_t structure.
*                           \n [in] The InstanceNumber field must be set to the instance number to retrieve.
*                           \n [out] The structure will be populated with the user configuration data.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pUserCfg is NULL, or if InstanceNumber is 0.
*
*/
int Utopia_GetUserCfg(UtopiaContext *ctx,void *pUserCfg);

/**
* @brief Set a user configuration by instance number.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] pUserCfg - Pointer to a userCfg_t structure containing the user configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pUserCfg is NULL, or if InstanceNumber is 0.
*
*/
int Utopia_SetUserCfg(UtopiaContext *ctx, void *pUserCfg);

/**
* @brief Set the instance number for a user entry at a given index.
*
* @param[in] ctx              - Pointer to the Utopia context.
* @param[in] ulIndex          - Index of the user entry (0-based).
* @param[in] ulInstanceNumber - Instance number to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL.
*
*/
int Utopia_SetUserValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNumber);

/**
* @brief Add a new user account.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] pUserCfg - Pointer to a userCfg_t structure containing the user configuration to be added.
*                       \n The InstanceNumber field must be valid (non-zero).
*                       \n The user count will be incremented automatically.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx or pUserCfg is NULL, or if InstanceNumber is 0.
*
*/
int Utopia_AddUser(UtopiaContext *ctx, void *pUserCfg);

/**
* @brief Delete a user account by instance number.
*
* @param[in] ctx              - Pointer to the Utopia context.
* @param[in] ulInstanceNumber - Instance number of the user account to be deleted.
*                               \n If the user is enabled and has remote access capability,
*                               \n the user will also be removed from the Linux system using deluser command.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_INVALID_ARGS if ctx is NULL or if InstanceNumber is 0.
*
*/
int Utopia_DelUser(UtopiaContext *ctx, unsigned long ulInstanceNumber);

/* Utility functions */
/**
* @brief Get a user configuration by index.
*
* @param[in]  ctx        - Pointer to the Utopia context.
* @param[in]  ulIndex    - Index of the user entry (0-based).
* @param[out] pUserCfg_t - Pointer to a userCfg_t structure where the user configuration will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_GetUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, userCfg_t *pUserCfg_t);

/**
* @brief Set a user configuration by index.
*
* @param[in] ctx        - Pointer to the Utopia context.
* @param[in] ulIndex    - Index of the user entry (0-based).
* @param[in] pUserCfg_t - Pointer to a userCfg_t structure containing the user configuration to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
*
*/
int Utopia_SetUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, userCfg_t *pUserCfg_t);

#endif // __UTAPI_TR_USER_H__
