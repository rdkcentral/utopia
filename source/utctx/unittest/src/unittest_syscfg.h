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
 * unittest_syscfg.h - Unittest SysCfg interface
 */

#ifndef __UNITTEST_SYSCFG_H__
#define __UNITTEST_SYSCFG_H__

/**
* @brief Commit all system configuration values to persistent storage.
*
* This function writes all system configuration key-value pairs from the in-memory linked list
* to the UTCTX_STATE_FILE. After writing, all nodes in the linked list are freed.
*
* @return None.
*
*/
extern void SysCfg_Commit(void);

/**
* @brief Initialize system configuration by loading from persistent storage.
*
* This function initializes the system configuration subsystem by reading configuration values
* from the UTCTX_STATE_FILE and populating an in-memory linked list. The function zeros out the global head
* pointer before loading.
*
* @return The status of the operation.
* @retval 1 if the configuration was successfully initialized.
* @retval 0 if the operation failed (file not found, parse error, or memory allocation error).
*
*/
extern int  SysCfg_Init(void);

/**
* @brief Retrieve a system configuration value by namespace and key.
*
* This function searches the in-memory configuration linked list for a matching namespace and key
* combination, and copies the associated value to the provided buffer.
*
* @param[in] pszNamespace - Null-terminated string specifying the namespace to search.
* @param[in] pszKey - Null-terminated string specifying the key to retrieve.
*                    \n Must not be NULL.
* @param[out] pszValue - Pointer to a buffer where the configuration value will be stored.
*                    \n Must be allocated by the caller.
* @param[in] cbBuf - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 1 if the configuration value was successfully retrieved.
* @retval 0 if the operation failed (NULL key, NULL value buffer, or key not found).
*
*/
extern int  SysCfg_Get(char* pszNamespace, char* pszKey, char* pszValue, int cbBuf);

/**
* @brief Retrieve all system configuration values in a single buffer.
*
* This function retrieves all configuration key-value pairs from the in-memory linked list and
* formats them into a single buffer.
*
* @param[out] pBuffer - Pointer to a buffer where all configuration values will be stored.
*                    \n Each entry is null-terminated and formatted as 'namespace::key=value'.
*                    \n Must be allocated by the caller.
* @param[in] ccbBuf - Size of the output buffer in bytes.
* @param[out] pccbBuf - Pointer to an integer where the total bytes used will be stored.
*                    \n Must not be NULL.
*
* @return The status of the operation.
* @retval 1 if all configuration values were successfully retrieved.
* @retval 0 if the operation failed (NULL buffer, NULL pccbBuf, or insufficient buffer space).
*
*/
extern int  SysCfg_GetAll(char* pBuffer, int ccbBuf, int* pccbBuf);

/**
* @brief Set a system configuration value by namespace and key.
*
* This function sets a configuration value in the in-memory linked list. If the namespace and key
* combination already exists, the value is updated. If it doesn't exist, a new node is created and
* appended to the end of the linked list.
*
* @param[in] pszNamespace - Null-terminated string specifying the namespace.
* @param[in] pszKey - Null-terminated string specifying the key to set.
*                    \n Must not be NULL.
* @param[in] pszValue - Null-terminated string containing the value to set.
*                    \n Must not be NULL.
*
* @return The status of the operation.
* @retval 1 if the configuration value was successfully set.
* @retval 0 if the operation failed (NULL key, NULL value, or memory allocation error).
*
*/
extern int  SysCfg_Set(char* pszNamespace, char* pszKey, char* pszValue);

/**
* @brief Unset (remove) a system configuration value by namespace and key.
*
* This function searches the in-memory configuration linked list for a matching namespace and key
* combination and removes the node from the list.
*
* @param[in] pszNamespace - Null-terminated string specifying the namespace to search.
*                    \n Pass NULL to search for keys without a namespace.
* @param[in] pszKey - Null-terminated string specifying the key to unset.
*                    \n Must not be NULL.
*
* @return The status of the operation.
* @retval 1 if the configuration value was successfully unset.
* @retval 0 if the operation failed (NULL key or key not found).
*
*/
extern int  SysCfg_Unset(char* pszNamespace, char* pszKey);

#endif /* __UNITTEST_SYSCFG_H__ */
