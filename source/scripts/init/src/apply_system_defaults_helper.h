/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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
 * Copyright 2023 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
**********************************************************************/
#ifndef _APPLY_SYSTEM_DEFAULTS_HELPER_H_
#define _APPLY_SYSTEM_DEFAULTS_HELPER_H_

#define APPLY_DEFAULTS_FACTORY_RESET  "/tmp/.apply_defaults_factory_reset"

#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#define PARTNER_ID_MAX_RETRY    5

/**
* @brief Fetch Partner ID with retry mechanism.
*
* Attempts to fetch the Partner ID from factory HAL or device properties with multiple retries.
* \n Validates the Partner ID and ensures it is not "Unknown".
* \n Maximum retry count is PARTNER_ID_MAX_RETRY.
* \n The buffer pointed by PartnerID should be allocated with a size of at least PARTNER_ID_LEN bytes.
*
* @param[out] PartnerID - Buffer to store the fetched Partner ID.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if failed after all retries.
*/
int PartnerId_FetchWithRetry(char *PartnerID );

/**
* @brief Write Partner ID to file.
*
* Writes the Partner ID string to the /nvram/.partner_ID file.
*
* @param[in] PartnerID - Partner ID string to write to file.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if error (file open failure or NULL Partner ID).
*/
int WritePartnerIDToFile(char* PartnerID);

/**
* @brief Check and handle invalid Partner ID recovery process.
*
* Detects invalid or "Unknown" Partner ID values and triggers recovery process.
* \n Retries fetching valid Partner ID, updates syscfg, triggers factory reset if needed,
* \n and creates /nvram/.Invalid_PartnerID file for tracking.
*
* @param[in,out] PartnerID - Partner ID buffer to validate and potentially update.
*
* @return None
*/
void CheckAndHandleInvalidPartnerIDRecoveryProcess(char *PartnerID);

#endif // (_RDKB_GLOBAL_PRODUCT_REQ_)

/**
* @brief Get the Partner ID.
*
* Retrieves Partner ID from /nvram/.partner_ID file if available,
* \n otherwise fetches from factory HAL or device.properties file.
* \n Falls back to platform-specific defaults if all sources fail.
* \n The buffer pointed by PartnerID should be allocated with a size of at least PARTNER_ID_LEN bytes.
*
* @param[out] PartnerID - Buffer to store the retrieved Partner ID.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero if error.
*/
int get_PartnerID( char *PartnerID);

/**
* @brief Get factory Partner ID from HAL.
*
* Retrieves the factory Partner ID from platform HAL with retry mechanism (3 attempts).
*
* @param[out] pValue - Buffer to store the factory Partner ID.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if failed after all retries or not supported.
*/
int getFactoryPartnerId (char *pValue);

/**
* @brief Parse command line arguments.
*
* Parses command line options, if any command line args then apply them.
*
* @param[in] argc - Argument count.
* @param[in] argv - Argument vector array.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if error.
*/
int parse_command_line(int argc, char **argv);

/**
* @brief Set system default values.
*
* Applies system defaults by setting syscfg and sysevent variables.
* \n Processes syscfg variables first, then sysevent variables.
* \n Checks version compatibility before applying defaults.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if error.
*/
int set_defaults(void);

/**
* @brief Set syscfg partner values.
*
* Sets and commits a syscfg parameter with the specified value for partner-specific configuration.
*
* @param[in] pValue - Value to set for the parameter.
* @param[in] param - Parameter name to set in syscfg.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval 1 if syscfg_set_commit failed.
*/
int set_syscfg_partner_values (char *pValue, char *param);

/**
* @brief Compare partner JSON parameters.
*
* Compares partner parameters between bootstrap.json (NVRAM) and partners_defaults.json (etc).
* \n Removes unknown objects from bootstrap.json and validates Partner ID.
* \n Reinitializes bootstrap.json if parsing errors occur.
*
* @param[in] partner_nvram_bs_obj - JSON string from bootstrap.json.
* @param[in] partner_etc_obj - JSON string from partners_defaults.json.
* @param[in] PartnerID - Partner ID to validate.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if JSON parse error or reinitialization needed.
*/
int compare_partner_json_param (char *partner_nvram_bs_obj, char *partner_etc_obj, char *PartnerID);

/**
* @brief Apply Partner ID specific default values.
*
* Applies partner-specific default values from JSON configuration.
* \n Handles syscfg and PSM parameter updates based on partner configuration.
* \n Checks /nvram/.apply_partner_defaults file to determine if defaults need to be applied.
*
* @param[in] data - JSON configuration data string.
* @param[in] PartnerID - Partner ID for which to apply defaults.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero if error.
*/
int apply_partnerId_default_values (char *data, char *PartnerID);

/**
* @brief Parse JSON file.
*
* Reads and loads a JSON file from the specified path into memory.
* \n Allocates memory for the file content which must be freed by the caller.
*
* @param[in] path - File path of the JSON file to parse.
*
* @return Pointer to allocates json string.
* @retval Pointer to allocated JSON string on success.
* @retval NULL on failure.
*/
char *json_file_parse (char *path);

/**
* @brief Initialize bootstrap JSON file.
*
* Creates or updates bootstrap.json by merging partner NVRAM and etc configurations.
* \n Adds properties, default values, active values, and update timestamps.
* \n Handles model-specific overrides and writes to /opt/secure/bootstrap.json.
*
* @param[in] partner_nvram_obj - JSON string from NVRAM partner configuration.
* @param[in] partner_etc_obj - JSON string from etc partner configuration.
* @param[in] PartnerID - Partner ID for which to initialize bootstrap.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Non-zero if error.
*/
int init_bootstrap_json (char *partner_nvram_obj, char *partner_etc_obj, char *PartnerID);

/**
* @brief Get Partner ID with retry mechanism.
*
* Attempts to retrieve Partner ID from syscfg.db with retries (up to RETRY_COUNT attempts).
* \n Falls back to factory Partner ID if syscfg retrieval fails after all retries.
* \n The buffer pointed by buf and PartnerID should be allocated with at least 64 bytes.
*
* @param[out] buf - Temporary buffer for syscfg retrieval.
* @param[out] PartnerID - Buffer to store the retrieved Partner ID.
*
* @return None
*/
void getPartnerIdWithRetry(char* buf, char* PartnerID);

/**
* @brief Initialize D-Bus connection.
*
* Initializes the CCSP message bus connection for D-Bus communication.
* \n Uses either synchronous or asynchronous initialization based on DBUS_INIT_SYNC_MODE.
* \n Sets up the global bus handle for subsequent D-Bus operations.
*
* @return The status of the operation.
* @retval 0 or positive value if successful.
* @retval -1 if initialization failed.
*/
int dbusInit(void);

/**
* @brief Set PSM record value.
*
* Sets a PSM (Persistent Storage Manager) record with the specified name and value.
* \n Includes retry mechanism to handle PSM initialization delays during early bootup.
*
* @param[in] name - Name of the PSM record.
* @param[in] str - Value to set for the PSM record.
*
* @return The status of the operation.
* @retval CCSP_SUCCESS if successful.
* @retval Error code if failed after all retries.
*/
int set_psm_record(char *name,char *str);

#endif /* _APPLY_SYSTEM_DEFAULTS_HELPER_H_ */
