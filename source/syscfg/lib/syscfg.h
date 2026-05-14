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

#ifndef _SYSCFG_H_
#define _SYSCFG_H_

#include <stddef.h>

#define SYSCFG_SZ (100 * 1024)

#define ERR_INVALID_PARAM     -1
#define ERR_NOT_INITIALIZED   -2
#define ERR_MEM_ALLOC         -3
#define ERR_INVALID_STATE     -4
#define ERR_SEMAPHORE_INIT    -5
#define ERR_NO_SPACE          -6
#define ERR_ENTRY_TOO_BIG     -7
#define ERR_SHM_CREATE        -10
#define ERR_SHM_INIT          -11
#define ERR_SHM_NO_FILE       -12
#define ERR_SHM_ATTACH        -13
#define ERR_SHM_FAILURE       -14
#define ERR_IO_FAILURE        -20
#define ERR_IO_FILE_OPEN      -21
#define ERR_IO_FILE_STAT      -22
#define ERR_IO_FILE_TOO_BIG   -23
#define ERR_IO_FILE_WRITE     -24

#ifdef __cplusplus
extern "C"{
#endif

/**
* @brief Create syscfg shared memory and load entries from persistent storage.
*
* @param[in] file  - Pointer to the filesystem file path where syscfg is stored.
* @param[in] max_file_sz  - Maximum file size in bytes for syscfg storage.
*                    \n If value is greater than 0, uses provided size; otherwise uses DEFAULT_MAX_FILE_SZ.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_INVALID_PARAM If invalid arguments.
* @retval ERR_SHM_CREATE If shared memory creation failed.
* @retval ERR_IO_FAILURE If syscfg file is unavailable or loading from store failed.
*
*/
int syscfg_create(const char *file, long int max_file_sz);

/**
* @brief Reload syscfg configuration from file.
*
* @param[in] file  - Pointer to the configuration file path to reload.
*
* @return The status of the operation.
* @retval 0 Configuration reloaded successfully.
* @retval ERR_INVALID_PARAM If file parameter is NULL.
* @retval Non-zero If error occurred while reloading config file.
*
*/
int syscfg_reload(const char *file);

/**
* @brief Acquire commit lock for syscfg operations.
*
* @return The status of the lock operation.
* @retval 0 Commit lock acquired successfully.
* @retval Non-zero Lock acquisition failed.
*
*/
int syscfg_commit_lock();

/**
* @brief Release commit lock for syscfg operations.
*
* @return The status of the unlock operation.
* @retval 0 Commit lock released successfully.
* @retval Non-zero Lock release failed.
*
*/
int syscfg_commit_unlock();

/*
 * Historically calling syscfg_init() was the responsibility of any code which
 * wanted to use syscfg. However, it's now handled automatically within
 * syscfg_lib.c so explicit calls to syscfg_init() are no longer required.
 * Keep a stub as a temp solution until all calls to syscfg_init() have been
 * removed from the code.
 */
static inline int syscfg_init (void)
{
    return 0;
}

/**
* @brief Destroy syscfg shared memory context.
*
* @return None.
*
* @note Syscfg destroy should happen only during system shutdown. NEVER call this API in any other scenario.
*
*/
void syscfg_destroy();

/**
* @brief Retrieve an entry from syscfg.
*
* @param[in] ns  - Pointer to the namespace string (optional).
* @param[in] name  - Pointer to the name string of the entry to retrieve. Cannot be NULL.
* @param[out] out_value  - Pointer to buffer where the output value string will be stored.
* @param[in] outbufsz  - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 0 Entry retrieved successfully.
* @retval -1 If name or out_value is NULL, entry not found, or initialization failed.
*
*/
int syscfg_get(const char *ns, const char *name, char *out_value, int outbufsz);

/**
* @brief Retrieve all entries from syscfg.
*
* @param[out] buf  - Pointer to output buffer to store syscfg entries.
* @param[in] bufsz  - Size of the output buffer in bytes.
* @param[out] outsz  - Pointer to store the number of bytes written to the buffer.
*
* @return The status of the operation.
* @retval 0 All entries retrieved successfully.
* @retval ERR_INVALID_PARAM If buf is NULL or bufsz is less.
* @retval ERR_xxx various errors codes dependening on the failure
*
* @note Useful for clients to dump the whole syscfg data.
*
*/
int syscfg_getall(char *buf, int bufsz, int *outsz);

/**
* @brief Retrieve all entries from syscfg with newline separators.
*
* @param[out] buf  - Pointer to output buffer to store syscfg entries.
* @param[in] bufsz  - Size of the output buffer in bytes.
* @param[out] outsz  - Pointer to store the number of bytes written to the buffer.
*
* @return The status of the operation.
* @retval 0 All entries retrieved successfully.
* @retval ERR_INVALID_PARAM If bufsz is less.
* @retval ERR_xxx various errors codes dependening on the failure
*
* @note Like syscfg_getall(), but returns pairs of entries separated by newlines instead of nul characters.
*
*/
int syscfg_getall2(char *buf, size_t bufsz, size_t *outsz);

/**
* @brief Add or update an entry in syscfg with namespace.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
* @retval ERR_xxx various errors codes dependening on the failure.
*
* @note Only changes syscfg hash table; persistent store contents not changed until 'commit' operation.
*
*/
int syscfg_set_ns             (const char *ns, const char *name, const char *value);

/**
* @brief Add or update an entry in syscfg with namespace and commit immediately.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
* @retval ERR_xxx  various errors codes dependening on the failure.
*
*/
int syscfg_set_ns_commit      (const char *ns, const char *name, const char *value);

/**
* @brief Add or update an unsigned long entry in syscfg with namespace.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx  various errors codes dependening on the failure.
*
*/
int syscfg_set_ns_u           (const char *ns, const char *name, unsigned long value);

/**
* @brief Add or update an unsigned long entry in syscfg with namespace and commit immediately.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx  various errors codes dependening on the failure.
*
*/
int syscfg_set_ns_u_commit    (const char *ns, const char *name, unsigned long value);

/**
* @brief Add or update an entry in syscfg without namespace.
*
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
*
*/
int syscfg_set_nns            (const char *name, const char *value);

/**
* @brief Add or update an entry in syscfg without namespace and commit immediately.
*
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
* @retval ERR_xxx various errors codes dependening on the failure.
*
*/
int syscfg_set_nns_commit     (const char *name, const char *value);

/**
* @brief Add or update an unsigned long entry in syscfg without namespace.
*
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx various errors codes dependening on the failure.
*
*/
int syscfg_set_nns_u          (const char *name, unsigned long value);

/**
* @brief Add or update an unsigned long entry in syscfg without namespace and commit immediately.
*
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx various errors codes dependening on the failure.
*
*/
int syscfg_set_nns_u_commit   (const char *name, unsigned long value);

/**
* @brief Add or update an entry in syscfg (wrapper function).
*
* @param[in] ns  - Pointer to the namespace string (optional).
*                    \n If non-NULL, calls syscfg_set_ns to store entry as "ns::name".
*                    \n If NULL, calls syscfg_set_nns to store entry without namespace.
* @param[in] name  - Pointer to the name string of the entry to add.
*                    \n Cannot be NULL.
* @param[in] value  - Pointer to the value string to associate with the name.
*                    \n Cannot be NULL.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
* @retval ERR_xxx Various errors codes dependening on the failure.
*
* @note Only changes syscfg hash table; persistent store contents not changed until 'commit' operation.
*
*/
static inline int syscfg_set (const char *ns, const char *name, const char *value)
{
    if (ns)
        return syscfg_set_ns (ns, name, value);
    else
        return syscfg_set_nns (name, value);
}

/**
* @brief Add or update an entry in syscfg and commit immediately.
*
* @param[in] ns  - Pointer to the namespace string (optional).
*                  If non-NULL, calls syscfg_set_ns_commit to store entry as "ns::name" and commit.
*                  If NULL, calls syscfg_set_nns_commit to store entry without namespace and commit.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name or value is NULL.
* @retval ERR_xxx Various errors codes dependening on the failure.
*
*/
static inline int syscfg_set_commit (const char *ns, const char *name, const char *value)
{
    if (ns)
        return syscfg_set_ns_commit (ns, name, value);
    else
        return syscfg_set_nns_commit (name, value);
}

/**
* @brief Add or update an unsigned long entry in syscfg.
*
* @param[in] ns  - Pointer to the namespace string.
*                  If non-NULL, calls syscfg_set_ns_u to store entry as "ns::name".
*                  If NULL, calls syscfg_set_nns_u to store entry without namespace.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx Various errors codes dependening on the failure.
*
*/
static inline int syscfg_set_u (const char *ns, const char *name, unsigned long value)
{
    if (ns)
        return syscfg_set_ns_u (ns, name, value);
    else
        return syscfg_set_nns_u (name, value);
}

/**
* @brief Add or update an unsigned long entry in syscfg and commit immediately.
*
* @param[in] ns  - Pointer to the namespace string.
*                  If non-NULL, calls syscfg_set_ns_u_commit to store entry as "ns::name" and commit.
*                  If NULL, calls syscfg_set_nns_u_commit to store entry without namespace and commit.
* @param[in] name  - Pointer to the name string of the entry to add.
* @param[in] value  - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 Entry set and committed successfully.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx Various errors codes dependening on the failure.
*
*/
static inline int syscfg_set_u_commit (const char *ns, const char *name, unsigned long value)
{
    if (ns)
        return syscfg_set_ns_u_commit (ns, name, value);
    else
        return syscfg_set_nns_u_commit (name, value);
}

/**
* @brief Remove an entry from syscfg.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the name string of the entry to remove.
*
* @return The status of the operation.
* @retval 0 Entry removed successfully or entry does not exist.
* @retval ERR_INVALID_PARAM If name is NULL.
* @retval ERR_xxx - various errors codes dependening on the failure.
*
* @note Only changes syscfg hash table; persistent store contents not changed until 'commit' operation.
*
*/
int syscfg_unset(const char *ns, const char *name);

/**
* @brief Commit current state of syscfg hash table data to persistent store.
*
* @return The status of the operation.
* @retval 0 Commit to persistent storage successful.
* @retval ERR_xxx Various IO errors depending on the failure.
*
* @note WARNING: This will overwrite persistent store. Persistent store location specified during
* syscfg_create() is cached in syscfg shared memory and used as the target for commit.
*
*/
int syscfg_commit();

/**
* @brief Get current and maximum persistent storage size of syscfg content.
*
* @param[out] used_sz  - Pointer to store the currently used storage size in bytes.
* @param[out] max_sz  - Pointer to store the maximum storage size in bytes.
*
* @return The status of the operation.
* @retval 0 - Retrieved current and maximum persistent storage size successfully.
* @retval ERR_xxx - various errors codes dependening on the failure.
*
*/
int syscfg_getsz (long int *used_sz, long int *max_sz);

#ifdef __cplusplus
}
#endif

#endif /* _SYSCFG_H_ */