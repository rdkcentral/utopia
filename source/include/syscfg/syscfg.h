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
* This function initialization SYSCFG from persistent storage.
*
* @param[in] file - Pointer to the filesystem file path string where syscfg is stored.
* @param[in] max_file_sz - Maximum file size in bytes for the syscfg persistent storage.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_INVALID_PARAM if invalid arguments are provided.
* @retval ERR_IO_FAILURE if syscfg file is unavailable.
* @retval ERR_SHM_CREATE if error creating shared memory.
*
*/
int syscfg_create(const char *file, long int max_file_sz);

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
* syscfg destroy should happen only during system shutdown, should never call
* this API in any other scenario.
*
* @return None.
*
*/
void syscfg_destroy();

/**
* @brief Retrieve an entry from syscfg.
*
* @param[in] ns - Pointer to the namespace string (optional, can be NULL).
* @param[in] name - Pointer to the name string of the entry to retrieve.
* @param[out] out_value - Pointer to the buffer to store the output value string.
* @param[in] outbufsz - Size of the output buffer in bytes.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval -1 on error.
*
*/
int syscfg_get(const char *ns, const char *name, char *out_value, int outbufsz);

/**
* @brief Retrieve all entries from syscfg.
*
* This function retrieves all entries from syscfg.
*
* @param[out] buf - Pointer to the output buffer to store syscfg entries.
* @param[in] bufsz - Size of the output buffer in bytes.
* @param[out] outsz - Pointer to store the number of bytes returned into the given buffer.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Useful for clients to dump the whole syscfg data.
*/
int syscfg_getall(char *buf, int bufsz, int *outsz);

/**
* @brief Retrieve all entries from syscfg with newline-separated pairs.
*
* @param[out] buf - Pointer to the output buffer to store syscfg entries.
* @param[in] bufsz - Size of the output buffer in bytes.
* @param[out] outsz - Pointer to store the number of bytes returned into the given buffer.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
*/
int syscfg_getall2(char *buf, size_t bufsz, size_t *outsz);

/**
* @brief Add an entry to syscfg with namespace.
*
* This function adds an entry to syscfg with namespace.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_ns             (const char *ns, const char *name, const char *value);

/**
* @brief Add an entry to syscfg with namespace and commit to persistent storage.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* * @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_ns_commit      (const char *ns, const char *name, const char *value);

/**
* @brief Add an entry with unsigned long value to syscfg with namespace.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_ns_u           (const char *ns, const char *name, unsigned long value);

/**
* @brief Add an entry with unsigned long value to syscfg with namespace and commit.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_ns_u_commit    (const char *ns, const char *name, unsigned long value);

/**
* @brief Add an entry to syscfg without namespace.
*
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_nns            (const char *name, const char *value);

/**
* @brief Add an entry to syscfg without namespace and commit to persistent storage.
*
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_nns_commit     (const char *name, const char *value);

/**
* @brief Add an entry with unsigned long value to syscfg without namespace.
*
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_nns_u          (const char *name, unsigned long value);

/**
* @brief Add an entry with unsigned long value to syscfg without namespace and commit.
*
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_set_nns_u_commit   (const char *name, unsigned long value);

/**
* @brief Add an entry to syscfg with optional namespace.
*
* This is a convenience wrapper function that automatically selects between namespace and
* non-namespace variants based on whether the ns parameter is NULL.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
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
* @brief Add an entry to syscfg with optional namespace and commit to persistent storage.
*
* This is a convenience wrapper function that automatically selects between namespace and
* non-namespace variants based on whether the ns parameter is NULL.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Pointer to the value string to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
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
* @brief Add an entry with unsigned long value to syscfg with optional namespace.
*
* This is a convenience wrapper function that automatically selects between namespace and
* non-namespace variants based on whether the ns parameter is NULL.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
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
* @brief Add an entry with unsigned long value to syscfg with optional namespace and commit.
*
* This is a convenience wrapper function that automatically selects between namespace and
* non-namespace variants based on whether the ns parameter is NULL.
*
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to add.
* @param[in] value - Unsigned long value to associate with the name.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
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
* @param[in] ns - Pointer to the namespace string.
* @param[in] name - Pointer to the name string of the entry to remove.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
* @note Only changes syscfg hash table, persistent store contents not changed until 'commit' operation.
*/
int syscfg_unset(const char *ns, const char *name);

/**
* @brief Commit current state of syscfg hash table data to persistent store.
*
* This function commits current stats of syscfg hash table to persistent storage.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_IO_xxx various IO error codes depending on the failure.
*
* @note This operation will overwrite the existing persistent storage.
* The persistent store location set during syscfg_create() is cached in syscfg
* shared memory and used as the commit target.
*/
int syscfg_commit();

/**
* @brief Get current and maximum persistent storage size of syscfg content.
*
* @param[out] used_sz - Pointer to store the used size in bytes.
* @param[out] max_sz - Pointer to store the maximum size in bytes.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval ERR_xxx various error codes depending on the failure.
*
*/
int syscfg_getsz (long int *used_sz, long int *max_sz);

#ifdef __cplusplus
}
#endif

#endif /* _SYSCFG_H_ */