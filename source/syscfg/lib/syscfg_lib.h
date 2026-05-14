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

#ifndef _SYSCFG_LIB_H_
#define _SYSCFG_LIB_H_

#define SYSCFG_HASH_TABLE_SZ 128      // number of buckets in hash table
#define MAX_NAME_LEN         128      // max name len including namespace
                                      //      size eg "cisco-org:lan0:dhcp:ipaddr"
#define NS_SEP "::"

#define SYSCFG_SHM_FILE "/tmp/syscfg.shmid"

#define SYSCFG_FILE       "/tmp/syscfg.db"
#define SYSCFG_BKUP_FILE "/nvram/syscfg.db"

#define SYSCFG_NEW_FILE "/opt/secure/data/syscfg.db"
#define SYSCFG_NEW_BKUP_FILE "/opt/secure/data/syscfg_bkup.db"

/*
 * Magic number within shared mem superblock for sanity check
 */
#define SYSCFG_SHM_MAGIC     0xDEADBEEF
/*
 * shared memory key unique to syscfg, used to retrieve shmid
 */
#define SYSCFG_SHM_PROJID    237

#ifdef PAGE_SIZE
#define SYSCFG_SHM_SIZE      (64*PAGE_SIZE)
#else
#define SYSCFG_SHM_SIZE      (64*getpagesize())
#endif

#define SYSCFG_STORE_PATH_SZ  128

/*
 * Note: values of DEFAULT_MAX_FILE_SZ and SYSCFG_SZ should match.
 */
#define DEFAULT_MAX_FILE_SZ   (100 * 1024)

#define LOG_FILE "/rdklogs/logs/Consolelog.txt.0"

/*
 * Number of free table buckets
 */
#define NUM_BUCKETS 7

/*
 * Current version 0.1
 */
#define SYSCFG_SHM_VERSION_MAJOR 0
#define SYSCFG_SHM_VERSION_MINOR 1

typedef enum {
    STORE_FILE,
    STORE_MTD_DEVICE
} store_type_t;

typedef struct {
    store_type_t type;
    char         path[SYSCFG_STORE_PATH_SZ];
    int          hdr_size;
    long int     max_size;
} store_info_t;

typedef unsigned int shmoff_t;

/*
 * syscfg controlblock placed at the beginning of shared memory region
 */
typedef struct {
    int  magic;
    uint version;
    int  size;         // size of shared memory
    int   shmid;
    store_type_t store_type;
    char         store_path[SYSCFG_STORE_PATH_SZ];
    long int     max_store_size;
    long int     used_store_size;
#ifdef SC_POSIX_SEM
    pthread_mutex_t read_lock;
    pthread_mutex_t write_lock;
    pthread_mutex_t commit_lock;
#elif SC_SYSV_SEM
    int semid;
#endif
} shm_cb;

typedef struct {
    int size;   // element size - one of 16b, 32b, 64b, 128b, 256b, 1024b
    int mf;     // multiply-factor - how many entries to pre-create
    shmoff_t head;
} shm_free_table;

typedef struct {
    int size;
    shmoff_t next;
} mm_item;


/******************************************************************************
 *                shm memory api
 ******************************************************************************/

#define MM_OVERHEAD (sizeof(mm_item))

#define MM_ITEM(ctx,offset)     ((mm_item *)(((char *)ctx)+offset))
#define MM_ITEM_NEXT(ctx,offset) (((mm_item *)(((char *)ctx)+offset))->next)
#define MM_ITEM_SIZE(ctx,offset) (((mm_item *)(((char *)ctx)+offset))->size)

/*
 * ft - free table. contains a linked list of mm_items
 */
typedef struct {
    int  db_size;     // size of data block within shm
    uint db_start;
    uint db_end;
    uint db_cur;
    shm_free_table  ft[NUM_BUCKETS];
} shm_mm;

typedef struct {
    uint name_sz;
    uint value_sz;
    shmoff_t next;
} ht_entry;

#define HT_ENTRY(ctx,offset)         ((ht_entry *)(((char *)ctx)+offset))
#define HT_ENTRY_NAMESZ(ctx,offset)  (((ht_entry *)(((char *)ctx)+offset))->name_sz)
#define HT_ENTRY_VALUESZ(ctx,offset) (((ht_entry *)(((char *)ctx)+offset))->value_sz)
#define HT_ENTRY_NEXT(ctx,offset)    (((ht_entry *)(((char *)ctx)+offset))->next)

#define HT_ENTRY_NAME(ctx,offset)  ((char *)(((char *)ctx)+offset+sizeof(ht_entry)))
#define HT_ENTRY_VALUE(ctx,offset) ((char *)(((char *)ctx)+offset+sizeof(ht_entry)+HT_ENTRY_NAMESZ(ctx,offset)))

/*
 * WARNING: if you add new elements into this struct, check to see if
 * offset calculation are still valid. Most often you need to fix them
 */
typedef struct {
    shm_cb          cb;
    shm_mm          mm;
    shmoff_t        ht[SYSCFG_HASH_TABLE_SZ];
    char           *data;
} syscfg_shm_ctx;

/*
 * shm_mm - shm memory management
 *   shm data segments is carved into chunks of 2^ sized elements
 *   shm_mm_alloc(sz) - will allocate a sz byte chunk closest to the chunk size
 */
/**
* @brief Create memory management items in shared memory free table.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
* @param[in,out] ft  - Pointer to a single shm_free_table entry.
*
* @return The number of memory management items created.
* @retval >0 Number of mm_items successfully created and added to the free list.
* @retval 0 If operation failed (invalid size or items already available).
*
* @note  argument "ft" should be treated as one shm_free_table entry, NOT as ft array.
*/
static int make_mm_items (syscfg_shm_ctx *ctx, shm_free_table *ft);

/**
* @brief Allocate memory from shared memory pool.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*                   Contains the memory management free table with linked lists of available memory items.
* @param[in] size  - The size in bytes to allocate.
* @param[out] out_offset  - Pointer to store the allocated memory offset.
*                           On success, contains the offset to the allocated memory.
*
* @return The status of the operation.
* @retval 0 Memory allocated successfully.
* @retval ERR_MEM_ALLOC If insufficient space available to create new memory items.
* @retval ERR_ENTRY_TOO_BIG If requested size exceeds maximum bucket size.
*
*/
static int shm_malloc (syscfg_shm_ctx *ctx, int size, shmoff_t *out_offset);

/**
* @brief Free previously allocated memory back to shared memory pool.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*                   Contains the memory management free table where the memory will be returned.
* @param[in] offset  - The offset of memory to free (past MM_OVERHEAD).
*                      The function clears the mm_item's data portion before returning it to the appropriate free list bucket.
*                      The offset is adjusted to point to the mm_item header (offset - MM_OVERHEAD).
*
* @return None.
*
*/
static void shm_free (syscfg_shm_ctx *ctx, shmoff_t offset);

/**
* @brief Initialize syscfg shared memory context by attaching to existing shared memory.
*
* @return The status of the operation.
* @retval 0 Shared memory context initialized successfully.
* @retval ERR_SHM_NO_FILE If shared memory file (SYSCFG_SHM_FILE) does not exist.
* @retval ERR_SHM_ATTACH If failed to attach to shared memory or magic number check failed.
*
*/
static int   syscfg_shm_init ();

/**
* @brief Create a new syscfg shared memory segment.
*
* @param[in] store_info  - Pointer to the store_info_t structure containing storage configuration.
* @param[out] out_shmid  - Pointer to store the shared memory ID.
*                          On success, contains the ID of the newly created shared memory segment.
*
* @return Pointer to the created shared memory context.
* @retval Non-NULL Pointer to syscfg_shm_ctx on successful creation.
* @retval NULL If creation failed (file creation error, old instance present, shmget failed, or control block initialization failed).
*
*/
static void *syscfg_shm_create (store_info_t *store_info, int *out_shmid);

/**
* @brief Attach to existing syscfg shared memory segment.
*
* @param[out] out_shmid  - Pointer to store the shared memory ID.
*                          On success, contains the ID of the attached shared memory segment.
*
* @return Pointer to the attached shared memory context.
* @retval Non-NULL Pointer to the attached shared memory on success.
* @retval NULL If attachment failed (syscfg_shm_getid failed or shmat failed).
*
*/
static void *syscfg_shm_attach (int *out_shmid);

/**
* @brief Get the shared memory ID for syscfg.
*
* @return The shared memory ID.
* @retval >0 Valid shared memory ID retrieved using ftok and shmget.
* @retval -1 If ftok or shmget failed (file not found or shared memory segment not available).
*
*/
static int   syscfg_shm_getid ();

/**
* @brief Destroy syscfg shared memory segment and clean up resources.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context to destroy.
*                   The function destroys locks, marks shared memory for deletion using IPC_RMID, detaches from shared memory, and unlinks SYSCFG_SHM_FILE.
*                   If ctx is NULL, the function returns without performing any operation.
*
* @return None.
*
*/
static void syscfg_shm_destroy (syscfg_shm_ctx *ctx);

/**
* @brief Get current and maximum storage size for syscfg.
*
* @param[out] used_sz  - Pointer to store the currently used storage size in bytes.
* @param[out] max_sz  - Pointer to store the maximum storage size in bytes.
*
* @return The status of the operation.
* @retval 0 size information retrieved successfully.
*
*/
static int _syscfg_getsz (long int *used_sz, long int *max_sz);

/**
* @brief Set a syscfg name-value pair in shared memory.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the configuration parameter name string.
* @param[in] value  - Pointer to the value string to set.
* @param[in] nolock  - Flag indicating if write lock is already acquired by caller.
*
* @return The status of the operation.
* @retval 0 Value set successfully.
* @retval ERR_NO_SPACE If insufficient storage space available to store the tuple.
* @retval Non-zero If hash table entry creation failed.
*
*/
static int _syscfg_set (const char *ns, const char *name, const char *value, int nolock);

/**
* @brief Unset (remove) a syscfg name-value pair from shared memory.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the configuration parameter name string to unset.
* @param[in] nolock  - Flag indicating if write lock is already acquired by caller.
*
* @return The status of the operation.
* @retval 0 Entry unset successfully or entry does not exist.
*
*/
static int _syscfg_unset (const char *ns, const char *name, int nolock);

/**
* @brief Get the value of a syscfg parameter from shared memory.
*
* @param[in] ns  - Pointer to the namespace string.
* @param[in] name  - Pointer to the configuration parameter name string.
*
* @return Pointer to the value string.
* @retval Non-NULL Pointer to the value string if the entry exists in shared memory on success.
* @retval NULL If the entry does not exist.
*
*/
static char* _syscfg_get (const char *ns, const char *name);

/**
* @brief Get all syscfg name-value pairs from shared memory.
*
* @param[out] buf  - Pointer to buffer where all name-value pairs will be stored.
* @param[in] bufsz  - The size of the buffer in bytes.
*
* @return The number of bytes written to the buffer.
* @retval >0 Number of bytes written (excluding final null terminator).
*
*/
static int _syscfg_getall (char *buf, int bufsz);

/**
* @brief Get all syscfg name-value pairs from shared memory (alternative format).
*
* @param[out] buf  - Pointer to buffer where all name-value pairs will be stored.
* @param[in] bufsz  - The size of the buffer in bytes.
* @param[in] nolock  - Flag indicating if read lock is already acquired by caller.
*
* @return The number of bytes written to the buffer.
* @retval >0 Number of bytes written (excluding final null terminator).
*
*/
static size_t _syscfg_getall2 (char *buf, size_t bufsz, int nolock);

/**
* @brief Destroy the syscfg shared memory context.
*
* @return None.
*
*/
static void _syscfg_destroy ();

/**
* @brief Acquire read lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the lock operation.
* @retval 0 Lock acquired successfully.
* @retval Non-zero Lock acquisition failed.
*
*/
static inline int read_lock (syscfg_shm_ctx *ctx);

/**
* @brief Release read lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the unlock operation.
* @retval 0 Lock released successfully.
* @retval Non-zero Lock release failed.
*
*/
static inline int read_unlock (syscfg_shm_ctx *ctx);

/**
* @brief Acquire write lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the lock operation.
* @retval 0 Lock acquired successfully.
* @retval Non-zero Lock acquisition failed.
*
*/
static inline int write_lock (syscfg_shm_ctx *ctx);

/**
* @brief Release write lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the unlock operation.
* @retval 0 Lock released successfully.
* @retval Non-zero Lock release failed.
*
*/
static inline int write_unlock (syscfg_shm_ctx *ctx);

/**
* @brief Acquire commit lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the lock operation.
* @retval 0 Lock acquired successfully.
* @retval Non-zero Lock acquisition failed.
*
*/
static inline int commit_lock (syscfg_shm_ctx *ctx);

/**
* @brief Release commit lock for syscfg shared memory.
*
* @param[in] ctx  - Pointer to the syscfg shared memory context.
*
* @return The status of the unlock operation.
* @retval 0 Lock released successfully.
* @retval Non-zero Lock release failed.
*
*/
static inline int commit_unlock (syscfg_shm_ctx *ctx);

#endif // _SYSCFG_LIB_H_