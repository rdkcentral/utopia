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

/*
 * ============================================================================
 *  syscfg_lib.h  (LMDB-only)
 *
 *  All legacy shared-memory, file-based storage, hash tables, and
 *  _syscfg_* internals have been removed.
 *
 *  This header now exposes only what is required for:
 *    - syscfg public APIs
 *    - LMDB-backed persistence
 * ============================================================================
 */

#include <stddef.h>
#include <stdint.h>

#include "syscfg_lmdb.h"

/* ---------------------------------------------------------------------------
 * General limits / naming
 * ---------------------------------------------------------------------------
 */

/* Max key length including namespace (e.g. "Device.WiFi.Radio.1.Enable") */
#define MAX_NAME_LEN        128

/* Namespace separator used by syscfg APIs */
#define NS_SEP              "."

/* ---------------------------------------------------------------------------
 * LMDB configuration
 * ---------------------------------------------------------------------------
 */

/* Persistent directory for syscfg LMDB */
#define LMDB_PERSIST_DIR    "/nvram/syscfg_lmdb"

/*
 * LMDB map size
 * Adjust if syscfg database grows significantly.
 */
#define MAPSIZE             (8u * 1024u * 1024u)   /* 8 MB */

/* Global LMDB context used by syscfg_lib.c */
extern syscfg_lmdb_t *g_lmdb_ctx;

/* ---------------------------------------------------------------------------
 * Notes
 * ---------------------------------------------------------------------------
 *
 * The following legacy concepts were intentionally removed:
 *
 *  - Shared memory (shm_cb, syscfg_shm_ctx, locks, semaphores)
 *  - Hash tables (SYSCFG_HASH_TABLE_SZ, ht_entry)
 *  - File-based persistence (syscfg.db, backups, store_info_t)
 *  - DEFAULT_MAX_FILE_SZ, SYSCFG_SHM_MAGIC, SYSCFG_SHM_VERSION_*
 *
 * All persistence, locking, and enumeration is handled by LMDB.
 *
 * If additional limits or configuration are needed, they should be
 * implemented in syscfg_lmdb.[ch], not here.
 */

#endif /* _SYSCFG_LIB_H_ */
