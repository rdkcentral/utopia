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
 *  syscfg_lib.h  (SQLite-only backend)
 *
 *  Minimal internal header used by syscfg_lib.c.
 *  - No shared-memory, no hash-table, no file-based legacy structures.
 *  - No LMDB references.
 *  - Uses your SQLite wrapper API from sqlite_db.h.
 * ============================================================================
 */

#include <stddef.h>
#include <stdint.h>
#include "sqlite_db.h"   /* syscfg_sqlite_ctx_t + syscfg_sqlite_* API */

/* ---------------------------------------------------------------------------
 * General limits / naming
 * --------------------------------------------------------------------------- */
#define MAX_NAME_LEN   128     /* Max key length including namespace */
#define NS_SEP         "."     /* Namespace separator, e.g. ns.name */

/* ---------------------------------------------------------------------------
 * SQLite configuration
 * --------------------------------------------------------------------------- */
/* Default DB path (can override at build time: -DSYSCFG_SQLITE_DB_PATH="...") */
#ifndef SYSCFG_SQLITE_DB_PATH
#define SYSCFG_SQLITE_DB_PATH "/nvram/syscfg_sqlite.db"
#endif

/* Global SQLite context used inside syscfg_lib.c */
extern syscfg_sqlite_ctx_t *g_sqlite_ctx;

#endif /* _SYSCFG_LIB_H_ */
