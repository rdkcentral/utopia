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

/* _GNU_SOURCE is needed for strchrnul() and program_invocation_short_name */

//#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

#include <ulog/ulog.h>
#include "syscfg_lib.h"   // internal interface
#include "syscfg.h"       // external interface used by users
#include "safec_lib_common.h"
#include "sqlite_db.h"    // SQLite wrapper (syscfg_sqlite_*)

/* ---- SQLite forward declarations ---- */
static int ensure_sqlite_open(void);
static int sqlite_set_helper(syscfg_sqlite_ctx_t *ctx, const char *key, const char *val);

/* Compose key with optional namespace: ns.name or just name */
static inline void compose_ns_key(const char *ns, const char *name, char *out, size_t outsz)
{
    if (ns && ns[0]) {
        (void)snprintf(out, outsz, "%s.%s", ns, name);
    } else {
        (void)snprintf(out, outsz, "%s", name);
    }
}

/* ---- SQLite context ---- */
static int sqlite_initialized = 0;
syscfg_sqlite_ctx_t *g_sqlite_ctx = NULL;

#ifndef SYSCFG_SQLITE_DB_PATH
#define SYSCFG_SQLITE_DB_PATH "/nvram/syscfg_sqlite.db"
#endif

/* Open g_sqlite_ctx once */
static int ensure_sqlite_open(void)
{
    if (!sqlite_initialized || !g_sqlite_ctx) {
        int rc = syscfg_sqlite_open(&g_sqlite_ctx, SYSCFG_SQLITE_DB_PATH);
        if (rc != 0 || !g_sqlite_ctx) {
            ulog_LOG_Err("syscfg_sqlite_open failed\n");
            return -1;
        }
        sqlite_initialized = 1;
    }
    return 0;
}

static void syscfg_sqlite_check_close(void)
{
    if (g_sqlite_ctx) {
        syscfg_sqlite_close(g_sqlite_ctx);
        g_sqlite_ctx = NULL;
    }
    sqlite_initialized = 0;
}

/* ----------------------------------------------------------------
 * External syscfg library access APIs (SQLite-only)
 * ---------------------------------------------------------------- */

/*
 * Procedure : syscfg_get
 * Purpose   : Retrieve an entry from SQLite
 * Return    : 0 on success, -1 if not found or on error
 */
int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz)
{
    if (name == NULL || out_val == NULL || outbufsz <= 0) {
        if (out_val) out_val[0] = '\0';
        return -1;
    }

    if (ensure_sqlite_open() != 0) {
        out_val[0] = '\0';
        return -1;
    }

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));

    int rc = syscfg_sqlite_get(g_sqlite_ctx, key, out_val, (size_t)outbufsz);
    if (rc == 0) {
        ulog_LOG_Info("syscfg_get: key=%s value=%s\n", key, out_val);
        syscfg_sqlite_check_close();
        return 0;
    }

    if (rc == 1) {
        ulog_LOG_Info("syscfg_get: not found: %s\n", key);
    } else {
        ulog_LOG_Err("syscfg_get: sqlite get failed for key=%s rc=%d\n", key, rc);
    }
    out_val[0] = '\0';
    syscfg_sqlite_check_close();
    return -1;
}

/*
 * Procedure : syscfg_set_ns
 * Purpose   : Set a value in SQLite
 * Return    : 0 on success, non-zero on error
 */
int syscfg_set_ns(const char *ns, const char *name, const char *value)
{
    if (name == NULL || value == NULL) {
        return ERR_INVALID_PARAM;
    }
    if (ensure_sqlite_open() != 0) return -1;

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));

    /* Overwrite semantics via helper */
    return sqlite_set_helper(g_sqlite_ctx, key, value);
}

int syscfg_set_ns_commit(const char *ns, const char *name, const char *value)
{
    int rc = syscfg_set_ns(ns, name, value);
    if (rc == 0) rc = syscfg_commit();
    return rc;
}

int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value)
{
    char buf[sizeof(unsigned long) * 3 + 2];
    (void)snprintf(buf, sizeof(buf), "%lu", value);
    return syscfg_set_ns(ns, name, buf);
}

int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value)
{
    int rc = syscfg_set_ns_u(ns, name, value);
    if (rc == 0) rc = syscfg_commit();
    return rc;
}

int syscfg_set_nns(const char *name, const char *value)
{
    return syscfg_set_ns(NULL, name, value);
}

int syscfg_set_nns_commit(const char *name, const char *value)
{
    return syscfg_set_ns_commit(NULL, name, value);
}

int syscfg_set_nns_u(const char *name, unsigned long value)
{
    return syscfg_set_ns_u(NULL, name, value);
}

int syscfg_set_nns_u_commit(const char *name, unsigned long value)
{
    return syscfg_set_ns_u_commit(NULL, name, value);
}

/*
 * Procedure : syscfg_unset
 * Purpose   : Remove key from SQLite
 * Return    : 0 on success, non-zero otherwise
 */
int syscfg_unset(const char *ns, const char *name)
{
    if (name == NULL) return ERR_INVALID_PARAM;
    if (ensure_sqlite_open() != 0) return -1;

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));

    int rc = syscfg_sqlite_unset(g_sqlite_ctx, key);
    if (rc == 0) {
        ulog_LOG_Info("syscfg_unset: unset key=%s\n", key);
    } else {
        ulog_LOG_Err("syscfg_unset: failed for key=%s rc=%d\n", key, rc);
    }
    syscfg_sqlite_check_close();
    return rc;
}

/*
 * Procedure : syscfg_getall
 * Purpose   : NOT SUPPORTED (sqlite wrapper has no enumeration yet)
 */
int syscfg_getall(char *buf, int bufsz, int *outsz)
{
    (void)buf; (void)bufsz; (void)outsz;
    ulog_LOG_Err("syscfg_getall: not supported by sqlite wrapper yet\n");
    return -1;
}

/*
 * Procedure : syscfg_getall2
 * Purpose   : NOT SUPPORTED (sqlite wrapper has no enumeration yet)
 */
int syscfg_getall2(char *buf, size_t bufsz, size_t *outsz)
{
    (void)buf; (void)bufsz; (void)outsz;
    ulog_LOG_Err("syscfg_getall2: not supported by sqlite wrapper yet\n");
    return -1;
}

/*
 * Procedure : syscfg_getsz
 * Purpose   : Return used & max sizes; not applicable for SQLite
 */
int syscfg_getsz(long int *used_sz, long int *max_sz)
{
    if (used_sz) *used_sz = 0;
    if (max_sz)  *max_sz  = 0;
    return 0;
}

/*
 * Procedure : syscfg_commit
 * Purpose   : Commit (no-op for now; wrapper can decide)
 */
int syscfg_commit(void)
{
    /* If you later implement implicit transactions in wrapper, call it here
       If not open, treat as no-op success for compatibility. */
    if (ensure_sqlite_open() == 0) {
        (void)syscfg_sqlite_commit(g_sqlite_ctx);
        syscfg_sqlite_check_close();
    }
    return 0;
}

/*
 * Procedure : syscfg_destroy
 */
void syscfg_destroy(void)
{
    if (g_sqlite_ctx) {
        syscfg_sqlite_close(g_sqlite_ctx);
        g_sqlite_ctx = NULL;
    }
    sqlite_initialized = 0;
}

/*
 * Procedure : syscfg_create
 * Purpose   : SQLite-only mode; file/max_file_sz ignored here
 */
int syscfg_create(const char *file, long int max_file_sz)
{
    (void)file;
    (void)max_file_sz;
    ulog_LOG_Info("syscfg_create: SQLite-only mode (ignoring file/max size)\n");
    return 0;
}

/*
 * Procedure : syscfg_reload
 * Purpose   : No-op for SQLite-only backend
 */
int syscfg_reload(const char *file)
{
    (void)file;
    return 0;
}

/*
 * Procedure : commit_lock / commit_unlock
 * Purpose   : No-ops kept for ABI compatibility
 */
int syscfg_commit_lock(void)   { return 0; }
int syscfg_commit_unlock(void) { return 0; }

/* ----------------------------------------------------------------
 * SQLite helpers
 * ---------------------------------------------------------------- */
static int sqlite_set_helper(syscfg_sqlite_ctx_t *ctx, const char *key, const char *val)
{
    if (!ctx || !key || !val) return EINVAL;

    int rc2 = syscfg_sqlite_set(ctx, key, val);
    if (rc2 != 0) {
        ulog_LOG_Err("SQLite set failed for key=%s rc=%d\n", key, rc2);
    } else {
        ulog_LOG_Info("SQLite set succeeded for key=%s\n", key);
    }
    syscfg_sqlite_check_close();
    return rc2;
}
