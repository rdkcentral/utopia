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

static int lmdb_initialized = 0;
syscfg_lmdb_t *g_lmdb_ctx = NULL;

/* ---- LMDB forward declarations ---- */
static int ensure_lmdb_open(void);
static int lmdb_set_helper(syscfg_lmdb_t *ctx, const char *key, const char *val);
static void syscfg_lmdb_check_close(void);

/* Helpers to enumerate LMDB into buffers */
static int   _lmdb_getall_helper(char *buf, int bufsz);
static size_t _lmdb_getall2_helper(char *buf, size_t bufsz);

/* Compose key with optional namespace: ns.name or just name */
static inline void compose_ns_key(const char *ns, const char *name, char *out, size_t outsz)
{
    if (ns && ns[0]) {
        (void)snprintf(out, outsz, "%s.%s", ns, name);
    } else {
        (void)snprintf(out, outsz, "%s", name);
    }
}

/* Open g_lmdb_ctx once */
static int ensure_lmdb_open(void)
{
    if (!lmdb_initialized || !g_lmdb_ctx) {
        int rc = syscfg_lmdb_open(&g_lmdb_ctx, LMDB_PERSIST_DIR, MAPSIZE, 0);
        if (rc != 0 || !g_lmdb_ctx) {
            ulog_LOG_Err("syscfg_lmdb_open failed (rc=%d)\n", rc);
            return -1;
        }
        lmdb_initialized = 1;
    }
    return 0;
}

static void syscfg_lmdb_check_close(void)
{
    // Cleanup LMDB context
    if (g_lmdb_ctx) {
        syscfg_lmdb_close(g_lmdb_ctx);
        g_lmdb_ctx = NULL;
    }
    lmdb_initialized = 0;
}

/* ----------------------------------------------------------------
 * External syscfg library access APIs (LMDB-only)
 * ---------------------------------------------------------------- */

/*
 * Procedure : syscfg_get
 * Purpose   : Retrieve an entry from LMDB
 * Return    : 0 on success, -1 if not found or on error
 */
int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz)
{
    if (name == NULL || out_val == NULL || outbufsz <= 0) {
        if (out_val) out_val[0] = '\0';
        return -1;
    }

    if (ensure_lmdb_open() != 0) {
        out_val[0] = '\0';
        return -1;
    }

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));

    int rc = syscfg_lmdb_get(g_lmdb_ctx, key, out_val, outbufsz);
    if (rc == 0) {
        ulog_LOG_Info("syscfg_get: key=%s value=%s\n", key, out_val);
		syscfg_lmdb_check_close();
        return 0;
    }

    ulog_LOG_Err("syscfg_get: LMDB get failed for key=%s rc=%d\n", key, rc);
    out_val[0] = '\0';
	syscfg_lmdb_check_close();
    return -1;
}

/*
 * Procedure : syscfg_set_ns
 * Purpose   : Set a value in LMDB
 * Return    : 0 on success, non-zero on error
 */
int syscfg_set_ns(const char *ns, const char *name, const char *value)
{
    if (name == NULL || value == NULL) {
        return ERR_INVALID_PARAM;
    }
    if (ensure_lmdb_open() != 0) return -1;

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));

    /* Use helper (unset-if-exists then set) to mimic legacy behavior */
    return lmdb_set_helper(g_lmdb_ctx, key, value);
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
 * Purpose   : Remove key from LMDB
 * Return    : 0 on success, non-zero otherwise
 */
int syscfg_unset(const char *ns, const char *name)
{
    if (name == NULL) return ERR_INVALID_PARAM;
    if (ensure_lmdb_open() != 0) return -1;

    char key[256];
    compose_ns_key(ns, name, key, sizeof(key));
    int rc = syscfg_lmdb_unset(g_lmdb_ctx, key);
    if (rc == 0) {
        ulog_LOG_Info("syscfg_unset: unset key=%s\n", key);
    } else {
        ulog_LOG_Err("syscfg_unset: failed for key=%s rc=%d\n", key, rc);
    }
	syscfg_lmdb_check_close();
    return rc;
}

/*
 * Procedure : syscfg_getall
 * Notes     : returns entries as "key=value\n" ... (nul-terminated)
 */
int syscfg_getall(char *buf, int bufsz, int *outsz)
{
    if (!buf || bufsz < 4 || !outsz) return ERR_INVALID_PARAM;

    int used = _lmdb_getall_helper(buf, bufsz);
    *outsz = (used >= 0) ? used : 0;
    return (used >= 0) ? 0 : -1;
}

/*
 * Procedure : syscfg_getall2
 * Notes     : same as getall but size_t
 */
int syscfg_getall2(char *buf, size_t bufsz, size_t *outsz)
{
    if (!buf || bufsz < 5 || !outsz) return ERR_INVALID_PARAM;

    size_t used = _lmdb_getall2_helper(buf, bufsz);
    *outsz = used;
    return 0;
}

/*
 * Procedure : syscfg_getsz
 * Purpose   : Return approximate "used" size in bytes as sum of "key=value\n".
 *             max_sz is not applicable for LMDB, so set to 0.
 */
int syscfg_getsz(long int *used_sz, long int *max_sz)
{
    if (ensure_lmdb_open() != 0) return -1;

    long int used = 0;
    char **keys = NULL;
    int count = 0;

    if (syscfg_lmdb_enum(g_lmdb_ctx, NULL, 0, &keys, &count) != 0) {
        if (used_sz) *used_sz = 0;
        if (max_sz)  *max_sz  = 0;
		syscfg_lmdb_check_close();
        return -1;
    }

    for (int i = 0; i < count; ++i) {
        char val[256];
        if (syscfg_lmdb_get(g_lmdb_ctx, keys[i], val, sizeof(val)) == 0) {
            used += (long int)(strlen(keys[i]) + 1 /* '=' */ + strlen(val) + 1 /* '\n' */);
        }
        free(keys[i]);
    }
    free(keys);

    if (used_sz) *used_sz = used;
    if (max_sz)  *max_sz  = 0;
	syscfg_lmdb_check_close();
    return 0;
}

/*
 * Procedure : syscfg_commit
 * Purpose   : LMDB commit/flush (if backend requires)
 */
int syscfg_commit(void)
{
    return 0;
}

/*
 * Procedure : syscfg_destroy
 */
void syscfg_destroy(void)
{
    // Cleanup LMDB context
    if (g_lmdb_ctx) {
        syscfg_lmdb_close(g_lmdb_ctx);
        g_lmdb_ctx = NULL;
    }
    lmdb_initialized = 0;
}

/*
 * Procedure : syscfg_create
 * Purpose   : Initialize LMDB context; file/max_file_sz parameters are ignored.
 */
int syscfg_create(const char *file, long int max_file_sz)
{
    (void)file;
    (void)max_file_sz;
    ulog_LOG_Info("syscfg_create: LMDB-only mode (ignoring file/max size)\n");
    return 0;
}

/*
 * Procedure : syscfg_reload
 * Purpose   : No-op for LMDB-only backend
 */
int syscfg_reload(const char *file)
{
    (void)file;
    return 0;
}

/*
 * Procedure : commit_lock / commit_unlock
 * Purpose   : No-ops kept for ABI compatibility with former shared-memory design
 */
int syscfg_commit_lock(void)   { return 0; }
int syscfg_commit_unlock(void) { return 0; }

/* ----------------------------------------------------------------
 * LMDB helpers
 * ---------------------------------------------------------------- */

static int _lmdb_getall_helper(char *buf, int bufsz)
{
    int used = 0;
    int trunc = 0;

    if (!buf || bufsz <= 0) return -1;
    if (ensure_lmdb_open() != 0) return -1;

    char **keys = NULL;
    int count = 0;
    int rc = syscfg_lmdb_enum(g_lmdb_ctx, NULL, 0, &keys, &count);
	if (rc != 0) {
		syscfg_lmdb_check_close();
		return -1;
	}

    for (int i = 0; i < count; ++i) {
        char val[256];
        rc = syscfg_lmdb_get(g_lmdb_ctx, keys[i], val, sizeof(val));
        if (rc == 0) {
            int space = bufsz - used;
            if (space > 0) {
                int n = snprintf(buf + used, (size_t)space, "%s=%s\n", keys[i], val);
                if (n < 0 || n >= space) {
                    trunc = 1;
                    buf[bufsz - 1] = '\0';
                } else {
                    used += n;
                }
            } else {
                trunc = 1;
            }
        }
        free(keys[i]);
        if (trunc) {
            for (int j = i + 1; j < count; ++j) free(keys[j]);
            break;
        }
    }
    free(keys);
	syscfg_lmdb_check_close();
    return used;
}

static size_t _lmdb_getall2_helper(char *buf, size_t bufsz)
{
    size_t used = 0;

    if (!buf || bufsz == 0) return 0;
    if (ensure_lmdb_open() != 0) return 0;

    char **keys = NULL;
    int count = 0;
    int rc = syscfg_lmdb_enum(g_lmdb_ctx, NULL, 0, &keys, &count);
    if (rc != 0) {
		syscfg_lmdb_check_close();
		return 0;
	}

    for (int i = 0; i < count; ++i) {
        char val[256];
        rc = syscfg_lmdb_get(g_lmdb_ctx, keys[i], val, sizeof(val));
        if (rc == 0) {
            size_t space = (used < bufsz) ? (bufsz - used) : 0;
            if (space == 0) { free(keys[i]); break; }
            size_t n = (size_t)snprintf(buf + used, space, "%s=%s\n", keys[i], val);
            if (n >= space) { free(keys[i]); break; }
            used += n;
        }
        free(keys[i]);
    }
    free(keys);
	syscfg_lmdb_check_close();
    return used;
}

static int lmdb_set_helper(syscfg_lmdb_t *ctx, const char *key, const char *val)
{
    if (!ctx || !key || !val) return EINVAL;

    /* Optionally unset existing key to preserve legacy semantics */
    char tmp[256];
    int rc = syscfg_lmdb_get(ctx, key, tmp, sizeof(tmp));
    if (rc == 0) {
        (void)syscfg_lmdb_unset(ctx, key);
    }

    int rc2 = syscfg_lmdb_set(ctx, key, val);
    if (rc2 != 0) {
        ulog_LOG_Err("LMDB set failed for key=%s rc=%d\n", key, rc2);
    } else {
        ulog_LOG_Info("LMDB set succeeded for key=%s\n", key);
    }
	syscfg_lmdb_check_close();
    return rc2;
}
