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
 * utctx.h - Utopia context.
 */

#ifndef __UTCTX_H__
#define __UTCTX_H__

#include "utctx_rwlock.h"


/*
 * Struct   : Utopia context
 * Purpose  : Stores transaction list, events to be triggered and sysevent handles
 */
typedef struct _UtopiaContext
{
    /* Utopia transaction list head pointer */
    void* pHead;

    /* HDK_Utopia_Event bitmask */
    unsigned int bfEvents;

    /* SysEvent handle and token */
    int iEventHandle;
    unsigned long uiEventToken;

    /* UtopiaRWLock handle */
    UtopiaRWLock rwLock;
} UtopiaContext;

/**
* @brief Initialize Utopia context.
*
* Initializes the Utopia context by clearing event flags, handles, and transaction list.
* Initializes the read/write lock and the syscfg system.
*
* @param[in,out] pUtopiaCtx - UtopiaContext pointer.
*
* @return The status of the operation.
* @retval 1 on success.
* @retval 0 on error.
*/
extern int Utopia_Init(UtopiaContext* pUtopiaCtx);

/**
* @brief Free Utopia context and optionally commit pending transactions.
*
* Frees all transaction nodes, releases the read/write lock, and closes event handles.
*
* @param[in,out] pUtopiaCtx - UtopiaContext pointer.
* @param[in] fCommit - Commit transaction if true, discard changes if false.
*
* @return None.
*/
extern void Utopia_Free(UtopiaContext* pUtopiaCtx, int fCommit);

#endif /* __UTCTX_H__ */
