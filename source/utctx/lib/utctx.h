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
* @brief Initialize Utopia context for configuration management.
*
* This function initializes a UtopiaContext structure by setting up the transaction list,
* clearing event flags, initializing the sysevent handle, and initializing both the UtopiaRWLock
* and syscfg subsystems.
*
* @param[in,out] pUtopiaCtx - Pointer to the UtopiaContext structure to initialize.
*                    \n The structure should be allocated by the caller.
*                    \n On success, all fields are initialized to their default states.
*
* @return The status of the operation.
* @retval 1 if the context was successfully initialized.
* @retval 0 if the operation failed.
*
*/
extern int Utopia_Init(UtopiaContext* pUtopiaCtx);

/**
* @brief Commit transaction values and free Utopia context resources.
*
* This function finalizes all configuration operations by optionally committing all pending
* transaction values to persistent storage, triggering registered system events, and freeing all allocated resources. If fCommit is false,
* free up context memory. The function releases the UtopiaRWLock, closes sysevent handles,
* and frees the transaction list.
*
* @param[in,out] pUtopiaCtx - Pointer to the UtopiaContext structure to free.
*                    \n All pending transactions will be committed or discarded based on fCommit.
*                    \n All allocated resources will be released.
* @param[in] fCommit - Boolean flag indicating whether to commit pending changes.
*                    \n Pass non-zero (true) to commit all transactions and trigger events.
*                    \n Pass 0 (false) to free up context memory without committing.
*
* @return None.
*
*/
extern void Utopia_Free(UtopiaContext* pUtopiaCtx, int fCommit);

#endif /* __UTCTX_H__ */
