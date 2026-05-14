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
 * utctx_rwlock.h - Utopia read/write lock
 */

#ifndef __UTCTX_RWLOCK_H__
#define __UTCTX_RWLOCK_H__

#include <semaphore.h>


/* Utopia Read/Write lock struct */
typedef struct _UtopiaRWLock
{
    /* Read lock obtained */
    int fReadLock;

    /* Write lock obtained */
    int fWriteLock;

#ifdef UTCTX_POSIX_SEM
    /* Read-write semaphore */
    sem_t* pSemaphore;

    /* Mutex protecting read-write semaphore for writes */
    sem_t* pMutex;
#else
    int hdSemId;
#endif
} UtopiaRWLock;


/**
* @brief Initialize Utopia read/write lock.
*
* This function initializes a UtopiaRWLock structure by clearing the read and write lock flags
* and initializing the underlying semaphore resources.
*
* @param[in,out] pLock - Pointer to the UtopiaRWLock structure to initialize.
*                    \n Must be allocated by the caller.
*
* @return The status of the operation.
* @retval 1 if the lock was successfully initialized.
* @retval 0 if the operation failed.
*
*/
extern int UtopiaRWLock_Init(UtopiaRWLock* pLock);

/**
* @brief Destroy Utopia read/write lock.
*
* This function destroys a UtopiaRWLock structure by releasing the underlying semaphore resources.
*
* @param[in,out] pLock - Pointer to the UtopiaRWLock structure to destroy.
*
* @return The status of the operation.
* @retval 1 if the lock was successfully destroyed.
* @retval 0 if the operation failed.
*
*/
extern int UtopiaRWLock_Destroy(UtopiaRWLock* pLock);

/**
* @brief Acquire a read lock if there isn't already a read or write lock.
*
* This function attempts to acquire a read lock on the UtopiaRWLock structure. If the lock already
* holds either a read or write lock, the function returns immediately with success.
*
* @param[in,out] pLock - Pointer to the UtopiaRWLock structure on which to acquire a read lock.
*
* @return The status of the operation.
* @retval 1 if the read lock was successfully acquired or already held.
* @retval 0 if the operation failed.
*
*/
extern int UtopiaRWLock_ReadLock(UtopiaRWLock* pLock);

/**
* @brief Acquire a write lock, releasing any read lock if present.
*
* This function attempts to acquire an exclusive write lock on the UtopiaRWLock structure. If the lock
* already holds a write lock, the function returns immediately with success. If a read lock is currently
* held, it will be automatically released before acquiring the write lock. Only one writer can hold a
* write lock at a time.
*
* @param[in,out] pLock - Pointer to the UtopiaRWLock structure on which to acquire a write lock.
*
* @return The status of the operation.
* @retval 1 if the write lock was successfully acquired or already held.
* @retval 0 if the operation failed.
*
*/
extern int UtopiaRWLock_WriteLock(UtopiaRWLock* pLock);

/**
* @brief Release locks and free up semaphore resources.
*
* This function releases any currently held read or write locks and closes the underlying semaphore
* resources. It clears both the read lock and write lock flags and releases the associated semaphores.
*
* @param[in,out] pLock - Pointer to the UtopiaRWLock structure to free.
*
* @return None.
*
*/
extern void UtopiaRWLock_Free(UtopiaRWLock* pLock);

#endif /* __UTCTX_RWLOCK_H__ */
