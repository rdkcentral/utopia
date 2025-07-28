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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include "utapi.h"
#include "utapi_util.h"
#include "utapi_tr_user.h"
#include "DM_TR181.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"

static int g_IndexMapUser[MAX_NUM_INSTANCES+1] = {-1};

int Utopia_GetNumOfUsers(UtopiaContext *ctx)
{
    int cnt = 0;

    if(NULL == ctx) {
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    if( 0 != Utopia_GetInt(ctx,UtopiaValue_User_Count,&cnt))
        return 0;
    else
        return cnt;
}

int Utopia_SetNumOfUsers(UtopiaContext *ctx, int count)
{
    if(NULL == ctx) {
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    Utopia_SetInt(ctx,UtopiaValue_User_Count,count); 
    return SUCCESS;
}

int Utopia_GetUserEntry(UtopiaContext *ctx, unsigned long ulIndex, void *pUserEntry)
{
    if((NULL == ctx) || (NULL == pUserEntry)){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

   userCfg_t *pUserEntry_t = (userCfg_t *)pUserEntry;

   /* Do we have an InstanceNumber already ? */
   if(0 != Utopia_GetIndexedInt(ctx,UtopiaValue_UserIndx_InsNum,(ulIndex + 1), (int *)&(pUserEntry_t->InstanceNumber))) {
       pUserEntry_t->InstanceNumber = 0;
   } else {
       g_IndexMapUser[pUserEntry_t->InstanceNumber] = ulIndex;
   }
   
   Utopia_GetUserByIndex(ctx,ulIndex,pUserEntry_t); 
   return SUCCESS;
}

int Utopia_GetUserCfg(UtopiaContext *ctx, void *pUserCfg)
{
    unsigned long ulIndex = 0;

    if((NULL == ctx) || (NULL == pUserCfg)){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif
    
    userCfg_t *pUserCfg_t = (userCfg_t *)pUserCfg;
    if(0 == pUserCfg_t->InstanceNumber)
        return ERR_INVALID_ARGS;

    ulIndex = g_IndexMapUser[pUserCfg_t->InstanceNumber];
    Utopia_GetUserByIndex(ctx,ulIndex,pUserCfg_t); 
    return SUCCESS;
}

int Utopia_AddUser(UtopiaContext *ctx, void *pUserCfg)
{
    unsigned long ulIndex = 0;
    int count = 0;
    
    if((NULL == ctx) || (NULL == pUserCfg)){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    userCfg_t *pUserCfg_t = (userCfg_t *)pUserCfg;

    if(0 == pUserCfg_t->InstanceNumber)
        return ERR_INVALID_ARGS;

    count = Utopia_GetNumOfUsers(ctx);
    ulIndex = count;
    g_IndexMapUser[pUserCfg_t->InstanceNumber] = ulIndex;
    Utopia_SetIndexedInt(ctx, UtopiaValue_UserIndx_InsNum, (ulIndex + 1) ,pUserCfg_t->InstanceNumber);
    Utopia_SetUserByIndex(ctx,ulIndex,pUserCfg_t);
    Utopia_SetNumOfUsers(ctx,(count + 1));

    return SUCCESS;
}

int Utopia_DelUser(UtopiaContext *ctx, unsigned long ulInstanceNumber)
{
    int count = 0;
    unsigned long ulIndex = 0;
    userCfg_t userCfg;

    if(NULL == ctx){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    if(0 == ulInstanceNumber)
        return ERR_INVALID_ARGS;
    ulIndex = g_IndexMapUser[ulInstanceNumber];

    count = Utopia_GetNumOfUsers(ctx);
    count = count - 1;
    Utopia_SetNumOfUsers(ctx,count);
    Utopia_GetUserByIndex(ctx,ulIndex,&userCfg);

    /* Delete user from Linux DB if user is added there */
    if((TRUE == userCfg.bEnabled) && (TRUE == userCfg.RemoteAccessCapable)) {
	if( (access( "/usr/sbin/deluser", F_OK ) != -1) || (access( "/usr/bin/deluser", F_OK ) != -1) ) {
		v_secure_system("deluser %s",userCfg.Username);
	}
    }

    if(count != 0)
    {
       ulIndex++;
       for(;ulIndex <= count; ulIndex++)
       {
          Utopia_GetUserByIndex(ctx,ulIndex,&userCfg);
          Utopia_GetIndexedInt(ctx,UtopiaValue_UserIndx_InsNum,(ulIndex + 1), (int *)&userCfg.InstanceNumber);
          Utopia_SetIndexedInt(ctx,UtopiaValue_UserIndx_InsNum,ulIndex, userCfg.InstanceNumber);

          g_IndexMapUser[userCfg.InstanceNumber] = (ulIndex - 1);

          Utopia_SetUserByIndex(ctx,(ulIndex - 1),&userCfg);
        }
        /* Now unset the last index */
        Utopia_UnsetIndexed(ctx,UtopiaValue_UserIndx_InsNum,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_UserName,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_Password,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_User_Language,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_User_Enabled,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_User_RemoteAccess,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_User_Access_Permissions,ulIndex);
        Utopia_UnsetIndexed(ctx,UtopiaValue_HashPassword,ulIndex);
    }

    return SUCCESS;
}

int Utopia_SetUserCfg(UtopiaContext *ctx, void *pUserCfg)
{
    unsigned long ulIndex = 0;

    if((NULL == ctx) || (NULL == pUserCfg)){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    userCfg_t *pUserCfg_t = (userCfg_t *)pUserCfg;

    if(0 == pUserCfg_t->InstanceNumber)
        return ERR_INVALID_ARGS;

    ulIndex = g_IndexMapUser[pUserCfg_t->InstanceNumber];
    Utopia_SetUserByIndex(ctx,ulIndex,pUserCfg_t);
    return SUCCESS;
}

int Utopia_SetUserValues(UtopiaContext *ctx, unsigned long ulIndex, unsigned long ulInstanceNumber)
{
    if(NULL == ctx){
        return ERR_INVALID_ARGS;
    }

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    Utopia_SetIndexedInt(ctx, UtopiaValue_UserIndx_InsNum, (ulIndex + 1) ,ulInstanceNumber);
    g_IndexMapUser[ulInstanceNumber] = ulIndex;
    return SUCCESS;
}

int Utopia_GetUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, userCfg_t *pUserCfg_t)
{
    int iVal = 0;

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    Utopia_GetIndexed(ctx,UtopiaValue_UserName,(ulIndex + 1),pUserCfg_t->Username,STR_SZ);
    Utopia_GetIndexed(ctx,UtopiaValue_Password,(ulIndex + 1),pUserCfg_t->Password,PWD_SZ);
    Utopia_GetIndexed(ctx,UtopiaValue_User_Language,(ulIndex + 1),pUserCfg_t->Language,sizeof(pUserCfg_t->Language));

    Utopia_GetIndexedInt(ctx,UtopiaValue_User_Enabled,(ulIndex + 1),&iVal);
    pUserCfg_t->bEnabled = (0 == iVal) ? FALSE : TRUE;
    iVal = 0; 

    Utopia_GetIndexedInt(ctx,UtopiaValue_User_RemoteAccess,(ulIndex + 1),&iVal);
    pUserCfg_t->RemoteAccessCapable = (0 == iVal) ? FALSE : TRUE;

    Utopia_GetIndexedInt(ctx,UtopiaValue_User_Access_Permissions,(ulIndex + 1),(int *)&(pUserCfg_t->AccessPermissions));
    Utopia_GetIndexed(ctx,UtopiaValue_HashPassword,(ulIndex + 1),pUserCfg_t->HashedPassword,sizeof(pUserCfg_t->HashedPassword));

    return SUCCESS;

}

int Utopia_SetUserByIndex(UtopiaContext *ctx, unsigned long ulIndex, userCfg_t *pUserCfg_t)
{
    int iVal = 0;
    char tmpBuf[STR_SZ] = {'\0'};

#ifdef _DEBUG_
    ulog_errorf(ULOG_CONFIG, UL_UTAPI, "%s: ********Entered ****** !!!", __FUNCTION__);
#endif

    /* First delete the old username from Linux if its already there */
    /* This is required to take care of the change in username itself */
    if(0 != Utopia_GetIndexed(ctx,UtopiaValue_UserName,(ulIndex + 1),tmpBuf,STR_SZ)) {
    if( (access( "/usr/sbin/deluser", F_OK ) != -1) || (access( "/usr/bin/deluser", F_OK ) != -1) ) {
		v_secure_system("deluser %s",tmpBuf);
	}
    }
    Utopia_SetIndexed(ctx,UtopiaValue_UserName,(ulIndex + 1), pUserCfg_t->Username);
    if(strcmp(pUserCfg_t->Username, "admin") != 0){
        Utopia_SetIndexed(ctx,UtopiaValue_Password,(ulIndex + 1),pUserCfg_t->Password);
    }
    Utopia_SetIndexed(ctx,UtopiaValue_User_Language,(ulIndex + 1),pUserCfg_t->Language);

    iVal = (FALSE == pUserCfg_t->bEnabled) ? 0 : 1;
    Utopia_SetIndexedInt(ctx,UtopiaValue_User_Enabled,(ulIndex + 1),iVal);
    iVal = 0; 

    iVal = (FALSE == pUserCfg_t->RemoteAccessCapable) ? 0 : 1;
    Utopia_SetIndexedInt(ctx,UtopiaValue_User_RemoteAccess,(ulIndex + 1),iVal);

    Utopia_SetIndexedInt(ctx,UtopiaValue_User_Access_Permissions,(ulIndex + 1),pUserCfg_t->AccessPermissions);
    Utopia_SetIndexed(ctx,UtopiaValue_HashPassword,(ulIndex + 1),pUserCfg_t->HashedPassword);

    if((TRUE == pUserCfg_t->bEnabled) && (TRUE == pUserCfg_t->RemoteAccessCapable)) {
        /* Add the user with a home directory */
        v_secure_system("adduser -h /tmp/home/%s %s",pUserCfg_t->Username,pUserCfg_t->Username);
        v_secure_system("echo %s:%s | chpasswd", pUserCfg_t->Username,pUserCfg_t->Password);
    }

    return SUCCESS;
}
