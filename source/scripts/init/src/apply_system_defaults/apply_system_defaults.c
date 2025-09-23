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
===================================================================
    This programs will compare syscfg database and sysevent database
    against a default database. If any tuple in syscfg or sysevent is
    not already set, then this program will set it according to the
    default value
===================================================================
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <syscfg/syscfg.h>
#include "sysevent/sysevent.h"
#include "time.h"
#include "secure_wrapper.h"
#include <sys/stat.h>
#if defined (_XB6_PRODUCT_REQ_) || defined(_HUB4_PRODUCT_REQ_) || defined(_SR300_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_)
#include "platform_hal.h"
#endif
#include <unistd.h>
#include <stdbool.h>
#include <cjson/cJSON.h>
#include  "safec_lib_common.h"

#include <telemetry_busmessage_sender.h>
#define PARTNERS_INFO_FILE  							"/nvram/partners_defaults.json"
#define PARTNERS_INFO_FILE_ETC                                                 "/etc/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE                                                    "/opt/secure/bootstrap.json"
#define BOOTSTRAP_INFO_FILE_BACKUP                                             "/nvram/bootstrap.json"
#define CLEAR_TRACK_FILE                                                       "/nvram/ClearUnencryptedData_flags"
#define NVRAM_BOOTSTRAP_CLEARED                                                (1 << 0)
#define VERSION_TXT_FILE							"/version.txt"
#define PARTNERID_FILE  								"/nvram/.partner_ID"
#define PARTNER_DEFAULT_APPLY_FILE  					"/nvram/.apply_partner_defaults"
#define PARTNER_DEFAULT_MIGRATE_PSM  					"/tmp/.apply_partner_defaults_psm"
#define PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER  	"/tmp/.apply_partner_defaults_new_psm_member"

#define PARTNER_ID_LEN 64

#ifndef UNIT_TEST_DOCKER_SUPPORT
#define STATIC static
#else
#define STATIC
#endif

#define PARTNER_ID_MAX_RETRY	5

static int   syscfg_dirty;

#define DEFAULT_FILE "/etc/utopia/system_defaults"
#define SE_NAME "system_default_set"

STATIC int global_fd = 0;
STATIC token_t global_id;

/*
   By default the variable "convert" will be set if $Version is found in
   system_defaults and its value does not match the currently configured value
   (the actual value isn't important, it just needs to be a different string).

   However, during development we want changes in system_defaults to be applied
   without the need to repeatedly update $Version. Setting ALWAYS_CONVERT
   effectively does that (ie it's the same as forcing the $Version check to
   always detect a difference even if the values match).

   The end result should be that values in system_defaults defined with $$ will
   always over-ride any setting which may have already been configured.
*/

//#define ALWAYS_CONVERT

#if ! defined (ALWAYS_CONVERT)
//Flag to indicate a db conversion is necessary
static int convert = 0;
#endif

#define RETRY_COUNT 3

#if defined (_CBR_PRODUCT_REQ_) || defined (_XB6_PRODUCT_REQ_)
        #define LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
	#define LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define APPLY_PRINT(fmt ...)   {\
   FILE *logfp = fopen ( LOG_FILE , "a+");\
   if (logfp)\
   {\
        fprintf(logfp,fmt);\
        fclose(logfp);\
   }\
}\


static char *trim (char *in)
{
    int len;

    /*
       Drop leading spaces (although there are not expected to be any).
    */
    while (isspace(*in)) {
        in++;
    }

    /*
       Drop trailing spaces (there will always be a newline at the end
       of lines read by fgets() and trim() is used to remove it).
    */
    len = (int) strlen(in);
    while (len > 0) {
        if (isspace(in[len - 1])) {
            in[len - 1] = 0;
            len--;
        }
        else
            break;
    }

    return in;
}

/*
 * Procedure     : parse_line
 * Purpose       : parses a line into a name and a value
 * Parameters    :
 *    in         : the line to parse
 *    name       : on return the name
 *    value      : on return the value
 * Return Value  : 0 if ok -1 if not
 * Note          : This function will change the contents of in
 */
static int parse_line (char *in, char **name, char **value)
{
   char *tok;

   tok = strchr(in, '=');
   if (tok == NULL)
      return -1;

   *tok = '\0';
   *name = in;
   *value = tok + 1;

   return 0;
}

/*
 * Procedure     : set_sysevent
 * Purpose       : sets a sysevent tuple if it is not already set
 * Parameters    :
 *    name       : the name of the tuple
 *    value      : the value to set the tuple to
 * Return Value  : 0 if ok, -1 if not
 */
static int set_sysevent(char *name, char *value, int flags) 
{
   char get_val[512];
   int rc;

   get_val[0] = 0;

   rc = sysevent_get (global_fd, global_id, name, get_val, sizeof(get_val));

   if (get_val[0] == 0)
   {
      if (flags != 0x00000000)
      {
         rc = sysevent_set_options (global_fd, global_id, name, flags);
      }

      // if the value is prefaced by '$' then we use the
      // current value of syscfg
      char *trimmed_val = trim(value);

      if (trimmed_val[0] == '$')
      {
         syscfg_get (NULL, trimmed_val+1, get_val, sizeof(get_val));
         rc = sysevent_set (global_fd, global_id, name, get_val, 0);
//       printf("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, get_val, flags);
      }
      else
      {
         rc = sysevent_set (global_fd, global_id, name, value, 0);
         APPLY_PRINT("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, value, flags);
         printf ("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, value, flags);
      }
   }
   else
   {
      rc = 0;
   }

   return rc;
}

/*
 * Procedure     : set_syscfg
 * Purpose       : sets a syscfg tuple if it is not already set
 * Parameters    :
 *    name       : the name of the tuple
 *    value      : the value to set the tuple to
 * Return Value  : 0 if ok, -1 if not
 */
static int set_syscfg (char *name, char *value) 
{
    int force = 0;
    int rc = 0;

    if ((value == NULL) || (value[0] == 0))
    {
        return 0;
    }

    /* Check for second $ (ie values defined with $$ prefix) */
    if (name[0] == '$')
    {
        name++;
#if defined (ALWAYS_CONVERT)
        force = 1;
#else
        if (convert)
            force = 1;
#endif
    }

    if (force)
    {
        printf ("[utopia] [init] apply_system_defaults set <$%s, %s> force=%d\n", name, value, force);
        rc = syscfg_set (NULL, name, value);
        syscfg_dirty++;
    }
    else
    {
        char get_val[512];

        syscfg_get (NULL, name, get_val, sizeof(get_val));

        if (get_val[0] == 0)
        {
            printf ("[utopia] [init] apply_system_defaults set <$%s, %s> force=%d\n", name, value, force);
            rc = syscfg_set (NULL, name, value);
            syscfg_dirty++;
        }
        else
        {
            printf ("[utopia] [init] syscfg_get <$%s, %s>\n", name, get_val);
            rc = 0;
        }
    }

    return rc;
}

#if ! defined (ALWAYS_CONVERT)
static int handle_version (char* name, char* value)
{
    char get_val[128];
    int ret = 0;
    int rc;

    if (strcmp (name, "$Version") == 0)
    {
        ret = 1;
        name++;

        rc = syscfg_get (NULL, name, get_val, sizeof(get_val));

        if ((rc != 0) || (get_val[0] == 0) || (strcmp (value, get_val) != 0))
        {
            convert = 1;
        }
    }

    return ret;
}

static int check_version (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         if (parse_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] [error] check_version failed to parse line (%s)\n", line);
         }
         else
         {
            if (handle_version (trim(name), trim(value)))
            {
                break;
            }
         }
      }
      else if (line[0] == '@')
      {
         // this is a sysevent line
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   return 0;
}
#endif

/*
 * Procedure     : set_syscfg_defaults
 * Purpose       : Go through a file, parse it into <name, value> tuples,
 *                 and set syscfg namespace (iff not already set),
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_syscfg_defaults (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         if (parse_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] [error] set_syscfg_defaults failed to parse line (%s)\n", line);
         }
         else
         {
            set_syscfg(trim(name), trim(value));
         }
      }
      else if (line[0] == '@')
      {
         // this is a sysevent line
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_syscfg_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   return 0;
}

/*
 * Procedure     : set_sysevent_defaults
 * Purpose       : Go through a file, parse it into <name, value> tuples,
 *                 and set sysevent namespace
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_sysevent_defaults (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         // this is a syscfg line
      }
      else if (line[0] == '@')
      {
         if (parse_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] set_sysevent_defaults failed to parse line (%s)\n", line);
         }
         else
         {
            char *val = trim(value);
            char *flagstr;
            int flags = 0x00000000;

            int i;
            int len = strlen(val);
            for (i=0; i<len; i++) {
               if (isspace(val[i])) {
                  flagstr = (&(val[i])+1);
                  val[i] = '\0';
                  flags = strtol(flagstr, NULL, 16);
                  break;
               }
            }
            set_sysevent(trim(name), val, flags);
         }
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_sysevent_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   return 0;
}

/*
 * Procedure     : set_defaults
 * Purpose       : Go through a file twice, first for syscfg variables 
 *                 (because sysevent might use syscfg values for initialization),
 *                 and then again for sysevent variables
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_defaults(void)
{
#if ! defined (ALWAYS_CONVERT)
   check_version();
#endif

   set_syscfg_defaults();
   set_sysevent_defaults();

   return 0;
}

static char *json_file_parse (char *path)
{
	FILE	 	*fileRead 	= NULL;
	char		*data 		= NULL;
	int 		 len 		= 0 , n=0;

	//File read
	fileRead = fopen( path, "r" );
  
	//Null Check
	if( fileRead == NULL ) 
	{
	 	APPLY_PRINT( "%s-%d : Error in opening %s JSON file\n" , __FUNCTION__, __LINE__,path );
		return NULL;
	}

	//Calculate length for memory allocation 
	fseek( fileRead, 0, SEEK_END );
	len = ftell( fileRead );
	fseek( fileRead, 0, SEEK_SET );

	APPLY_PRINT("%s-%d : %s Total File Length :%d \n", __FUNCTION__, __LINE__, path, len );

	if( len > 0 )
 	{
		 data = ( char* )malloc( sizeof(char) * (len + 1) );
		 //Check memory availability
		 if ( data != NULL ) 
		 {
			memset( data, 0, ( sizeof(char) * (len + 1) ));
			/* CID 58465: Ignoring number of bytes read */
			if((n = fread( data, 1, len, fileRead )) <= 0)
			{
			   APPLY_PRINT("%s-%d : fread failed Length :%d\n", __FUNCTION__, __LINE__, n );
			   fclose(fileRead);
			   free(data);
			   return NULL;
			}
		 } 
		 else 
		 {
			 APPLY_PRINT("%s-%d : Memory allocation failed Length :%d\n", __FUNCTION__, __LINE__, len );
		 }
 	}
	 
	if( fileRead )
	fclose( fileRead );
	
	return data;
}

static int writeToJson(char *data, char *file)
{
    FILE 	*fp;
    fp = fopen(file, "w");
    if (fp == NULL) 
    {
        return -1;
    }
    
    fwrite(data, strlen(data), 1, fp);
    fclose(fp);
    return 0;
}

static int IsValuePresentinSyscfgDB (char *param)
{
	char buf[ 512 ];
	int  ret;

	//check whether passed param with value is already existing or not
	memset( buf, 0, sizeof( buf ));
	ret = syscfg_get( NULL, param, buf, sizeof(buf));

	if( ( ret != 0 ) || ( buf[ 0 ] == '\0' ) )
	{
		return 0;
	}

	return 1;
}

static int set_syscfg_partner_values (char *pValue, char *param)
{
	if ((syscfg_set_commit(NULL, param, pValue) != 0)) 
	{
        	APPLY_PRINT("set_syscfg_partner_values : syscfg_set failed\n");
		return 1;
	}
	else 
	{
		return 0;
	}
}

static int GetDevicePropertiesEntry (char *pOutput, int size, char *sDevicePropContent)
{
    FILE 	*fp1 		 = NULL;
    char 	 buf[ 1024 ] = { 0 },
	  		*urlPtr 	 = NULL;
    int 	 ret		 = -1;
    errno_t safec_rc = -1;

    // Read the device.properties file 
    fp1 = fopen( "/etc/device.properties", "r" );
	
    if ( fp1 == NULL ) 
	{
        APPLY_PRINT("Error opening properties file! \n");
        return -1;
    }

    while ( fgets( buf, sizeof( buf ), fp1 ) != NULL ) 
    {
        // Look for Device Properties Passed Content
        if ( strstr( buf, sDevicePropContent ) != NULL ) 
	{
		 buf[strcspn( buf, "\r\n" )] = 0; // Strip off any carriage returns
		 // grab content from string(entry)
		urlPtr = strstr( buf, "=" );
                if ( !urlPtr )  // CID 61154: Dereference null return value (NULL_RETURNS)
                {
                    continue;
                }
                urlPtr++;
                safec_rc = strcpy_s( pOutput, size, urlPtr );
                ERR_CHK(safec_rc);
		ret=0;
		break;
        }
    }

    fclose( fp1 );
    return ret;
}

static int getFactoryPartnerId (char *pValue)
{
#if defined (_XB6_PRODUCT_REQ_) || defined(_HUB4_PRODUCT_REQ_) || defined(_SR300_PRODUCT_REQ_) || defined(_WNXL11BWL_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
	if(0 == platform_hal_getFactoryPartnerId(pValue))
	{
		APPLY_PRINT("%s:%d - %s\n",__FUNCTION__, __LINE__,pValue);
		return 0;		 
	}
	else
	{
		int count = 0 ;
		while ( count < 3 )
		{
			APPLY_PRINT(" Retrying for getting partnerID from HAL, Retry Count:%d\n", count + 1);
			if(0 == platform_hal_getFactoryPartnerId(pValue))
			{
				APPLY_PRINT("%s:%d - %s\n",__FUNCTION__, __LINE__,pValue);
				return 0;
			}
			sleep(3);
			count++;
		}
		//TCCBR-4426 getFactoryPartnerId is implemented for XB6/HUB4 Products as of now
		APPLY_PRINT("%s - Failed Get factoryPartnerId \n", __FUNCTION__);
                t2_event_d("SYS_ERROR_Factorypartner_fetch_failed", 1);
	}
#endif
	return -1;
}

static int validatePartnerId (char *PartnerID)
{
   int result = 0;
   char* ptr_etc_jsons = NULL;
   cJSON * subitem_etc = NULL;
   ptr_etc_jsons = json_file_parse( PARTNERS_INFO_FILE_ETC );
   if(ptr_etc_jsons)
   {
      cJSON * root_etc_json = cJSON_Parse(ptr_etc_jsons);
      if(root_etc_json)
      {
         subitem_etc = cJSON_GetObjectItem(root_etc_json,PartnerID);
         if(subitem_etc)
         {
            printf("##############Partner ID Found\n");
            result = 1;
         }
         else
         {
            printf("Partner ID NOT Found\n");
            sprintf(PartnerID,"%s","unknown");
         }
         cJSON_Delete(root_etc_json);
      }
      free(ptr_etc_jsons);
   }
   return result;
}

#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
static int PartnerId_FetchWithRetry(char *PartnerID ) {
    int retries = 0;
    char buf[PARTNER_ID_LEN] = {0};

    for(retries = 0; retries < PARTNER_ID_MAX_RETRY; retries++) {
        memset(PartnerID, 0, PARTNER_ID_LEN);

        if((0 == getFactoryPartnerId(PartnerID)) && (PartnerID[0] != '\0') &&
            validatePartnerId(PartnerID) && (0 != strcasecmp (PartnerID, "Unknown"))) {
            return 0;
        }
        else {
            memset(buf, 0, sizeof(buf));

            if ( 0 == GetDevicePropertiesEntry(buf, sizeof(buf), "PARTNER_ID")) {
                if(buf[0] !=  '\0') {
                    strncpy(PartnerID, buf, strlen(buf));
                    PartnerID[strlen(buf)] = '\0';

                    if(validatePartnerId(PartnerID) && (0 != strcasecmp(PartnerID, "Unknown") )) {
                        return 0;
                    }
                }
            }
        }

        if((retries + 1) < PARTNER_ID_MAX_RETRY) {
            APPLY_PRINT("%s - Still obtaining invalid PartnerID value from various sources so Retrying, Iteration: <%d>\n", __FUNCTION__, retries);
            sleep(2);
        }
    }

    return 1;
}

int WritePartnerIDToFile(char* PartnerID) {
    FILE *fp = NULL;

    fp = fopen(PARTNERID_FILE, "w");
    if(NULL == fp) {
        APPLY_PRINT("%s - Failed to open file %s\n", __FUNCTION__, PARTNERID_FILE);
        return 1;
    }

    if( (NULL != PartnerID) && (strlen(PartnerID) > 0) ) {
        fwrite(PartnerID, strlen(PartnerID), 1, fp);
        APPLY_PRINT("%s - PartnerID %s written to file %s\n", __FUNCTION__, PartnerID, PARTNERID_FILE);
    }
    else {
        APPLY_PRINT("%s - PartnerID is NULL\n", __FUNCTION__);
        if(fp) {
            fclose(fp);
        }

        return 1;
    }

    if(fp) {
        fclose(fp);
    }

    return 0;
}

void CheckAndHandleInvalidPartnerIDRecoveryProcess(char *PartnerID) {
    if( '\0' == PartnerID[0] || (0 == validatePartnerId(PartnerID)) || (0 == strcasecmp (PartnerID, "Unknown")) ) {
        memset(PartnerID, 0, PARTNER_ID_LEN);

        APPLY_PRINT("%s - Current PartnerID value is Unknown/Invalid, So retrying to obtain valid PartnerID values. \n", __FUNCTION__);
        t2_event_d("SYS_ERROR_INVALID_PARTNER_ID_DETECTED", 1);
        if( 0 == PartnerId_FetchWithRetry(PartnerID) ) {
            APPLY_PRINT("%s - INVALID_PARTNER_ID_RECOVERY_SUCCESS - Obtained Valid PartnerID is %s\n", __FUNCTION__, PartnerID );
            t2_event_d("SYS_INVALID_PARTNER_ID_RECOVERY_SUCCESS", 1);

            if (syscfg_set_commit(NULL, "PartnerID", PartnerID) != 0) {
                APPLY_PRINT("%s - PartnerID syscfg_set failed\n", __FUNCTION__);
            }

            WritePartnerIDToFile(PartnerID);

            if (syscfg_set_commit(NULL, "factory_reset", "y") != 0) {
                APPLY_PRINT("%s - syscfg_set failed\n", __FUNCTION__);
            }

            creat("/nvram/.Invalid_PartnerID", 0644);
            v_secure_system("/rdklogger/backupLogs.sh");

        }
        else {
            if (syscfg_set_commit(NULL, "PartnerID", "Unknown") != 0) {
                APPLY_PRINT("%s - syscfg_set failed\n", __FUNCTION__);
            }

            APPLY_PRINT("%s - INVALID_PARTNER_ID_RECOVERY_FAILURE - PartnerID is %s\n", __FUNCTION__, PartnerID );
            t2_event_d("SYS_ERROR_INVALID_PARTNER_ID_RECOVERY_FAILURE", 1);
        }
    }
    else {
        APPLY_PRINT("%s - Current PartnerID : %s value is Valid \n", __FUNCTION__, PartnerID );
    }
}

#endif // (_RDKB_GLOBAL_PRODUCT_REQ_)

static int get_PartnerID (char *PartnerID)
{
	char buf[PARTNER_ID_LEN];
	memset(buf, 0, sizeof(buf));
	//int isValidPartner = 0;

	/* 
	  *  Check whether /nvram/.partner_ID file is available or not. 
	  *  If available then read it and apply defaults based on new partnerID
	  *  If not available then read it from HAL and create the /nvram/.partner_ID file
	  *     then apply defaults based on current partnerID	  
	  */
	if ( access( PARTNERID_FILE , F_OK ) != 0 )	 
	{

		APPLY_PRINT("%s - %s is not there\n", __FUNCTION__, PARTNERID_FILE );
		if( ( 0 == getFactoryPartnerId( PartnerID ) ) && ( PartnerID [ 0 ] != '\0' ) )
		{
			APPLY_PRINT("%s - PartnerID from HAL: %s\n",__FUNCTION__,PartnerID );
			validatePartnerId ( PartnerID );
		}
		else
		{
			if ( 0 == GetDevicePropertiesEntry( buf, sizeof( buf ),"PARTNER_ID" ) )
			{
				if(buf[0] !=  '\0') // CID 73353: Array compared against 0 (NO_EFFECT)
                                {
				    strncpy(PartnerID,buf,strlen(buf));
				    PartnerID[strlen(buf)] = '\0'; // CID 340497: String not null terminated (STRING_NULL)
				    APPLY_PRINT("%s - PartnerID from device.properties: %s\n",__FUNCTION__,PartnerID );
                                }
			}
			else		
			{
                                APPLY_PRINT("%s:ERROR.....partnerId from factory also NULL setting it to unknown\n",__FUNCTION__);
				
#if defined (_XB6_PRODUCT_REQ_)
				sprintf( PartnerID, "%s", "unknown" );
#elif defined (_RDK_REF_PLATFORM_)
                                sprintf( PartnerID, "%s", "RDKM");
#elif defined (_SR300_PRODUCT_REQ_) /* Default fall back option for ADA devices SKYH4-4946 */
				sprintf( PartnerID, "%s", "sky-uk");
#elif defined (_HUB4_PRODUCT_REQ_) /* Default fall back option for HUB4 devices SKYH4-4946 */
			        sprintf( PartnerID, "%s", "sky-italia");
#else
				sprintf( PartnerID, "%s", "comcast" );
#endif
				APPLY_PRINT("%s - Failed Get factoryPartnerId so set it PartnerID as: %s\n", __FUNCTION__, PartnerID );
                                t2_event_d("SYS_ERROR_Factorypartner_fetch_failed", 1);

                                if (strncmp(PartnerID, "comcast", strlen("comcast")) == 0)
                                        t2_event_d("SYS_ERROR_Factory_partner_set_comcast", 1);
			}
		}
	}
	else
	{
		FILE	   *FilePtr 			= NULL;
		char		fileContent[ 256 ]	= { 0 };

	        /* TODO CID 135527: Time of check time of use 
                *  As per code flow either access() or fopen() will be invoked
                *  so we could not hit the TOCTOU issue. It could be a false positive.*/
		FilePtr = fopen( PARTNERID_FILE, "r" );
		
		if ( FilePtr ) 
		{
			char *pos;
		
			fgets( fileContent, 256, FilePtr );
			fclose( FilePtr );
			FilePtr = NULL;
			
			// Remove line \n charecter from string  
			if ( ( pos = strchr( fileContent, '\n' ) ) != NULL )
			 *pos = '\0';

			sprintf( PartnerID, "%s", fileContent );

			APPLY_PRINT("%s - PartnerID from File: %s\n",__FUNCTION__,PartnerID );
			validatePartnerId ( PartnerID );
		}
		unlink("/nvram/.partner_ID");
	}
	set_syscfg_partner_values(PartnerID,"PartnerID");

	//To print Facgtory PartnerID on every boot-up
	memset(buf, 0, sizeof(buf));
	if( 0 == getFactoryPartnerId( buf ) )
	{
		APPLY_PRINT("[GET-PARTNERID] Factory_PartnerID:%s\n", buf );
                t2_event_s("getfactorypartner_split", buf);
	}
   	else
    {
       APPLY_PRINT("[GET-PARTNERID] Factory_PartnerID:NULL\n" );
       t2_event_s("getfactorypartner_split", NULL);
   	}

	APPLY_PRINT("[GET-PARTNERID] Current_PartnerID:%s\n", PartnerID );
        t2_event_s("getcurrentpartner_split", PartnerID);
	
	return 0;	
}

static void ValidateAndUpdatePartnerVersionParam (cJSON *root_etc_json, cJSON *root_nvram_json, bool *do_compare, char *PartnerID)
{
    cJSON *properties_etc = NULL;
    cJSON *properties_nvram = NULL;
    char *version_etc = NULL;
    char *version_nvram = NULL;
    cJSON *version_nvram_key = NULL;
  
    if (!do_compare || !root_etc_json || !root_nvram_json)
        return;

    /* Check if entire parameters need to be compared based on version number
    */
    properties_etc = cJSON_GetObjectItem(root_etc_json,"properties");
  
    if (!properties_etc)
        *do_compare = true;
  
    if (properties_etc)
    {
        properties_nvram = cJSON_GetObjectItem(root_nvram_json,"properties");
        version_etc = cJSON_GetObjectItem(properties_etc,"version")->valuestring;
        if (properties_nvram)
        {
            int etc_major = 0;
            int etc_minor = 0;
            int nvram_major = 0;
            int nvram_minor = 0;

            if (version_etc)
            {        
                sscanf(version_etc,"%d.%d",&etc_major,&etc_minor);
                printf ("\n READ version ######## etc: major %d minor %d \n",etc_major, etc_minor);
            }
            /* Check if version exists inside properties object */
            version_nvram_key = (cJSON *)cJSON_GetObjectItem(properties_nvram,"version");
            if(version_nvram_key)
            {
                version_nvram = cJSON_GetObjectItem(properties_nvram,"version")->valuestring;
            }
            else
            {
                 printf("version key is missing in properties\n");
                 *do_compare = true;
                 /* version is missing, so delete entire properties */
                 cJSON_DeleteItemFromObject(root_nvram_json,"properties");
            }
            /* If version exists in both nvram and etc, then compare the version number */
            if ( version_nvram && version_etc)
            {
                sscanf(version_nvram,"%d.%d",&nvram_major,&nvram_minor);
                printf ("\n READ version ######## nvram: major %d minor %d\n",nvram_major, nvram_minor);
                if (nvram_major != etc_major || nvram_minor != etc_minor)
                {
                    *do_compare = true;
                }

                if (*do_compare)
                {
                    printf ("\n VERSION MISMATCH ######## nvram %s etc %s \n", version_nvram, version_etc);
                }
		else
		{
		   /* A rare corner case, were version is getting updated,but key and value not added to the
		    * bootstrap file, this will make the newly added key not available until there is a new
		    * update version in partner json file, so handling here this case also as compare needed
		    * case*/
		   cJSON * subitem_etc = cJSON_GetObjectItem(root_etc_json,PartnerID);
		   cJSON * subitem_nvram_bs = cJSON_GetObjectItem(root_nvram_json,PartnerID);
		   int subitem_etc_count = cJSON_GetArraySize(subitem_etc);
		   int subitem_nvram_bs_count = cJSON_GetArraySize(subitem_nvram_bs);
		   APPLY_PRINT ("\nversion:%d.%d KEY COUNT in nvram %d and etc %d\n", nvram_major, nvram_minor,
                                                                 subitem_nvram_bs_count,subitem_etc_count);
		   if (subitem_etc_count != subitem_nvram_bs_count)
	           {
		      APPLY_PRINT ("\nversion:%d.%d KEY COUNT MISMATCH in nvram %d and etc %d,do compare\n", nvram_major, nvram_minor,
				                                 subitem_nvram_bs_count,subitem_etc_count);
		      *do_compare = true;
                   }

		}
            }                   
        }
        else
        {
            *do_compare = true;
        }
    }    

    if (version_etc)
    {
        /* If version doesn't exist in nvram file, then insert it at the 0th index 
           else just replace the object 
        */ 
        if (!version_nvram)
        {
            printf ("\n NVRAM VERSION not found  ######## etc %s \n", version_etc);
            cJSON_InsertItemInArray(root_nvram_json, 0, cJSON_DetachItemFromObject(root_etc_json,"properties") );
        }
        else
        {
            printf("\n NVRAM VERSION FOUND\n");
            cJSON_ReplaceItemInArray(root_nvram_json, 0, cJSON_DetachItemFromObject(root_etc_json,"properties") );
        }
        char *out = cJSON_Print(root_nvram_json);
        if(out)
        {
         writeToJson(out, BOOTSTRAP_INFO_FILE);
         //Check CLEAR_TRACK_FILE and update in nvram, if needed.
         unsigned int flags = 0;
         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
         if (fp)
         {
             fscanf(fp, "%u", &flags);
             fclose(fp);
         }
         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
         {
             APPLY_PRINT("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
             writeToJson(out, BOOTSTRAP_INFO_FILE_BACKUP);
         }
         free(out);
         out = NULL;
        }
    }
}

static char *getBuildTime (void)
{
    static char buildTime[50] = {0};
    if (buildTime[0] != '\0')
        return buildTime;
    
    FILE *fptr;
    if ((fptr = fopen(VERSION_TXT_FILE, "r")) == NULL)
    {
        printf( "%s: Trying to open a non-existent file [%s] \n", __FUNCTION__, VERSION_TXT_FILE);
    }
    else
    {
        char * line = NULL;
        size_t len = 0;
        int read;

        while ((read = getline(&line, &len, fptr)) != -1)
        {
            if (strstr(line, "BUILD_TIME"))
            {
                char *substr = strtok(line, "\"");
                if (substr)
                {
                   substr = strtok(NULL,"\"");
                   if (substr)
                   {
                      strncpy(buildTime, substr, sizeof(buildTime));
                   }
                }
                break;
            }
        }
        if (line)
           free(line);

        fclose(fptr);
    }
    return buildTime;
}

#if 0
static char *getTime (void)
{
    time_t timer;
    static char buffer[50];
    struct tm* tm_info;
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 50, "%Y-%m-%d %H:%M:%S ", tm_info);
    return buffer;
}
#endif

static int addParamInPartnersFile (char *pKey, char *PartnerId, char *pValue)
{
	cJSON *partnerObj = NULL;
	cJSON *json = NULL;
	FILE *fileRead = NULL;
	char * cJsonOut = NULL;
	char* data = NULL;
	 int len, n;
	 int configUpdateStatus = -1;
	 fileRead = fopen( PARTNERS_INFO_FILE, "r" );
	 if( fileRead == NULL ) 
	 {
		 APPLY_PRINT("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ );
		 return -1;
	 }
	 
	 fseek( fileRead, 0, SEEK_END );
	 len = ftell( fileRead );
	 /* CID 59376: Argument cannot be negative */
	 if(len < 0)
         {
            APPLY_PRINT("len can't be negative value\n");
            fclose( fileRead );
            return -1;
         }
	 fseek( fileRead, 0, SEEK_SET );
	 data = ( char* )malloc( sizeof(char) * (len + 1) );
	 if (!data) 
	 {	
	     APPLY_PRINT("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__);
	     fclose( fileRead );
	     return -1;
	 }
	 memset( data, 0, ( sizeof(char) * (len + 1) ));
	 /* CID 65253: Ignoring number of bytes read */
         if ((n= fread( data, 1, len, fileRead )) <=0)
         {
              APPLY_PRINT("%s-%d : fread failed Length :%d\n", __FUNCTION__, __LINE__, n );
              fclose(fileRead);
	      free(data);
              return -1;
	 }
	 /*CID 135511 String not null terminated */
	 data[len] = '\0';

	 fclose( fileRead );
	 if ( data == NULL )
	 {
		APPLY_PRINT("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__);
		return -1;
	 }
	 else if (data[0])
	 {
		 json = cJSON_Parse( data );
		 if( !json ) 
		 {
			 APPLY_PRINT(  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__);
			 free(data);
			 return -1;
		 } 
		 partnerObj = cJSON_GetObjectItem( json, PartnerId );
		 if ( NULL != partnerObj)
		 {
			 if (NULL == cJSON_GetObjectItem( partnerObj, pKey) )
			 {
				cJSON_AddItemToObject(partnerObj, pKey, cJSON_CreateString(pValue));
			 }
			 else
			 {
				 cJSON_ReplaceItemInObject(partnerObj, pKey, cJSON_CreateString(pValue));
			 }
			 cJsonOut = cJSON_Print(json);
          if(cJsonOut)
          {
               configUpdateStatus = writeToJson(cJsonOut, PARTNERS_INFO_FILE);
               if ( configUpdateStatus)
               {
                   APPLY_PRINT( "Failed to update value for %s partner\n",PartnerId);
                   APPLY_PRINT( "Param:%s\n",pKey);
                   free(cJsonOut);
                   cJSON_Delete(json);
                   free(data);
                   return -1;
               }
               free(cJsonOut);
          }
          APPLY_PRINT( "Added/Updated Value for %s partner\n",PartnerId);
			 APPLY_PRINT( "Param:%s - Value:%s\n",pKey,pValue);
		 }
		 else
		 {
		 	APPLY_PRINT("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ );
		 	cJSON_Delete(json);
         free(data);
		 	return -1;
		 }
		 cJSON_Delete(json);
       free(data);
	  }
	  else
	  {
		APPLY_PRINT("PARTNERS_INFO_FILE %s is empty\n", PARTNERS_INFO_FILE);
		/* CID: 66806 Resource leak*/
       free(data);
		return -1;
	  }
	 return 0;
}

/** ApplyPartnersObjectItemsIntoSysevents() */
static int ApplyPartnersObjectItemsIntoSysevents( char *pcPartnerID )
{
   if( NULL == pcPartnerID )
   {
      APPLY_PRINT("%s-%d, Error: PartnerID Value is NULL so unable to proceed for \n", __FUNCTION__,__LINE__);
      return -1;
   }

   APPLY_PRINT("%s-%d, For PartnerID:%s from '%s' file\n", __FUNCTION__, __LINE__, pcPartnerID, PARTNERS_INFO_FILE_ETC);

   char  *ptr_etc_json       = json_file_parse( PARTNERS_INFO_FILE_ETC );
   cJSON *pCJsonRootEtc      = cJSON_Parse( ptr_etc_json );

   if( NULL != pCJsonRootEtc )
   {
      //cJSON *pCJsonProp           = cJSON_GetObjectItem( pCJsonRootEtc, "properties" );
      cJSON *pCJsonSubitemEtc   = cJSON_GetObjectItem( pCJsonRootEtc, pcPartnerID );

      if ( NULL != pCJsonSubitemEtc )
      {
         cJSON *pCJsonApplytoSyseventsBlock  = cJSON_GetObjectItem( pCJsonSubitemEtc, "apply_value_to_sysevent" );

         if( NULL != pCJsonApplytoSyseventsBlock )
         {
            char  *key = NULL, *value = NULL;
            cJSON *pCJsonChildParam     = pCJsonApplytoSyseventsBlock->child;

            while( pCJsonChildParam )
            {
               key = pCJsonChildParam->string;
               cJSON * value_obj = cJSON_GetObjectItem(pCJsonApplytoSyseventsBlock, key);

               if (value_obj)
                  value = value_obj->valuestring;

               if (value == NULL)
               {
                  APPLY_PRINT("%s-%d, Value is NULL for key = %s, skip it...\n", __FUNCTION__, __LINE__, key);
                  pCJsonChildParam = pCJsonChildParam->next;
                  continue;
               }

               APPLY_PRINT("%s, Applying Key = %s Value = %s to sysevents\n", __FUNCTION__, key, value);

               if ( 0 == strcmp ( key, "Device.X_RDK_Features.NTPHealthCheck") )
               {
                  sysevent_set (global_fd, global_id, "NTPHealthCheckSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.SelfhelpWANConnectionDiag") )
               {
                  sysevent_set (global_fd, global_id, "SelfhelpWANConnectionDiagSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.LANIPv6GUA") )
               {
                  sysevent_set (global_fd, global_id, "LANIPv6GUASupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.HarvesterTimeOffset") )
               {
                  sysevent_set (global_fd, global_id, "HarvesterTimeOffsetSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.HarvesterScanPublicWiFi") )
               {
                  sysevent_set (global_fd, global_id, "HarvesterScanPublicWiFiSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.HomeSecurity.Enable") )
               {
                  sysevent_set (global_fd, global_id, "HomeSecuritySupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.GatewayFailover.Enable") )
               {
                  sysevent_set (global_fd, global_id, "GatewayFailoverSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.UseCEDMPasswordForGUI") )
               {
                  sysevent_set (global_fd, global_id, "UseCEDMPasswordForGUI", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.HotSpotSupport.Enable") )
               {
                  sysevent_set (global_fd, global_id, "HotSpotSupport", value, 0);
               }
               else if ( 0 == strcmp ( key, "Device.X_RDK_Features.VlanDiscovery.Enable") )
               {
                  sysevent_set (global_fd, global_id, "VlanDiscoverySupport", value, 0);
               }

               pCJsonChildParam = pCJsonChildParam->next;
            }
         }
      }

      //Free allocated resource
      cJSON_Delete(pCJsonRootEtc);
   }

   //Free allocated resource
   if( NULL != ptr_etc_json )
   {
      free(ptr_etc_json);
      ptr_etc_json = NULL;
   }

   return 0;
}

STATIC void addInSysCfgdDB (char *key, char *value)
{
   /* There are parameters which needs to be available in syscfg/PSM DBs
      Check if all of these parameters are SET into DBs
   */
   int IsPSMMigrationNeeded = 0;

   //If WiFiPersonalization.Support is false, set redirection_flag to false to disable Captive Portal
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support") )
   {
      if ( 0 == strcmp(value, "false") )
      {
         APPLY_PRINT("%s: Setting redirection_flag and WiFiPersonalizationSupport to FALSE\n", __FUNCTION__);
         set_syscfg_partner_values( value, "redirection_flag" );
         set_syscfg_partner_values( value, "WiFiPersonalizationSupport" );
      }
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialForwardedMark") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "DSCP_InitialForwardedMark" ) )
      {
         set_syscfg_partner_values( value,"DSCP_InitialForwardedMark" );
      }
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.WANsideSSH.Enable") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "WANsideSSH_Enable" ) )
      {
         set_syscfg_partner_values( value,"WANsideSSH_Enable" );
      }
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialOutputMark") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "DSCP_InitialOutputMark" ) )
      {
         set_syscfg_partner_values( value,"DSCP_InitialOutputMark" );
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.StartupIPMode") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "StartupIPMode" ) )
      {
         set_syscfg_partner_values( value,"StartupIPMode" );
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4PrimaryDhcpServerOptions") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "IPv4PrimaryDhcpServerOptions" ) )
      {
         set_syscfg_partner_values( value,"IPv4PrimaryDhcpServerOptions" );
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4SecondaryDhcpServerOptions") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "IPv4SecondaryDhcpServerOptions" ) )
      {
         set_syscfg_partner_values( value,"IPv4SecondaryDhcpServerOptions" );
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6PrimaryDhcpServerOptions") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "IPv6PrimaryDhcpServerOptions" ) )
      {
         set_syscfg_partner_values( value,"IPv6PrimaryDhcpServerOptions" );
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_WebConfig.URL") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "WEBCONFIG_INIT_URL" ) )
      {
         set_syscfg_partner_values( value,"WEBCONFIG_INIT_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_WebConfig.SupplementaryServiceUrls.Telemetry") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "TELEMETRY_INIT_URL" ) )
      {
         set_syscfg_partner_values( value,"TELEMETRY_INIT_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.BrokerURL") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "MQTT_INIT_URL" ) )
      {
         set_syscfg_partner_values( value,"MQTT_INIT_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.LocationID") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "MQTT_INIT_LOCATIONID" ) )
      {
         set_syscfg_partner_values( value,"MQTT_INIT_LOCATIONID" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.Port") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "MQTT_INIT_PORT" ) )
      {
         set_syscfg_partner_values( value,"MQTT_INIT_PORT" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.Server.URL") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "WEBPA_SERVER_URL" ) )
      {
         set_syscfg_partner_values( value,"WEBPA_SERVER_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "TOKEN_SERVER_URL" ) )
      {
         set_syscfg_partner_values( value,"TOKEN_SERVER_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "DNS_TEXT_URL" ) )
      {
         set_syscfg_partner_values( value,"DNS_TEXT_URL" );
         IsPSMMigrationNeeded = 1;
      }
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6SecondaryDhcpServerOptions") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "IPv6SecondaryDhcpServerOptions" ) )
      {
         set_syscfg_partner_values( value,"IPv6SecondaryDhcpServerOptions" );
      }
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.HomeSec.SSIDprefix") )
   {
      set_syscfg_partner_values( value,"XHS_SSIDprefix" );
      IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Default_VoIP_Configuration_FileName") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "Default_VoIP_Configuration_FileName" ) )
      {
         set_syscfg_partner_values( value,"Default_VoIP_Configuration_FileName" );
      }
   }

#if defined (SPEED_BOOST_SUPPORTED)

   if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.FQDN") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "Advertisement_pvd_fqdn" ) )
      {
         set_syscfg_partner_values( value,"Advertisement_pvd_fqdn" );
      }
   }

   if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.Enable") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "Advertisement_pvd_enable" ) )
      {
         set_syscfg_partner_values( value,"Advertisement_pvd_enable" );
      }
   }
#endif

#if defined (_WNXL11BWL_PRODUCT_REQ_) 
   if ( 0 == strcmp ( key, "Device.Time.NTPServer1") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "ntp_server1" ) )
      {
         set_syscfg_partner_values( value,"ntp_server1" );
      }
   }
#endif

   #ifdef MTA_TR104SUPPORT
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TR104.Enable") )
   {
     if ( 0 == IsValuePresentinSyscfgDB( "TR104enable" ) )
       {
           set_syscfg_partner_values( value,"TR104enable" );
       }
   }
   #else
       APPLY_PRINT("TR104 is not supported so making TR104 value as false\n");
       set_syscfg_partner_values( "false","TR104enable" );
   #endif

   #if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.MAP-T.Enable") )
   {
       if ( 0 == IsValuePresentinSyscfgDB( "MAPT_Enable" ) )
       {
           set_syscfg_partner_values( value,"MAPT_Enable" );
       }
   }
   #endif

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
   if ( 0 == strcmp ( key, "Device.X_RDK_Features.WANConnectivityCheckType") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "ConnectivityCheckType" ) )
      {
         set_syscfg_partner_values( value,"ConnectivityCheckType" );
         IsPSMMigrationNeeded = 1;
      }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.LANIPv6ULA") )
   {
       if ( 0 == IsValuePresentinSyscfgDB( "LANULASupport" ) )
       {
           set_syscfg_partner_values( value,"LANULASupport" );
           IsPSMMigrationNeeded = 1;
       }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.LostandFound.Enable") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "lost_and_found_enable" ) )
      {
         set_syscfg_partner_values( value,"lost_and_found_enable" );
      }
   }  

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.BackupWanDns") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "BackupWanDnsSupport" ) )
      {
         set_syscfg_partner_values( value,"BackupWanDnsSupport" );
         IsPSMMigrationNeeded = 1;
      }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.IPv6EUI64FormatSupport") )
   {
       if ( 0 == IsValuePresentinSyscfgDB( "IPv6EUI64FormatSupport" ) )
       {
           set_syscfg_partner_values( value,"IPv6EUI64FormatSupport" );
           IsPSMMigrationNeeded = 1;
       }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.ConfigureWANIPv6OnLANBridgeSupport") )
   {
      if ( 0 == IsValuePresentinSyscfgDB( "ConfigureWANIPv6OnLANBridgeSupport" ) )
      {
         set_syscfg_partner_values( value,"ConfigureWANIPv6OnLANBridgeSupport" );
         IsPSMMigrationNeeded = 1;
      }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.UseWANMACForManagementServices") )
   {
       if ( 0 == IsValuePresentinSyscfgDB( "UseWANMACForManagementServices" ) )
       {
           set_syscfg_partner_values( value,"UseWANMACForManagementServices" );
           IsPSMMigrationNeeded = 1;
       }
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.InterfaceVLANMarkingSupport") )
   {
       if ( 0 == IsValuePresentinSyscfgDB( "InterfaceVLANMarkingSupport" ) )
       {
           set_syscfg_partner_values( value,"InterfaceVLANMarkingSupport" );
           IsPSMMigrationNeeded = 1;
       }
   }
#endif /* _RDKB_GLOBAL_PRODUCT_REQ_ */   

   //Check whether migration needs to be handled or not
   if( 1 == IsPSMMigrationNeeded )
   {
      APPLY_PRINT("%s - Adding new member in %s file\n", __FUNCTION__, BOOTSTRAP_INFO_FILE);
      APPLY_PRINT("%s - PSM Migration needed for %s param so touching %s file\n", __FUNCTION__, key, PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER );

      //Need to touch /tmp/.apply_partner_defaults_new_psm_member for PSM migration handling
      creat(PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
   }
}

STATIC void updateSysCfgdDB (char *key, char *value)
{
   /* There are parameters which needs to be available in syscfg/PSM DBs
      Check if all of these parameters are SET into DBs
   */
   int IsPSMMigrationNeeded = 0;
   //If WiFiPersonalization.Support is false, set redirection_flag to false to disable Captive Portal
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support") )
   {
      if ( 0 == strcmp(value, "false") )
      {
         APPLY_PRINT("%s: Setting redirection_flag and WiFiPersonalizationSupport to FALSE\n", __FUNCTION__);
         set_syscfg_partner_values( value, "redirection_flag" );
         set_syscfg_partner_values( value, "WiFiPersonalizationSupport" );
      }
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialForwardedMark") )
   {
         set_syscfg_partner_values( value,"DSCP_InitialForwardedMark" );
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.WANsideSSH.Enable") )
   {
         set_syscfg_partner_values( value,"WANsideSSH_Enable" );
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialOutputMark") )
   {
         set_syscfg_partner_values( value,"DSCP_InitialOutputMark" );
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.StartupIPMode") )
   {
         set_syscfg_partner_values( value,"StartupIPMode" );
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4PrimaryDhcpServerOptions") )
   {
         set_syscfg_partner_values( value,"IPv4PrimaryDhcpServerOptions" );
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4SecondaryDhcpServerOptions") )
   {
         set_syscfg_partner_values( value,"IPv4SecondaryDhcpServerOptions" );
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_WebConfig.URL") )
   {
         set_syscfg_partner_values( value,"WEBCONFIG_INIT_URL" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_WebConfig.SupplementaryServiceUrls.Telemetry") )
   {
         set_syscfg_partner_values( value,"TELEMETRY_INIT_URL" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.BrokerURL") )
   {
         set_syscfg_partner_values( value,"MQTT_INIT_URL" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.LocationID") )
   {
         set_syscfg_partner_values( value,"MQTT_INIT_LOCATIONID" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDK_MQTT.Port") )
   {
         set_syscfg_partner_values( value,"MQTT_INIT_PORT" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.Server.URL") )
   {
         set_syscfg_partner_values( value,"WEBPA_SERVER_URL" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL") )
   {
         set_syscfg_partner_values( value,"TOKEN_SERVER_URL" );
         IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL") )
   {
         set_syscfg_partner_values( value,"DNS_TEXT_URL" );
         IsPSMMigrationNeeded = 1;
   }   
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6PrimaryDhcpServerOptions") )
   {
         set_syscfg_partner_values( value,"IPv6PrimaryDhcpServerOptions" );
   }
   if ( 0 == strcmp ( key, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6SecondaryDhcpServerOptions") )
   {
         set_syscfg_partner_values( value,"IPv6SecondaryDhcpServerOptions" );
   }
   if ( 0 == strcmp ( key, "Device.ManagementServer.EnableCWMP") )
   {
         set_syscfg_partner_values( value,"Syndication_EnableCWMP" );
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.HomeSec.SSIDprefix") )
   {
      set_syscfg_partner_values( value,"XHS_SSIDprefix" );
      IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code") )
   {
      set_syscfg_partner_values( value,"WiFiRegionCode" );
      IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.TR69CertLocation") )
   {
      set_syscfg_partner_values( value,"TR69CertLocation" );
      IsPSMMigrationNeeded = 1;
   }
   if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.AllowEthernetWAN") )
   {
         set_syscfg_partner_values( value,"AllowEthernetWAN" );
   }
   if ( 0 == strcmp ( key, "Default_VoIP_Configuration_FileName") )
   {
         set_syscfg_partner_values( value,"Default_VoIP_Configuration_FileName" );
   }

#if defined (SPEED_BOOST_SUPPORTED)

   if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.FQDN") )
   {
         set_syscfg_partner_values( value,"Advertisement_pvd_fqdn" );
   }

   if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.Enable") )
   {
         set_syscfg_partner_values( value,"Advertisement_pvd_enable" );
   }
#endif

#ifdef MTA_TR104SUPPORT
      if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TR104.Enable" ) )
      {
          set_syscfg_partner_values( value, "TR104enable");
      }
#else
      if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TR104.Enable" ) )
      {
          APPLY_PRINT("TR104 is not supported so making TR104 value as false\n");
          set_syscfg_partner_values( "false", "TR104enable");
      }
#endif

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
      if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.MAP-T.Enable" ) )
      {
          set_syscfg_partner_values( value, "MAPT_Enable");
      }
#endif

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
   if ( 0 == strcmp ( key, "Device.X_RDK_Features.WANConnectivityCheckType") )
   {
      set_syscfg_partner_values( value,"ConnectivityCheckType" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.LANIPv6ULA") )
   {
      set_syscfg_partner_values( value,"LANULASupport" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.BackupWanDns") )
   {
      set_syscfg_partner_values( value,"BackupWanDnsSupport" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.IPv6EUI64FormatSupport") )
   {
      set_syscfg_partner_values( value,"IPv6EUI64FormatSupport" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.ConfigureWANIPv6OnLANBridgeSupport") )
   {
      set_syscfg_partner_values( value,"ConfigureWANIPv6OnLANBridgeSupport" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.UseWANMACForManagementServices") )
   {
      set_syscfg_partner_values( value,"UseWANMACForManagementServices" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.InterfaceVLANMarkingSupport") )
   {
      set_syscfg_partner_values( value,"InterfaceVLANMarkingSupport" );
      IsPSMMigrationNeeded = 1;
   }

   if ( 0 == strcmp ( key, "Device.X_RDK_Features.LostandFound.Enable") )
   {
         set_syscfg_partner_values( value,"lost_and_found_enable" );
   }

#endif /* _RDKB_GLOBAL_PRODUCT_REQ_ */   

   //Check whether migration needs to be handled or not
   if( 1 == IsPSMMigrationNeeded )
   {
      APPLY_PRINT("%s - Updating member in %s file\n", __FUNCTION__, BOOTSTRAP_INFO_FILE);
      APPLY_PRINT("%s - PSM Migration needed for %s param so touching %s file\n", __FUNCTION__, key, PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER );

      //Need to touch /tmp/.apply_partner_defaults_new_psm_member for PSM migration handling
      creat(PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
   }
}

// This function can be removed after a few release cycles
static int init_bootstrap_json (char *partner_nvram_obj, char *partner_etc_obj, char *PartnerID)
{
   APPLY_PRINT("%s\n", __FUNCTION__);

   cJSON * root_nvram_json = cJSON_Parse(partner_nvram_obj);
   cJSON * root_etc_json = cJSON_Parse(partner_etc_obj);

   cJSON *root_nvram_bs_json;
   root_nvram_bs_json = cJSON_CreateObject();

   cJSON *prop = cJSON_GetObjectItem(root_etc_json,"properties");
   cJSON_AddItemReferenceToObject(root_nvram_bs_json, "properties", prop);

   cJSON * subitem_etc = cJSON_GetObjectItem(root_etc_json,PartnerID);
   cJSON * subitem_nvram = cJSON_GetObjectItem(root_nvram_json,PartnerID);

   cJSON * overrideObj = NULL;
   char devModel[20] = "\0";

   GetDevicePropertiesEntry (devModel, sizeof(devModel), "MODEL_NUM");
   overrideObj = cJSON_GetObjectItem (cJSON_GetObjectItem(subitem_etc, "override"), devModel);

   if( subitem_etc )
   {
      cJSON *param = subitem_etc->child;
      cJSON *newPartnerObj = cJSON_CreateObject();
      while( param )
      {
         char *key = NULL, *value = NULL, *value_nvram = NULL, *value_etc = NULL;
         cJSON *newParamObj = cJSON_CreateObject();
         key = param->string;
         cJSON * value_obj = cJSON_GetObjectItem(subitem_etc, key);

         if (!strncmp(key, "no_apply_system_default", 23))
         {
            APPLY_PRINT("%s - Skipping no_apply_system_default\n", __FUNCTION__);
            param = param->next;
            continue;
         }

         if (!strncmp(key, "apply_value_to_sysevent", 23))
         {
            APPLY_PRINT("%s - Skipping DB update for apply_value_to_sysevent block\n", __FUNCTION__);
            param = param->next;
            continue;
         }

         if (!strncmp(key, "override", 8))
         {
            param = param->next;
            continue;
         }

         if (overrideObj && cJSON_HasObjectItem(overrideObj, key))
         {
            value_etc = value_obj->valuestring;
            value_obj = cJSON_GetObjectItem(overrideObj, key);
         }

         if (value_obj)
            value = value_obj->valuestring;

         if (value == NULL)
         {
            APPLY_PRINT("etc value is NULL for key = %s, skip it...\n", key);
            param = param->next;
            continue;
         }

         cJSON_AddStringToObject(newParamObj, "DefaultValue", value);
         cJSON_AddStringToObject(newParamObj, "BuildTime", getBuildTime());

         if ( subitem_nvram )
         {
            cJSON * value_nvram_obj = cJSON_GetObjectItem(subitem_nvram, key);
            if (value_nvram_obj)
               value_nvram = value_nvram_obj->valuestring;

            /* etc value and nvram value are different, then nvram value is choosed.
               etc and nvram are same, but override value differs, then override value is choosed.
            */
            if ( value_nvram && strcmp((value_etc)?value_etc:value, value_nvram) != 0 && !value_etc)
            {
               APPLY_PRINT("nvram value = %s\n", value_nvram);
               cJSON_AddStringToObject(newParamObj, "ActiveValue", value_nvram);
               cJSON_AddStringToObject(newParamObj, "UpdateTime", "unknown");
               cJSON_AddStringToObject(newParamObj, "UpdateSource", "webpa"); //Assuming as webpa since we don't know who actually updated
            }
            else
            {
               cJSON_AddStringToObject(newParamObj, "ActiveValue", value);
               cJSON_AddStringToObject(newParamObj, "UpdateTime", "-");
               cJSON_AddStringToObject(newParamObj, "UpdateSource", "-");
            }
         }
         else
         {
            cJSON_AddStringToObject(newParamObj, "ActiveValue", value);
            cJSON_AddStringToObject(newParamObj, "UpdateTime", "-");
            cJSON_AddStringToObject(newParamObj, "UpdateSource", "-");
         }
         cJSON_AddItemToObject(newPartnerObj, key, newParamObj);
         addInSysCfgdDB(key, value);
         param = param->next;
      }
      cJSON_AddItemToObject(root_nvram_bs_json, PartnerID, newPartnerObj);

      char *out = cJSON_Print(root_nvram_bs_json);
      if(out)
      {
         //APPLY_PRINT("out1 = %s\n", out);
         writeToJson(out, BOOTSTRAP_INFO_FILE);
         //Check CLEAR_TRACK_FILE and update in nvram, if needed.
         unsigned int flags = 0;
         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
         if (fp)
         {
             fscanf(fp, "%u", &flags);
             fclose(fp);
         }
         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
         {
             APPLY_PRINT("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
             writeToJson(out, BOOTSTRAP_INFO_FILE_BACKUP);
         }
         free(out);
         out = NULL;
      }
   }

   cJSON_Delete(root_nvram_json);
   cJSON_Delete(root_etc_json);

   return 0;
}

STATIC int compare_partner_json_param (char *partner_nvram_bs_obj, char *partner_etc_obj, char *PartnerID)
{
   APPLY_PRINT("%s\n", __FUNCTION__);

   cJSON * root_nvram_bs_json = cJSON_Parse(partner_nvram_bs_obj);
   cJSON * partnerobj_nvram_bs = NULL;
   if(root_nvram_bs_json)
   {
      partnerobj_nvram_bs = cJSON_GetObjectItem(root_nvram_bs_json,PartnerID);
   }

   /* The below block of code identifies any unknown/wrong objects in /opt/secure/bootstrap.json and removes them */
   if (!root_nvram_bs_json || !partnerobj_nvram_bs)
   {
      APPLY_PRINT("json parse error for bootstrap.json\n");
      APPLY_PRINT("rm %s", BOOTSTRAP_INFO_FILE);
      unlink(BOOTSTRAP_INFO_FILE);
      char *ptr_nvram_json = json_file_parse( PARTNERS_INFO_FILE );
      init_bootstrap_json( ptr_nvram_json, partner_etc_obj, PartnerID );
      free(ptr_nvram_json);
      cJSON_Delete(root_nvram_bs_json);
      return -1;
   }

   cJSON *root_nvram_bs_json_copy=cJSON_Parse(partner_nvram_bs_obj);
   cJSON *current_element = NULL;
   bool jsonChanged = false;
   cJSON_ArrayForEach(current_element, root_nvram_bs_json_copy)
   {
      char *current_key = current_element->string;
      /* if the key is not properties and not partnerID, then remove that object */
      if (strcmp(current_key, "properties") && strcmp(current_key, PartnerID))
      {
         jsonChanged = true;
         cJSON_DeleteItemFromObject(root_nvram_bs_json, current_key);
         printf("Remove unknown object: %s\n", current_key);
      }
   }
   cJSON_Delete(root_nvram_bs_json_copy);
   if (jsonChanged)
   {
      char *out = cJSON_Print(root_nvram_bs_json);
      if(out)
      {
         writeToJson(out, BOOTSTRAP_INFO_FILE);
         //Check CLEAR_TRACK_FILE and update in nvram, if needed.
         unsigned int flags = 0;
         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
         if (fp)
         {
             fscanf(fp, "%u", &flags);
             fclose(fp);
         }
         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
         {
             APPLY_PRINT("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
             writeToJson(out, BOOTSTRAP_INFO_FILE_BACKUP);
         }
         free(out);
         out = NULL;
      }
   }
   /* The above code block can be removed in future when we ae sure there will be no unknown objects in bootstrap.json */

   /* Check if version exists or has changed.
      If the function returns "true" proceed for comparison
      else there is no change. Just return
   */
   bool do_compare = false;
   cJSON * root_etc_json = cJSON_Parse(partner_etc_obj);
   ValidateAndUpdatePartnerVersionParam(root_etc_json, root_nvram_bs_json, &do_compare,PartnerID);
   cJSON_Delete(root_nvram_bs_json);
   cJSON_Delete(root_etc_json);
   if (!do_compare && !jsonChanged)
   {
      return -1;
   }

   printf("versions are different...\n");
   char* ptr_nvram_bs_json = NULL;
   ptr_nvram_bs_json = json_file_parse( BOOTSTRAP_INFO_FILE );
   root_nvram_bs_json=cJSON_Parse(ptr_nvram_bs_json);
   root_etc_json = cJSON_Parse(partner_etc_obj);
   cJSON * subitem_etc = cJSON_GetObjectItem(root_etc_json,PartnerID);
   cJSON * subitem_nvram_bs = cJSON_GetObjectItem(root_nvram_bs_json,PartnerID);
   cJSON * overrideObj = NULL;
   cJSON * notApplyObj = NULL;
   cJSON * ApplySyseventObj = NULL;
   char *key=NULL, *value=NULL;
   char devModel[20] = "\0";
   if(ptr_nvram_bs_json)
   {
      free(ptr_nvram_bs_json);
   }

   GetDevicePropertiesEntry (devModel, sizeof(devModel), "MODEL_NUM");
   overrideObj = cJSON_GetObjectItem (cJSON_GetObjectItem(subitem_etc, "override"), devModel);
   notApplyObj = cJSON_GetObjectItem (cJSON_GetObjectItem(subitem_etc, "no_apply_system_default"), devModel);
   ApplySyseventObj = cJSON_GetObjectItem (subitem_etc, "apply_value_to_sysevent");

   if( subitem_etc )
   {
      cJSON *param = subitem_etc->child;
      while( param )
      {
         key = param->string;
         cJSON * value_obj = cJSON_GetObjectItem(subitem_etc, key);

         if (!strncmp(key, "no_apply_system_default", 23))
         {
            APPLY_PRINT("%s - Skipping no_apply_system_default\n", __FUNCTION__);
            param = param->next;
            continue;
         }

         if (!strncmp(key, "apply_value_to_sysevent", 23))
         {
            APPLY_PRINT("%s - Skipping DB update for apply_value_to_sysevent block\n", __FUNCTION__);
            param = param->next;
            continue;
         }

         if (!strncmp(key, "override", 8))
         {
            param = param->next;
            continue;
         }

         if (overrideObj && cJSON_HasObjectItem(overrideObj, key))
         {
            value_obj = cJSON_GetObjectItem(overrideObj, key);
         }

         if (value_obj)
         {
            value = value_obj->valuestring;
         }
         else
         {
            cJSON_Delete(root_nvram_bs_json);
            cJSON_Delete(root_etc_json);
            return -1;
         }

         APPLY_PRINT("key = %s value = %s\n", key, value);

         cJSON *bs_obj = cJSON_GetObjectItem(subitem_nvram_bs, key);
         if ( !strcmp(key,"Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TR104.Enable"))
         {
           if(1 == IsValuePresentinSyscfgDB( "TR104Enable" ))
           {
              cJSON_DeleteItemFromObject(bs_obj,key);
              bs_obj = NULL;
              APPLY_PRINT("deleted entry in partner_default.json under nvram\n");
              APPLY_PRINT("removing the TR104Enable entry in syscfg\n");
              if ((syscfg_unset(NULL, "TR104Enable") != 0))
              {
                 APPLY_PRINT("syscfg_unset failed\n");
              }
           }
         }

         //If WiFiPersonalization.Support is false, set redirection_flag to false to disable Captive Portal
         if ( 0 == strcmp ( key, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.WiFiPersonalization.Support") )
         {
            if ( 0 == strcmp(value, "false") )
            {
               APPLY_PRINT("%s: Setting redirection_flag and WiFiPersonalizationSupport to FALSE\n", __FUNCTION__);
               set_syscfg_partner_values( value, "redirection_flag" );
               set_syscfg_partner_values( value, "WiFiPersonalizationSupport" );
            }
         }
         #if defined (SPEED_BOOST_SUPPORTED)

         if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.FQDN") )
         {
            if ( 0 == IsValuePresentinSyscfgDB( "Advertisement_pvd_fqdn" ) )
            {
               set_syscfg_partner_values( value,"Advertisement_pvd_fqdn" );
            }
         }
         if ( 0 == strcmp ( key, "Device.RouterAdvertisement.X_RDK_PvD.Enable") )
         {
            if ( 0 == IsValuePresentinSyscfgDB( "Advertisement_pvd_enable" ) )
            {
               set_syscfg_partner_values( value,"Advertisement_pvd_enable" );
            }
         }
         #endif
         
         if (bs_obj == NULL)
         {
            APPLY_PRINT("param %s does not exist in nvram bootstrap json. Adding it...\n", key);
            cJSON *newParamObj = cJSON_CreateObject();
            cJSON_AddStringToObject(newParamObj, "DefaultValue", value);
            cJSON_AddStringToObject(newParamObj, "BuildTime", getBuildTime());
            cJSON_AddStringToObject(newParamObj, "ActiveValue", value);
            cJSON_AddStringToObject(newParamObj, "UpdateTime", "-");
            cJSON_AddStringToObject(newParamObj, "UpdateSource", "-");
            cJSON_AddItemToObject(subitem_nvram_bs, key, newParamObj);

            addInSysCfgdDB(key, value);

            //Also add in the /nvram/partners_defaults.json
            addParamInPartnersFile(key, PartnerID, value);
         }
         else
         {
            cJSON * value_bs_obj = cJSON_GetObjectItem(bs_obj, "ActiveValue");
            char * value_bs = NULL;
            if (value_bs_obj)
            {
               value_bs = value_bs_obj->valuestring;
            }
            else
            {
               cJSON_Delete(root_nvram_bs_json);
               cJSON_Delete(root_etc_json);
               return -1;
            }

            cJSON * source_bs_obj = cJSON_GetObjectItem(bs_obj, "UpdateSource");
            char * source_bs = NULL;
            if (source_bs_obj)
            {
               source_bs = source_bs_obj->valuestring;
            }
            else
            {
               cJSON_Delete(root_nvram_bs_json);
               cJSON_Delete(root_etc_json);
               return -1;
            }
            //printf("value_bs = %s, source_bs = %s\n", value_bs, source_bs);
            if (strcmp(value, value_bs))
            {
               APPLY_PRINT("** Param %s value changed in firmware **\n", key);
               cJSON_ReplaceItemInObject(bs_obj,"DefaultValue", cJSON_CreateString(value));
               cJSON_ReplaceItemInObject(bs_obj,"BuildTime", cJSON_CreateString(getBuildTime()));
               if (!strcmp(source_bs,"-"))
               {
                  APPLY_PRINT(" ** Param was not overridden previously. Update the active value..\n");
                  cJSON_ReplaceItemInObject(bs_obj,"ActiveValue", cJSON_CreateString(value));
                  updateSysCfgdDB(key, value);
               }
            }
         }
         param = param->next;
      }

      /* Check if nvram file has same count as etc file
         if nvram has more entries, we may need to check what was
         removed from etc in current release.
      */
      int subitem_etc_count = cJSON_GetArraySize(subitem_etc) - !(!overrideObj) - !(!notApplyObj) - !(!ApplySyseventObj);
      int subitem_nvram_bs_count = cJSON_GetArraySize(subitem_nvram_bs);
      int iCount = 0;
      if ( subitem_etc_count < subitem_nvram_bs_count)
      {
         for (iCount=0;iCount<subitem_nvram_bs_count;iCount++)
         {
            key=cJSON_GetArrayItem(subitem_nvram_bs,iCount)->string;
            //printf("String key is : %s\n",key);
            cJSON * etc_key=cJSON_GetObjectItem(subitem_etc,key);
            if(etc_key == NULL &&
               !(overrideObj && cJSON_HasObjectItem(overrideObj, key)))
            {
               APPLY_PRINT("Delete parameter %s from /opt/secure/bootstrap.json\n", key);
               //key=cJSON_GetArrayItem(subitem_nvram_bs,iCount);
               cJSON_DeleteItemFromArray(subitem_nvram_bs,iCount);
               //Decrement the count when an element is deleted
               subitem_nvram_bs_count --;
            }
         }//for loop
      }

      char *out = cJSON_Print(root_nvram_bs_json);
      if(out)
      {
         //printf("compare out = %s\n", out);
         writeToJson(out, BOOTSTRAP_INFO_FILE);
         //Check CLEAR_TRACK_FILE and update in nvram, if needed.
         unsigned int flags = 0;
         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
         if (fp)
         {
             fscanf(fp, "%u", &flags);
             fclose(fp);
         }
         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
         {
             APPLY_PRINT("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
             writeToJson(out, BOOTSTRAP_INFO_FILE_BACKUP);
         }
         free(out);
         out = NULL;
      }
   }

   cJSON_Delete(root_nvram_bs_json);
   cJSON_Delete(root_etc_json);

   return 0;
}

static int apply_partnerId_default_values (char *data, char *PartnerID)
{
	cJSON 	*partnerObj 	= NULL;
	cJSON 	*json 			= NULL;
	cJSON	*paramObjVal	= NULL;
	char 	*userName 		= NULL, 
		    *defaultAdminIP = NULL,	 
		    *passWord 		= NULL,	 
		    *subnetRange 	= NULL,
	*minAddress = NULL,
	*maxAddress = NULL,
        *allow_ethernet_wan = NULL,
        *initialForwardedMark = NULL,
        *initialOutputMark = NULL,
        *startupipmode = NULL,
        *pridhcpoption = NULL,
        *secdhcpoption = NULL,
        *voiceDefaultConfigFile = NULL;
    int	    isNeedToApplyPartnersDefault = 1;
    int	    isNeedToApplyPartnersPSMDefault = 0;
    char    ntpServer[64]     = {0};
    char    *jsonNTPServer    = NULL;
    cJSON   *alwaysPartnerObj  = NULL;
    cJSON   *alwaysJson        = NULL;
    cJSON   *alwaysParamObjVal = NULL;
    char    *error_ptr         = NULL;
    int     iterator           = 0;

	/*
	  * Case 1:
	  * Check whether PartnerID is comcast of not. 
	  * if "comcast" then we don't want to apply any defaults 
	  * if not "comcast" then we should apply partners defaults
	  *
	  * Case 2:
	  * Check whether PartnerID is comcast of not. 
	  * if "/nvram/.apply_partner_defaults" file available or not
	  * if available then go ahead and apply default values corresponding partners
	  * if not available then it would have applied before boot-up
	  *
	  * Case 3:
	  * Check whether /tmp/.apply_partner_defaults_psm file has touched or not
	  * if touched then we need to do migration for PSM members like RegionCode and CertLocation only
	  *
	  */
	if ( access( PARTNER_DEFAULT_APPLY_FILE , F_OK ) != 0 )  
	{
		isNeedToApplyPartnersDefault = 0;
	}
	else
  	{
   		APPLY_PRINT("%s - Deletion of %s file handled in PSM init \n", __FUNCTION__, PARTNER_DEFAULT_APPLY_FILE );
		//Delete at PSM init
		//system( "rm -rf /nvram/.apply_partner_defaults" );
  	}

	if ( access( PARTNER_DEFAULT_MIGRATE_PSM , F_OK ) == 0 )  
	{
		isNeedToApplyPartnersPSMDefault = 1;

		APPLY_PRINT("%s - %s file available so need to do partner's PSM member migration \n", __FUNCTION__, PARTNER_DEFAULT_MIGRATE_PSM );
		APPLY_PRINT("%s - Deletion of %s file handled in PSM init \n", __FUNCTION__, PARTNER_DEFAULT_MIGRATE_PSM );
	}

	if( ( 1 == isNeedToApplyPartnersDefault ) || \
		( 1 == isNeedToApplyPartnersPSMDefault ) 
	  )
	{
          	APPLY_PRINT("%s - Applying  %s default configuration\n", __FUNCTION__, PartnerID );
		json = cJSON_Parse( data );
		if( !json ) 
		{
			APPLY_PRINT(  "%s-%d : json file parser error\n", __FUNCTION__,__LINE__ );
			return -1;
		} 
		else
		{
			int isThisComcastPartner = 0;
			//Check whether this is comcast partner or not
			if( 0 == strcmp( "comcast", PartnerID ) )
			{
				isThisComcastPartner = 1;
			}
				
			partnerObj = cJSON_GetObjectItem( json, PartnerID );
			if( partnerObj != NULL) 
			{
				// Don't overwrite this value into syscfg.db for comcast partner
				if( ( 0 == isThisComcastPartner ) && \
					( 1 == isNeedToApplyPartnersDefault )
				  )
				{
					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.LocalUI.DefaultLoginUsername"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						userName = paramObjVal->valuestring; 
					
						if (userName != NULL) 
						{
							set_syscfg_partner_values(userName,"user_name_3");
							userName = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - DefaultLoginUsername Value is NULL\n", __FUNCTION__ );
						}	
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.LocalUI.DefaultLoginPassword"), "ActiveValue");
                                        if ( paramObjVal != NULL )
					{
						passWord = paramObjVal->valuestring;

                                                if (strstr( PartnerID, "sky-" ) != NULL)
                                                {
                                                    APPLY_PRINT("%s - Fetching %s password from serial data \n",__FUNCTION__, PartnerID);
                                                    // For Sky, we need to pull the default login from the /tmp/serial.txt file.
                                                    FILE *fp = NULL;
                                                    char DefaultPassword[25] = {0};
                                                    #if defined (_SCER11BEL_PRODUCT_REQ_)
                                                    fp = popen("grep 'WIFI_PASSWORD' /tmp/serial.txt | cut -d '=' -f 2 | tr -d [:space:]", "r");
                                                    #else
                                                    fp = popen("grep 'WIFIPASSWORD' /tmp/serial.txt | cut -d '=' -f 2 | tr -d [:space:]", "r");
                                                    #endif /** _SCER11BEL_PRODUCT_REQ_ */
                                                    if (fp == NULL)
                                                    {
                                                        APPLY_PRINT("%s - ERROR Grabbing the default password\n",__FUNCTION__);
                                                    } else {
                                                                fgets(DefaultPassword, sizeof(DefaultPassword), fp);
                                                                pclose(fp);
                                                    }
 
                                                    if (DefaultPassword[0] != '\0')
                                                        {
                                                                set_syscfg_partner_values(DefaultPassword,"user_password_3");
                                                        }
                                                        else
                                                        {
                                                                APPLY_PRINT("%s - DefaultLoginPassword Value is NULL\n", __FUNCTION__ );
                                                        }
                                                }
					
						else if (passWord != NULL) 
						{
							set_syscfg_partner_values(passWord,"user_password_3");
							passWord = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - DefaultLoginUsername Value is NULL\n", __FUNCTION__ );
						}	
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.DefaultAdminIP"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						defaultAdminIP = paramObjVal->valuestring; 
					
						if (defaultAdminIP != NULL) 
						{
							set_syscfg_partner_values(defaultAdminIP,"lan_ipaddr");
							defaultAdminIP = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - DefaultAdminIP Value is NULL\n", __FUNCTION__ );
						}	
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.DefaultLocalIPv4SubnetRange"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						subnetRange = paramObjVal->valuestring; 
					
						if (subnetRange != NULL) 
						{
							set_syscfg_partner_values(subnetRange,"lan_netmask");
							subnetRange = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - DefaultLocalIPv4SubnetRange Value is NULL\n", __FUNCTION__ );
						}	
					}
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DHCPv4.Server.Pool.1.MinAddress"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						minAddress = paramObjVal->valuestring;

						if (minAddress != NULL)
						{
							set_syscfg_partner_values(minAddress,"dhcp_start");
							minAddress = NULL;
						}
						else
						{
							APPLY_PRINT("%s - Default DHCP minAddress Value is NULL\n", __FUNCTION__ );
						}
					}
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DHCPv4.Server.Pool.1.MaxAddress"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                maxAddress = paramObjVal->valuestring;

                                                if (maxAddress != NULL)
                                                {
                                                        set_syscfg_partner_values(maxAddress,"dhcp_end");
                                                        maxAddress = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - Default DHCP maxAddress Value is NULL\n", __FUNCTION__ );
                                                }
                                        }
					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.AllowEthernetWAN"), "ActiveValue");
					if ( paramObjVal != NULL )
                    {
                        allow_ethernet_wan = paramObjVal->valuestring;

                        if (allow_ethernet_wan != NULL)
                        {
                            set_syscfg_partner_values(allow_ethernet_wan,"AllowEthernetWAN");
                            allow_ethernet_wan = NULL;
                        }
                        else
                        {
                            APPLY_PRINT("%s - AllowEthernetWAN Value is NULL\n", __FUNCTION__ );
                        }
                    }
 
				}

				if( ( 1 == isNeedToApplyPartnersDefault ) || \
						( 1 == isNeedToApplyPartnersPSMDefault ) 
					  )
				{
					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.WiFi.X_RDKCENTRAL-COM_Syndication.WiFiRegion.Code"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						char *pcWiFiRegionCode = NULL;
						
						pcWiFiRegionCode = paramObjVal->valuestring; 
			
						if (pcWiFiRegionCode != NULL) 
						{
							set_syscfg_partner_values(pcWiFiRegionCode,"WiFiRegionCode");
							pcWiFiRegionCode = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - DefaultWiFiRegionCode Value is NULL\n", __FUNCTION__ );
						}	
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.TR69CertLocation"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
							char *tr69CertLocation = NULL;
					
							tr69CertLocation = paramObjVal->valuestring;
					
							if (tr69CertLocation != NULL)
							{
									set_syscfg_partner_values(tr69CertLocation,"TR69CertLocation");
									tr69CertLocation = NULL;
							}
							else
							{
									APPLY_PRINT("%s - Default TR69CertLocation Value is NULL\n", __FUNCTION__ );
							}
					}
					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_WebConfig.URL"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *webconfigurl = NULL;
					 	webconfigurl = paramObjVal->valuestring;

						if (webconfigurl != NULL)
						{
							 set_syscfg_partner_values(webconfigurl,"WEBCONFIG_INIT_URL");
							webconfigurl = NULL;
						}
						else
						{
							APPLY_PRINT("%s - webconfigurl Value is NULL\n", __FUNCTION__ );
						}
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_WebConfig.SupplementaryServiceUrls.Telemetry"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *telemetryurl = NULL;
						telemetryurl = paramObjVal->valuestring;

						if (telemetryurl != NULL)
						{
							set_syscfg_partner_values(telemetryurl,"TELEMETRY_INIT_URL");
							telemetryurl = NULL;
						}
						else
						{
							APPLY_PRINT("%s - telemetryurl Value is NULL\n", __FUNCTION__ );
						}
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_MQTT.BrokerURL"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *mqtturl = NULL;
						mqtturl = paramObjVal->valuestring;

						if (mqtturl != NULL)
						{
							set_syscfg_partner_values(mqtturl,"MQTT_INIT_URL");
							mqtturl = NULL;
						}
						else
						{
							APPLY_PRINT("%s - mqtturl Value is NULL\n", __FUNCTION__ );
						}
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_MQTT.LocationID"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *mqttlocation = NULL;
						mqttlocation = paramObjVal->valuestring;

						if (mqttlocation != NULL)
						{
							set_syscfg_partner_values(mqttlocation,"MQTT_INIT_LOCATIONID");
							mqttlocation = NULL;
						}
						else
						{
							APPLY_PRINT("%s - mqttlocationid Value is NULL\n", __FUNCTION__ );
						}
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_MQTT.Port"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *mqttport = NULL;
						mqttport = paramObjVal->valuestring;

						if (mqttport != NULL)
						{
							set_syscfg_partner_values(mqttport,"MQTT_INIT_PORT");
							mqttport = NULL;
						}
						else
						{
							APPLY_PRINT("%s - mqttport Value is NULL\n", __FUNCTION__ );
						}
					}
         				#if defined (SPEED_BOOST_SUPPORTED)

               				paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.RouterAdvertisement.X_RDK_PvD.FQDN"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *adv_fdqn = NULL;
						adv_fdqn = paramObjVal->valuestring;

						if (adv_fdqn != NULL)
						{
							set_syscfg_partner_values(adv_fdqn,"Advertisement_pvd_fqdn");
							adv_fdqn = NULL;
						}
						else
						{
							APPLY_PRINT("%s - adv_fdqn Value is NULL\n", __FUNCTION__ );
						}
					}
               
               				paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.RouterAdvertisement.X_RDK_PvD.Enable"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
						char *adv_fdqn_enable = NULL;
						adv_fdqn_enable = paramObjVal->valuestring;

						if (adv_fdqn_enable != NULL)
						{
							set_syscfg_partner_values(adv_fdqn_enable,"Advertisement_pvd_enable");
							adv_fdqn_enable = NULL;
						}
						else
						{
							APPLY_PRINT("%s - adv_fdqn_enable Value is NULL\n", __FUNCTION__ );
						}
					}
         				#endif

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_Webpa.Server.URL"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *webpaurl = NULL;
                                                webpaurl = paramObjVal->valuestring;

                                                if (webpaurl != NULL)
                                                {
                                                         set_syscfg_partner_values(webpaurl,"WEBPA_SERVER_URL");
                                                        webpaurl = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - webpaurl Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tokenurl = NULL;
                                                tokenurl = paramObjVal->valuestring;

                                                if (tokenurl != NULL)
                                                {
                                                         set_syscfg_partner_values(tokenurl,"TOKEN_SERVER_URL");
                                                        tokenurl = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - tokenurl Value is NULL\n", __FUNCTION__ );
                                                }
                                        }	
				
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *dnsurl = NULL;
                                                dnsurl = paramObjVal->valuestring;

                                                if (dnsurl != NULL)
                                                {
                                                         set_syscfg_partner_values(dnsurl,"DNS_TEXT_URL");
                                                        dnsurl = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - dnsurl Value is NULL\n", __FUNCTION__ );
                                                }
                                        }					

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.HomeSec.SSIDprefix"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						char *pcSSIDprefix = NULL;
						
						pcSSIDprefix = paramObjVal->valuestring; 
			
						if (pcSSIDprefix != NULL) 
						{
							set_syscfg_partner_values(pcSSIDprefix,"XHS_SSIDprefix");
							pcSSIDprefix = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - XHS_SSIDprefix Value is NULL\n", __FUNCTION__ );
						}	
					}
                                        paramObjVal = cJSON_GetObjectItem( cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.OAUTH.AuthMode" ), "ActiveValue" );
                                        if( paramObjVal != NULL )
                                        {
                                            char *pcAuthMode = NULL;
                    
                                            pcAuthMode = paramObjVal->valuestring;
                    
                                            if( pcAuthMode != NULL )
                                            {
                                                set_syscfg_partner_values( pcAuthMode, "OAUTHAuthMode" );
												if (strcmp(pcAuthMode, "sso") == 0)
                                                {
                                                    APPLY_PRINT("%s - OAuth AuthMode defaulted to SSO\n", __FUNCTION__);
                                                }
                                                pcAuthMode = NULL;
                                            }
                                            else
                                            {
                                                APPLY_PRINT( "%s - OAUTHAuthMode is NULL\n", __FUNCTION__ );
                                            }
                                        }
                                        paramObjVal = cJSON_GetObjectItem( cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.OAUTH.ServerUrl" ), "ActiveValue" );
                                        if( paramObjVal != NULL )
                                        {
                                            char *pcServerUrl = NULL;
                    
                                            pcServerUrl = paramObjVal->valuestring;
                    
                                            if( pcServerUrl != NULL )
                                            {
                                                set_syscfg_partner_values( pcServerUrl, "OAUTHServerUrl" );
                                                pcServerUrl = NULL;
                                            }
                                            else
                                            {
                                                APPLY_PRINT( "%s - OAUTHServerUrl is NULL\n", __FUNCTION__ );
                                            }
                                        }

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.WANConnectivityCheckType"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *check_connection_type = NULL;
                                                check_connection_type = paramObjVal->valuestring;

                                                if (check_connection_type != NULL)
                                                {
                                                         set_syscfg_partner_values(check_connection_type,"ConnectivityCheckType");
                                                         check_connection_type = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - ConnectivityCheckType Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.LANIPv6ULA"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                             char *lanulaSupport = NULL;
                                             lanulaSupport = paramObjVal->valuestring;

                                             if (lanulaSupport != NULL)
                                             {
                                                      set_syscfg_partner_values(lanulaSupport,"LANULASupport");
                                                      lanulaSupport = NULL;
                                             }
                                             else
                                             {
                                                      APPLY_PRINT("%s - lanulaSupport Value is NULL\n", __FUNCTION__ );
                                             }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.BackupWanDns"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tmpValue = NULL;
                                                tmpValue = paramObjVal->valuestring;

                                                if (tmpValue != NULL)
                                                {
                                                         set_syscfg_partner_values(tmpValue,"BackupWanDnsSupport");
                                                         tmpValue = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - BackupWanDnsSupport Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.IPv6EUI64FormatSupport"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tmpValue = NULL;
                                                tmpValue = paramObjVal->valuestring;

                                                if (tmpValue != NULL)
                                                {
                                                         set_syscfg_partner_values(tmpValue,"IPv6EUI64FormatSupport");
                                                         tmpValue = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - IPv6EUI64FormatSupport Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.ConfigureWANIPv6OnLANBridgeSupport"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tmpValue = NULL;
                                                tmpValue = paramObjVal->valuestring;

                                                if (tmpValue != NULL)
                                                {
                                                         set_syscfg_partner_values(tmpValue,"ConfigureWANIPv6OnLANBridgeSupport");
                                                         tmpValue = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - ConfigureWANIPv6OnLANBridgeSupport Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.UseWANMACForManagementServices"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tmpValue = NULL;
                                                tmpValue = paramObjVal->valuestring;

                                                if (tmpValue != NULL)
                                                {
                                                         set_syscfg_partner_values(tmpValue,"UseWANMACForManagementServices");
                                                         tmpValue = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - UseWANMACForManagementServices Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.InterfaceVLANMarkingSupport"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *tmpValue = NULL;
                                                tmpValue = paramObjVal->valuestring;

                                                if (tmpValue != NULL)
                                                {
                                                         set_syscfg_partner_values(tmpValue,"InterfaceVLANMarkingSupport");
                                                         tmpValue = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - InterfaceVLANMarkingSupport Value is NULL\n", __FUNCTION__ );
                                                }
                                        }

                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDK_Features.LostandFound.Enable"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
                                                char *lnf = NULL;
                                                lnf = paramObjVal->valuestring;

                                                if (lnf != NULL)
                                                {
                                                        set_syscfg_partner_values(lnf,"lost_and_found_enable");
                                                        lnf = NULL;
                                                }
                                                else
                                                {
                                                        APPLY_PRINT("%s - lnf Value is NULL\n", __FUNCTION__ );
                                                }
                                        }
#endif /* _RDKB_GLOBAL_PRODUCT_REQ_ */
                                }

				if( 1 == isNeedToApplyPartnersDefault )
				{
					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialForwardedMark"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
					  initialForwardedMark = paramObjVal->valuestring; 
					  if (initialForwardedMark[0] != '\0')
					  {
						set_syscfg_partner_values(initialForwardedMark,"DSCP_InitialForwardedMark");
						initialForwardedMark = NULL;
					  }
					}
					else
					{
					  APPLY_PRINT("%s - Default Value of InitialForwardedMark is NULL\n", __FUNCTION__ );
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SyndicationFlowControl.InitialOutputMark"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
					  initialOutputMark = paramObjVal->valuestring; 
					  if (initialOutputMark[0] != '\0')
					  {
						set_syscfg_partner_values(initialOutputMark,"DSCP_InitialOutputMark");
						initialOutputMark = NULL;
					  }
					}
					else
					{
					  APPLY_PRINT("%s - Default Value of InitialOutputMark is NULL\n", __FUNCTION__ );
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.StartupIPMode"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
					   startupipmode = paramObjVal->valuestring;
					   if(startupipmode[0]!='\0')
					   {
					            set_syscfg_partner_values(startupipmode,"StartupIPMode");
					            startupipmode = NULL;
					   }
					}
					else
				        {
				            APPLY_PRINT("%s - Default Value of StartupIPMode is NULL\n", __FUNCTION__ );
				        }


               paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Default_VoIP_Configuration_FileName"), "ActiveValue");
               if ( paramObjVal != NULL )
               {
                  voiceDefaultConfigFile = paramObjVal->valuestring;
                  if(voiceDefaultConfigFile[0] !='\0')
                  {
                     set_syscfg_partner_values(voiceDefaultConfigFile,"Default_VoIP_Configuration_FileName");
                     voiceDefaultConfigFile = NULL;
                  }
               }
               else
               {
                  APPLY_PRINT("%s - Default Value of Default_VoIP_Configuration_FileName is NULL\n", __FUNCTION__ );
               }

paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4PrimaryDhcpServerOptions"), "ActiveValue");
if ( paramObjVal != NULL )
{
   pridhcpoption = paramObjVal->valuestring;
   if(pridhcpoption[0]!='\0')
       {
            set_syscfg_partner_values(pridhcpoption,"IPv4PrimaryDhcpServerOptions");
            pridhcpoption = NULL;
       }
}
   else
       {
            APPLY_PRINT("%s - Default Value of primary dhcp server option is NULL\n", __FUNCTION__ );
       }

paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv4SecondaryDhcpServerOptions"), "ActiveValue");
if ( paramObjVal != NULL )
{
   secdhcpoption = paramObjVal->valuestring;
   if(secdhcpoption[0]!='\0')
       {
            set_syscfg_partner_values(secdhcpoption,"IPv4SecondaryDhcpServerOptions");
            secdhcpoption = NULL;
       }
}
   else
       {
            APPLY_PRINT("%s - Default Value of Secondary dhcp server option is NULL\n", __FUNCTION__ );
       }

paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6PrimaryDhcpServerOptions"), "ActiveValue");
if ( paramObjVal != NULL )
{
   pridhcpoption = paramObjVal->valuestring;
   if(pridhcpoption[0]!='\0')
       {
            set_syscfg_partner_values(pridhcpoption,"IPv6PrimaryDhcpServerOptions");
            pridhcpoption = NULL;
       }
}
   else
       {
            APPLY_PRINT("%s - Default Value of primary dhcp server option is NULL\n", __FUNCTION__ );
       }

paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.X_RDKCENTRAL-COM_EthernetWAN_MTA.IPv6SecondaryDhcpServerOptions"), "ActiveValue");
if ( paramObjVal != NULL )
{
   secdhcpoption = paramObjVal->valuestring;
   if(secdhcpoption[0]!='\0')
       {
            set_syscfg_partner_values(secdhcpoption,"IPv6SecondaryDhcpServerOptions");
            secdhcpoption = NULL;
       }
}
   else
       {
            APPLY_PRINT("%s - Default Value of Secondary dhcp server option is NULL\n", __FUNCTION__ );
       }

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.WANsideSSH.Enable"), "ActiveValue");
					if ( paramObjVal != NULL )
					{
							char *WANsideSSHEnable = NULL;

							WANsideSSHEnable = paramObjVal->valuestring;

							if (WANsideSSHEnable != NULL)
							{
									set_syscfg_partner_values(WANsideSSHEnable,"WANsideSSH_Enable");
									WANsideSSHEnable = NULL;
							}
							else
							{
									APPLY_PRINT("%s - Default WANsideSSHEnable Value is NULL\n", __FUNCTION__ );
							}
					}
					else
					{
						APPLY_PRINT("%s - Default WANsideSSHEnable object is NULL\n", __FUNCTION__ );
					}

					paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.ManagementServer.EnableCWMP"), "ActiveValue");
                                        if ( paramObjVal != NULL )
                                        {
						char *pcEnableCWMP = NULL;
						
						pcEnableCWMP = paramObjVal->valuestring; 
			
						if (pcEnableCWMP != NULL) 
						{
							set_syscfg_partner_values( pcEnableCWMP,"Syndication_EnableCWMP" );
							pcEnableCWMP = NULL;
						}	
						else
						{
							APPLY_PRINT("%s - Default Syndication_EnableCWMP Value is NULL\n", __FUNCTION__ );
						}	
					}
#ifdef MTA_TR104SUPPORT
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TR104.Enable"), "ActiveValue");
                                                            if ( paramObjVal != NULL )
{
    char *TR104enable = NULL;
    TR104enable = paramObjVal->valuestring;
    if(1 == IsValuePresentinSyscfgDB( "TR104Enable" ))
    {
        APPLY_PRINT("removing the TR104Enable entry in syscfg\n");
        if ((syscfg_unset(NULL, "TR104Enable") != 0))
        {
            APPLY_PRINT("syscfg_unset failed\n");
        }
    }
    if(TR104enable != NULL)
    {
        set_syscfg_partner_values(TR104enable,"TR104enable");
        TR104enable = NULL;
    }
    else
    {
        APPLY_PRINT("%s - TR104enable Value is NULL\n", __FUNCTION__ );
    }
}
#else
    APPLY_PRINT("TR104 is not supported so making TR104 value as false\n");
    set_syscfg_partner_values("false","TR104enable");
#endif

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
                                        paramObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( partnerObj, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.MAP-T.Enable"), "ActiveValue");
                                                            if ( paramObjVal != NULL )
{
    char *MAPT_Enable = NULL;
    MAPT_Enable = paramObjVal->valuestring;
    if(MAPT_Enable != NULL)
    {
        set_syscfg_partner_values(MAPT_Enable,"MAPT_Enable");
        MAPT_Enable = NULL;
    }
    else
    {
        APPLY_PRINT("%s - MAPT_Enable Value is NULL\n", __FUNCTION__ );
    }
}
#endif

				}
			}
			else
			{
				APPLY_PRINT("%s - partnerObj Object is NULL\n", __FUNCTION__ );
			}
         cJSON_Delete(json);
		}
	}

   int numNtpServers = 1;
   char newNTP[6] = {0};

   if (syscfg_get(NULL, "new_ntp_enabled", newNTP, sizeof(newNTP)) == 0)
   {
      if(0 == strncmp(newNTP, "true", sizeof(newNTP))) {
         APPLY_PRINT("%s New NTP is enabled\n", __FUNCTION__);
         numNtpServers = 5;
      }
   }
   for (int serverNum = 1; serverNum <= numNtpServers; serverNum++)
   {
      char ntpServerName[12] = {0};
      char jsonNTPItem[64] = {0};
      snprintf(ntpServerName, sizeof(ntpServerName), "ntp_server%d", serverNum);
      snprintf(jsonNTPItem, sizeof(jsonNTPItem), "Device.Time.NTPServer%d", serverNum);
      //Objects that always need to be checked
      // RDKB-28869 With Two Box Solutions NTP is now critical. JSON NTP Server 1 value must always be added if nothing exists for XBs to come online
      for (iterator = 0; iterator <= RETRY_COUNT; iterator++)
      {
         if (   ( 0 == syscfg_get(NULL, ntpServerName, ntpServer, sizeof(ntpServer)))
            || (RETRY_COUNT == iterator)
         )
         {
            if(   (0 == strncmp(ntpServer, "no_ntp_address", sizeof(ntpServer)))
               || (0 == strnlen(ntpServer, sizeof(ntpServer)))
            )
            {
               alwaysJson = cJSON_Parse( data );
               if( !alwaysJson ) 
               {
                  error_ptr = (char *)cJSON_GetErrorPtr();
                  if (error_ptr != NULL)
                  {
                     APPLY_PRINT(  "%s-%d : json file parser error at %s\n", __FUNCTION__,__LINE__, error_ptr);
                  }
                  else
                  {
                     APPLY_PRINT(  "%s-%d : json file parser error\n", __FUNCTION__,__LINE__ );
                  }
                  return -1;
               } 
               else
               {
                  APPLY_PRINT("%s - Applying  %s default %s configuration\n", __FUNCTION__, PartnerID, ntpServerName );
                  alwaysPartnerObj = cJSON_GetObjectItem( alwaysJson, PartnerID );

                  if(NULL != alwaysPartnerObj)
                  {
                     /* NTP Server1 is blank set JSON value */
                     alwaysParamObjVal = cJSON_GetObjectItem(cJSON_GetObjectItem( alwaysPartnerObj, jsonNTPItem), "ActiveValue");

                     if ( alwaysParamObjVal != NULL )
                     {
                        jsonNTPServer = alwaysParamObjVal->valuestring;

                        if(jsonNTPServer != NULL)
                        {
                           if(jsonNTPServer[0]) //CID 172848: Wrong sizeof argument
                           {
                              set_syscfg_partner_values(jsonNTPServer, ntpServerName);
                              APPLY_PRINT(" %s %s set to json value:%s\n", __FUNCTION__, ntpServerName, jsonNTPServer);
                           }
                           else
                           {
                              APPLY_PRINT(" %s %s NOT SET as json value from parse was EMPTY String\n", __FUNCTION__, ntpServerName);
                           }
                           jsonNTPServer = NULL;
                        }
                        else
                        {
                           APPLY_PRINT("%s - jsonNTPServer Value is NULL\n", __FUNCTION__ );
                        }
                     } //if ( alwaysParamObjVal != NULL )
                     else
                     {
                        APPLY_PRINT("%s - alwaysParamObjVal Object is NULL\n", __FUNCTION__ );
                     }
                  } //if(NULL == alwaysPartnerObj)
                  else
                  {
                     APPLY_PRINT("%s - alwaysPartnerObj Object is NULL\n", __FUNCTION__ );
                  }
                  cJSON_Delete(alwaysJson);
               } //if( !alwaysJson )
            }
            else
            {
               APPLY_PRINT(" %s %s not default\n", __FUNCTION__, ntpServerName);
            }

            break;
         }
         else
         {
            APPLY_PRINT("%s syscfg_get %d for %s failed!\n", __FUNCTION__, iterator+1, ntpServerName);
            sleep(1);
         }
      } //For Loop
      //Clear ntpServerName and jsonNTPItem
      memset(ntpServerName, 0, sizeof(ntpServerName));
      memset(jsonNTPItem, 0, sizeof(jsonNTPItem));
   }
    return 0;
}
#if defined (_XB6_PRODUCT_REQ_) || defined(_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
static void getPartnerIdWithRetry(char* buf, char* PartnerID)
{
        int i;
        //RDKB-23050: Chnage: Adding few retries to get the partnerId from syscfg.db and if still fails fall back to factory_partnerId
        for(i=0; i < RETRY_COUNT;i++)
        {
                //Get the partner ID
                syscfg_get( NULL, "PartnerID", buf, 64); //CID 59410: Wrong sizeof argument
                if(buf[0] !=  '\0')
                {
                        strncpy( PartnerID, buf , strlen( buf ) ); // CID 339994: String not null terminated (STRING_NULL)
                        PartnerID[strlen(buf)] = '\0';
                        APPLY_PRINT("%s:partnerId read from syscfg=%s\n",__FUNCTION__,PartnerID);
                        return;
                }
                else
                {
                        APPLY_PRINT("%s: will retry to get partnerId after 1 sec retrynum=%d\n",__FUNCTION__,i+1);
                        sleep(1);
                }
        }
        if(i == RETRY_COUNT)
        {
                APPLY_PRINT("%s: Did not get the partner Id with rety=%d also and fall back to factory_partnerId\n",__FUNCTION__,RETRY_COUNT);
                //fall back to factory_partnerId
                get_PartnerID(buf);
                if( buf[ 0 ] != '\0' )
                {
                        strncpy( PartnerID, buf , strlen( buf ) );
                }
                APPLY_PRINT("%s:partnerId read from factory=%s\n",__FUNCTION__,PartnerID);

        }
        return;
}
#endif

/*
 * main()
 */

 #ifdef UNIT_TEST_DOCKER_SUPPORT
 int ApplySystemDefaults_main(int argc, char *argv[])
 #else
 int main(int argc, char *argv[])
 #endif
{
   char *ptr_etc_json = NULL, *ptr_nvram_json = NULL, *ptr_nvram_bs_json = NULL, *db_val = NULL;
   char  PartnerID[ PARTNER_ID_LEN+255 ]  = { 0 };
   int   isNeedToApplyPartnersDefault = 1;
   int   isMigrationReq = 0;
   int retryCount = RETRY_COUNT + 1;

   t2_init("apply_system_defaults");

   syscfg_dirty = 0;

   while ( retryCount && ((global_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, SE_NAME, &global_id)) <= 0 ))
   {
      struct timeval t;

      APPLY_PRINT("[Utopia] global_fd is %d\n",global_fd);

      APPLY_PRINT("[Utopia] %s unable to register with sysevent daemon.\n", argv[0]);
      printf("[Utopia] %s unable to register with sysevent daemon.\n", argv[0]);

      //sleep with subsecond precision
      t.tv_sec = 0;
      t.tv_usec = 100000;
      select(0, NULL, NULL, NULL, &t);

      retryCount--;
   }

   set_defaults();
   
   if (syscfg_dirty) 
   {
      printf("[utopia] [init] committing default syscfg values\n");
      syscfg_commit();
      APPLY_PRINT("Number_Of_Entries_Commited_to_Sysconfig_Database=%d\n",syscfg_dirty);
   }

#if defined(_SYNDICATION_BUILDS_)
   v_secure_system( "/lib/rdk/apply_partner_customization.sh" );
#endif

  if ( access( PARTNER_DEFAULT_APPLY_FILE , F_OK ) != 0 )  
  {
	  isNeedToApplyPartnersDefault = 0;
        APPLY_PRINT("%s - Device in Reboot mode :%s\n", __FUNCTION__, PARTNER_DEFAULT_APPLY_FILE );
	if ( access(PARTNERS_INFO_FILE, F_OK ) != 0 ) // Fix: RDKB-21731, Check if is single build migration
	{
		isMigrationReq = 1;
		APPLY_PRINT("%s - Device in Reboot mode, Syndication Migration Required\n", __FUNCTION__ )
	}
	
  }
  else
  {
	  isMigrationReq = 1;
	  APPLY_PRINT("%s - Device in FR mode :%s\n", __FUNCTION__, PARTNER_DEFAULT_APPLY_FILE );
          t2_event_d("SYS_INFO_FRMode", 1);
  }
  
  if( (1 == isNeedToApplyPartnersDefault)||(isMigrationReq == 1) )  
  {
  	get_PartnerID ( PartnerID );
  }
  else
  {
    char buf[ 64 ] = { 0 };

#if defined(INTEL_PUMA7) && !defined(_XB7_PRODUCT_REQ_)
	//Below validation is needed to make sure the factory_partnerid and syscfg_partnerid are in sync.
	//This is mainly to address those units where customer_index/factory_partnerid was modified in the field through ARRISXB6-8400.
	v_secure_system( "/lib/rdk/validate_syscfg_partnerid.sh" );
#endif
	
	//Get the partner ID
  	syscfg_get( NULL, "PartnerID", buf, sizeof( buf ));

	//Copy is it is not NULL. 
    if( buf[ 0 ] != '\0' )
    {
        strncpy( PartnerID, buf , strlen( buf ) );
    }
	else
	{

#if !defined (_XB6_PRODUCT_REQ_) && !defined(_HUB4_PRODUCT_REQ_) && !defined(_SR300_PRODUCT_REQ_)
		//Partner ID is null so need to set default partner ID as "comcast"
		memset( PartnerID, 0, sizeof( PartnerID ) );
#if defined (_RDK_REF_PLATFORM_)
                sprintf( PartnerID, "%s", "RDKM");
#else
		sprintf( PartnerID, "%s", "comcast" );
#endif
		set_syscfg_partner_values( PartnerID, "PartnerID" );
		APPLY_PRINT("%s - PartnerID is NULL so set default partner :%s\n", __FUNCTION__, PartnerID );		
#else
 		//RDKB-23050: Change: Adding few retries to get the partnerId from syscfg.db and if still fails fall back to factory_partnerId
                getPartnerIdWithRetry(buf,PartnerID);
#endif

	}
  }

  // if the syscfg partnerID is unknown, and we have a valid partnerID file "/nvram/.partner_ID" that was received from XConf, use the valid partnerID.
  if ( 0 == strcasecmp (PartnerID, "Unknown") && access( PARTNERID_FILE , F_OK ) == 0 ) {
    APPLY_PRINT("%s - PartnerID :%s. Calling get_PartnerID() to get a valid PartnerID that was received from XConf \n", __FUNCTION__, PartnerID );
    get_PartnerID ( PartnerID );
  }

#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   CheckAndHandleInvalidPartnerIDRecoveryProcess(PartnerID);
#endif // (_RDKB_GLOBAL_PRODUCT_REQ_)

   APPLY_PRINT("%s - PartnerID :%s\n", __FUNCTION__, PartnerID );

   unsigned int flags = 0;
   FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
   if (fp)
   {
      fscanf(fp, "%u", &flags);
      fclose(fp);
   }

   ptr_etc_json = json_file_parse( PARTNERS_INFO_FILE_ETC );
   if ( ptr_etc_json )
   {
      ptr_nvram_bs_json = json_file_parse( BOOTSTRAP_INFO_FILE );
      if ( ptr_nvram_bs_json == NULL )
      {
         if (access(BOOTSTRAP_INFO_FILE_BACKUP, F_OK) == 0)
         {
            //If backup file exists, compare and copy it to /opt/secure/bootstrap.json
            if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
            {
               char *ptr_nvram_bkup_json = NULL;
               ptr_nvram_bkup_json = json_file_parse(BOOTSTRAP_INFO_FILE_BACKUP);
               if (ptr_nvram_bkup_json)
               {
                  APPLY_PRINT("%s-%d Comparing %s and %s\n", __FUNCTION__, __LINE__, BOOTSTRAP_INFO_FILE_BACKUP, PARTNERS_INFO_FILE_ETC);
                  compare_partner_json_param( ptr_nvram_bkup_json, ptr_etc_json, PartnerID );
                  free(ptr_nvram_bkup_json);
               }
            }
         }
         else
         {
            ptr_nvram_json = json_file_parse( PARTNERS_INFO_FILE ); // nvram/partners_defaults.json can be removed after a few sprints.
            init_bootstrap_json( ptr_nvram_json, ptr_etc_json, PartnerID );
            if ( ptr_nvram_json == NULL )
            {
               APPLY_PRINT("cp %s %s", PARTNERS_INFO_FILE_ETC, PARTNERS_INFO_FILE);
               v_secure_system("cp "PARTNERS_INFO_FILE_ETC " " PARTNERS_INFO_FILE);

               //Need to touch /tmp/.apply_partner_defaults_psm for PSM migration handling
               creat(PARTNER_DEFAULT_MIGRATE_PSM,S_IRUSR |S_IWUSR |S_IRGRP |S_IROTH); // FIX: RDKB-20566 to handle migration
            }
            else
               free( ptr_nvram_json );
         }
      }
      else
      {
         //If backup file exist, then compare with /etc/partners_defaults.json and update /opt/secure/bootstrap.json
         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
         {
            char *ptr_nvram_bkup_json = NULL;
            ptr_nvram_bkup_json = json_file_parse(BOOTSTRAP_INFO_FILE_BACKUP);
            if (ptr_nvram_bkup_json)
            {
               APPLY_PRINT("%s-%d - Comparing %s and %s\n", __FUNCTION__, __LINE__, BOOTSTRAP_INFO_FILE_BACKUP, PARTNERS_INFO_FILE_ETC);
               compare_partner_json_param( ptr_nvram_bkup_json, ptr_etc_json, PartnerID );
               free(ptr_nvram_bkup_json);
            }
         }
         else
         {
            APPLY_PRINT("%s-%d - Comparing %s and %s\n", __FUNCTION__, __LINE__, BOOTSTRAP_INFO_FILE, PARTNERS_INFO_FILE_ETC);
            compare_partner_json_param( ptr_nvram_bs_json, ptr_etc_json, PartnerID );
         }
         free( ptr_nvram_bs_json );
      }
      free( ptr_etc_json );
   }

   //Apply partner default values during FR/partner FR case
   db_val = json_file_parse( BOOTSTRAP_INFO_FILE );

   if( db_val )
   {
		apply_partnerId_default_values( db_val ,PartnerID );

		if( NULL != db_val )
		free( db_val );
   }

   /** Applying Partners Objects into Sysevents */
   if( 0 != ApplyPartnersObjectItemsIntoSysevents( PartnerID ) )
   {
      APPLY_PRINT("%s - Failed to apply_value_to_sysevent block into sysevent for '%s'\n", __FUNCTION__, PartnerID);
   }

   sysevent_close(global_fd, global_id);

   return(0);
}

