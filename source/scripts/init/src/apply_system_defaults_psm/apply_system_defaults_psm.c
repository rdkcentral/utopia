/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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
 * Copyright 2023 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
**********************************************************************/

/*===================================================================

  This programs handles PSM initialization

===================================================================*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <syscfg/syscfg.h>
#include "sysevent/sysevent.h"
#include "time.h"
#include "secure_wrapper.h"
#include <sys/stat.h>
#include "safec_lib_common.h"
#include <unistd.h>
#include <stdbool.h>
#include <cjson/cJSON.h>
#include "apply_system_defaults_helper.h"
#include <telemetry_busmessage_sender.h>
#define PARTNERS_INFO_FILE                                "/nvram/partners_defaults.json"
#define PARTNERS_INFO_FILE_ETC                            "/etc/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE                               "/opt/secure/bootstrap.json"
//#define VERSION_TXT_FILE                                "/version.txt"
#define PARTNERID_FILE                                    "/nvram/.partner_ID"
#define PARTNER_DEFAULT_APPLY_FILE                        "/nvram/.apply_partner_defaults"
#define PARTNER_DEFAULT_MIGRATE_PSM                       "/tmp/.apply_partner_defaults_psm"
//#define PARTNER_DEFAULT_MIGRATE_FOR_NEW_PSM_MEMBER      "/tmp/.apply_partner_defaults_new_psm_member"
#define PARTNER_ID_LEN 64

extern char default_file[1024];
int syscfg_supported = 0;
int psm_supported = 1;

// The sysevent server is local
#define SE_WELL_KNOWN_IP    "127.0.0.1"
extern short server_port;
extern char  server_ip[19];
extern int   syscfg_dirty;
#define DEFAULT_FILE "/etc/utopia/system_defaults"
#define SE_NAME "system_default_set"

int global_fd = 0;

// we can use one global id for sysevent because we are single threaded
token_t global_id;

#if defined (_CBR_PRODUCT_REQ_) || defined (_XB6_PRODUCT_REQ_)
        #define LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
        #define LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define RETRY_COUNT 60
#define APPLY_PRINT(fmt ...)   {\
   FILE *logfp = fopen ( LOG_FILE , "a+");\
   if (logfp)\
   {\
        fprintf(logfp,fmt);\
        fclose(logfp);\
   }\
}\

/*
 * main()
 */
int main( int argc, char **argv )
{
    char *ptr_etc_json = NULL, *ptr_nvram_json = NULL, *ptr_nvram_bs_json = NULL, *db_val = NULL;
    char  PartnerID[ PARTNER_ID_LEN+255 ]  = { 0 };
    int   isNeedToApplyPartnersDefault = 1;
    int   isMigrationReq = 0;
    int retryCount = RETRY_COUNT;

    t2_init("apply_system_defaults");
    //Fill basic contents
    server_port = SE_SERVER_WELL_KNOWN_PORT;

    snprintf( server_ip, sizeof( server_ip ), "%s", SE_WELL_KNOWN_IP );
    snprintf( default_file, sizeof( default_file ), "%s", DEFAULT_FILE );

    syscfg_dirty = 0;

    parse_command_line(argc, argv);
    while ( retryCount && ((global_fd = sysevent_open(server_ip, server_port, SE_VERSION, SE_NAME, &global_id)) <= 0 ))
    {
        struct timeval t;

        APPLY_PRINT("[Utopia] global_fd is %d\n",global_fd);

        APPLY_PRINT("[Utopia] %s unable to register with sysevent daemon.\n", argv[0]);
        printf("[Utopia] %s unable to register with sysevent daemon.\n %s", argv[0]);

        //sleep with subsecond precision
        t.tv_sec = 0;
        t.tv_usec = 100000;
        select(0, NULL, NULL, NULL, &t);

        retryCount--;
    }

    if ( global_fd <= 0 )
    {
        APPLY_PRINT("[Utopia] Retrying sysevent open\n");

        global_fd=0;
        global_fd = sysevent_open(server_ip, server_port, SE_VERSION, SE_NAME, &global_id);
        APPLY_PRINT("[Utopia] Global fd after retry is %d\n",global_fd);

        if ( global_fd <= 0)
            APPLY_PRINT("[Utopia] Retrying sysevent open also failed %d\n",global_fd);

    }

    dbusInit();

    if (syscfg_dirty)
    {
        printf("[utopia] [init] committing default syscfg values\n");
        syscfg_commit();
        APPLY_PRINT("Number_Of_Entries_Commited_to_Sysconfig_Database=%d\n",syscfg_dirty);
    }

    sysevent_close(global_fd, global_id);

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
            //PartnerID is NULL so setting partnerID again as a recovery mechanism.
            getPartnerIdWithRetry(buf,PartnerID);
            APPLY_PRINT("%s - PartnerID is NULL so setting partnerID as :%s\n", __FUNCTION__, PartnerID );
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

    ptr_etc_json = json_file_parse( PARTNERS_INFO_FILE_ETC );
    if ( ptr_etc_json )
    {
        ptr_nvram_bs_json = json_file_parse( BOOTSTRAP_INFO_FILE );
        if ( ptr_nvram_bs_json == NULL )
        {
            ptr_nvram_json = json_file_parse( PARTNERS_INFO_FILE ); // nvram/partners_defaults.json can be removed after a few sprints.
            init_bootstrap_json( ptr_nvram_json, ptr_etc_json, PartnerID );
            if ( ptr_nvram_json == NULL )
            {
                APPLY_PRINT("cp %s %s", PARTNERS_INFO_FILE_ETC, PARTNERS_INFO_FILE);
                v_secure_system("cp "PARTNERS_INFO_FILE_ETC " " PARTNERS_INFO_FILE);

                //Need to touch /tmp/.apply_partner_defaults_psm for PSM migration handling
                creat(PARTNER_DEFAULT_MIGRATE_PSM,S_IRUSR |S_IWUSR |S_IRGRP |S_IROTH); // FIX: RDKB-20566 to handle migration
                creat(APPLY_DEFAULTS_FACTORY_RESET, S_IRUSR |S_IWUSR |S_IRGRP |S_IROTH);
	    }
            else
                free( ptr_nvram_json );
        }
        else
        {
            compare_partner_json_param( ptr_nvram_bs_json, ptr_etc_json, PartnerID );
            free( ptr_nvram_bs_json );
        }
        free( ptr_etc_json );
    }

    //Apply partner default values during FR/partner FR case
    db_val = json_file_parse( BOOTSTRAP_INFO_FILE );

    if( db_val )
    {
        apply_partnerId_default_values( db_val, PartnerID );

        if( NULL != db_val )
            free( db_val );
    }

    return(0);
}

