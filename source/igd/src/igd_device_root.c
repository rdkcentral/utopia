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
 * FileName:   igd_device_root.c
 * Author:      Jianrong xiao(jianxiao@cisco.com)
 * Date:         April-22-2009
 * Description: This file contains data structure definitions and function for the IGD device
 *****************************************************************************/
/*$Id: igd_device_root.c,v 1.7 2009/05/26 09:40:08 jianxiao Exp $
 *
 *$Log: igd_device_root.c,v $
 *Revision 1.7  2009/05/26 09:40:08  jianxiao
 *Modify the function IGD_pii_get_uuid
 *
 *Revision 1.6  2009/05/21 06:30:57  jianxiao
 *Change the interface of PII
 *
 *Revision 1.5  2009/05/15 08:00:21  bowan
 *1st Integration
 *
 *Revision 1.3  2009/05/14 02:39:26  jianxiao
 *Modify the interface of the template
 *
 *Revision 1.2  2009/05/14 01:43:31  jianxiao
 *Change the included header name
 *
 *Revision 1.1  2009/05/13 03:13:02  jianxiao
 *create orignal version
 *

 *
 **/
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

#include <utctx/utctx_api.h>
#include <utapi/utapi.h>

#include  "safec_lib_common.h"
#include "pal_upnp_device.h"
#include "pal_kernel.h"
#include "igd_platform_independent_inf.h"
#include "igd_utility.h"

#define DEFAULT_WEB_DIR "/var/IGD"

#define DEFAULT_ADVR_EXPIRE 1800
#define VERSION_MAJOR 		1
#define VERSION_MINOR 		0

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif

/* Logger support. */
#ifdef FEATURE_SUPPORT_RDKLOG
#define DEBUG_INI_NAME "/etc/debug.ini"
#define RDK_LOG_COMP_NAME "LOG.RDK.IGD"
#endif

extern INT32 IGD_pii_get_lan_device_number(VOID);
extern INT32 IGD_service_Layer3ForwardingInit(IN VOID* input_index_struct, INOUT FILE *fp);
extern struct upnp_device *IGD_device_LANDeviceInit(IN VOID * input_index_struct, IN const CHAR *udn, INOUT FILE *fp);
extern struct upnp_device *IGD_device_WANDeviceInit(IN VOID * input_index_struct, IN const CHAR *udn, INOUT FILE *fp);
extern struct upnp_service Layer3Forwarding_service;

static CHAR ip_address[IP_ADDRESS_LEN];
static CHAR DESC_DOC_NAME[30];
static CHAR DESC_DOC_PATH[60];

LOCAL INT32 _igd_root_device_init(VOID);
LOCAL INT32 _igd_root_device_destroy(IN struct upnp_device *device);
LOCAL INT32 _igd_root_device_registerAndgetsignal( VOID );

LOCAL struct upnp_service *IGD_services[] = 
{
         &Layer3Forwarding_service,
         NULL
};

struct upnp_device IGD_device = 
{
         .init_function          = _igd_root_device_init,
         .destroy_function       = _igd_root_device_destroy,
         .services               = IGD_services,
};
/************************************************************
 * Function: _igd_root_device_desc_file 
 *
 *  Parameters:	
 *      uuid: Input. the uuid of the Root device.
 *      fp: Input/Output. the description file pointer.
 * 
 *  Description:
 *      This functions generate the description file of the Root device.
 *
 *  Return Values: INT32
 *      0 if successful ,-1 for error
 ************************************************************/ 
LOCAL INT32 _igd_root_device_desc_file(INOUT FILE *fp,IN const CHAR *uuid)
{
	if(fp==NULL)
		return -1;
	fprintf(fp, "<?xml version=\"1.0\"?>\n");
	fprintf(fp, "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n");
		fprintf(fp, "<specVersion>\n");
			fprintf(fp, "<major>%d</major>\n",VERSION_MAJOR);
			fprintf(fp, "<minor>%d</minor>\n",VERSION_MINOR);
		fprintf(fp, "</specVersion>\n");
		fprintf(fp, "<device>\n");
			fprintf(fp, "<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\n");
			fprintf(fp, "<friendlyName>%s</friendlyName>\n",(char *)ROOT_FRIENDLY_NAME);
			fprintf(fp, "<manufacturer>%s</manufacturer>\n",MANUFACTURER);
			fprintf(fp, "<manufacturerURL>%s</manufacturerURL>\n",MANUFACTURER_URL);
			fprintf(fp, "<modelDescription>%s</modelDescription>\n",(char *)MODULE_DESCRIPTION);
			fprintf(fp, "<modelName>%s</modelName>\n",(char *)MODULE_NAME);
			fprintf(fp, "<modelNumber>%s</modelNumber>\n",(char *)MODULE_NUMBER);
			fprintf(fp, "<modelURL>%s</modelURL>\n",MODULE_URL);
			fprintf(fp, "<serialNumber>%s</serialNumber>\n",IGD_pii_get_serial_number());
			fprintf(fp, "<UDN>%s</UDN>\n", uuid);
			fprintf(fp, "<UPC>%s</UPC>\n",(char *)UPC);
			fprintf(fp, "<serviceList>\n");
	return 0;
}
/************************************************************
 * Function: _igd_root_device_init 
 *
 *  Parameters:	
 * 
 *  Description:
 *      This functions initialize the IGD Root device.
 *
 *  Return Values: INT32
 *      0 if successful ,error code for error
 ************************************************************/ 
LOCAL INT32 _igd_root_device_init(VOID)
{
	INT32 wan_index=1;
	struct upnp_device *wan_device=NULL;
	struct upnp_device *next_device=NULL;
	struct device_and_service_index igd_index;
	CHAR device_udn[UPNP_UUID_LEN_BY_VENDER];
	INT32 wan_device_number = 0, ret = 0;
	FILE *fp=NULL;
        errno = 0;
//    CHAR ip_address[IP_ADDRESS_LEN] = {'\0'};
    //UtopiaContext utctx;

    /* Retrieve gateway IP */
    //Utopia_Init(&utctx);
    //Utopia_RawGet(&utctx,NULL,"lan_ipaddr",ip_address,sizeof(ip_address));
    //Utopia_Free(&utctx,FALSE);

	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Initilize IGD root device\n");
	if(IGD_pii_get_uuid(IGD_device.udn))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Get UUID for the root device fail\n");
		return -1;
	}
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","\nRoot Device UUID:%s\n",IGD_device.udn);

        /* CID 64826: Unchecked return value from library */
	ret = mkdir(DEFAULT_WEB_DIR,0755);
        if(ret !=0 && errno != EEXIST) {
	   RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Failed to Create IGD directory.\n");
	   return -1;
	}

	unlink(DESC_DOC_PATH);
	fp=fopen(DESC_DOC_PATH, "w");
	if(fp==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Create %s fail, %s",DESC_DOC_PATH,strerror(errno));
		return -1;
	}
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","\n\nCreate description file\n");
	if(_igd_root_device_desc_file(fp,IGD_device.udn))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","create IGD description file fail!\n");
		fclose(fp);
		return -1;
	}
		
	if(IGD_service_Layer3ForwardingInit(NULL,fp))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","layer3forwarding init fail!\n");
		fclose(fp);
		return -1;
	}
	
	fprintf(fp, "</serviceList>\n");
	fprintf(fp, "<deviceList>\n");

	wan_device_number = IGD_pii_get_wan_device_number();
	if(wan_device_number <= 0)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","WANDevice error:%d\n",wan_device_number);
		fclose(fp);
		return -1;
	}
	while(wan_index < wan_device_number+1)
	{
		memset(&igd_index,0,sizeof(struct device_and_service_index));
		igd_index.wan_device_index = wan_index;

		if(IGD_pii_get_uuid(device_udn))
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Get UUID for WANDevice fail\n");
			fclose(fp);
			return -1;
		}
		wan_device = IGD_device_WANDeviceInit((VOID*)(&igd_index),device_udn,fp);
		if(NULL == wan_device)
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","IGD WAN device:%d init failed\n",wan_index);
			/*upnp_device_destroy() will destroy the initialized device*/
			fclose(fp);
			return -1;
		}
		else
		{
			next_device = &IGD_device;
			while(next_device->next!=NULL)
				next_device=next_device->next;
			next_device->next= wan_device;
		}
		wan_index++;
	}

	fprintf(fp, "</deviceList>\n");
    /* absolute URL as using an external web server */
    fprintf(fp, "<presentationURL>http://%s/</presentationURL>", ip_address); 
	fprintf(fp, "</device>\n");
    fprintf(fp, "</root>\n");
    fclose(fp);
	return 0;
}
/************************************************************
 * Function: _igd_root_device_destroy 
 *
 *  Parameters:	
 *      pdevice: Input. the device handle.
 * 
 *  Description:
 *      This functions destroy the Root device.
 *
 *  Return Values: INT32
 *      0 if successful ,-1 for error
 ************************************************************/ 
LOCAL INT32 _igd_root_device_destroy(IN struct upnp_device *pdevice)
{
	(void) pdevice;
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Destroy IGD root device\n");
	if(Layer3Forwarding_service.destroy_function)
		Layer3Forwarding_service.destroy_function(&Layer3Forwarding_service);
	return 0;
}

INT32
main( IN INT32 argc,
      IN CHAR **argv)
{
        (void) argc;
        (void) argv;
    	
    	INT32 receivedsignal;
    	INT32 ret;
        char igd_upnp_interface[10];
        char igd_advr_expire[10] = {'\0'};
        int igdAdvrExpire = 0;    /* in seconds */
        UtopiaContext utctx;
	errno_t safec_rc = -1;

        if (argc < 2) {
            printf("IGD needs interface arguement. Failed to start.\n");
            exit(0);
        }
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif

#ifdef FEATURE_SUPPORT_RDKLOG
        rdk_logger_init(DEBUG_INI_NAME);
#endif
        snprintf(DESC_DOC_NAME, sizeof(DESC_DOC_NAME), "IGDdevicedesc_%s.xml", argv[1]);
        snprintf(DESC_DOC_PATH, sizeof(DESC_DOC_PATH), DEFAULT_WEB_DIR"/%s", DESC_DOC_NAME);
        
        safec_rc = strcpy_s(igd_upnp_interface, sizeof(igd_upnp_interface), argv[1]); // CID 189745: Buffer not null terminated (BUFFER_SIZE)
	ERR_CHK(safec_rc);
#ifdef PAL_LOG_ENABLE
        printf("Starting log_router_transmitter!!\n");
        system("./pal_log_router_transmitter &");//to start log transmitter
        sleep(5);
#endif
	/*CID 67479: Unchecked return value */
        if (!Utopia_Init(&utctx)) {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "%s: Error, in getting utctx object", __FUNCTION__);
            return -1;
	}

        //Utopia_RawGet(&utctx,NULL,"lan_ifname",igd_upnp_interface, sizeof(igd_upnp_interface));
        Utopia_RawGet(&utctx,NULL, "upnp_igd_advr_expire",igd_advr_expire,sizeof(igd_advr_expire));
        Utopia_Free(&utctx, FALSE);
        

		if (PAL_get_if_IpAddress(igd_upnp_interface,ip_address) == -1) 
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Invalid internal interface name '%s'\n",igd_upnp_interface);
			exit(0);
		}
		RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","IP address:%s\n",ip_address);

#ifdef CISCO_CONFIG_TRUE_STATIC_IP
        /*
         * When true static ip is enabled, there could be multiple ip addresses on brlan0. 
         * Chances could be ip_address will be static ip configured                      .
         * Double check if ip_address is the actuall lan gw ip address                                                                             .
         *                                                                                                                                         .
         * ## FIXME: how to check if static ip is run-time enabled cross processes                                                                                                                                       .
         */
        {
            char lan_ifname[10] = {'\0'};
            char lan_ipaddr[IP_ADDRESS_LEN] = {'\0'};

            Utopia_Init(&utctx);
            Utopia_Get(&utctx, UtopiaValue_LAN_IfName, lan_ifname, sizeof(lan_ifname));
            Utopia_Get(&utctx, UtopiaValue_LAN_IPAddr, lan_ipaddr, sizeof(lan_ipaddr));
            Utopia_Free(&utctx, FALSE);

            if((strcmp(igd_upnp_interface, lan_ifname) == 0) &&
               (strcmp(ip_address, lan_ipaddr) != 0)) {
                memset(ip_address, 0, sizeof(ip_address));
                strncpy(ip_address, lan_ipaddr, sizeof(ip_address));
            }
        }
#endif

        if(strlen(igd_advr_expire)){
            igdAdvrExpire = atoi(igd_advr_expire);
        }else{
            igdAdvrExpire = DEFAULT_ADVR_EXPIRE;
        }

        ret=PAL_upnp_device_init(&IGD_device,igd_upnp_interface,0,igdAdvrExpire,DESC_DOC_NAME,DEFAULT_WEB_DIR);
		if(ret)
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","initialize device fail '%d'\n", ret);
			PAL_upnp_device_destroy(&IGD_device);
			exit(0);
		}

		do
                {
			  receivedsignal = _igd_root_device_registerAndgetsignal( );
                          if ( receivedsignal == -1)
                          {
                            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "Failed to register and get signal. Trying again...\n");
                            
                          }
                            
			  RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Received signal is %d\n", receivedsignal);

			  /*
			     * SIGTERM - 15
			     * SIGINT - 2
			     */
			     
		} while ( ( 15 != receivedsignal )  && ( 2 != receivedsignal ) );

    	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Shutting down on signal %d...\n", receivedsignal );
    	PAL_upnp_device_destroy(&IGD_device);
    	exit( 0 );
}

/************************************************************
 * Function: _igd_root_device_registerAndgetsignal 
 *
 *  Parameters:	
 *      none
 *      fp: Input/Output. the description file pointer.
 * 
 *  Description:
 *      This functions generate the description file of the Root device.
 *
 *  Return Values: INT32
 *      return received signal value
 ************************************************************/ 
LOCAL INT32 _igd_root_device_registerAndgetsignal( VOID )
{
	sigset_t signaltocatch;
	INT32 	 receivedsignal;

	/* Nullify all signal before registration */
	sigemptyset(&signaltocatch);

	/*
	   * SIGTERM  - 15
	   * SIGUSR1  - 10
	   * SIGINT    - 2
	   */
	sigaddset( &signaltocatch, 15 ); 
	sigaddset( &signaltocatch, 10 ); 
	sigaddset( &signaltocatch, 2 );	 
	
	if(pthread_sigmask( SIG_SETMASK, &signaltocatch, NULL )!=0)
	{    
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "Failed to set signal mask");
		return -1;
	}

	if(sigwait( &signaltocatch, &receivedsignal )!=0)
	{   
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "Failed to wait for signal");
		return -1;
	}

	return receivedsignal;
}
