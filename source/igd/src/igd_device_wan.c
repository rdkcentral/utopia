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

/**********************************************************************
 * FileName:   igd_device_wan.c
 * Author:      Jianrong xiao(jianxiao@cisco.com)
 * Date:         April-22-2009
 * Description: This file contains data structure definitions and function for the IGD WANDevice
 *****************************************************************************/
/*$Id: igd_device_wan.c,v 1.5 2009/05/26 09:40:55 jianxiao Exp $
 *
 *$Log: igd_device_wan.c,v $
 *Revision 1.5  2009/05/26 09:40:55  jianxiao
 *Modify the function IGD_pii_get_uuid
 *
 *Revision 1.4  2009/05/21 06:31:06  jianxiao
 *Change the interface of PII
 *
 *Revision 1.3  2009/05/15 05:41:50  jianxiao
 *Add event handler
 *
 *Revision 1.2  2009/05/14 02:39:43  jianxiao
 *Modify the interface of the template
 *
 *Revision 1.1  2009/05/13 03:13:02  jianxiao
 *create orignal version
 *

 *
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pal_upnp_device.h"
#include "pal_def.h"
#include "pal_kernel.h"
#include "igd_platform_independent_inf.h"
#include "igd_utility.h"

extern struct upnp_service* IGD_service_WANCommonInterfaceConfigInit(IN VOID* input_index_struct, INOUT FILE *fp);
extern VOID IGD_service_WANCommonInterfaceConfigEventHandler(IN struct upnp_device  *pdevice,IN struct upnp_service  *pservice);
extern struct upnp_device *IGD_wan_connection_device_init (IN VOID* input_index_struct,IN const CHAR *udn,INOUT FILE *wan_desc_file);
extern VOID IGD_WANCommonInterfaceConfig_eventvariables_init(struct upnp_service *ps);

/************************************************************
 * Function: _igd_wan_device_desc_file 
 *
 *  Parameters:	
 *      uuid: Input. the uuid of the WANDevice.
 *      fp: Input/Output. the description file pointer.
 * 
 *  Description:
 *      This functions generate the description file of the WANDevice.
 *
 *  Return Values: INT32
 *      0 if successful ,-1 for error
 ************************************************************/ 
LOCAL INT32 _igd_wan_device_desc_file(INOUT FILE *fp,IN const CHAR *uuid)
{
	if(fp==NULL)
		return -1;
	fprintf(fp, "<device>\n");
		fprintf(fp, "<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\n");
		fprintf(fp, "<friendlyName>%s</friendlyName>\n",WANDEVICE_FRIENDLY_NAME);
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
* Function: _igd_wan_device_destroy
*
*  Parameters: 
*	   pdevice:		   IN. Upnp device pointer. 
* 
*  Description:
*	  This function destroy the WANDevice.  
*
*  Return Values: INT32
*	   0 if successful else error code.
************************************************************/
LOCAL INT32 _igd_wan_device_destroy (IN struct upnp_device *pdevice)
{
	INT32 i=0;

	if(NULL == pdevice)
		return -1;
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Destroy WANDevice\n");
	if(pdevice->services)
	{
		while(pdevice->services[i])
		{
			if(pdevice->services[i]->destroy_function)
				pdevice->services[i]->destroy_function(pdevice->services[i]);
			i++;
		}
	}
	SAFE_FREE(pdevice->services);
	SAFE_FREE(pdevice);
	return 0;
}

/************************************************************
* Function: IGD_device_WANDeviceInit
*
*  Parameters: 
*	   input_index_struct:		   IN. the device index struct. 
*	   udn:   IN. the uuid of the WANDevice. 
*	   fp:   INOUT. the description file pointer. 
* 
*  Description:
*	  This function initialize the WANDevice.  
*
*  Return Values: struct upnp_service*
*	   The device pointer if successful else NULL.
************************************************************/
struct upnp_device * IGD_device_WANDeviceInit(IN VOID * input_index_struct, IN const CHAR *udn, INOUT FILE *fp)
{
	struct upnp_device *wan_connection_device=NULL;
	struct upnp_device *wandevice=NULL;
	struct upnp_device *next_device=NULL;
	struct upnp_service *WANCommonInterfaceConfig_service=NULL;
	struct device_and_service_index wan_index;
	INT32 wan_connection_index=1;
	INT32 wan_connection_device_number = 0;
	CHAR device_udn[UPNP_UUID_LEN_BY_VENDER];
	
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Initilize WANDevice %d\n",((struct device_and_service_index*)input_index_struct)->wan_device_index);
	wandevice=(struct upnp_device *)calloc(1,sizeof(struct upnp_device));
	if(wandevice==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory,wandevice!\n");
		return NULL;
	}
	
	wandevice->destroy_function=_igd_wan_device_destroy;
	strncpy(wandevice->udn, udn, UPNP_UUID_LEN_BY_VENDER);

	if(_igd_wan_device_desc_file(fp,udn))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","create WANDevice description file fail!\n");
		SAFE_FREE(wandevice);
		return NULL;
	}

	wandevice->services = (struct upnp_service **)calloc(2,sizeof(struct upnp_service *));
	if(wandevice->services==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory!\n");
		SAFE_FREE(wandevice);
		return NULL;
	}
		
	if((WANCommonInterfaceConfig_service=IGD_service_WANCommonInterfaceConfigInit(input_index_struct,fp))==NULL)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","WANCommonInterfaceConfig init fail!\n");
		SAFE_FREE(wandevice->services);
		SAFE_FREE(wandevice);
        return NULL;
    }
	wandevice->services[0]=WANCommonInterfaceConfig_service;
	wandevice->services[1]=NULL;

    /* init WANCommonInterfaceConfig_service state_variables */
    IGD_WANCommonInterfaceConfig_eventvariables_init(WANCommonInterfaceConfig_service);
    	
	/*register the event handler*/
	IGD_timer_register(wandevice,WANCommonInterfaceConfig_service, IGD_service_WANCommonInterfaceConfigEventHandler, 2, timer_function_mode_cycle);

	fprintf(fp, "</serviceList>\n");
	fprintf(fp, "<deviceList>\n");
	wan_connection_device_number = IGD_pii_get_wan_connection_device_number(((struct device_and_service_index*)input_index_struct)->wan_device_index);
	if(wan_connection_device_number <= 0)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","wan_connection_device_number error:%d\n",wan_connection_device_number);
		SAFE_FREE(wandevice->services);
		SAFE_FREE(wandevice);
        return NULL;
	}
	
	while(wan_connection_index < wan_connection_device_number + 1)
	{
		memset(&wan_index,0,sizeof(struct device_and_service_index));
		wan_index.wan_device_index = ((struct device_and_service_index*)input_index_struct)->wan_device_index;
		wan_index.wan_connection_device_index= wan_connection_index;

		if(IGD_pii_get_uuid(device_udn))
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","Get UUID fail\n");
			goto Destroy_device_recursively;
		}
		wan_connection_device = IGD_wan_connection_device_init((VOID*)(&wan_index),device_udn,fp);
		if(NULL == wan_connection_device)
		{
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","IGD WAN connection device:%d init failed\n", wan_connection_index);
			/*because return NULL so upnp_device_destroy() will not destroy the initialized WANConnectionDevice*/
	Destroy_device_recursively:
			while(wandevice!=NULL)
			{
				next_device=wandevice->next;
				if(wandevice->destroy_function)
					wandevice->destroy_function(wandevice);
				SAFE_FREE(wandevice);
				wandevice = next_device;
			}
			return NULL;
		}
		else
		{
			next_device = wandevice;
			while(next_device->next!=NULL)
				next_device=next_device->next;
			next_device->next= wan_connection_device;
			wan_connection_device->next = NULL;
		}
		wan_connection_index++;
	}
	
	fprintf(fp, "</deviceList>\n");
	fprintf(fp, "</device>\n");
	
	return wandevice;
}


