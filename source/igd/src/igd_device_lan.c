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
 * FileName:   igd_device_lan.c
 * Cloned by: Sridhar Ramaswamy
 * Author:      Jianrong xiao(jianxiao@cisco.com)
 * Date:         April-22-2009
 * Description: This file contains data structure definitions and function for the IGD LANDevice
 *****************************************************************************/
/*$Id: igd_device_lan.c,v 1.5 2009/05/26 09:40:55 jianxiao Exp $
 *
 *$Log: igd_device_lan.c,v $
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

extern struct upnp_service* IGD_service_LANHostConfigManagementInit(IN VOID* input_index_struct, INOUT FILE *fp);

/************************************************************
 * Function: _igd_lan_device_desc_file 
 *
 *  Parameters:	
 *      uuid: Input. the uuid of the LANDevice.
 *      fp: Input/Output. the description file pointer.
 * 
 *  Description:
 *      This functions generate the description file of the LANDevice.
 *
 *  Return Values: INT32
 *      0 if successful ,-1 for error
 ************************************************************/ 
LOCAL INT32 _igd_lan_device_desc_file(INOUT FILE *fp,IN const CHAR *uuid)
{
	if(fp==NULL)
		return -1;
	fprintf(fp, "<device>\n");
		fprintf(fp, "<deviceType>urn:schemas-upnp-org:device:LANDevice:1</deviceType>\n");
		fprintf(fp, "<friendlyName>%s</friendlyName>\n",LANDEVICE_FRIENDLY_NAME);
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
* Function: _igd_lan_device_destroy
*
*  Parameters: 
*	   pdevice:		   IN. Upnp device pointer. 
* 
*  Description:
*	  This function destroy the LANDevice.  
*
*  Return Values: INT32
*	   0 if successful else error code.
************************************************************/
LOCAL INT32 _igd_lan_device_destroy (IN struct upnp_device *pdevice)
{
	INT32 i=0;

	if(NULL == pdevice)
		return -1;
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Destroy LANDevice\n");
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
* Function: IGD_device_LANDeviceInit
*
*  Parameters: 
*	   input_index_struct:		   IN. the device index struct. 
*	   udn:   IN. the uuid of the LANDevice. 
*	   fp:   INOUT. the description file pointer. 
* 
*  Description:
*	  This function initialize the LANDevice.  
*
*  Return Values: struct upnp_service*
*	   The device pointer if successful else NULL.
************************************************************/
struct upnp_device * IGD_device_LANDeviceInit(IN VOID * input_index_struct, IN const CHAR *udn, INOUT FILE *fp)
{
	struct upnp_device *landevice=NULL;
	struct upnp_service *LANHostConfigManagement_service=NULL;
	
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Initilize LANDevice %d\n",((struct device_and_service_index*)input_index_struct)->lan_device_index);

	landevice=(struct upnp_device *)calloc(1,sizeof(struct upnp_device));
	if(landevice==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory,landevice!\n");
		return NULL;
	}
	
	landevice->destroy_function=_igd_lan_device_destroy;
	strncpy(landevice->udn, udn, UPNP_UUID_LEN_BY_VENDER);

	if(_igd_lan_device_desc_file(fp,udn))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","create LANDevice description file fail!\n");
		SAFE_FREE(landevice);
		return NULL;
	}

	landevice->services = (struct upnp_service **)calloc(2,sizeof(struct upnp_service *));
	if(landevice->services==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory!\n");
		SAFE_FREE(landevice);
		return NULL;
	}
		
	if((LANHostConfigManagement_service=IGD_service_LANHostConfigManagementInit(input_index_struct,fp))==NULL)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","LANHostConfigManagement init fail! \n");
		SAFE_FREE(landevice->services);
		SAFE_FREE(landevice);
        return NULL;
    }
	landevice->services[0]=LANHostConfigManagement_service;
	landevice->services[1]=NULL;

	
	/*no event handler registered as this device/services doesn't 
         any eventable variables*/

	fprintf(fp, "</serviceList>\n");
	fprintf(fp, "</device>\n");
	
	return landevice;
}


