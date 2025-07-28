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
 * FileName:   igd_service_wan_ethlink_cfg.c
 * Author:      Jianrong xiao(jianxiao@cisco.com)
 * Date:         April-22-2009
 * Description: This file contains data structure definitions and function for the IGD WANEthernetLinkConfig service
 *****************************************************************************/
/*$Id: igd_service_wan_ethlink_cfg.c,v 1.8 2009/05/26 09:42:29 jianxiao Exp $
 *
 *$Log: igd_service_wan_ethlink_cfg.c,v $
 *Revision 1.8  2009/05/26 09:42:29  jianxiao
 *Modify the  function IGD_pii_get_ethernet_link_status
 *
 *Revision 1.7  2009/05/21 06:31:06  jianxiao
 *Change the interface of PII
 *
 *Revision 1.6  2009/05/21 02:00:01  jianxiao
 *Support two or more  WANEthernetLinkConfig services in difference WANConnectionDevice
 *
 *Revision 1.5  2009/05/15 08:09:01  jianxiao
 *save the status
 *
 *Revision 1.4  2009/05/15 05:42:22  jianxiao
 *Add event handler
 *
 *Revision 1.3  2009/05/14 02:39:59  jianxiao
 *Modify the interface of PAL_xml_node_GetFirstbyName
 *
 *Revision 1.2  2009/05/14 01:46:35  jianxiao
 *Change the included header name, the function name
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
#include "pal_upnp.h"
#include "pal_def.h"
#include "igd_utility.h"
#include "igd_platform_independent_inf.h"

#define WANETHERNETLINKCONFIG_SERVICE_ID "urn:upnp-org:serviceId:WANEthLinkC1"
#define WANETHERNETLINKCONFIG_SERVICE_TYPE "urn:schemas-upnp-org:service:WANEthernetLinkConfig:1"
#define ETHERNETLINKSTATUS_PARA_NUM 1
#define	ETHERNETLINKSTATUS_STRING_LEN	16
#define WANETHLINKCFG_MAX_EVENT_NUM 1

LOCAL INT32 _igd_get_EthernetLinkStatus (INOUT struct action_event *event);

INT32 IGD_pii_get_ethernet_link_status(IN INT32 WanDeviceIndex,
                                                    IN INT32 WanConnectionDeviceIndex,
                                                    OUT CHAR *EthernetLinkStatus);

LOCAL struct upnp_action WANEthernetLinkConfig_actions[] =
{
	{"GetEthernetLinkStatus", _igd_get_EthernetLinkStatus},
	{NULL, NULL}
};
LOCAL const CHAR * WANEthernetLinkConfig_variables_name[] = 
{
    "EthernetLinkStatus",
    NULL
};
/************************************************************
 * Function: _igd_service_WANEthernetLinkConfig_desc_file 
 *
 *  Parameters:	
 *      fp: Input/Output. the description file pointer.
 * 
 *  Description:
 *      This functions generate the description file of the WANEthernetLinkConfig service.
 *
 *  Return Values: INT32
 *      0 if successful ,-1 for error
 ************************************************************/ 
LOCAL INT32 _igd_service_WANEthernetLinkConfig_desc_file(INOUT FILE *fp)
{
	LOCAL INT32 service_index=0;
	if(fp==NULL)
		return -1;
	fprintf(fp, "<service>\n");
      fprintf(fp, "<serviceType>%s</serviceType>\n",WANETHERNETLINKCONFIG_SERVICE_TYPE);
      fprintf(fp, "<serviceId>%s</serviceId>\n",WANETHERNETLINKCONFIG_SERVICE_ID);
	  fprintf(fp, "<SCPDURL>/WANEthernetLinkConfigSCPD.xml</SCPDURL>\n");
      fprintf(fp, "<controlURL>/upnp/control/WANEthernetLinkConfig%d</controlURL>\n",service_index);
      fprintf(fp, "<eventSubURL>/upnp/event/WANEthernetLinkConfig%d</eventSubURL>\n",service_index);
    fprintf(fp, "</service>\n");
	service_index++;
	return 0;
}
/************************************************************
* Function: _igd_service_WANEthernetLinkConfig_destroy
*
*  Parameters: 
*	   pservice:		   IN. the service pointer. 
* 
*  Description:
*	  This function destroy the service WANEthernetLinkConfig.  
*
*  Return Values: INT32
*	   0 if successful else error code.
************************************************************/
LOCAL INT32 _igd_service_WANEthernetLinkConfig_destroy(IN struct upnp_service *pservice)
{
	/* pservice->serviceID is a 'const CHAR *' type and required to remove
	   const before call free() function */
	CHAR * serviceID = (CHAR *)NULL;

	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Destroy WANConnectionDevice WANEthernetLinkConfig\n");
	if(pservice==NULL)
		return -1;
	serviceID = (CHAR *)pservice->serviceID; /*RDKB-7138, CID-33146, use after null check */
	SAFE_FREE(pservice->type);
	SAFE_FREE(serviceID);
	SAFE_FREE(pservice->state_variables);
	SAFE_FREE(pservice->event_variables);
	SAFE_FREE(pservice->private);
	pthread_mutex_destroy(&pservice->service_mutex);
	SAFE_FREE(pservice);
	return 0;
}
/************************************************************
* Function: IGD_service_WANEthernetLinkConfigInit
*
*  Parameters: 
*	   input_index_struct:		   IN. the device index struct. 
*	   fp:   INOUT. the description file pointer. 
* 
*  Description:
*	  This function initialize the service WANEthernetLinkConfig.  
*
*  Return Values: struct upnp_service*
*	   The service pointer if successful else NULL.
************************************************************/
struct upnp_service* IGD_service_WANEthernetLinkConfigInit(IN VOID* input_index_struct, INOUT FILE *fp)
{	
	INT32 i;
	struct upnp_service *WANEthernetLinkConfig_service=NULL;
	
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Initilize WANEthernetLinkConfig of WANDevice:WANConnectionDevice %d:%d\n",((struct device_and_service_index*)input_index_struct)->wan_device_index,((struct device_and_service_index*)input_index_struct)->wan_connection_device_index);
	WANEthernetLinkConfig_service=(struct upnp_service *)calloc(1,sizeof(struct upnp_service));
	if(WANEthernetLinkConfig_service==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory,upnp_service!\n");
		return NULL;
	}

	if(pthread_mutex_init(&WANEthernetLinkConfig_service->service_mutex, NULL ))
	{
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "Init mutex fail!\n");
        _igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
        return NULL;
	}
	
	WANEthernetLinkConfig_service->destroy_function = _igd_service_WANEthernetLinkConfig_destroy;

	WANEthernetLinkConfig_service->type=(CHAR *)calloc(1,strlen(WANETHERNETLINKCONFIG_SERVICE_TYPE)+1);
	if(WANEthernetLinkConfig_service->type==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory,type!\n");
		_igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
		return NULL;
	}
	/* CID 135634 : BUFFER_SIZE_WARNING */
	strncpy(WANEthernetLinkConfig_service->type, WANETHERNETLINKCONFIG_SERVICE_TYPE, strlen(WANETHERNETLINKCONFIG_SERVICE_TYPE)+1);
	WANEthernetLinkConfig_service->type[strlen(WANETHERNETLINKCONFIG_SERVICE_TYPE)] = '\0';
	
	WANEthernetLinkConfig_service->serviceID=(CHAR *)calloc(1,strlen(WANETHERNETLINKCONFIG_SERVICE_ID)+1);
	if(WANEthernetLinkConfig_service->serviceID==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory,serviceID!\n");
		_igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
		return NULL;
	}
	strncpy((CHAR *)WANEthernetLinkConfig_service->serviceID, WANETHERNETLINKCONFIG_SERVICE_ID, strlen(WANETHERNETLINKCONFIG_SERVICE_ID)+1);

	WANEthernetLinkConfig_service->actions = WANEthernetLinkConfig_actions;

    WANEthernetLinkConfig_service->state_variables = (struct upnp_variable *)calloc(sizeof(WANEthernetLinkConfig_variables_name)/sizeof(CHAR *),sizeof(struct upnp_variable));
    if (!WANEthernetLinkConfig_service->state_variables)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "out of memory,state_variables!\n");
        _igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
        return NULL;
    }
    for(i=0; WANEthernetLinkConfig_variables_name[i]!= NULL; i++)
        WANEthernetLinkConfig_service->state_variables[i].name = WANEthernetLinkConfig_variables_name[i];

    WANEthernetLinkConfig_service->event_variables = (struct upnp_variable *)calloc(sizeof(WANEthernetLinkConfig_variables_name)/sizeof(CHAR *), sizeof(struct upnp_variable));
    if (!WANEthernetLinkConfig_service->event_variables)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "out of memory,event_variables!\n");
        _igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
        return NULL;
    }
    for(i=0; WANEthernetLinkConfig_variables_name[i]!= NULL; i++){
        WANEthernetLinkConfig_service->event_variables[i].name = WANEthernetLinkConfig_variables_name[i];
	}
	WANEthernetLinkConfig_service->private=(struct device_and_service_index *)calloc(1,sizeof(struct device_and_service_index));
	if(WANEthernetLinkConfig_service->private==NULL)
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","out of memory!\n");
		_igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
		return NULL;
	}
	memcpy(WANEthernetLinkConfig_service->private, input_index_struct, sizeof(struct device_and_service_index));

	if(_igd_service_WANEthernetLinkConfig_desc_file(fp))
	{
		RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD","create WANEthernetLinkConfig description file fail!\n");
		_igd_service_WANEthernetLinkConfig_destroy(WANEthernetLinkConfig_service);
		return NULL;
	}
	
	return WANEthernetLinkConfig_service;
}
/************************************************************
 * Function: IGD_service_WANEthernetLinkConfigEventHandler
 *
 *  Parameters:	
 *      pdevice: Input. struct of upnp_device.
 *      pservice: Input. struct of upnp_service.
 *
 *  Description:
*	  handle the event
 *      notification if needed.
 *      This function is called periodically.
 *
 *  Return Values: VOID
 ************************************************************/ 
VOID IGD_service_WANEthernetLinkConfigEventHandler(IN struct upnp_device  *pdevice,
                                        IN struct upnp_service  *pservice)
{
		struct device_and_service_index *pIndex = NULL;
		CHAR status[ETHERNETLINKSTATUS_STRING_LEN];
		CHAR *var_name[WANETHLINKCFG_MAX_EVENT_NUM] = {0};
    	CHAR *var_value[WANETHLINKCFG_MAX_EVENT_NUM] = {0};
	
		if (NULL == pdevice) {
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pdevice is NULL");
			return;
		}
		if (NULL == pservice) {
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pservice is NULL");
			return;
		}
		pthread_mutex_lock(&pservice->service_mutex);
	
		pIndex = (struct device_and_service_index *)(pservice->private);
		if (NULL == pIndex) {
			RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "No interface infomation");
			pthread_mutex_unlock(&pservice->service_mutex);
			return;
		}
	    /*CID 189925 : Waiting while holding a lock*/
		pthread_mutex_unlock(&pservice->service_mutex);
		if(IGD_pii_get_ethernet_link_status(pIndex->wan_device_index,pIndex->wan_connection_device_index,status))
		{
			RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","EthernetLinkStatus get fail\n");
			return;
		}
		pthread_mutex_lock(&pservice->service_mutex);
		if(0!= strcmp(status, pservice->state_variables[0].value))
		{
			strncpy(pservice->state_variables[0].value,status, strlen(status)+1);
			strncpy(pservice->event_variables[0].value,status, strlen(status)+1);
			var_name[0] = (CHAR *)pservice->event_variables[0].name;
            var_value[0] = pservice->event_variables[0].value;
			RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD", "Eventing:%s=%s",var_name[0],var_value[0]);
			if(PAL_upnp_notify (PAL_upnp_device_getHandle(),
                        		(const CHAR *)pdevice->udn,
                        		pservice->serviceID,
                        		(const CHAR **)var_name,
                        		(const CHAR **)var_value,
                        		1))
			{
				RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "PAL_upnp_notify() fail");
			}
		}
	
		pthread_mutex_unlock(&pservice->service_mutex);
	
		return;
}

/************************************************************
* Function: _igd_get_EthernetLinkStatus
*
*  Parameters: 
*
*	   event:   INOUT. the action_event struct of the action. 
* 
*  Description:
*	  This function do the action of GetEthernetLinkStatus.  
*
*  Return Values: INT32
*	   0 if successful else error code.
************************************************************/
LOCAL INT32 _igd_get_EthernetLinkStatus (INOUT struct action_event *event)
{
	struct device_and_service_index local_index;
	pal_string_pair params[ETHERNETLINKSTATUS_PARA_NUM];	
	CHAR status[ETHERNETLINKSTATUS_STRING_LEN];

	local_index = *((struct device_and_service_index*)event->service->private);
	RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","GetEthernetLinkStatus of WAN%d\n",local_index.wan_device_index);

	if(IGD_pii_get_ethernet_link_status(local_index.wan_device_index,local_index.wan_connection_device_index,status))
	{
		RDK_LOG(RDK_LOG_INFO, "LOG.RDK.IGD","Layer3Forwarding action:Action fail\n");
		strncpy(event->request->error_str, "Action Fail,get status fail",PAL_UPNP_LINE_SIZE);
		event->request->error_code = 501;
		PAL_upnp_make_action(&event->request->action_result,"GetEthernetLinkStatus",WANETHERNETLINKCONFIG_SERVICE_TYPE,0,NULL,PAL_UPNP_ACTION_RESPONSE);
		return(event->request->error_code);
	}
	params[0].name="NewEthernetLinkStatus";
	params[0].value=status;
	event->request->error_code = PAL_UPNP_E_SUCCESS;
	strncpy(event->service->state_variables[0].value,status, strlen(status)+1);
	PAL_upnp_make_action(&event->request->action_result,"GetEthernetLinkStatus",WANETHERNETLINKCONFIG_SERVICE_TYPE,1,params,PAL_UPNP_ACTION_RESPONSE);
	return(event->request->error_code);
}

