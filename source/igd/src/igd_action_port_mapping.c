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
 *    FileName:    igd_action_port_mapping.c
 *      Author:    Lipin Zhou(zlipin@cisco.com)
 *        Date:    2009-04-30
 * Description:    IGD port map implementation of UPnP IGD project
 *****************************************************************************/
/*$Id: igd_action_port_mapping.c,v 1.5 2009/05/27 02:14:22 zlipin Exp $
 *
 *$Log: igd_action_port_mapping.c,v $
 *Revision 1.5  2009/05/27 02:14:22  zlipin
 *Fix Warnings.
 *
 *Revision 1.4  2009/05/26 09:54:57  zlipin
 *modifed the PII interface
 *
 *Revision 1.3  2009/05/22 05:38:33  zlipin
 *Adjust the PII "PortMapping" module interface
 *
 *Revision 1.2  2009/05/15 08:00:21  bowan
 *1st Integration
 *
 *Revision 1.1  2009/05/14 01:58:14  zlipin
 *First version
 *
 *
 **/

#include <string.h>
 
#include "igd_utility.h"
#include "igd_service_wan_connect.h"
#include "igd_action_port_mapping.h"
#include "igd_platform_independent_inf.h"
#include "syscfg/syscfg.h"

#define ARRAY_INDEX_INVALID                     713
#define NO_SUCH_ENTRY_IN_ARRAY              714

#define WildCard_NotPermitted_InSrcIP            715
#define WildCard_NotPermitted_InExtPort         716
#define Conflict_In_MappingEntry                       718
#define Same_PortValues_Required                    724
#define Only_Permanent_Leases_Supported      725
#define RemoteHost_OnlySupports_Wildcard      726
#define ExternalPort_OnlySupports_Wildcard     727

#define ARRAY_INDEX_INVALID_STR                 "SpecifiedArrayIndexInvalid"
#define NO_SUCH_ENTRY_IN_ARRAY_STR          "NoSuchEntryInArray"

#define WildCard_NotPermitted_InSrcIP_STR        "The source IP address cannot be wild-carded"
#define WildCard_NotPermitted_InExtPort_STR     "The external port cannot be wild-carded"
#define Conflict_In_MappingEntry_STR                   "The port mapping entry specified conflicts with a mapping assigned previously to another client"
#define Same_PortValues_Required_STR                "Internal and External port values must be the same"
#define Only_Permanent_Leases_Supported_STR  "The NAT implementation only supports permanent lease times on port mappings"
#define RemoteHost_OnlySupports_Wildcard_STR  "RemoteHost must be a wildcard and cannot be a specific IP address or DNS name"
#define ExternalPort_OnlySupports_Wildcard_STR "ExternalPort must be a wildcard and cannot be a specific port value"

#define MAX_NUM_TO_STR_LEN       10

#define PORTMAP_INDEX_FIELD_NUM    3

typedef enum PortMapElem{
    REMOTE_HOST,
    EXTERNAL_PORT,
    PROTOCOL,
    
    INTERNAL_PORT,
    INTERNAL_CLIENT,

    ENABLED,
    PORTMAPPING_DESCRIPTION,
    LEASE_DURATION,

    PORTMAP_ENTRY_FIELD_NUM
} E_PortMapElem;

// Portmap Entry parameter set
LOCAL CHAR *PM_SET[PORTMAP_ENTRY_FIELD_NUM] = {
    "NewRemoteHost",
    "NewExternalPort",
    "NewProtocol",
    
    "NewInternalPort",
    "NewInternalClient",

    "NewEnabled",
    "NewPortMappingDescription",
    "NewLeaseDuration"
};


 /************************************************************
 * Function: IGD_get_NATRSIP_status
 *
 *  Parameters:	
 *      event: 		INOUT.  action request from upnp template 
 * 
 *  Description:
 *     This function process the action "IGD_get_NATRSIP_status".  
 *
 *  Return Values: INT32
 *      0 if successful else error code.
 ************************************************************/  
INT32 IGD_get_NATRSIP_status(INOUT struct action_event *event)
{
    struct device_and_service_index *pIndex = NULL;
    BOOL natStatus, rsipStatus;
    INT32 ret = PAL_UPNP_E_SUCCESS;
    pal_string_pair response[] = {
        {"NewRSIPAvailable", 0},
        {"NewNATEnabled", 0}
    };

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "ENTER %s...", __func__);

    if (!event || !(event->request)) 
    {
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "Input parameter error");

        ret = IGD_GENERAL_ERROR;
        return ret;
    }

    pIndex = (struct device_and_service_index *)(event->service->private);
    if (NULL == pIndex) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pIndex is NULL");

        ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
        event->request->error_code = ret;
	/*CID 135237 :BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';

        return ret;
    }
    
    ret = IGD_pii_get_NAT_RSIP_status(pIndex->wan_device_index,
                                 pIndex->wan_connection_device_index,
                                 pIndex->wan_connection_service_index,
                                 (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                 &natStatus, &rsipStatus);

    if(ret != PAL_UPNP_E_SUCCESS)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "get_nat_rsip_status error");

        event->request->error_code = ret;
        event->request->action_result = NULL;
    }else {
        event->request->error_code = PAL_UPNP_E_SUCCESS;

        if(rsipStatus == BOOL_TRUE)
        {
            response[0].value = "1";
        }else {
            response[0].value = "0";
        }
        if(natStatus == BOOL_TRUE)
        {
            response[1].value = "1";
        }else {
            response[1].value = "0";
        }

        ret = PAL_upnp_make_action(&(event->request->action_result), event->request->action_name, 
                                                            event->service->type, 2, response, PAL_UPNP_ACTION_RESPONSE);
        if(ret != PAL_UPNP_E_SUCCESS)
        {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_upnp_make_action error: %d", ret);

            event->request->error_code = ret;
            event->request->action_result = NULL;
        }
    }

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "EXIT %s...", __func__);

    return ret;
}

 /************************************************************
 * Function: IGD_get_GenericPortMapping_entry
 *
 *  Parameters:	
 *      event: 		INOUT.  action request from upnp template 
 * 
 *  Description:
 *     This function process the action "IGD_get_GenericPortMapping_entry".  
 *
 *  Return Values: INT32
 *      0 if successful else error code.
 ************************************************************/  
INT32 IGD_get_GenericPortMapping_entry(INOUT struct action_event *event)
{
    struct device_and_service_index *pIndex = NULL;
    CHAR internalPort[MAX_NUM_TO_STR_LEN], externalPort[MAX_NUM_TO_STR_LEN], leaseTime[MAX_NUM_TO_STR_LEN];
    IGD_PortMapping_Entry portmapEntry;
    genPortMapIndex portmapIndex = {0, 0};
    INT32 entryNum, ret;
    

   PAL_XML2S_TABLE tableGenPorMap[] = {
        {"NewPortMappingIndex", PAL_XML2S_UINT16, XML2S_MSIZE(genPortMapIndex, portMapIndex), NULL, MASK_OF_PORTMAP_INDEX},
        XML2S_TABLE_END
    };
    pal_string_pair response[PORTMAP_ENTRY_FIELD_NUM] = {
        { PM_SET[REMOTE_HOST] ,                       NULL },
        { PM_SET[EXTERNAL_PORT] ,                    NULL },
        { PM_SET[PROTOCOL] ,                             NULL },
        { PM_SET[INTERNAL_PORT] ,                     NULL },
        { PM_SET[INTERNAL_CLIENT] ,                  NULL },
        { PM_SET[ENABLED] ,                               NULL },
        { PM_SET[PORTMAPPING_DESCRIPTION] , NULL },
        { PM_SET[LEASE_DURATION] ,                  NULL }
    };

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "ENTER %s...", __func__);

    if (!event || !(event->request)) 
    {
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "Input parameter error");

        ret = IGD_GENERAL_ERROR;
        return ret;
    }
    
    pIndex = (struct device_and_service_index *)(event->service->private);
    if (NULL == pIndex) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pIndex is NULL");

        ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
        event->request->error_code = ret;
	/*CID 135271 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';

        return ret;
    }
    
    bzero(&portmapIndex, sizeof(portmapIndex));
    ret = PAL_xml2s_process(event->request->action_request, tableGenPorMap, &portmapIndex);
    if (ret < 0){
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_xml2s_process error");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/*CID 135271 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
    } else {
        ret = IGD_pii_get_portmapping_entry_num(pIndex->wan_device_index,
                                 pIndex->wan_connection_device_index,
                                 pIndex->wan_connection_service_index,
                                 (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                 &entryNum);
        if(ret == 0)
        {
            if(portmapIndex.portMapIndex >= entryNum)
            {
                RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "portmap index error");
                
                ret = ARRAY_INDEX_INVALID;
                event->request->error_code = ret;
                strncpy(event->request->error_str, ARRAY_INDEX_INVALID_STR, strlen(ARRAY_INDEX_INVALID_STR) + 1);
            } else {
                ret = IGD_pii_get_portmapping_entry_generic(pIndex->wan_device_index,
                                         pIndex->wan_connection_device_index,
                                         pIndex->wan_connection_service_index,
                                         (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                         portmapIndex.portMapIndex,
                                         &portmapEntry);

                if(ret == 0)
                {
                    event->request->error_code = PAL_UPNP_E_SUCCESS;

                    response[REMOTE_HOST].value = strdup(portmapEntry.remoteHost);

                    snprintf(externalPort, MAX_NUM_TO_STR_LEN, "%d", portmapEntry.externalPort);
                    response[EXTERNAL_PORT].value = externalPort;

                    response[PROTOCOL].value = strdup(portmapEntry.protocol);

                    snprintf(internalPort, MAX_NUM_TO_STR_LEN, "%d", portmapEntry.internalPort);
                    response[INTERNAL_PORT].value = internalPort;

                    response[INTERNAL_CLIENT].value = strdup(portmapEntry.internalClient);

                    if(portmapEntry.enabled == BOOL_TRUE)
                    {
                        response[ENABLED].value = "1";
                    } else {
                        response[ENABLED].value = "0";
                    }

                    response[PORTMAPPING_DESCRIPTION].value = strdup(portmapEntry.description);

                    snprintf(leaseTime, MAX_NUM_TO_STR_LEN, "%d", portmapEntry.leaseTime);
                    response[LEASE_DURATION].value = leaseTime;

                    ret = PAL_upnp_make_action(&(event->request->action_result), event->request->action_name, 
                                    event->service->type, PORTMAP_ENTRY_FIELD_NUM, response, PAL_UPNP_ACTION_RESPONSE);
                    if(ret != PAL_UPNP_E_SUCCESS)
                    {
                        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_upnp_make_action error");

                        event->request->error_code = ret;
                        event->request->action_result = NULL;
                    }

                    if(response[REMOTE_HOST].value)
                    {
                        free(response[REMOTE_HOST].value);
                    }
                    if(response[PROTOCOL].value)
                    {
                        free(response[PROTOCOL].value);
                    }
                    if(response[INTERNAL_CLIENT].value)
                    {
                        free(response[INTERNAL_CLIENT].value);
                    }
                    if(response[PORTMAPPING_DESCRIPTION].value)
                    {
                        free(response[PORTMAPPING_DESCRIPTION].value);
                    }
                }else {  //IGD_pii_get_portmapping_entry_generic error
                    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_pii_get_portmapping_entry_num error");

                    ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), PAL_UPNP_LINE_SIZE);
                }
            }   // end if (portmapIndex.portMapIndex >= entryNum)
        } else {   //IGD_pii_get_portmapping_entry_num error
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_pii_get_portmapping_entry_num error");

            ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
            event->request->error_code = ret;
            strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), PAL_UPNP_LINE_SIZE);
        }
        
        PAL_xml2s_free(&portmapIndex, tableGenPorMap);
    }

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "EXIT %s...", __func__);

    return ret;
}

 /************************************************************
 * Function: IGD_get_SpecificPortMapping_entry
 *
 *  Parameters:	
 *      event: 		INOUT.  action request from upnp template 
 * 
 *  Description:
 *     This function process the action "IGD_get_SpecificPortMapping_entry".  
 *
 *  Return Values: INT32
 *      0 if successful else error code.
 ************************************************************/  
INT32 IGD_get_SpecificPortMapping_entry(INOUT struct action_event *event)
{
    struct device_and_service_index *pIndex = NULL;
    CHAR internalPort[MAX_NUM_TO_STR_LEN], leaseTime[MAX_NUM_TO_STR_LEN];
    IGD_PortMapping_Entry portmapEntry;
    PORT_MAP_INDEX portmapIndex;
    struct in_addr addr;
    INT32 ret;

    PAL_XML2S_TABLE tableSpecPorMap[] = {
        {PM_SET[REMOTE_HOST],    PAL_XML2S_STRING, XML2S_MSIZE(PORT_MAP_INDEX, remoteHost),  NULL, MASK_OF_INDEX_REMOTE_HOST},
        {PM_SET[EXTERNAL_PORT], PAL_XML2S_UINT16,  XML2S_MSIZE(PORT_MAP_INDEX, externalPort), NULL, MASK_OF_INDEX_EXTERNAL_PORT},
        {PM_SET[PROTOCOL],         PAL_XML2S_STRING,  XML2S_MSIZE(PORT_MAP_INDEX, pmProtocol),  NULL, MASK_OF_INDEX_PROTOCOL},
        XML2S_TABLE_END
    };
    pal_string_pair response[PORTMAP_ENTRY_FIELD_NUM - PORTMAP_INDEX_FIELD_NUM] = {
        { PM_SET[INTERNAL_PORT] ,                     NULL },
        { PM_SET[INTERNAL_CLIENT] ,                  NULL },
        { PM_SET[ENABLED] ,                               NULL },
        { PM_SET[PORTMAPPING_DESCRIPTION] , NULL },
        { PM_SET[LEASE_DURATION] ,                  NULL }
    };
    
    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "ENTER %s...", __func__);

    if (!event || !(event->request)) 
    {
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "Input parameter error");

        ret = IGD_GENERAL_ERROR;
        return ret;
    }

    pIndex = (struct device_and_service_index *)(event->service->private);
    if (NULL == pIndex) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pIndex is NULL");

        ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
        event->request->error_code = ret;
	/* CID 135641 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';

        return ret;
    }
    
    bzero(&portmapIndex, sizeof(portmapIndex));
    ret = PAL_xml2s_process(event->request->action_request, tableSpecPorMap, &portmapIndex);

    if (ret < 0){
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_xml2s_process error");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/* CID 135641 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
    } else if ((portmapIndex.remoteHost != NULL)
                &&(0 == inet_pton(AF_INET, portmapIndex.remoteHost, &addr))){ 
        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "remoteHost format error: x.x.x.x");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/* CID 135641 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
        event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
	PAL_xml2s_free(&portmapIndex, tableSpecPorMap);
    } else {
        bzero(&portmapEntry, sizeof(portmapEntry));
        if(portmapIndex.remoteHost != NULL)
        {
            /* CID 135641 : BUFFER_SIZE_WARNING */
            strncpy(portmapEntry.remoteHost, portmapIndex.remoteHost, sizeof(portmapEntry.remoteHost)-1);
	    portmapEntry.remoteHost[sizeof(portmapEntry.remoteHost)-1] = '\0';
        }
        portmapEntry.externalPort = portmapIndex.externalPort;
        if(portmapIndex.pmProtocol != NULL)
        {
            /* CID 135641 : BUFFER_SIZE_WARNING */ 
            strncpy(portmapEntry.protocol, portmapIndex.pmProtocol, sizeof(portmapEntry.protocol)-1);
	    portmapEntry.protocol[sizeof(portmapEntry.protocol)-1] = '\0';
        }

        ret = IGD_pii_get_portmapping_entry_specific(pIndex->wan_device_index,
                                 pIndex->wan_connection_device_index,
                                 pIndex->wan_connection_service_index,
                                 (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                 &portmapEntry);
        if(ret == 0)
        {
            event->request->error_code = PAL_UPNP_E_SUCCESS;

            snprintf(internalPort, MAX_NUM_TO_STR_LEN, "%d", portmapEntry.internalPort);
            response[INTERNAL_PORT - PORTMAP_INDEX_FIELD_NUM].value = internalPort;

            response[INTERNAL_CLIENT - PORTMAP_INDEX_FIELD_NUM].value = strdup(portmapEntry.internalClient);

            if(portmapEntry.enabled == BOOL_TRUE)
            {
                response[ENABLED - PORTMAP_INDEX_FIELD_NUM].value = "1";
            } else {
                response[ENABLED - PORTMAP_INDEX_FIELD_NUM].value = "0";
            }
            
            response[PORTMAPPING_DESCRIPTION - PORTMAP_INDEX_FIELD_NUM].value = strdup(portmapEntry.description);

            snprintf(leaseTime, MAX_NUM_TO_STR_LEN, "%d", portmapEntry.leaseTime);
            response[LEASE_DURATION - PORTMAP_INDEX_FIELD_NUM].value = leaseTime;
            
            ret = PAL_upnp_make_action(&(event->request->action_result), event->request->action_name, event->service->type, 
                                            PORTMAP_ENTRY_FIELD_NUM - PORTMAP_INDEX_FIELD_NUM, response, PAL_UPNP_ACTION_RESPONSE);
            if(ret != PAL_UPNP_E_SUCCESS)
            {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_upnp_make_action error");

                event->request->error_code = ret;
                event->request->action_result = NULL;
            }
            
            if(response[INTERNAL_CLIENT - PORTMAP_INDEX_FIELD_NUM].value)
            {
                free(response[INTERNAL_CLIENT - PORTMAP_INDEX_FIELD_NUM].value);
            }
            if(response[PORTMAPPING_DESCRIPTION - PORTMAP_INDEX_FIELD_NUM].value)
            {
                free(response[PORTMAPPING_DESCRIPTION - PORTMAP_INDEX_FIELD_NUM].value);
            }
            
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_pii_get_portmapping_entry_specific error");

            ret = NO_SUCH_ENTRY_IN_ARRAY;
            event->request->error_code = ret;
            strncpy(event->request->error_str, NO_SUCH_ENTRY_IN_ARRAY_STR, sizeof(NO_SUCH_ENTRY_IN_ARRAY_STR)+1);
        }
        
        PAL_xml2s_free(&portmapIndex, tableSpecPorMap);
    }

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "EXIT %s...", __func__);

    return ret;
}

 /************************************************************
 * Function: IGD_add_PortMapping
 *
 *  Parameters:	
 *      event: 		INOUT.  action request from upnp template 
 * 
 *  Description:
 *     This function process the action "IGD_add_PortMapping".  
 *
 *  Return Values: INT32
 *      0 if successful else error code.
 ************************************************************/  
INT32 IGD_add_PortMapping(INOUT struct action_event *event)
{
    struct device_and_service_index *pIndex = NULL;
    IGD_PortMapping_Entry pii_pmEntry;
    PORT_MAP_ENTRY portmapEntry;
    struct in_addr addr;
    INT32 ret;
    struct sockaddr_in* src_addr;
    char buf[INET_ADDRSTRLEN];

    PAL_XML2S_TABLE tableAddPorMap[] = {
        {PM_SET[REMOTE_HOST],                       PAL_XML2S_STRING,   XML2S_MSIZE(PORT_MAP_ENTRY, remoteHost),    NULL, MASK_OF_ENTRY_REMOTE_HOST},
        {PM_SET[EXTERNAL_PORT],                    PAL_XML2S_UINT16,    XML2S_MSIZE(PORT_MAP_ENTRY, externalPort),   NULL, MASK_OF_ENTRY_EXTERNAL_PORT},
        {PM_SET[PROTOCOL],                            PAL_XML2S_STRING,   XML2S_MSIZE(PORT_MAP_ENTRY, pmProtocol),     NULL, MASK_OF_ENTRY_PROTOCOL},
        {PM_SET[INTERNAL_PORT],                    PAL_XML2S_UINT16,    XML2S_MSIZE(PORT_MAP_ENTRY, internalPort),     NULL, MASK_OF_ENTRY_INTERNAL_PORT},
        {PM_SET[INTERNAL_CLIENT],                  PAL_XML2S_STRING,   XML2S_MSIZE(PORT_MAP_ENTRY, internalClient),  NULL, MASK_OF_ENTRY_INTERNAL_CLIENT},
        {PM_SET[ENABLED],                               PAL_XML2S_UINT8,     XML2S_MSIZE(PORT_MAP_ENTRY, pmEnabled),      NULL, MASK_OF_ENTRY_ENABLED},
        {PM_SET[PORTMAPPING_DESCRIPTION], PAL_XML2S_STRING,   XML2S_MSIZE(PORT_MAP_ENTRY, pmDescription), NULL, MASK_OF_ENTRY_DESCRIPTION},
        {PM_SET[LEASE_DURATION],                  PAL_XML2S_UINT32,    XML2S_MSIZE(PORT_MAP_ENTRY, pmLeaseTime),  NULL, MASK_OF_ENTRY_LEASE_TIME},
        XML2S_TABLE_END
    };

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "ENTER %s...", __func__);

    if (!event || !(event->request)) 
    {
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "Input parameter error");

        ret = IGD_GENERAL_ERROR;
        return ret;
    }

    pIndex = (struct device_and_service_index *)(event->service->private);
    if (NULL == pIndex) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pIndex is NULL");

        ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
        event->request->error_code = ret;
	/* CID 135442: BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0' ;

        return ret;
    }

    bzero(&portmapEntry, sizeof(portmapEntry));
    ret = PAL_xml2s_process(event->request->action_request, tableAddPorMap, &portmapEntry);

    src_addr = (struct sockaddr_in*)(&(event->request->cp_addr));
    strncpy(buf,inet_ntoa(src_addr->sin_addr),INET_ADDRSTRLEN);
    buf[INET_ADDRSTRLEN-1] = '\0';

    if (ret < 0){
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_xml2s_process error: %d", ret);

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/* CID 135442: BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0' ;
    } else if (((portmapEntry.remoteHost != NULL)
                &&(0 == inet_pton(AF_INET, portmapEntry.remoteHost, &addr)))
                ||(portmapEntry.internalClient == NULL) /* WANIpConnection v1: internalClient can not be wildcard (i.e. empty string) */
                ||(0 == inet_pton(AF_INET, portmapEntry.internalClient, &addr))
                ||(0 != strncmp(buf,portmapEntry.internalClient,INET_ADDRSTRLEN)) 
                ||(!chkPortMappingClient(portmapEntry.internalClient))){ 
        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "remoteHost or internalClient format error: x.x.x.x");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/*CID 163387 : BUFFER_SIZE */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
	PAL_xml2s_free(&portmapEntry, tableAddPorMap);
    } else {
        bzero(&pii_pmEntry, sizeof(pii_pmEntry));

        if(portmapEntry.remoteHost != NULL)
        {
            strncpy(pii_pmEntry.remoteHost, portmapEntry.remoteHost, IPV4_ADDR_LEN);
        }
        pii_pmEntry.externalPort = portmapEntry.externalPort;
        if(portmapEntry.pmProtocol != NULL)
        {
            strncpy(pii_pmEntry.protocol, portmapEntry.pmProtocol, PORT_MAP_PROTOCOL_LEN);
        }
        pii_pmEntry.internalPort = portmapEntry.internalPort;
        if(portmapEntry.internalClient != NULL)
        {
            strncpy(pii_pmEntry.internalClient, portmapEntry.internalClient, IPV4_ADDR_LEN);
        }
        pii_pmEntry.enabled = portmapEntry.pmEnabled;
        if(portmapEntry.pmDescription != NULL)
        {
            strncpy(pii_pmEntry.description, portmapEntry.pmDescription, sizeof(pii_pmEntry.description)-1);
        }

#if defined (SPEED_BOOST_SUPPORTED)
        if( IGD_checkport_SpeedboostPort(pii_pmEntry.externalPort , pii_pmEntry.internalPort ))
        {
           ret = Conflict_In_MappingEntry;
           event->request->error_code = ret;
           strncpy(event->request->error_str, Conflict_In_MappingEntry_STR, PAL_UPNP_LINE_SIZE);
           //printf(" IGD_checkport_SpeedboostPort : UPnP External or Internal are overlap with Speedboost range \n");
           return ret;
        }
#endif

	// Setting the lease time for Port Mapping entry , once lease expires rule will get deleted from iptable
	portmapEntry.pmLeaseTime = 86400;
        pii_pmEntry.leaseTime = portmapEntry.pmLeaseTime;
        ret = IGD_pii_add_portmapping_entry(pIndex->wan_device_index,
                                 pIndex->wan_connection_device_index,
                                 pIndex->wan_connection_service_index,
                                 (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                 &pii_pmEntry);
        if(ret == 0)
        {
            event->request->error_code = PAL_UPNP_E_SUCCESS;
            ret = PAL_upnp_make_action(&(event->request->action_result), event->request->action_name, 
                            event->service->type, 0, NULL, PAL_UPNP_ACTION_RESPONSE);
            if(ret != PAL_UPNP_E_SUCCESS)
            {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_upnp_make_action error");
                event->request->error_code = ret;
                event->request->action_result = NULL;
            }
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_pii_add_portmapping_entry error");
            switch(ret) 
            { 
                case ERROR_WILDCARD_NOTPERMIT_FOR_SRC_IP: 
                    ret = WildCard_NotPermitted_InSrcIP;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, WildCard_NotPermitted_InSrcIP_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_WILDCARD_NOTPERMIT_FOR_EXTERNAL_PORT: 
                    ret = WildCard_NotPermitted_InExtPort;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, WildCard_NotPermitted_InExtPort_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_CONFLICT_FOR_MAPPING_ENTRY: 
                    ret = Conflict_In_MappingEntry;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, Conflict_In_MappingEntry_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_SAME_PORT_VALUE_REQUIRED: 
                    ret = Same_PortValues_Required;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, Same_PortValues_Required_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_ONLY_PERMANENT_LEASETIME_SUPPORTED: 
                    ret = Only_Permanent_Leases_Supported;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, Only_Permanent_Leases_Supported_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_REMOST_HOST_ONLY_SUPPORT_WILDCARD: 
                    ret = RemoteHost_OnlySupports_Wildcard;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, RemoteHost_OnlySupports_Wildcard_STR, PAL_UPNP_LINE_SIZE);
                    break;
                case ERROR_EXTERNAL_PORT_ONLY_SUPPORT_WILDCARD: 
                    ret = ExternalPort_OnlySupports_Wildcard;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, ExternalPort_OnlySupports_Wildcard_STR, PAL_UPNP_LINE_SIZE);
                    break;
                default:
                    ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
                    event->request->error_code = ret;
                    strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), PAL_UPNP_LINE_SIZE);
                    break;
            }
        }
        
        PAL_xml2s_free(&portmapEntry, tableAddPorMap);
    }

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "EXIT %s...", __func__);

    return ret;
}


#if defined (SPEED_BOOST_SUPPORTED)
/*************************************************************************************
*  Function   : IGD_checkport_SpeedboostPort
*
*  Parameters :
*    fp       : External and internal port for UPnP mapping
*
*  Description:
*    check if Extenal or Internal port overlaps with Speedboot Range port
*
*  Return     :
*    TRUE     : Ext/Int upnp port range is overlapping with xm speedboost port ranges
*    FALSE    : Ext/Int upnp port range is NOT overlapping with xm speedboost port ranges
***************************************************************************************/
INT32 IGD_checkport_SpeedboostPort(UINT16 ExternalPort, UINT16 InternalPort)
{
    char pvd_enabled[8]={0};
    char sb_port_startv4[16]={0};
    char sb_port_endv4[16]={0};
    char sb_port_startv6[16]={0};
    char sb_port_endv6[16]={0};
    memset(pvd_enabled, 0, sizeof(pvd_enabled));
    memset(sb_port_startv4, 0, sizeof(sb_port_startv4));
    memset(sb_port_endv4, 0, sizeof(sb_port_endv4));
    memset(sb_port_startv6, 0, sizeof(sb_port_startv6));
    memset(sb_port_endv6, 0, sizeof(sb_port_endv6));

    int rc = syscfg_get( NULL, "Advertisement_pvd_enable" , pvd_enabled , sizeof( pvd_enabled ) ) ;

    if (rc == 0 && (0 == strcmp("1", pvd_enabled) || 0 == strcasecmp("true", pvd_enabled)))
    {
       rc = syscfg_get( NULL, "SpeedBoost_Port_StartV4" , sb_port_startv4 , sizeof( sb_port_startv4 ) );
       rc |= syscfg_get( NULL, "SpeedBoost_Port_EndV4" , sb_port_endv4 , sizeof( sb_port_endv4 ) );
       rc |= syscfg_get( NULL, "SpeedBoost_Port_StartV6" , sb_port_startv6 , sizeof( sb_port_startv6 ) );
       rc |= syscfg_get( NULL, "SpeedBoost_Port_EndV6" , sb_port_endv6 , sizeof( sb_port_endv6 ) );

       if (rc == 0 && sb_port_startv4[0] != '\0' && sb_port_endv4[0] != '\0' && sb_port_startv6[0] != '\0' && sb_port_endv6[0] != '\0')
       {
          if ((atoi(sb_port_startv4) <= ExternalPort && ExternalPort <= atoi(sb_port_endv4)) || \
              (atoi(sb_port_startv4) <= InternalPort && InternalPort <= atoi(sb_port_endv4)) || \
              (atoi(sb_port_startv6) <= ExternalPort && ExternalPort <= atoi(sb_port_endv6)) || \
              (atoi(sb_port_startv6) <= InternalPort && InternalPort <= atoi(sb_port_endv6)) )
          {
             RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_checkport_SpeedboostPort UPnP External or Internal port Overlaps with Speedboost ports ");
             return TRUE;
          }
       }
    }
    return FALSE;
}
#endif


 /************************************************************
 * Function: IGD_delete_PortMapping
 *
 *  Parameters:	
 *      event: 		INOUT.  action request from upnp template 
 * 
 *  Description:
 *     This function process the action "IGD_delete_PortMapping".  
 *
 *  Return Values: INT32
 *      0 if successful else error code.
 ************************************************************/  
INT32 IGD_delete_PortMapping(INOUT struct action_event *event)
{
    struct device_and_service_index *pIndex = NULL;
    PORT_MAP_INDEX portmapIndex;
    struct in_addr addr;
    INT32 ret;
    
    PAL_XML2S_TABLE tableDelPorMap[] = {
        {PM_SET[REMOTE_HOST],    PAL_XML2S_STRING,  XML2S_MSIZE(PORT_MAP_INDEX, remoteHost),  NULL, MASK_OF_INDEX_REMOTE_HOST},
        {PM_SET[EXTERNAL_PORT], PAL_XML2S_UINT16,   XML2S_MSIZE(PORT_MAP_INDEX, externalPort), NULL, MASK_OF_INDEX_EXTERNAL_PORT},
        {PM_SET[PROTOCOL],         PAL_XML2S_STRING,   XML2S_MSIZE(PORT_MAP_INDEX, pmProtocol),  NULL, MASK_OF_INDEX_PROTOCOL},
        XML2S_TABLE_END
    };

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "ENTER %s...", __func__);

    if (!event || !(event->request)) 
    {
        RDK_LOG(RDK_LOG_NOTICE, "LOG.RDK.IGD", "Input parameter error");

        ret = IGD_GENERAL_ERROR;
        return ret;
    }
    
    pIndex = (struct device_and_service_index *)(event->service->private);
    if (NULL == pIndex) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "pIndex is NULL");

        ret = PAL_UPNP_SOAP_E_ACTION_FAILED;
        event->request->error_code = ret;
	/* CID 135406 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_ACTION_FAILED), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';

        return ret;
    }
    
    bzero(&portmapIndex, sizeof(portmapIndex));
    ret = PAL_xml2s_process(event->request->action_request, tableDelPorMap, &portmapIndex);
    if (ret < 0){
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_xml2s_process error");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/* CID 135406 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
    } else if ((portmapIndex.remoteHost != NULL)
                &&(0 == inet_pton(AF_INET, portmapIndex.remoteHost, &addr))){ 
        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "remoteHost format error: x.x.x.x");

        ret = PAL_UPNP_SOAP_E_INVALID_ARGS;
        event->request->error_code = ret;
	/* CID 163319 : BUFFER_SIZE_WARNING */
        strncpy(event->request->error_str, PAL_upnp_get_error_message(PAL_UPNP_SOAP_E_INVALID_ARGS), sizeof(event->request->error_str)-1);
	event->request->error_str[sizeof(event->request->error_str)-1] = '\0';
	PAL_xml2s_free(&portmapIndex, tableDelPorMap);
    } else {

        ret = IGD_pii_del_portmapping_entry(pIndex->wan_device_index,
                                 pIndex->wan_connection_device_index,
                                 pIndex->wan_connection_service_index,
                                 (strcmp(WAN_IP_CONNECTION_SERVICE_TYPE,event->service->type) == 0) ? SERVICETYPE_IP : SERVICETYPE_PPP,
                                 portmapIndex.remoteHost,
                                 portmapIndex.externalPort,
                                 portmapIndex.pmProtocol);

        if(ret == 0)
        {
            event->request->error_code = PAL_UPNP_E_SUCCESS;
            ret = PAL_upnp_make_action(&(event->request->action_result), event->request->action_name, 
                            event->service->type, 0, NULL, PAL_UPNP_ACTION_RESPONSE);
            if(ret != PAL_UPNP_E_SUCCESS)
            {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "PAL_upnp_make_action error");

                event->request->error_code = ret;
                event->request->action_result = NULL;
            }
        } else {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.IGD", "IGD_pii_del_portmapping_entry error");

            ret = NO_SUCH_ENTRY_IN_ARRAY;
            event->request->error_code = ret;
            strncpy(event->request->error_str, NO_SUCH_ENTRY_IN_ARRAY_STR, strlen(NO_SUCH_ENTRY_IN_ARRAY_STR) + 1);
        }
        
        PAL_xml2s_free(&portmapIndex, tableDelPorMap);
    }

    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.IGD", "EXIT %s...", __func__);

    return ret;
}


