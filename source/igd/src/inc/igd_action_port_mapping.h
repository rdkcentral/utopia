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
 *    FileName:    igd_action_port_mapping.h
 *      Author:    Lipin Zhou(zlipin@cisco.com)
 *        Date:    2009-04-30
 * Description:    IGD port map implementation of UPnP IGD project
 *****************************************************************************/
/*$Id: igd_action_port_mapping.h,v 1.4 2009/05/22 05:36:58 zlipin Exp $
 *
 *$Log: igd_action_port_mapping.h,v $
 *Revision 1.4  2009/05/22 05:36:58  zlipin
 *Adjust the PII "PortMapping" module interface
 *
 *Revision 1.3  2009/05/15 08:00:21  bowan
 *1st Integration
 *
 *Revision 1.2  2009/05/14 05:56:05  zlipin
 *update the included file name
 *
 *Revision 1.1  2009/05/14 01:58:26  zlipin
 *First version
 *
 *
 **/
 
#ifndef _IGD_ACTION_PORT_MAPPING_
#define _IGD_ACTION_PORT_MAPPING_

/***************************including***************************/
#include "igd_platform_independent_inf.h"
#include "pal_upnp_device.h"
#include "pal_xml2s.h"
#include "pal_def.h"
/***************************including end***********************/


/***************************data structure***********************/

#define IGD_GENERAL_ERROR           -1

typedef struct _genPortMapIndex{
    PAL_XML2S_FDMSK fieldMask;
    
    #define MASK_OF_PORTMAP_INDEX    0x00000001

    UINT16 portMapIndex;
}genPortMapIndex;

typedef struct _PORT_MAP_INDEX{
    PAL_XML2S_FDMSK fieldMask;
    
    #define MASK_OF_INDEX_REMOTE_HOST       0x00000001
    #define MASK_OF_INDEX_EXTERNAL_PORT    0x00000002
    #define MASK_OF_INDEX_PROTOCOL              0x00000004
    
    CHAR    *remoteHost;
    UINT16  externalPort;
    CHAR    *pmProtocol;
}PORT_MAP_INDEX, *PPORT_MAP_INDEX;

typedef struct _PORT_MAP_ENTRY{
    PAL_XML2S_FDMSK fieldMask;
    
    #define MASK_OF_ENTRY_REMOTE_HOST       0x00000001
    #define MASK_OF_ENTRY_EXTERNAL_PORT    0x00000002
    #define MASK_OF_ENTRY_PROTOCOL              0x00000004
    #define MASK_OF_ENTRY_INTERNAL_PORT    0x00000008
    #define MASK_OF_ENTRY_INTERNAL_CLIENT 0x00000010
    #define MASK_OF_ENTRY_ENABLED                0x00000020
    #define MASK_OF_ENTRY_DESCRIPTION         0x00000040
    #define MASK_OF_ENTRY_LEASE_TIME           0x00000080
    
    CHAR    *remoteHost;
    UINT16  externalPort;
    CHAR    *pmProtocol;
    UINT16  internalPort;
    CHAR    *internalClient;
    BOOL     pmEnabled;
    CHAR    *pmDescription;
    UINT32  pmLeaseTime;
}PORT_MAP_ENTRY, *PPORT_MAP_ENTRY;

/***************************data structure end********************/


/***************************interface function***************************/

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
INT32 IGD_get_NATRSIP_status(INOUT struct action_event *event);

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
INT32 IGD_get_GenericPortMapping_entry(INOUT struct action_event *event);

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
INT32 IGD_get_SpecificPortMapping_entry(INOUT struct action_event *event);

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
INT32 IGD_add_PortMapping(INOUT struct action_event *event);

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
INT32 IGD_delete_PortMapping(INOUT struct action_event *event);

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
 ************************************************************/
INT32 IGD_checkport_SpeedboostPort(UINT16 ExternalPort, UINT16 InternalPort);
#endif
 
/***************************interface function end***********************/

#endif  //_IGD_ACTION_PORT_MAPPING_

