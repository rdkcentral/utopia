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
 *    FileName:    upnp_device.h
 *      Author:    Jerry Liu(zhiyliu@cisco.com)
 *        Date:    2009-04-15
 * Description:    UPnP device template head code of UPnP IGD project
 *****************************************************************************/
/*$Id: pal_upnp_device.h,v 1.2 2009/05/15 08:00:21 bowan Exp $
 *
 *$Log: pal_upnp_device.h,v $
 *Revision 1.2  2009/05/15 08:00:21  bowan
 *1st Integration
 *
 *Revision 1.1  2009/05/14 01:52:28  zhiyliu
 *init version
 *
 *
 **/

#ifndef _UPNP_DEVICE_H
#define _UPNP_DEVICE_H

#include <pthread.h>
#include "pal_upnp.h"

#define UDT_LNAME	"UDT"

struct action_event
{
	pal_upnp_action_request *request;
	struct upnp_service *service;
};

struct upnp_action
{
	const CHAR *action_name;
	INT32 (*callback)(struct action_event *);
};

struct upnp_variable
{
	const CHAR 	*name;									//state variable name
	CHAR 		value[PAL_UPNP_LINE_SIZE];				//state variable value
};

struct upnp_device
{
	INT32 (*init_function)(VOID);						//device init function
	INT32 (*destroy_function)(struct upnp_device *);	//device destroy function
	CHAR udn[PAL_UPNP_LINE_SIZE];						//UPnP device UDN
	struct upnp_service **services;						//UPnP device service array, NULL as the end
	struct upnp_device *next;							//UPnP device list
};

struct upnp_service
{
	pthread_mutex_t service_mutex;						//service mutex
	INT32 (*destroy_function)(struct upnp_service *);	//service destroy function
	CHAR *type;									        //UPnP service type
	const CHAR *serviceID;								//UPnP service ID
	struct upnp_action *actions;						//UPnP service action array, NULL as the end
	struct upnp_variable *state_variables;				//UPnP service state variable array, NULL as the end
	struct upnp_variable *event_variables;				//UPnP service event variable array, NULL as the end
	VOID *private;										//service private variable
};


/**
* @brief Initialize a UPnP device.
*
* Initializes the UPnP device by calling the device's init function,
* \n initializing the UPnP library with the specified interface and port,
* \n registering the root device with the description file and web directory,
* \n and sending UPnP advertisements with the specified timeout.
*
* @param[in] device - UPnP device pointer.
* @param[in] ip_address - Local IP address or interface name. NULL for automatic selection.
*                        \n If ip_address is NULL, an appropriate IP address will be automatically selected.
* @param[in] port - Local port to listen for incoming connections. 0 for automatic selection.
*                   \n If port is 0, an appropriate port will be automatically selected.
* @param[in] timeout - UPnP device alive timeout value in seconds. 0 for default timeout.
* @param[in] desc_doc_name - Device description file name.
*                           \n Default value will be used if desc_doc_name is NULL.
* @param[in] web_dir_path - Local path for device description file.
*                           \n Default value will be used if web_dir_path is NULL.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if error (initialization failure, registration failure, or advertisement failure).
*/
extern INT32 PAL_upnp_device_init(IN struct upnp_device *device,
							IN CHAR *ip_address,
							IN UINT32 port,
							IN UINT32 timeout,
							IN const CHAR *desc_doc_name,
							IN const CHAR *web_dir_path);


/**
* @brief Destroy a UPnP device.
*
* Destroys the UPnP device by calling the destroy function for the device and all linked devices,
* \n unregistering the root device from the UPnP library, and cleaning up UPnP resources.
* \n Resets the device handle and initialization status.
*
* @param[in] device - UPnP device pointer.
*
* @return The status of the operation.
* @retval 0 if successful.
*/
extern INT32 PAL_upnp_device_destroy(IN struct upnp_device *device);


/**
* @brief Get the UPnP device handle.
*
* Returns the device handle assigned during device initialization.
* \n This handle is used for UPnP operations such as sending notifications.
*
* @return The UPnP device handle.
*/
extern pal_upnp_device_handle PAL_upnp_device_getHandle(VOID);


#endif /* _UPNP_DEVICE_H */
