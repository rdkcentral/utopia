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
 *    FileName:    wan_connection_device_internal.h
 *      Author:    Tao Hong(tahong@cisco.com)
 *        Date:    2009-05-03
 * Description:    WAN connection Device inner used header file of UPnP IGD project
 *****************************************************************************/
/*$Id: igd_utility.h,v 1.6 2009/05/21 06:27:43 jianxiao Exp $
 *
 *$Log: igd_utility.h,v $
 *Revision 1.6  2009/05/21 06:27:43  jianxiao
 *Add struct device_and_service_index
 *
 *Revision 1.5  2009/05/15 08:00:20  bowan
 *1st Integration
 *
 *Revision 1.3  2009/05/14 02:36:37  jianxiao
 *Add the header string.h
 *
 *Revision 1.2  2009/05/14 01:47:55  jianxiao
 *Add the macro SAFE_FREE
 *
 *Revision 1.1  2009/05/13 08:57:57  tahong
 *create orignal version
 *
 *
 **/

#ifndef WAN_CONNECTION_DEVICE_INTERNAL_H
#define WAN_CONNECTION_DEVICE_INTERNAL_H

#include <string.h>

#include "pal_upnp_device.h"
#include "pal_def.h"

#define INVALID_DEVICE_UUID 			720
#define INVALID_SERVICE_ID 				721
#define INVALID_CONN_SERVICE_SELECTION 	723
#define ACTION_FAIL 					501
#define INVALID_ARGS					402

#define LOG_IGD_NAME	"IGD"

#define SAFE_FREE(p) if(p!=NULL){\
						free(p);\
						p=NULL;}

struct device_and_service_index{
	INT32 wan_device_index;             //begin from 1
	INT32 wan_connection_device_index;  //begin from 1
	INT32 wan_connection_service_index; //begin from 1
	INT32 lan_device_index;             //begin from 1
	};

//for timer

enum timer_function_mode
{
    timer_function_mode_run_once = 0,
    timer_function_mode_cycle
};

typedef VOID (*timer_function_t)(struct upnp_device *input_upnp_device, struct upnp_service *input_upnp_service);
struct timer_function_node
{
    struct upnp_device * upnp_device;
    struct upnp_service * upnp_service;
    timer_function_t timer_function;
    INT32 trigger_second;
    INT32 accumulate_second;
    INT32 mode;
    struct timer_function_node* next;
};

/**
 * @brief Start the IGD timer mechanism.
 *
 * This function initializes and starts two timer threads (timer_thread_id_run_once and timer_thread_id_cycle)
 * for managing run-once and cyclic timer callbacks. It initializes the necessary mutexes and creates detached
 * threads for timer processing. The function ensures thread safety and proper initialization of the timer system.
 *
 * @return None
 */
extern VOID IGD_timer_start(VOID);
/**
 * @brief Stop the IGD timer mechanism.
 *
 * This function stops the two timer threads (timer_thread_id_run_once and timer_thread_id_cycle) and
 * destroys the associated mutexes. It cancels the running timer threads and cleans up the timer system resources.
 *
 * @return None
 */
extern VOID IGD_timer_stop(VOID);
/**
 * @brief Register a timer callback function with the IGD timer mechanism.
 *
 * This function registers a timer callback function to be executed either once or cyclically based on the
 * specified mode. The callback is associated with a UPnP device and service context, and will be triggered
 * after the specified time interval. The function is added to either the run-once or cyclic timer list
 * depending on the mode parameter.
 *
 * @param[in] input_upnp_device - Pointer to the UPnP device structure associated with the timer callback
 * @param[in] input_upnp_service - Pointer to the UPnP service structure associated with the timer callback
 * @param[in] input_timer_function - Pointer to the timer callback function to be executed
 * @param[in] input_trigger_second - Time interval in seconds for the timer trigger (must be greater than 0)
 * @param[in] input_mode - Timer execution mode (timer_function_mode_run_once or timer_function_mode_cycle)
 *
 * @return None
 */
extern VOID IGD_timer_register(IN struct upnp_device * input_upnp_device,
                                 IN struct upnp_service * input_upnp_service,
                                 IN timer_function_t input_timer_function,
                                 IN INT32 input_trigger_second,
                                 IN INT32 input_mode);
/**
 * @brief Check if the internal client address is valid for port mapping.
 *
 * This function validates whether the specified client IP address is valid for port mapping operations.
 * It retrieves the LAN settings and checks if the client address is on the same network, is not the
 * gateway address itself, and is not a broadcast or network address.
 *
 * @param[in] client - String representation of the internal client IP address to validate
 *
 * @return Status of internal client address
 * @retval TRUE - Client address is valid for port mapping
 * @retval FALSE - Client address is invalid (same as gateway, broadcast, network address, or not on same subnet)
 */
extern BOOL chkPortMappingClient(char* client);

#endif /*WAN_CONNECTION_DEVICE_INTERNAL_H*/

