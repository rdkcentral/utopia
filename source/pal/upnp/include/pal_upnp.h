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
 *    FileName:    pal_upnp.h
 *      Author:    Barry Wang (bowan@cisco.com)
 *        Date:    2009-05-05
 * Description:    Header file of PAL UPnP abstract interfaces
 *****************************************************************************/
 /*******************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/
/*$Id: pal_upnp.h,v 1.2 2009/05/19 07:41:12 bowan Exp $
 *
 *$Log: pal_upnp.h,v $
 *Revision 1.2  2009/05/19 07:41:12  bowan
 *change some comments and data type as per common type definition
 *
 *Revision 1.1  2009/05/13 07:56:44  bowan
 *no message
 *
 *
 **/

#ifndef __PAL_UPNP_H__
#define __PAL_UPNP_H__

#include <upnp/upnp.h>
#include "pal_def.h"
#include "pal_xml.h"
#include <arpa/inet.h>

#ifndef IN
	#define IN
#endif

#ifndef OUT
	#define OUT
#endif

#ifndef INOUT
	#define INOUT
#endif

#define PAL_UPNP_SID_MAX_LENGTH  256
#define PAL_UPNP_DESC_URL_SIZE   256
#define PAL_UPNP_LINE_SIZE       180
#define PAL_UPNP_NAME_SIZE       256
#define PAL_UPNP_SID_SIZE        44
#define PAL_UPNP_DEFAULT_WEB_DIR "./web"

typedef INT32 pal_upnp_device_handle;
typedef INT32 pal_upnp_cp_handle;
typedef CHAR pal_upnp_sid[PAL_UPNP_SID_SIZE];

#define PAL_UPNP_E_SUCCESS          0
#define PAL_UPNP_E_INVALID_HANDLE   -100
#define PAL_UPNP_E_INVALID_PARAM    -101
#define PAL_UPNP_E_OUTOF_HANDLE     -102
#define PAL_UPNP_E_OUTOF_CONTEXT    -103
#define PAL_UPNP_E_OUTOF_MEMORY     -104
#define PAL_UPNP_E_INIT             -105
#define PAL_UPNP_E_BUFFER_TOO_SMALL -106
#define PAL_UPNP_E_INVALID_DESC     -107
#define PAL_UPNP_E_INVALID_URL      -108
#define PAL_UPNP_E_INVALID_SID      -109
#define PAL_UPNP_E_INVALID_DEVICE   -110
#define PAL_UPNP_E_INVALID_SERVICE  -111
#define PAL_UPNP_E_BAD_RESPONSE     -113
#define PAL_UPNP_E_BAD_REQUEST      -114
#define PAL_UPNP_E_INVALID_ACTION   -115
#define PAL_UPNP_E_FINISH           -116
#define PAL_UPNP_E_INIT_FAILED      -117
#define PAL_UPNP_E_URL_TOO_BIG      -118
#define PAL_UPNP_E_BAD_HTTPMSG      -119
#define PAL_UPNP_E_ALREADY_REGISTERED -120
#define PAL_UPNP_E_NETWORK_ERROR    -200
#define PAL_UPNP_E_SOCKET_WRITE     -201
#define PAL_UPNP_E_SOCKET_READ      -202
#define PAL_UPNP_E_SOCKET_BIND      -203
#define PAL_UPNP_E_SOCKET_CONNECT   -204
#define PAL_UPNP_E_OUTOF_SOCKET     -205
#define PAL_UPNP_E_LISTEN           -206
#define PAL_UPNP_E_TIMEDOUT         -207
#define PAL_UPNP_E_SOCKET_ERROR	    -208
#define PAL_UPNP_E_FILE_WRITE_ERROR -209
#define PAL_UPNP_E_CANCELED         -210
#define PAL_UPNP_E_EVENT_PROTOCOL         -300
#define PAL_UPNP_E_SUBSCRIBE_UNACCEPTED   -301
#define PAL_UPNP_E_UNSUBSCRIBE_UNACCEPTED -302
#define PAL_UPNP_E_NOTIFY_UNACCEPTED      -303
#define PAL_UPNP_E_INVALID_ARGUMENT       -501
#define PAL_UPNP_E_FILE_NOT_FOUND         -502
#define PAL_UPNP_E_FILE_READ_ERROR        -503
#define PAL_UPNP_E_EXT_NOT_XML            -504
#define PAL_UPNP_E_NO_WEB_SERVER          -505
#define PAL_UPNP_E_OUTOF_BOUNDS	          -506
#define PAL_UPNP_E_NOT_FOUND	          -507
#define PAL_UPNP_E_INTERNAL_ERROR         -911

/* SOAP-related error codes */
#define PAL_UPNP_SOAP_E_INVALID_ACTION    401
#define PAL_UPNP_SOAP_E_INVALID_ARGS      402
#define PAL_UPNP_SOAP_E_OUT_OF_SYNC       403
#define PAL_UPNP_SOAP_E_INVALID_VAR       404
#define PAL_UPNP_SOAP_E_ACTION_FAILED     501



/*for event callback function*/
typedef INT32 (*pal_upnp_func)(
    IN Upnp_EventType event_type,
    IN VOID *event,
    IN VOID *cookie);

typedef struct{
    CHAR* name;
    CHAR* value;
}pal_string_pair;

typedef enum{
    PAL_UPNP_ACTION_REQUEST,
    PAL_UPNP_ACTION_RESPONSE
}pal_upnp_action_type;


typedef struct{
  /** The result of the operation. */
  INT32 error_code;
  /** The socket number of the connection to the requestor. */
  INT32 socket;
  /** The error string in case of error. */
  CHAR error_str[PAL_UPNP_LINE_SIZE];
  /** The Action Name. */
  CHAR action_name[PAL_UPNP_NAME_SIZE];
  /** The unique device ID. */
  CHAR dev_udn[PAL_UPNP_NAME_SIZE];
  /** The service ID. */
  CHAR service_id[PAL_UPNP_NAME_SIZE];
  /** The DOM document describing the action. */
  pal_xml_top *action_request;
  /** The DOM document describing the result of the action. */
  pal_xml_top *action_result;
  /** IP address of the control point requesting this action. */
  struct in_addr cp_addr;
  /** The DOM document containing the information from the
      the SOAP header. */
  pal_xml_top *soap_header;

}pal_upnp_action_request;

/** Represents the request for current value of a state variable in a service
 *  state table.  */

typedef struct{
  /** The result of the operation. */
  INT32 error_code;
  /** The socket number of the connection to the requestor. */
  INT32 socket;
  /** The error string in case of error. */
  CHAR err_str[PAL_UPNP_LINE_SIZE];
  /** The unique device ID. */
  CHAR dev_udn[PAL_UPNP_NAME_SIZE];
  /** The  service ID. */
  CHAR service_id[PAL_UPNP_NAME_SIZE];
  /** The name of the variable. */
  CHAR statvar_name[PAL_UPNP_NAME_SIZE];
  /** IP address of sender requesting the state variable. */
  struct in_addr cp_addr;
  /** The current value of the variable. This needs to be allocated by
   *  the caller.  When finished with it, the SDK frees this {\bf DOMString}. */
  CHAR* CurrentVal;
}pal_upnp_state_var_request;


typedef struct{
  /** The identifier for the service being subscribed to. */
  CHAR *ServiceId;
  /** Universal device name. */
  CHAR *UDN;
  /** The assigned subscription ID for this subscription. */
  pal_upnp_sid Sid;
}pal_upnp_subscription_request;

/**
* @brief Initialize the UPnP stack.
*
* Starts the UPnP library initialization with the specified interface and port.
*
* @param[in] lo_ip - Local IP address or interface name. NULL for automatic selection.
*                    \n If lo_ip is NULL, an appropriate IP address will be automatically selected.
* @param[in] lo_port - Local port to listen for incoming connections. 0 for automatic selection.
*                    \n If lo_port is 0, an appropriate port will be automatically selected.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if initialization fails.
*/
INT32 PAL_upnp_init(IN const CHAR *lo_ip, IN UINT16 lo_port);

/**
* @brief Get the local IP address.
*
* Returns the IP address string of the UPnP server.
*
* @return The ip address.
* @retval The IP address string on success.
* @retval NULL on failure.
*/
CHAR *PAL_upnp_get_ipaddress();

/**
* @brief Get the local IPv6 address.
*
* Returns the IPv6 address string of the UPnP server.
*
* @return The IPv6 address.
* @retval The IPv6 address string on success.
* @retval NULL on failure.
*/
CHAR *PAL_upnp_get_ip6address();

/**
* @brief Get the UPnP server port.
*
* Returns the port number used by the UPnP server for listening to SSDP.
*
* @return The port number.
* @retval The port number on success.
* @retval 0 on failure.
*/
UINT16 PAL_upnp_get_port();

/**
* @brief Register a root device with the UPnP library.
*
* Registers a device application with the UPnP library using the device description file.
* \n Sets the web server root directory and creates the device description URL.
* \n A device application cannot make any other API calls until it registers using this function.
* \n This path also serves as the web root directory.
*
* @param[in] lo_path - Local path for device description file. NULL for default web directory.
* @param[in] file_name - File name of device description file.
* @param[in] func - Callback function for device events.
* @param[in] cookie - Reserved for future use.
* @param[out] handle - Pointer to store the device handle.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if registration fails.
*/
INT32 PAL_upnp_register_root_device(IN const CHAR *lo_path,
                                  IN const CHAR *file_name,
                                  IN pal_upnp_func func,
                                  IN const VOID *cookie,
                                  OUT pal_upnp_device_handle *handle);

/**
* @brief Unregister a root device from the UPnP library.
*
* Unregisters a root device registered with PAL_upnp_register_root_device.
* \n After this call, the pal_upnp_device_handle is no longer valid.
* \n For all advertisements that have not yet expired, the UPnP library sends
* \n a device unavailable message automatically.
*
* @param[in] handle - Device handle to unregister.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if unregistration fails.
*/
 INT32 PAL_upnp_unregister_root_device(IN pal_upnp_device_handle handle);

/**
* @brief Send device advertisement.
*
* Sends the UPnP device advertisement and schedules a job for the next
* \n advertisement after the specified expire time.
*
* @param[in] handle - Handle for device instance.
* @param[in] expire - Time in seconds for resending the advertisement.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if advertisement fails.
*/
 INT32 PAL_upnp_send_advertisement(IN pal_upnp_device_handle handle, IN INT32 expire);

/**
* @brief Register a control point with the UPnP library.
*
* Registers a control point application with the UPnP library for receiving asynchronous events.
* \n A control point application cannot make any other API calls until it registers using this function.
*
* @param[in] func - Pointer to a callback function for receiving asynchronous events.
* @param[in] cookie - Reserved for future use.
* @param[out] handle - Pointer to store the new control point handle.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if registration fails.
*/
 INT32 PAL_upnp_register_cp (IN pal_upnp_func func,
                           IN const VOID *cookie,
                           OUT pal_upnp_cp_handle *handle);

/**
* @brief Unregister a control point from the UPnP library.
*
* Unregisters a client registered with PAL_upnp_register_cp.
* \n After this call, the pal_upnp_cp_handle is no longer valid.
* \n The UPnP library generates no more callbacks after this function returns.
*
* @param[in] handle - The handle of the control point instance to unregister.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if unregistration fails.
*/
 INT32 PAL_upnp_unregister_cp(IN pal_upnp_cp_handle handle);

 /**
* @brief Search for devices asynchronously.
*
* Searches for UPnP devices for the specified maximum time.
* \n This is an asynchronous function that schedules a search job and returns immediately.
* \n The control point is notified about search results through callbacks after the search timer expires.
*
* @param[in] handle - The handle of the control point instance.
* @param[in] max_timeout - Maximum time in seconds to wait for search replies.
* @param[in] target - Search target string.
* @param[in] cookie - Reserved for future use.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if search initiation fails.
*/
 INT32 PAL_upnp_search_async(IN pal_upnp_cp_handle handle,
                           IN INT32 max_timeout,
                           IN const CHAR *target,
                           IN const VOID *cookie);


/**
* @brief Create a UPnP action request or response.
*
* Creates an action document (request or response) from the argument list.
* \n This function creates the action request or response if it is a first
* \n argument else it will add the argument in the document.
*
* @param[in,out] action - Pointer to action buffer. NULL to create new, existing to add arguments.
* @param[in] action_name - Action name.
* @param[in] service_type - Service type string.
* @param[in] nb_params - Number of parameter pairs.
* @param[in] params - Array of parameter name-value pairs.
* @param[in] action_type - Request or response as PAL_UPNP_ACTION_REQUEST or PAL_UPNP_ACTION_RESPONSE.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval -1 if error (invalid parameters or action creation fails).
*/
 INT32 PAL_upnp_make_action( INOUT pal_xml_top** action,
                           IN const CHAR *action_name,
                           IN const CHAR *service_type,
                           IN INT32 nb_params,
                           IN const pal_string_pair* params,
                           IN pal_upnp_action_type action_type);


/**
* @brief Send a UPnP action to a service.
*
* Sends a SOAP message to change a state variable in a service.
* \n This is a synchronous call that does not return until the action is complete.
* \n The UPnP library allocates the response buffer and the caller needs to free it.
*
* @param[in] handle - Handle of control point to send action.
* @param[in] action_url - The action URL of the service.
* @param[in] service_type - The type of the service.
* @param[in] action - The action document structure.
* @param[out] response - Pointer to store the response document structure.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if action fails.
*/
 INT32 PAL_upnp_send_action( IN pal_upnp_cp_handle handle,
                           IN const CHAR *action_url,
                           IN const CHAR *service_type,
                           IN  pal_xml_top* action,
                           OUT  pal_xml_top **response);


/**
* @brief Download an XML document from a URL.
*
* Downloads and parses a device description or service description file from the specified URL.
* \n This is a synchronous call that does not return until the download is complete.
* \n The UPnP library allocates the xml_top buffer and the caller needs to free it.
*
* @param[in] url - Device or service description URL for file downloading.
* @param[out] xml_top - Pointer to store the parsed XML document structure.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if download or parsing fails.
*/
 INT32 PAL_upnp_download_xmldoc(IN const CHAR *url, OUT pal_xml_top **xml_top);


/**
* @brief Resolve a relative URL to an absolute URL.
*
* Concatenates the base URL and relative URL to generate the absolute URL.
* \n The UPnP library allocates the abs_url buffer and the caller needs to free it.
*
* @param[in] base_url - Base URL string.
* @param[in] rel_url - Relative URL string.
* @param[out] abs_url - Pointer to store the resolved absolute URL string.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if URL resolution fails.
*/
 INT32 PAL_upnp_resolve_url(IN const CHAR *base_url,
                          IN const CHAR *rel_url,
                          OUT CHAR **abs_url);


/**
* @brief Stop the UPnP library and clean up resources.
*
* Terminates the UPnP library operation and frees all allocated resources.
* \n Should be called when the application no longer needs UPnP functionality.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if cleanup fails.
*/
 INT32 PAL_upnp_finish();


/**
* @brief Subscribe to receive event notifications from a service.
*
* Registers a control point to receive event notifications from another device.
* \n This operation is synchronous and does not return until subscription is complete.
* \n Upon return, timeout contains the actual subscription time returned from the service.
*
* @param[in] handle - Handle of the control point to register event.
* @param[in] event_url - The URL of the service to subscribe to.
* @param[in,out] timeout - Pointer to requested subscription time in seconds. Returns actual subscription time.
* @param[out] sid - Pointer to store the subscription ID (SID).
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if subscription fails.
*/
 INT32 PAL_upnp_subscribe (IN pal_upnp_cp_handle handle,
                         IN const CHAR *event_url,
                         INOUT INT32 *timeout,
                         OUT pal_upnp_sid sid);


/**
* @brief Accept a subscription request and send initial event state.
*
* Accepts a subscription request and sends out the current state of the eventable variables for a service.
* \n The device application should call this function when it receives a UPNP_EVENT_SUBSCRIPTION_REQUEST callback.
* \n This function is synchronous and generates no callbacks.
*
* @param[in] handle - The handle of the device.
* @param[in] device_id - The device ID of the subdevice of the service generating the event.
* @param[in] service_id - The unique service identifier of the service generating the event.
* @param[in] var_names - Pointer to an array of event variable names.
* @param[in] var_vals - Pointer to an array of values for the event variables.
* @param[in] var_nb - The number of event variables in var_names.
* @param[in] sub_id - The subscription ID of the newly registered control point.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if acceptance fails.
*/
INT32 PAL_upnp_accept_subscription(IN pal_upnp_device_handle handle,
                                 IN const CHAR *device_id,
                                 IN const CHAR *service_id,
                                 IN const CHAR **var_names,
                                 IN const CHAR **var_vals,
                                 IN INT32 var_nb,
                                 IN pal_upnp_sid sub_id);


 /**
* @brief Send event change notification to subscribed control points.
*
* Sends out an event change notification to all control points subscribed to a particular service.
* \n This function is synchronous and generates no callbacks.
*
* @param[in] handle - The handle to the device sending the event.
* @param[in] device_id - The device ID of the subdevice of the service generating the event.
* @param[in] service_name - The unique identifier of the service generating the event.
* @param[in] var_name - Pointer to an array of variables that have changed.
* @param[in] new_value - Pointer to an array of new values for those variables.
* @param[in] var_number - The count of variables included in this notification.
*
* @return The status of the operation.
* @retval 0 if successful.
* @retval Error code if notification fails.
*/
 INT32 PAL_upnp_notify (IN pal_upnp_device_handle handle,
                      IN const CHAR *device_id,
                      IN const CHAR *service_name,
                      IN const CHAR **var_name,
                      IN const CHAR **new_value,
                      IN INT32 var_number);

/**
* @brief Get error message string for an error code.
*
* Returns the error string mapped to the specified UPnP error code.
*
* @param[in] errno - Error code.
*
* @return Error message string.
* @retval Error message string on success.
* @retval "Unknown Error" if error code is not recognized.
*/
 const CHAR *PAL_upnp_get_error_message(IN INT32 errno);

#endif //__PAL_UPNP_H__