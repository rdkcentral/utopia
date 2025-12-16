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

#ifndef _SRVMGR_H_
#define _SRVMGR_H_

#if defined (_CBR_PRODUCT_REQ_) || defined (_XB6_PRODUCT_REQ_)
#define CONSOLE_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
#define CONSOLE_LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define DBG_PRINT(fmt ...)     {\
										FILE     *fp        = NULL;\
                                        fp = fopen ( CONSOLE_LOG_FILE, "a+");\
                                        if (fp)\
                                        {\
                                            fprintf(fp,fmt);\
                                            fclose(fp);\
                                        }\
                               }\

/*
 * These are flags which correspond to sysevent.h flags.
 * They MUST be in sync
 */
#define TUPLE_FLAG_NORMAL                   "0x00000000"
#define TUPLE_FLAG_SERIAL                   "0x00000001"
#define TUPLE_FLAG_EVENT                    "0x00000002"
#define ACTION_FLAG_NORMAL                  "0x00000000"
#define ACTION_FLAG_NOT_THREADSAFE          "0x00000001"
#define ACTION_FLAG_COLLAPSE_PENDING_QUEUE  "0x00000002"

/*
 * Typedef      : cmd_type_t
 * Purpose      : The command line parameter
 */
typedef enum {
   nochoice,
   start,
   stop,
   restart
} cmd_type_t;

/**
* @brief Parse command line parameters to determine service operation.
*
* @param[in] argc  - The number of command line parameters.
*                    \n Specifies the count of command line arguments passed to the program.
* @param[in] argv  - The command line string array.
*                    \n Array of strings containing the command line arguments.
*                    \n Expected values for argv[1] are "start", "stop", or "restart".
*
* @return The parsed command type.
* @retval start If argv[1] is "start".
* @retval stop If argv[1] is "stop".
* @retval restart If argv[1] is "restart".
* @retval nochoice If argc is less than 2 or argv[1] does not match any expected command.
*
*/
cmd_type_t parse_cmd_line (int argc, char **argv);

/**
* @brief Register a service's handler for activation upon default and custom events.
*
* @param[in] srv_name  - Pointer to the name of the service registering.
*                    \n The service name is used to construct default event names (<srv_name>-start, <srv_name>-stop, <srv_name>-restart).
* @param[in] default_handler  - Pointer to the path/file to the handler for default events.
*                    \n This handler will be activated for service start, stop, and restart events.
*                    \n Default events have tuple flag 0x00000002 set to trigger even when value is unchanged.
*                    \n Can be NULL if only custom events are needed.
* @param[in] custom  - Array of strings containing information about custom events and handlers.
*                    \n Each string uses the format: "event_name | path/file to handler | sysevent activation flags or NULL | sysevent tuple flags or NULL | extra parameters".
*                    \n Extra parameters can be syscfg runtime values (e.g., $wan_proto), sysevent runtime values (e.g., @current_wan_ipaddr), or constants.
*                    \n The array must be NULL-terminated.
*                    \n Can be NULL if no custom events are needed.
*
* @return The status of the operation.
* @retval 0 Registration successful.
* @retval <0 Registration failed .
*
*/
int sm_register (const char* srv_name, const char* default_handler, const char** custom);

/**
* @brief Unregister all event notifications for a service.
*
* @param[in] srv_name  - Pointer to the name of the service unregistering.
*                    \n The function removes all registered handlers for default events (<srv_name>-start, <srv_name>-stop, <srv_name>-restart) and custom events.
*                    \n Opens connection to syseventd to cancel all async notifications associated with the service.
*
* @return The status of the operation.
* @retval 0 Unregistration successful.
* @retval -1 Unregistration failed.
*
*/
int sm_unregister (const char* srv_name);

#endif  // _SRVMGR_H_
