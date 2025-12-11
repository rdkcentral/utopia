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

/**
 * @file   rpc_client.h
 * @author Comcast Inc
 * @date   13 May 2013
 * @brief  rpc client initialising api declaration
 */

#ifndef RPCCLIENT_H
#define RPCCLIENT_H

#include <stdio.h>
#include <rpc/rpc.h>
//static CLIENT *clnt;

/**
* @brief Initialize RPC client and establish connection to RPC server daemon.
*
* This function initializes the RPC client by storing the server IP address and creating
* a client connection using clnt_create() with TCP protocol.
*
* @param[in] mainArgv - Null-terminated string containing the IP address of the machine where
*                    \n the RPC daemon is running.
*                    \n Maximum length is limited by rpcServerIp buffer size.
*
* @return The status of the RPC connection.
* @retval 1 if the RPC connection was successfully established.
* @retval 0 if the RPC connection failed.
*
*/
int initRPC(char* mainArgv);

/**
* @brief Retrieve the RPC client instance.
*
* This function returns a pointer to the global RPC CLIENT instance that was created during
* initRPC(). The CLIENT pointer is used to make RPC calls to the remote server.
*
* @return Pointer to the RPC CLIENT instance.
* @retval CLIENT* pointer if the RPC client is initialized.
* @retval NULL if the RPC client is not initialized or connection failed.
*
*/
CLIENT* getClientInstance();

/**
* @brief Check if RPC connection loss occurred based on error string.
*
* This function examines an error string to determine if it indicates an RPC connection loss.
*
* @param[in] errString - Null-terminated string containing the error message to analyze..
*
* @return Boolean indicating whether the error represents a connection loss.
* @retval true if the error string contains "Connection reset by peer".
* @retval false if the error string does not indicate a connection loss.
*
*/
bool isRPCConnectionLoss(char* errString);
#endif