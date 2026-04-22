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

#ifndef __CLIENTS_MGR_H_
#define __CLIENTS_MGR_H_

#include <pthread.h>
#include "sysevent/sysevent.h"

// define the number of a_client_t elements to increase our dynamic
// clients array by each time
#define NUM_CLIENTS_IN_ALLOCATED_BLOCK  4

// define the maximum length of a client name
#define CLIENT_NAME_SIZE 15

/*
 * Typedef      : a_client_t
 * Purpose      : Hold information about one connected client
 * Fields       :
 *   used          : does this structure contain information
 *                   0 is unused, non-zeof means it contains
 *                   information about some connected client
 *   id            : id assigned by the server for this client.
 *                   This is an opaque value to the client, but
 *                   the client must send this value when
 *                   communicating with the server
 *   fd            : The file descriptor that the server uses
 *                   to communicate with this client
 *   notifications : The number of notifications registered by this client
 *   errors        : The number of errors detected on this client
 *   name          : A string which the client self assigned as
 *                   identification. Its value is only used
 *                   as human viewable info about the client.
 */
typedef struct {
   int       used;
   token_t   id;
   int       fd;
   int       notifications;
   int       errors;
   char      name[CLIENT_NAME_SIZE];
   int       isData;
} a_client_t;

/*
 * Typedef      : clients_t
 * Purpose      : Hold information about all connected clients
 * Fields       :
 *   mutex           :  The mutex protecting this data structure
 *   num_cur_clients :  The number of clients in array of clients
 *   max_cur_clients :  The maximum number of clients that can fit
 *                      in the array of clients as it is currently
 *                      sized.
 *   clients         :  A dynamically growable array of clients
 */
typedef struct {
    pthread_mutex_t mutex;
    unsigned int    num_cur_clients;
    unsigned int    max_cur_clients;
    a_client_t     *clients;
} clients_t;

/**
* @brief Print all elements in the clients_t structure.
*
* This function prints detailed information about all clients currently managed by the client manager.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int print_clients_t(void);

/**
* @brief Given a client ID, return the file descriptor of that client.
*
* This function looks up a client in the clients table using the provided client ID
* and returns the associated file descriptor used for communication with that client.
*
* @param[in] id - The client ID of the client to look up.
*
* @return The file descriptor of the client or an error code.
* @retval >0 The file descriptor that the client listens on.
* @retval 0 Client ID not found.
* @retval <0 Some error.
*
*/
int CLI_MGR_id2fd (token_t id);

/**
* @brief Given a file descriptor, return the corresponding client ID.
*
* This function looks up a client in the clients table using the provided file descriptor
* and returns the associated client ID (token).
*
* @param[in] fd - A file descriptor.
*
* @return The client ID token
* @retval token_t Valid client ID on success
* @retval TOKEN_INVALID Not a valid client.
*
* @note Due to the multi-threaded nature of syseventd, you cannot guarantee anything about
*       the client or its validity after this call ends. Don't use the return token.
*/
token_t CLI_MGR_fd2id (const int fd);

/**
* @brief Add a new client to the database of clients.
*
* This function creates a new client entry in the clients table, assigns it a unique
* client ID, and associates it with the provided file descriptor for communication.
*
* @param[in] name - A printable name assigned by the client.
* @param[in] fd - The connection ID (file descriptor) for communication with this client.
*
* @return Pointer to the newly created client structure
* @retval Non-NULL pointer to a_client_t structure on success.
* @retval NULL if error occurred.
*
*/
a_client_t *CLI_MGR_new_client(const char *name, const int fd);

/**
* @brief Remove a client from the table of clients.
*
* This function removes a client entry from the clients table identified by its file descriptor.
* If the client has registered for notifications, those registrations will be removed as well.
*
* @param[in] fd - The file descriptor that we receive messages from that client.
* @param[in] id - The client ID, if known.
* @param[in] force - Flag to force removal even if ID doesn't match CLI_MGR data.
*                    \n 0 is not force, 1 is force.
*
* @return The status of the operation.
* @retval 0 on Success.
* @retval <0 on error.
*/
int CLI_MGR_remove_client_by_fd (const int fd, const token_t id, const int force);

/**
* @brief Clear the number of errors for a client.
*
* This function resets the error counter to zero for a client identified by its file descriptor.
*
* @param[in] fd - The file descriptor that we receive messages from that client.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int CLI_MGR_clear_client_error_by_fd (int fd);

/**
* @brief Increment the number of errors for a client and handle threshold.
*
* This function increments the error counter for a client identified by its file descriptor.
* If the number of errors surpasses a threshold, then force closed and removed from the clients table.
*
* @param[in] fd - The file descriptor that we receive messages from that client.
*
* @return The status of the operation.
* @retval 0 Errors incremented.
* @retval 1 Client forcibly disconnected.
* @retval <0 An error occurred.
*
*/
int CLI_MGR_handle_client_error_by_fd (int fd);

/**
* @brief Increment the number of notifications that a client has registered for.
*
* This function increments the notification counter for a client identified by its file descriptor.
* This counter tracks how many event notifications the client has subscribed to.
*
* @param[in] fd - The file descriptor that we receive messages from that client.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int CLI_MGR_add_notification_to_client_by_fd (int fd);


/**
* @brief Initialize the table of clients.
*
* This function initializes the global clients table.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
* @retval <0 Some error occurred.
*
*/
int CLI_MGR_init_clients_table(void);

/**
* @brief Uninitialize the table of clients.
*
* This function cleans up the global clients table by freeing all client structures,
* closing their connections, releasing allocated memory, and resetting the client ID counter.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int CLI_MGR_deinit_clients_table(void);

/**
* @brief Given a client ID, return the client's name.
*
* This function looks up a client in the clients table using the provided client ID
* and returns the client's self-assigned name string.
*
* @param[in] id - The client ID of the client to look up.
*
* @return Pointer to the client's name string.
* @retval Valid client name string on initialization.
* @retval "null" If client ID not found or client manager not initialized.
*
*/
char* CLI_MGR_id2name (token_t id);

#endif   // __CLIENTS_MGR_H_