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

#ifndef __DATA_MGR_H_
#define __DATA_MGR_H_

#define MIMIC_BROADCOM_RC 1
#include "triggerMgr.h"

#ifdef MIMIC_BROADCOM_RC
/**
* @brief Commit data changes.
*
* This function commits pending data changes in the data manager.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int  DATA_MGR_commit();
#endif

/*
 * data_element_t
 *
 * A data elements (name/value) and the trigger id of this data element
 *
 * Fields:
 *    used              : An indication of whether the data_element is
 *                        used or empty
 *    source            : The original source of this set
 *    tid               : The transaction id associated with this element
 *    trigger_id        : The id of the trigger associated with this element,
 *                         0 is no trigger
 *    options           : A bitfield describing options. Note that
 *                        options are also kept in triggerMgr
 *    name              : The name of the data element
 *    value             : The current value of the data element
 */
typedef struct {
   int                   used;
   int                   source;
   int                   tid;
   int                   trigger_id;
   tuple_flag_t          options;
   char                  *name;
   char                  *value;
   int                  value_length;
} data_element_t;

/*
 * data_element_list_t
 *
 * A list of data_element_t
 *
 * Fields:
 *   mutex             : The mutex protecting this data structure
 *   max_elements      : The maximum number of data elements that can be in the list
 *   num_elements      : The number of data elements currently in the list
 *   elements          : The list of data elements
 */
typedef struct {
   pthread_mutex_t  mutex;
   unsigned int     max_elements;
   unsigned int     num_elements;
   data_element_t   *elements;
} data_element_list_t;


/**
* @brief Get the value of a particular data item.
*
* This function retrieves the value of a data item identified by its name and copies
* it to the provided buffer.
*
* @param[in] name - The data item to retrieve.
* @param[out] value_buf - The buffer to copy the value in.
* @param[in,out] buf_size - On input the number of bytes in value_buf.
*                           \n On output the number of bytes copied into value_buf.
*                           \n subject to the Notes below
*
* @return Pointer to the buffer containing the value.
* @retval Non-NULL Pointer to the buffer containing the value on success.
* @retval NULL No such data item found, or NULL is the data item value.
*
* @note If the value_buf is too small then the value WILL be truncated. There will always
* be a '\0' at the end of the value_buf string. If the return value of buf_size is >= the
* input size of buf_size, then the value_buf contains a truncated string. The string will
* be untruncated only if outgoing buf_size < incoming buf_size.
*/
char *DATA_MGR_get(char *name, char *value_buf, int *buf_size);

/**
* @brief Get the binary value of a particular data item.
*
* This function retrieves the binary value of a data item identified by its name and
* copies it to the provided buffer.
*
* @param[in] name - The data item to retrieve.
* @param[out] value_buf - The buffer to copy the value in.
* @param[in,out] buf_size - On input the number of bytes in value_buf.
*                           On output the number of bytes copied into value_buf.
*
* @return Pointer to the buffer containing the value.
* @retval Non-NULL Pointer to the buffer containing the value on success.
* @retval NULL No such data item found, or NULL is the data item value.
*
*/
char *DATA_MGR_get_bin(char *name, char *value_buf, int *buf_size);

/**
* @brief Set the value of a particular data item and execute all actions for that trigger.
*
* This function sets the value of a data item identified by its name. If the value has changed,
* it executes all actions associated with the trigger for that data element.
*
* @param[in] name - The name of the data item to set value.
* @param[in] value - The value to set the data item to.
* @param[in] source - The original source of this set.
* @param[in] tid - Transaction ID for this set.
* @param[in] who - Token identifying the caller.
*
* @return The status of the operation.
* @retval 0 on Success.
* @retval Non-zero on error.
*
*/
int DATA_MGR_set(char *name, char *value, int source, int tid, token_t who);

/**
* @brief Set the binary value of a particular data item and execute all actions for that trigger.
*
* This function sets the binary value of a data item identified by its name. If the value has changed,
* it executes all actions associated with the trigger for that data element.
*
* @param[in] name - The name of the data item to set value.
* @param[in] value - The binary value to set the data item to.
* @param[in] value_length - The length of the binary value in bytes.
* @param[in] source - The original source of this set.
* @param[in] tid - Transaction ID for this set.
*
* @return The status of the operation.
* @retval 0 on Success.
* @retval Non-Zero on error.
*
*/
int DATA_MGR_set_bin(char *name, char *value, int value_length, int source, int tid);

/**
* @brief Create a unique tuple using name as a seed and set its value.
*
* This function creates a unique tuple (data element) based on the provided name seed
* and assigns it the specified value. The unique name is returned in the provided buffer.
*
* @param[in] name - The preamble name of the data item to create and set value.
* @param[in] value - The value to set the data item to.
* @param[out] uname_buf - The buffer to copy the unique name in.
* @param[in,out] buf_size - On input the number of bytes in name_buf.
*                           \n On output the number of bytes copied into name_buf.
 *                           \n subject to the Notes below
*
* @return Pointer to the buffer containing the assigned unique name.
* @retval Pointer to the unique name on success.
* @retval NULL No such data item found, or NULL is the data item value.
*
* @note If the value_buf is too small then the value WILL be truncated.
* There will always be a '\0' at the end of the name_buf string. If the
* return value of buf_size is >= the input size of buf_size, then the name_buf
* contains a truncated string. The string will be untruncated only if outgoing
* buf_size < incoming buf_size.
*/
char *DATA_MGR_set_unique(char *name, char *value, char *uname_buf, int *buf_size);

/**
* @brief Get the value of the next tuple in a namespace.
*
* This function retrieves the next tuple (data element) from a namespace using an iterator.
* Both the unique name and value are returned in the provided buffers.
*
* @param[in] name - The namespace.
* @param[in,out] iterator - An iterator for within the namespace.
*                           Updated to point to the next element after the current one.
* @param[out] sub_buf - The buffer to copy the unique name of the subject.
* @param[in,out] sub_size - On input the number of bytes in sub_buf.
*                           On output the number of copied bytes.
* @param[out] value_buf - The buffer to copy the value in.
* @param[in,out] value_size - On input the number of bytes in value_buf.
*                             \n On output the number of bytes copied into value_buf.
*                             \n subject to the Notes below
*
* @return Pointer to the buffer containing the value.
* @retval Non-NULL Pointer to the buffer containing the value on success.
* @retval NULL No such data item found, or NULL is the data item value.
*
* @note If the value_buf is too small then the value WILL be truncated. There will
* always be a '\0' at the end of the name_buf string. If the return value of buf_size
* is >= the input size of buf_size, then the name_buf contains a truncated string. The
* string will be untruncated only if outgoing buf_size < incoming buf_size
*/
char *DATA_MGR_get_unique(char *name, unsigned int *iterator, char *sub_buf, unsigned int *sub_size, char *value_buf, unsigned int *value_size);

/**
* @brief Delete one element from a unique namespace.
*
* This function deletes a specific element from a unique namespace identified by the iterator.
*
* @param[in] name - The namespace.
* @param[in] iterator - An iterator for within the namespace of the element to delete.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int DATA_MGR_del_unique(char *name, unsigned int iterator);

/**
* @brief Given a namespace and an iterator, return the next iterator.
*
* This function retrieves the next iterator value for traversing a namespace.
*
* @param[in] name - The namespace.
* @param[in,out] iterator - An iterator for within the namespace.
*                           Updated to point to the next iterator value.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int DATA_MGR_get_next_iterator(char *name, unsigned int *iterator);

/**
* @brief Set the option flags of a particular data item.
*
* This function sets the tuple option flags for a data item, which control its behavior.
*
* @param[in] name - The name of the data item to set flags.
* @param[in] flags - The flag values of the data item.
*
* @return The status of the operation.
* @retval 0 on Success.
* @retval Non-Zero on error.
*
*/
int DATA_MGR_set_options(char *name, tuple_flag_t flags);

/**
* @brief Assign an argument vector to a global argv making string substitutions.
*
* This function creates a new argument vector by making inline substitutions wherever
* original arguments start with SYSCFG_NAMESPACE_SYMBOL or SYSEVENT_NAMESPACE_SYMBOL.
*
* @param[in] in_argv - The original argument vector.
*
* @return The argument vector replacement.
* @retval Non-NULL The argument vector replacement on success.
* @retval NULL on error occurred.
*
* @note The caller must NOT free any of the memory associated with the returned argument
* It will be freed as required by the data manager. This procedure should be called with
* the data manager locked.
*/
char **DATA_MGR_get_runtime_values (char **in_argv);

/**
* @brief Set an async notification on a data element which calls an external executable.
*
* This function registers an asynchronous notification on a data element that executes
* an external program when the data variable changes value.
*
* @param[in] name - The name of the data item to add an async notification to.
* @param[in] owner - Owner of the async notification.
* @param[in] action_flags - Flags to apply to the action.
* @param[in] action - The path and filename of the action to call when the data element changes value.
* @param[in] args - The arguments of the command to add to the action list.
*                   The arguments are expected to be in the form
*                   arg[0]   = path and filename of executable
*                   arg[1-x] = arguments to send to executable
*                   last argument is NULL.
* @param[out] trigger_id - On return the ID of the trigger.
* @param[out] action_id - On return the ID of the action.
*
* @return The status of the operation.
* @retval 0 on Success.
* @retval Non-Zero on error.
*
*/
int DATA_MGR_set_async_external_executable(char *name, token_t owner, action_flag_t action_flags, char *action, char **args, int *trigger_id, int *action_id);

/**
* @brief Set an async notification on a data element which sends a message.
*
* This function registers an asynchronous notification on a data element that sends
* a message to the connected client when a data variable changes value.
*
* @param[in] name - The name of the data item to add an async notification to.
* @param[in] owner - Owner of the async notification.
* @param[in] action_flags - Flags to apply to the action.
* @param[out] trigger_id - On return the ID of the trigger.
* @param[out] action_id - On return the ID of the action.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval Non-Zero on error.
*
*/
int DATA_MGR_set_async_message_notification(char *name, token_t owner, action_flag_t action_flags, int *trigger_id, int *action_id);

/**
* @brief Remove an async notification on a data element.
*
* This function removes a previously registered asynchronous notification from a data element.
*
* @param[in] trigger_id - The ID of the trigger.
* @param[in] action_id - The ID of the action.
* @param[in] owner - Owner of the async notification.
*
* @return The status of the operation.
* @retval 0 on success.
* @retval Non-Zero on error.
*
*/
int DATA_MGR_remove_async_notification(int trigger_id, int action_id, const token_t owner);

/**
* @brief Initialize the DATA MGR.
*
* This function initializes the data manager by setting up the data element list
* and preparing the internal structures for managing tuples.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
* @retval <0 on error.
*
*/
int DATA_MGR_init(void);

/**
* @brief Uninitialize the DATA MGR.
*
* This function cleans up the data manager by freeing all data elements and
* releasing allocated memory.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int DATA_MGR_deinit(void);

/**
* @brief Print the value of all data items known to syseventd.
*
* This function dumps all data items (tuples).
*
* @param[in] file - Name of the file to dump the values to.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int DATA_MGR_show(char *file);

#endif   // __DATA_MGR_H_