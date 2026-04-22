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

#ifndef __TRIGGER_MGR_H_
#define __TRIGGER_MGR_H_

#include <pthread.h>
#include "sysevent/sysevent.h"


/*
 ====================================================================
                           Typedefs

The structures trigger_list_t, trigger_t, and trigger_action_t are
all related:
A triggerlist_t contains pointers to an arbitrary number of trigger_t
and a trigger_t contains pointers to an arbitrary number of trigger_action_t.

Each of the above structures are designed to hold arbitrary numbers of
other structures. This allows them to grow as required, and in theory
to shrink as well (although shrinking is not currently supported since
it does not appear that there will be a need for this).

 ====================================================================
 */
typedef enum {
   ACTION_TYPE_UNKNOWN,
   ACTION_TYPE_EXT_FUNCTION,
   ACTION_TYPE_MESSAGE
}  action_type_t;

/*
 * trigger_action_t
 *
 * An action to execute when a trigger hits
 *
 * Fields:
 *    used              : An indication of whether the action is
 *                        used or empty
 *    owner             : The owner of the action
 *    action_flags      : The flags of the action
 *    action_type       : The type of action
 *    action_id         : The id of the action
 *    action            : The path and name of the action
 *    argc              : The number of arguments
 *    argv              : The arguments
 */
typedef struct {
   int                   used;
   token_t               owner;
   action_flag_t         action_flags;
   action_type_t         action_type;
   int                   action_id;
   char                  *action;
   int                    argc;
   char                   **argv;
} trigger_action_t;

/*
 * trigger_t
 *
 * The list of triggers along with the actions associated with the trigger
 * A trigger is a trigger id along with a set of actions.
 *
 * Fields:
 *    used                : An indication of whether the action is
 *                          used or empty
 *    trigger_id          : The id of the trigger
 *    max_actions         : The maximum number of actions that can be in the list
 *    num_actions         : The number of actions currently in the list
 *    next_action_id      : The next action_id to allocate for a new action
 *    trigger_actions     : Actions to execute when the trigger hits
 *    trigger_flags       : Flags to control trigger action execution
 */
typedef struct {
   int                   used;
   int                   trigger_id;
   unsigned int          max_actions;
   unsigned int          num_actions;
   int                   next_action_id;
   tuple_flag_t          trigger_flags;
   trigger_action_t      *trigger_actions;
} trigger_t;

/*
 * trigger_list_t
 *
 * A list of trigger and the notifications associated with them
 *
 * Fields:
 *   mutex             : The mutex protecting this data structure
 *   max_triggers      : The maximum number of triggers that can be in the list
 *   num_triggers      : The number of triggers curerntly in the list
 *   triggers          : A list of triggers and notifications
 */
typedef struct {
   pthread_mutex_t  mutex;
   unsigned int     max_triggers;
   unsigned int     num_triggers;
   trigger_t        *trigger_list;
} trigger_list_t;

/*
 ====================================================================
                       FUNCTIONS

The TRIGGER_MGR is responsible for maintaining triggers and actions
to be applied when those triggers change state.

An action is a call that is executed when the trigger changes state.
An action is a function call along with the parameters to be passed
in that call. In general parameters are passed with exactly the same
value as was given when creating the action. However, if the parameter
begins with a $ then the value sent will be the current value of the
trigger for that value. If no such trigger exists yet, then "NULL" will
be sent as that parameter.


 ====================================================================
 */

#ifdef SE_SERVER_CODE_DEBUG
/**
* @brief Print the global list of triggers.
*
* This function prints detailed information about all triggers and their associated actions
* in the global trigger list. Used for debugging purposes.
*
* @return The status of the operation.
* @retval 0 Success.
*
*/
int TRIGGER_MGR_print_trigger_list_t(void);
#endif

/**
* @brief Set the flags on a trigger.
*
* This function sets the tuple flags on an existing trigger or creates a new trigger
* with the specified flags.
*
* @param[in] target_id - A trigger ID if assigned or 0 for a new trigger.
* @param[in] flags - The flags to set.
* @param[out] trigger_id - On return, the trigger ID with the flags set.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note This function is called by data manager while it has a mutex lock. DO NOT CALL ANY DATA_MGR functions.
*/
int TRIGGER_MGR_set_flags(int target_id, tuple_flag_t flags, int *trigger_id);

/**
* @brief Remove a specific action from a trigger.
*
* This function removes an action from a trigger identified by the trigger ID and action ID.
* The trigger and action IDs must match those returned when the action was originally added.
*
* @param[in] trigger_id - The trigger ID given when the action was added.
* @param[in] action_id - The action ID given when the action was added.
* @param[in] owner - Owner of the trigger action.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note In order to find the appropriate trigger, the trigger_id must match the trigger_id that was returned
* when the action was added, AND the action_id must match the action_id that was given when the action was added.
* owner is not currently used, but it is included in the call for future use if needed.
*/
int TRIGGER_MGR_remove_action(int trigger_id, int action_id, const token_t owner);

/**
* @brief Remove all actions owned by a trigger and remove the trigger.
*
* This function removes all actions associated with a trigger and then removes the trigger itself,
* freeing all associated resources.
*
* @param[in] trigger_id - The trigger ID of the trigger to remove.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero some error.
*
*/
int TRIGGER_MGR_remove_trigger(int trigger_id);

/**
* @brief Add an action to call an external executable when a trigger value changes.
*
* This function registers an action that executes an external program when the trigger's associated data
* tuple changes value. The action is added to the specified trigger, or a new trigger is created if target_id is 0.
*
* @param[in] target_id - The trigger_id to which to add this action.
*                        0 means a new trigger should be assigned.
* @param[in] owner - Owner of the trigger action.
* @param[in] action_flags - Flags to apply to this action.
* @param[in] action - The path and filename of the action to call when the trigger changes value.
* @param[in] args - The arguments of the command to add to the action list.
*                   The arguments are expected to be in the form:
*                   arg[0] = path and filename of executable
*                   arg[1-x] = arguments to send to executable
*                   last argument is NULL.
* @param[out] trigger_id - On return the ID of the trigger.
* @param[out] action_id - On return the ID of the action.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero some error.
*
* @note This function is called by data manager while it has a mutex lock. DO NOT CALL ANY DATA_MGR functions.
*/
int TRIGGER_MGR_add_executable_call_action(int target_id, const token_t owner, action_flag_t action_flags, char *action, char **args, int *trigger_id, int *action_id);

/**
* @brief Add an action to send a message when a trigger value changes.
*
* This function add an action to call an external executable which will be executed when a trigger value changes.
*
* @param[in] target_id - The trigger_id to which to add this action.
*                        0 means a new trigger should be assigned.
* @param[in] owner - Owner of the trigger action.
* @param[in] action_flags - Flags to apply to this action.
* @param[out] trigger_id - On return the ID of the trigger.
* @param[out] action_id - On return the ID of the action.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note This function is called by data manager while it has a mutex lock. DO NOT CALL ANY DATA_MGR functions.
*/
int TRIGGER_MGR_add_notification_message_action(int target_id, const token_t owner, action_flag_t action_flags, int *trigger_id, int *action_id);

/**
* @brief Remove all notification message actions owned by a particular owner.
*
* This function removes all IPC notification message actions (SE_MSG_NOTIFICATION) that
* are owned by the specified owner. Typically called when a client disconnects.
*
* @param[in] owner - Owner of the trigger actions to remove.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note This only affects IPC notifications (SE_MSG_NOTIFICATION).
*/
int TRIGGER_MGR_remove_notification_message_actions(const token_t owner);

/**
* @brief Execute all actions set for a trigger.
*
* This function executes all registered actions associated with a trigger when the trigger's data tuple changes value.
*
* @param[in] trigger_id - The trigger ID of the trigger upon which to execute actions.
* @param[in] name - The name of the data tuple that the trigger is on.
* @param[in] value - The value of the data tuple that the trigger is on.
* @param[in] source - The original source of this set.
* @param[in] tid - A transaction ID for notification messages.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note This function is called by data manager while it has a mutex lock. DO NOT CALL ANY DATA_MGR functions.
*/
int TRIGGER_MGR_execute_trigger_actions(const int trigger_id, const char* const name, const char* const value, const int source, const int tid);

/**
* @brief Execute all actions set for a trigger with binary data.
*
* This function executes all registered actions associated with a trigger when the trigger's
* data tuple changes value. This variant handles binary data values.
*
* @param[in] trigger_id - The trigger ID of the trigger upon which to execute actions.
* @param[in] name - The name of the data tuple that the trigger is on.
* @param[in] value - The binary value of the data tuple that the trigger is on.
* @param[in] value_length - The length of the binary value in bytes.
* @param[in] source - The original source of this set.
* @param[in] tid - A transaction ID for notification messages.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*/
int TRIGGER_MGR_execute_trigger_actions_data(const int trigger_id, const char* const name, const char* const value, const int value_length, const int source, const int tid);

/**
* @brief Find and clone an action given a trigger_id and action_id.
*
* This function locates an action within a trigger and creates a copy of it in the provided
* structure. The caller must free the cloned action using TRIGGER_MGR_free_cloned_action.
*
* @param[in] trigger_id - The trigger ID of the trigger.
* @param[in] action_id - The action_id of the action.
* @param[out] in_action - A pointer to a trigger_action_t to put the action.
*
* @return The status of the operation.
* @retval 0 Success.
* @retval Non-zero Some error.
*
* @note Caller must free the action using TRIGGER_MGR_free_cloned_action.
*/
int TRIGGER_MGR_get_cloned_action(int trigger_id, int action_id, trigger_action_t *in_action);

/**
* @brief Free a cloned action.
*
* This function frees all memory associated with a cloned trigger_action_t structure
* that was obtained via TRIGGER_MGR_get_cloned_action.
*
* @param[in,out] action - A pointer to a trigger_action_t clone to free.
*
* @return The status of the operation.
* @retval 0 Success.
*
*/
int TRIGGER_MGR_free_cloned_action(trigger_action_t *action);

/**
* @brief Initialize the Trigger Manager.
*
* This function initializes the trigger manager by setting up the global trigger list and preparing internal structures
* for managing triggers and actions. This must be called before any other trigger manager functions are used.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
* @retval <0 Some error occurred.
*
*/
int TRIGGER_MGR_init(void);

/**
* @brief Uninitialize the Trigger Manager.
*
* This function cleans up the trigger manager by freeing all triggers, actions, and releasing allocated memory.
*
* @return The status of the operation.
* @retval 0 if the operation is successful.
*
*/
int TRIGGER_MGR_deinit(void);


#endif   // __TRIGGER_MGR_H_