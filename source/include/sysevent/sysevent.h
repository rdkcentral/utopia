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

#ifndef __LIB_SYSEVENT_H_
#define __LIB_SYSEVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>


/*
 * Well known port of the sysevent daemon
 */
#define SE_SERVER_WELL_KNOWN_PORT  52367

/*
 * Well known UDS
 */
#define UDS_PATH "/tmp/syseventd_connection"


/*
 * current version of se messages
 */
#define SE_VERSION          1


/*
 * Given a *se_msg_hdr calculate the address of the body
 * of the message
 */
#define SE_MSG_HDR_2_BODY(a) ((char *)(a) + sizeof(se_msg_hdr))

/*
 * The maximum size of a SE msg
 * Note: For ARM linux this value must be a multiple of
 * sizeof(int) - 1
 */
#define SE_MAX_MSG_SIZE 1023
#define SE_MAX_MSG_DATA_SIZE 40960 /* 40K Max */
#define SE_MAX_MSG_DATA_SIZE_READ_FILE "/tmp/sysevent_binsize_max"

/*
 * null async_id_t
 */
#define NULL_ASYNC_ID {0,0}
/*
 * For iterating through unique namespaces (in dataMgr) we use an iterator
 * which users initialize to NULL_ITERATOR
 */
#define SYSEVENT_NULL_ITERATOR 0xFFFFFFFF

/*
 * The ARM processor will not necessarily align
 * a char * on a 4 byte boundry, but SE msg
 * contain an int which needs to be properly aligned.
 * This makes a problem when typecasting from char * to se_msg
 * as is commonly done for reading from an fd into a buffer
 * and then using that buffer as a structure
 */
typedef char se_buffer[SE_MAX_MSG_SIZE+1] __attribute__ ((aligned(4)));

/*
 *    Errors
 */
#define ERR_NAME_TOO_LONG        -1241
#define ERR_BAD_PORT             -1242
#define ERR_INCORRECT_VERSION    -1243
#define ERR_BAD_DESTINATION      -1244
#define ERR_MSG_PREPARE          -1245
#define ERR_SOCKET_OPEN          -1246
#define ERR_CANNOT_CONNECT       -1247
#define ERR_REGISTRATION_REFUSED -1248
#define ERR_ALREADY_CONNECTED    -1249
#define ERR_NOT_CONNECTED        -1250
#define ERR_NO_PING_REPLY        -1251
#define ERR_INSUFFICIENT_ROOM    -1252
#define ERR_BAD_BUFFER           -1253
#define ERR_SERVER_ERROR         -1254
#define ERR_MSG_TOO_LONG         -1255
#define ERR_VALUE_NOT_FOUND      -1256
#define ERR_CANNOT_SET_STRING    -1257
#define ERR_PARAM_NOT_FOUND      -1258
#define ERR_OUT_OF_ORDER         -1259
#define ERR_CORRUPTED            -1260
#define ERR_DUPLICATE_MSG        -1261

typedef enum
{
   SE_MSG_NONE                        = 0,
   /* inter-thread messages */
   SE_MSG_DIE                         = 1,
   SE_MSG_SEND_NOTIFICATION           = 2,
   SE_MSG_EXECUTE_SERIALLY            = 3,
   SE_MSG_RUN_EXTERNAL_EXECUTABLE     = 4,
   /* inter-process messages */
   SE_MSG_OPEN_CONNECTION             = 5,
   SE_MSG_OPEN_CONNECTION_REPLY       = 6,
   SE_MSG_CLOSE_CONNECTION            = 7,
   SE_MSG_CLOSE_CONNECTION_REPLY      = 8,
   SE_MSG_PING                        = 9,
   SE_MSG_PING_REPLY                  = 10,
   SE_MSG_NEW_CLIENT                  = 11,
   SE_MSG_GET                         = 12,
   SE_MSG_GET_REPLY                   = 13,
   SE_MSG_SET                         = 14,
   SE_MSG_SET_REPLY                   = 15,
   SE_MSG_SET_UNIQUE                  = 16,
   SE_MSG_SET_UNIQUE_REPLY            = 17,
   SE_MSG_DEL_UNIQUE                  = 18,
   SE_MSG_SET_OPTIONS                 = 19,
   SE_MSG_SET_OPTIONS_REPLY           = 20,
   SE_MSG_ITERATE_GET                 = 21,   /* get value of next unique element in namespace using a given iterator */
   SE_MSG_ITERATE_GET_REPLY           = 22,
   SE_MSG_NEXT_ITERATOR_GET           = 23,   /* get next iterator of a namespace using current iterator as seed */
   SE_MSG_NEXT_ITERATOR_GET_REPLY     = 24,
   SE_MSG_SET_ASYNC_ACTION            = 25,
   SE_MSG_SET_ASYNC_MESSAGE           = 26,
   SE_MSG_SET_ASYNC_REPLY             = 27,
   SE_MSG_REMOVE_ASYNC                = 28,
   SE_MSG_REMOVE_ASYNC_REPLY          = 29,
   SE_MSG_NOTIFICATION                = 30,
   SE_MSG_SHOW_DATA_ELEMENTS          = 31,
   SE_MSG_ERRORED                     = 32,  /* msg corrupted */
   SE_MSG_DEBUG                       = 33,   /* change debug level */
   SE_MSG_SET_DATA                    = 34,
   SE_MSG_GET_DATA                    = 35,
   SE_MSG_GET_DATA_REPLY              = 36,
   SE_MSG_SEND_NOTIFICATION_DATA      = 37,
   SE_MSG_SET_ASYNC_MESSAGE_DATA      = 38,
   SE_MSG_NOTIFICATION_DATA           = 39,
   SE_MSG_RUN_EXTERNAL_EXECUTABLE_DATA = 40,
   SE_MSG_OPEN_CONNECTION_DATA        = 41,
} se_msg_type;

typedef unsigned int token_t;

#define TOKEN_NULL     0
#define TOKEN_INVALID -1
#define MSG_DELIMITER 0xFEEDFAD0
/*
 * se_msg_hdr
 *
 * The header of every SE message below
 *
 * Fields  :
 *    poison  : A field that must be set to 0xfeedfad0
 *    mbytes  : The total number of bytes in the message including the header
 *    mtype   : The type of message
 *    sender  : The sender of the message
 *              0 is from the sysevent daemon
 *              a client uses the token_id from the se_open_connection_reply_msg
 *              (except for se_open_connection_msg when it doesn't have an token_id yet)
 * Note  : It is better if the se_msg_hdr is word aligned
 */
typedef struct
{
   int           poison;
   int           mbytes;  /* number of bytes in message */
   se_msg_type   mtype;   /* type of message            */
   token_t       sender_token;  /* id of sender               */
} se_msg_hdr;

/*
 * se_msg_footer
 * The transport footer of each SE message
 *
 * Fields  :
 *   poison  : A field that is st to 0xfeedfad0 during transport
 *
 * Notes   : The footer is added prior to sending a message and it is removed when received
 *           by the transport layer
 */
typedef struct
{
   int           poison;
} se_msg_footer;

/*
 * note that in all of the messages, strings are represented as
 * se_msg_string types
 */

/*
 * se_msg_string
 *    The representation of a string in a SE message
 *    size          : the number of bytes in the next field
 *    str           : the string
 * NOTE: There are places in libsystem.c that assume that the string
 * is immediately after size. Do not add any variables into the structure
 * without considering that implication
 */
typedef struct {
    unsigned int  size;
/*    char          str[0];  */ /* for ISO C compatibility, 0 len not allowed */
}se_msg_string;
/*
 * convenience to get overhead of se_msg_string to the char string itself
 * used in case we change the contents of a se_msg_string in the future
 */
#define SE_MSG_STRING_OVERHEAD (sizeof(unsigned int))

/**
* @brief Get a string from a sysevent message buffer.
*
* This function retrieves a string from a SE_msg buffer. The buffer must be pointing
* at the se_msg_string containing the string.
*
* @param[in] msg - Pointer to the start of the se_msg_string.
* @param[out] size - Pointer to store the number of bytes that the se_msg_string occupied.
*
* @return Pointer to the string.
* @retval Non-NULL pointer to the string on success.
* @retval NULL if there is a problem and string cannot be retrieved.
*/
char *SE_msg_get_string(char *msg, int *size);

/*
 ==========================================================================
         inter-process messages
         Communication between clients and the server
 ==========================================================================
 */
/*
 * se_open_connection_msg
 *
 * A request by a client to connect to the sysevent daemon
 *
 * Fields  :
 *    version : The version of SE message the client understands
 *    data    : An user readable (and hopefully unique) id that the client
 *              calls itself.
 */
typedef struct
{
   int   version;
   void *data;
} se_open_connection_msg;

/*
 * se_open_connection_reply_msg
 *
 * A response to the open connection message
 *
 * Fields  :
 *    status  : Status of registration
 *              0 is success, !0 is failure
 *    token_id: The id to use in future messages to the sysevent daemon
 */
typedef struct
{
   int     status;
   token_t token_id;
} se_open_connection_reply_msg;


/*
 * se_close_connection_msg
 *
 * A request by a connected client to close its connection
 *
 * Fields  :
 *    reserved: Not currently used
 */
typedef struct
{
   void *reserved;
} se_close_connection_msg;

/*
 * se_close_connection_reply_msg
 *
 * A response to an close connection message
 *
 * Fields  :
 *    reserved: Not currently used
 */
typedef struct
{
   void *reserved;
} se_close_connection_reply_msg;

/*
 * se_ping_msg
 *
 * A request to indicate sign of life via ping reply
 *
 * Fields  :
 *    reserved: Not currently used
 */
typedef struct
{
   void *reserved;
} se_ping_msg;

/*
 * se_ping_reply_msg
 *
 * A response to request for indication  of sign of life
 *
 * Fields  :
 *    reserved: Not currently used
 */
typedef struct
{
   void *reserved;
} se_ping_reply_msg;

/*
 * se_debug_msg
 *
 * Change the debug level of syseventd
 *
 * Fields  :
 *    level: The debug level to use (see server/syseventd.h for debug flags)
 */
typedef struct
{
   int level;
} se_debug_msg;

/*
 * se_new_client_msg
 *
 * A message from the TCP accept wait thread to the general Listener
 * thread to indicate that a new client has connected
 *
 * Fields  :
 *    token_id: The id that the acceptor has assigned to the client
 *              after it has already been added to the list of clients
 */
typedef struct
{
   token_t token_id;
} se_new_client_msg;

/*
 * se_get_msg
 *
 * A request to retrieve the value of a subject known to
 * the sysevent daemon.
 *
 * Fields  :
 *    data    : a se_msg_string which contains the name of the subject
 *              for which the value is requested
 */
typedef struct
{
   void *data;
} se_get_msg;


/*
 * se_get_reply_msg
 *
 * A response from the sysevent daemon to a se_get_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 *    data    : 2 se_msg_strings
 *              The first contains the name of the subject for which the value
 *              had been requested
 *              The second contains the current value
 */
typedef struct
{
   int   status;
   void *data;
} se_get_reply_msg;

/*
 * se_set_msg
 *
 * A request to set the value of a subject known to
 * the sysevent daemon.
 *
 * Fields  :
 *    source  : source of the message
 *    tid     : transaction id for the message
 *    data    : 2 se_msg_strings
 *              The first contains the name of the tuple for which the value
 *              is to be set
 *              The second contains the value it is to be set to
 */
typedef struct
{
   int          source;
   int          tid;
   void        *data;   /* this will be 2 character strings
                         * the first is subject_bytes long
                         * the second is value_bytes long
                         */
} se_set_msg;

/*
 * se_set_reply_msg
 *
 * A response from the sysevent daemon to a se_set_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 */
typedef struct
{
   int   status;
} se_set_reply_msg;

/*
 * se_set_unique_msg
 *
 * A request to create a new subject with a given preamble and set the value
 *
 * Fields  :
 *    data    : 2 se_msg_strings
 *              The first contains the preamble name(namespace) of the tuple to create
 *              The second contains the value it is to be set to
 */
typedef struct
{
   void        *data;   /* this will be 2 character strings
                         * the first is subject_bytes long
                         * the second is value_bytes long
                         */
} se_set_unique_msg;

/*
 * se_set_unique_reply_msg
 *
 * A response from the sysevent daemon to a se_set_unique_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 *    data    : 2 se_msg_strings
 *              The first contains the unique name of the subject that was assigned
 */
typedef struct
{
   int   status;
   void *data;
} se_set_unique_reply_msg;

/*
 * se_iterate_get_msg
 *
 * A request to get the value of the next data element is a namespace
 *
 * Fields  :
 *    iterator : an opaque field initially set to SYSEVENT_NULL_ITERATOR
 *    data    : a se_msg_string which contains the name of the subject
 *              for which the value is requested
 */
typedef struct
{
   unsigned int iterator;
   void        *data;
} se_iterate_get_msg;

/*
 * se_iterate_get_reply_msg
 *
 * A response from the sysevent daemon to a get_unique_iterate_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 *    iterator: the new value to set in the caller's iterator
 *    data    : 2 se_msg_strings
 *              The first contains the name of the subject for which the value
 *              had been requested. It is the unique name of that subject.
 *              The second contains the current value
 */
typedef struct
{
   int            status;
   unsigned int   iterator;
   void          *data;
} se_iterate_get_reply_msg;

/*
 * se_del_unique_msg
 *
 * A request to delete a new UNIQUE element
 *
 * Fields  :
 *    iterator: A iterator pointing at the element to delete
 *    data    : 1 se_msg_strings
 *              The first contains the preamble name(namespace) of the tuple to delete
 */
typedef struct
{
   unsigned int iterator;
   void        *data;
}se_del_unique_msg;

/*
 * se_iterate_get_iterator__msg
 *
 * Return an iterator to the next UNIQUE element in a namespace
 *
 * Fields  :
 *    iterator: the value of the current iterator
 *              NULL_ITERATOR means first iterator
 *    data    : 1 se_msg_strings
 *              The first contains the namespace of the subject
 */
typedef struct
{
   unsigned int   iterator;
   void          *data;
} se_iterate_get_iterator_msg;

/*
 * se_iterate_get_iterator_reply_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 *    iterator: the value of the next iterator
 *    data    : 1 se_msg_strings
 *              The first contains the namespace of the subject for which the value
 */
typedef struct
{
   int            status;
   unsigned int   iterator;
   void          *data;
} se_iterate_get_iterator_reply_msg;

/*
 * tuple_flag_t
 *   Controls that can be put on a tuple's execution
 *   0x00000000    : Use defaults
 *   0x00000001    : Order of action execution must be serialized in the order of
 *                   the action was registered
 *   0x00000002    : Execute any notifications on a tuple whether there is a
 *                   change of tuple value or not
 *   0x00000004    : The tuple value can be read often, but is only writable once
 *
 * IMPORTANT: IF YOU CHANGE THESE VALUES YOU MUST CHANGE ..../init/init.d/event_flags AS WELL
 *
 */
typedef enum {
   TUPLE_FLAG_NONE                 = 0,                   /* 0x00000000 */
   TUPLE_FLAG_SERIAL               = 1,                   /* 0x00000001 */
   TUPLE_FLAG_EVENT                = 2,                   /* 0x00000002 */
   TUPLE_FLAG_WORM                 = 4,                   /* 0x00000004 */
   TUPLE_FLAG_RESERVED             = -1   /*ULONG_MAX */  /* 0xFFFFFFFF */
} tuple_flag_t;
/*
 * strings for TUPLE FLAGS
 */
#define SYSEVENT_TUPLE_FLAG_SERIAL "0x00000001"
#define SYSEVENT_TUPLE_FLAG_EVENT  "0x00000002"
#define SYSEVENT_TUPLE_FLAG_WORM   "0x00000003"

/*
 * action_flag_t
 *   Controls that can be put on a action
 *   0x00000000    : Use defaults
 *   0x00000001    : When execle an executable (activation) then the normal behavior
 *                   is to only allow one executable target to be active at a time.
 *                   This behavior blocks exec of the same target while one target
 *                   is running (targets are short lived processes). If this flag is
 *                   set, then multiple execs of the same target are allowed.
 *  0x00000002     : When waiting for an executable target to be ready for activation,
 *                   keep the waiting queue at a depth of 1 - the currently running
 *                   process, and the latest request
 *
 *
 * IMPORTANT: IF YOU CHANGE THESE VALUES YOU MUST CHANGE ..../init/init.d/event_flags AS WELL
 */
typedef enum {
   ACTION_FLAG_NONE                   = 0,                   /* 0x00000000 */
   ACTION_FLAG_MULTIPLE_ACTIVATION    = 1,                   /* 0x00000001 */
   ACTION_FLAG_COLLAPSE_PENDING_QUEUE = 2,                   /* 0x00000002 */
   ACTION_FLAG_RESERVED               = -1   /*ULONG_MAX */  /* 0xFFFFFFFF */
} action_flag_t;
/*
 * strings for ACTION FLAGS
 */
#define SYSEVENT_ACTION_FLAG_MULTIPLE_ACTIVATION    "0x00000001"
#define SYSEVENT_ACTION_FLAG_COLLAPSE_PENDING_QUEUE "0x00000002"

/*
 * se_set_options_msg
 *
 * A request to set the flag options of a subject known to
 * the sysevent daemon.
 *
 * Fields  :
 *
 *    flags   : flags to be set on the tuple
 *    data    :  se_msg_strings
 *              The first contains the name of the tuple for which the flag options
 *              is to be set
 */
typedef struct
{
   tuple_flag_t flags;
   void        *data;   /* this will be 1 character strings
                         * the first is subject_bytes long
                         */
} se_set_options_msg;

/*
 * se_set_options_reply_msg
 *
 * A response from the sysevent daemon to a se_set_options_msg
 *
 * Fields  :
 *    status  : the status of the response. 0 means no error
 */
typedef struct
{
   int   status;
} se_set_options_reply_msg;

/*
 * se_set_async_action_msg
 *
 * A request to set an executable and parameters to be called whenever
 * a trigger changes value
 * the sysevent daemon.
 *
 * Fields  :
 *   flags      : flags to be applied to this activation
 *    num_params : The number of parameters given in data
 *    data       : se_msg_strings
 *                 The first contains the name of the subject/trigger to monitor
 *                 The second contains the executable that is to be called when trigger
 *                 changes value
 *                 The rest are num_params parameters to provide the executable
 */
typedef struct
{
   action_flag_t flags;
   int  num_params;
   void *data;
} se_set_async_action_msg;

/*
 * se_set_async_message_msg
 *
 * A request to set an executable and parameters to be called whenever
 * a trigger changes value
 * the sysevent daemon.
 *
 * Fields  :
 *   flags      : flags to be applied to this trigger
 *    data       : se_msg_strings
 *                 The first contains the name of the subject/trigger to monitor
 */
typedef struct
{
   action_flag_t flags;
   void *data;
} se_set_async_message_msg;

/*
 * async_id_t
 * Used to identify the trigger and action of an async
 * in case someone wants to cancel it
 */
typedef struct
{   unsigned int trigger_id;
    unsigned int action_id;
} async_id_t;

/*
 * se_set_async_reply_msg
 *
 * A response from the sysevent daemon to a se_set_async_action_msg
 * or a se_set_async_notification_msg
 *
 * Fields  :
 *    status     : the status of the response. 0 means no error
 *
 *    async_id   : the id of the action that the async is attached to
 *                 This are used to cancel the async
 */
typedef struct
{
   int        status;
   async_id_t async_id;
} se_set_async_reply_msg;

/*
 * se_remove_async_msg
 *
 * A request to remove an async action from a trigger
 *
 * Fields  :
 *    async_id   : the id of the action that the async is attached to
 *                 This came from a previous se_set_async_reply_msg
 */
typedef struct
{
   async_id_t async_id;
} se_remove_async_msg;

/*
 * se_remove_async_reply_msg
 *
 * A response from the sysevent daemon to a se_remove_async_msg
 *
 * Fields  :
 *    status     : the status of the response. 0 means no error
 */
typedef struct
{
   int        status;
} se_remove_async_reply_msg;

/*
 * se_notification_msg
 *
 * An asynchronous notification to a client that a data value has changed
 *
 * Fields  :
 *    source  : source of the message
 *    tid        : transaction id of the message
 *    async_id   : the id of the notification
 *    data    : 2 se_msg_strings
 *              The first contains the name of the subject for which the value
 *              had been requested
 *              The second contains the current value
 */
typedef struct
{
   int          source;
   int        tid;
   async_id_t async_id;
   void      *data;
} se_notification_msg;

/*
 * se_show_data_elements_msg
 *
 * A request to retrieve the value of a subject known to
 * the sysevent daemon.
 *
 * Fields  :
 *    data    : a se_msg_string which contains the name of the file
 *              to write the data elements to
 */

typedef struct
{
   void *data;
} se_show_data_elements_msg;

/*
 ==========================================================================
         inter-thread messages
 ==========================================================================
 */
/*
 * se_die_msg
 *
 * A command to stop execution and close connections
 *
 * Fields  :
 *    reserved: Not currently used
 */
typedef struct
{
   void *reserved;
} se_die_msg;

/*
 * se_send_notification_msg
 *
 * A command to message a client that some data value has changed
 *
 * Fields  :
 *    source  : source of the message
 *    tid        : transaction id of the message
 *    token_id   : id of the client to send message to
 *    async_id   : the id of the notification
 *    flags      : flags to modify behavior of action
 *    data    : 2 se_msg_strings
 *              The first contains the name of the subject for which the value
 *              had been requested
 *              The second contains the current value
 */
typedef struct
{
   int           source;
   int           tid;
   token_t       token_id;
   async_id_t    async_id;
   action_flag_t flags;
   void         *data;
} se_send_notification_msg;

/*
 * se_run_executable_msg
 *
 * A command to run an executable in response to a value change
 *
 * Fields  :
 *    token_id   : id of the client which registered the executable
 *    async_id   : the id of the notification
 *    flags      : flags to modify behavior of action
 *    data    : 2 se_msg_strings
 *              The first contains the name of the subject for which the value
 *              had been requested
 *              The second contains the current value
 */
typedef struct
{
   token_t    token_id;
   async_id_t async_id;
   action_flag_t flags;
   void         *data;
} se_run_executable_msg;

/*
 * se_run_serially_msg
 *
 * An inter-thread message describing a list of events to run serially to completion
 *
 * Fields  :
 *    async_id   : the id of the notification
 *    num_msgs : the number of messages in the serial_msg_list_t
 *    data    : a pointer to serial_msg_list_t containing a list to run serially
 */
typedef struct
{
   async_id_t async_id;
   int        num_msgs;
   void      *data;
} se_run_serially_msg;

/*
===============================================================
    Functions
===============================================================
*/

/**
* @brief Returns a string description of a sysevent error code.
*
* This function converts a numeric error code returned by other sysevent APIs into a
* human-readable string.
*
* @param[in] error - The error code.
*
* @return Pointer to a static string describing the error.
*
* @note Do NOT save this string. It has no lifespan.
*/
char *SE_strerror (int error);

/**
* @brief Return a string representation for a message type.
*
* @param[in] mtype - The message type.
*
* @return Pointer to the message type string.
*
* @note Do NOT save this string. It has no lifespan.
*/
char *SE_print_mtype (int mtype);

/**
* @brief Initialize the libsysevent library.
*
* @param[in] name - Name of the user of this library.
*
* @return None.
*
* @note  This doesn't need to be called by most users of libsysevent
* since it is implicitly called during sysevent_open. It is used by syseventd
*/
void init_libsysevent(const char* const name);

/**
* @brief Connect to the sysevent daemon.
*
* @param[in] ip - IP address to connect to.
* @param[in] port - Port to connect to.
* @param[in] version - Version of client.
* @param[in] id - Name of client.
* @param[out] token - Pointer to receive an opaque value.
*
* @return File descriptor for the connection.
* @retval >0 file descriptor if connection is successful.
* @retval -1 on error.
*/
int sysevent_open(char *ip, unsigned short port, int version, char *id, token_t *token);

/**
* @brief Connect to the sysevent daemon for binary data operations.
*
* @param[in] ip - IP address of the sysevent daemon.
* @param[in] port - Port number of the sysevent daemon.
* @param[in] version - Version of client.
* @param[in] id - Human-readable client identifier.
* @param[out] token - Pointer to receive an opaque value.
*
* @return File descriptor for the connection.
* @retval >0 file descriptor if connection is successful.
* @retval -1 on error.
*/
int sysevent_open_data (char *ip, unsigned short port, int version, char *id, token_t *token);

/**
* @brief Connect to the sysevent daemon using Unix Domain Socket.
*
* @param[in] target - The name of the UDS to connect to.
* @param[in] version - Version of client.
* @param[in] id - Name of client.
* @param[out] token - Pointer to receive opaque id.
*
* @return The file descriptor.
* @retval >=0 file descriptor on success.
* @retval -1 on error.
*/
int sysevent_local_open (char *target, int version, char *id, token_t *token);

/**
* @brief Connect to the sysevent daemon using Unix Domain Socket for binary data operations.
*
* @param[in] target - The name of the UDS to connect to.
* @param[in] version - Version of client.
* @param[in] id - Name of client.
* @param[out] token - Pointer to receive opaque id.
*
* @return The file descriptor.
* @retval >=0 file descriptor on success.
* @retval -1 on error.
*/
int sysevent_local_open_data (char *target, int version, char *id, token_t *token);

/**
* @brief Disconnect from the sysevent daemon.
*
* This function close a connection to the sysevent daemon.
*
* @param[in] fd - The file descriptor to close.
* @param[in] token - The server provided opaque id of the client.
*
* @return Status of the operation.
* @retval 0 if disconnected successfully.
* @retval Non-zero on error.
*/
int sysevent_close(const int fd, const token_t token);

/**
* @brief Ping a connection to the sysevent daemon.
*
* @param[in] fd - The file descriptor to ping.
* @param[in] token - Server provided opaque value.
*
* @return Status of the operation.
* @retval 0 if ping message sent successfully.
* @retval Non-zero on error.
*
* @note We only told sysevent daemon to ping reply. We are not handling the
* reply itself. That is up to the caller. Note that there is no current need
* to ping. If the server breaks the connection then there will be a series of
* SE_MSG_NONE coming on the connection. Receipt of several SE_MSG_NONE can be
* used by clients to realize the connection is broken. If you are looking for a
* blocking ping test which waits for a ping reply then use sysevent_ping_test.
*/
int sysevent_ping (int fd, token_t token);

/**
* @brief Ping a connection to the sysevent daemon and wait for reply.
*
* @param[in] fd - The file descriptor to ping.
* @param[in] token - Server provided opaque value.
* @param[in] tv - Pointer to a timeval structure describing how long to wait.
*
* @return Status of the operation.
* @retval 0 if ping reply message received.
* @retval Non-zero on error.
*
*/
int sysevent_ping_test (int fd, token_t token, struct timeval* tv);

/**
* @brief Send a get request to the sysevent daemon and receive reply.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] inbuf - A null terminated string which is the thing to get.
* @param[out] outbuf - A buffer to hold returned value.
* @param[in] outbytes - The maximum number of bytes in outbuf.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note  If outbuf is not big enough to hold the reply value, then the value will
* be truncated to fit. An error of ERR_INSUFFICIENT_ROOM will be returned.
* The value will always be NULL terminated, so the outbuf must contain enough bytes
* for the return value as well as the NULL byte.
*/
int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes);

/**
* @brief Send a get request for binary data to the sysevent daemon and receive reply.
*
* @param[in] fd - The connection id.
* @param[in] token - Server provided opaque value.
* @param[in] inbuf - A null terminated string which is the thing to get.
* @param[out] outbuf - A buffer to hold returned value.
* @param[in] outbytes - The maximum number of bytes in outbuf.
* @param[out] actualsizecopied - Pointer to store the actual number of bytes copied into outbuf.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note If outbuf is not big enough to hold the reply value, then the value will
* be truncated to fit. An error of ERR_INSUFFICIENT_ROOM will be returned.The value
* will always be NULL terminated, so the outbuf must contain enough bytes for the
* return value as well as the NULL byte.
*/
int sysevent_get_data(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes,int *actualsizecopied);

/**
* @brief Send a set request to the sysevent daemon.
*
* A set may change the value of a tuple.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] name - A null terminated string which is the tuple to set.
* @param[in] value - A null terminated string which is the value to set tuple to, or NULL.
* @param[in] conf_req - Configuration request flag.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_set(const int fd, const token_t token, const char *name, const char *value, int conf_req);

/**
* @brief Send a set request with binary data to the sysevent daemon.
*
* This function send a set to the sysevent daemon. A set may change the value of a tuple.
*
* @param[in] fd - The connection id.
* @param[in] token - Server provided opaque value.
* @param[in] name - A null terminated string which is the tuple to set.
* @param[in] value - Buffer holding binary data which is the value to set tuple to, or NULL.
* @param[in] value_length - Actual size of binary data buffer.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*/
int sysevent_set_data(const int fd, const token_t token, const char *name, const char *value, int value_length);

/**
* @brief Send a set request with NULL value to clear existing tuple value from volatile memory.
*
* Send a set to the sysevent daemon. A set with NULL value of a tuple to clear existing value from volatile memory.
*
* @param[in] fd - The connection id.
* @param[in] token - Server provided opaque value.
* @param[in] name - A null terminated string which is the tuple to set.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*/
int sysevent_unset (const int fd, const token_t token, const char *name);

/**
* @brief Send a set request with transaction ID to the sysevent daemon.
*
* Send a set to the sysevent daemon. A set may change the value of a tuple.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - Server provided opaque value.
* @param[in] name - A null terminated string which is the tuple to set.
* @param[in] value - A null terminated string which is the value to set tuple to, or NULL.
* @param[in] source - Source of message.
* @param[in] tid - Transaction id.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_set_with_tid (const int fd, const token_t token, const char *name, const char *value, const int source, const int tid);

/**
* @brief Send a set unique request to the sysevent daemon and receive reply.
*
* A set will create a new tuple with name derived from client request, and it will set this new tuple to the value.
* Send a set unique to the sysevent daemon.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] name - A null terminated string which is the namespace of the tuple to create and set.
* @param[in] value - A null terminated string which is the value to set tuple to, or NULL.
* @param[out] outbuf - A buffer to hold returned unique tuple name.
* @param[in] outbytes - The maximum number of bytes in outbuf.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note the position of the newly added item within its namespace is not guaranteed to be
* in a particular order when iterating through the space using sysevent_get_unique.
* If you need to guarantee that the newly added item is iterated in order of its addition to the
* namespace (and are willing to cost the system some memory for each element in the namespace) then
* you must use the ! character as the first character in your namespace
*/
int sysevent_set_unique(const int fd, const token_t token, const char *name, const char *value, char *outbuf, int outbytes);

/**
* @brief Send a get request for a unique element to the sysevent daemon and receive reply.
*
* This function send to the sysevent daemon and receive reply
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] inbuf - A null terminated string which is the namespace of the thing to get.
* @param[in,out] iterator - A iterator which is initialized to NULL.
* @param[out] subjectbuf - A buffer to hold returned unique name.
* @param[in] subjectbytes - The maximum number of bytes in subjectbuf.
* @param[out] valuebuf - A buffer to hold returned value.
* @param[in] valuebytes - The maximum number of bytes in valuebuf.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note If either is not big enough to hold the reply value, then the value will
* be truncated to fit. An error of ERR_INSUFFICIENT_ROOM will be returned.
* The value will always be NULL terminated, so the outbuf must contain
* enough bytes for the return value as well as the NULL byte.
*/
int sysevent_get_unique(const int fd, const token_t token, const char *inbuf, unsigned int *iterator, char *subjectbuf, int subjectbytes, char *valuebuf, int valuebytes);

/**
* @brief Send a delete request for a unique element from its namespace.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] inbuf - A null terminated string which is the namespace of the thing to delete.
* @param[in,out] iterator - A iterator which is describing the element to delete within the namespace.
*                          \n The first iterator is SYSEVENT_NULL_ITERATOR
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_del_unique(const int fd, const token_t token, const char *inbuf, unsigned int *iterator);

/**
* @brief Get the next iterator for a namespace.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] inbuf - A null terminated string which is the namespace.
* @param[in,out] iterator - A iterator which is describing the current iterator. Initially set to 0.
*                           On return it contains the next iterator to the namespace.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_get_next_iterator(const int fd, const token_t token, const char *inbuf, unsigned int *iterator);

/**
* @brief Send a set options flag request to the sysevent daemon and receive reply.
*
* A set may change the event flags of that tuple.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] name - A null terminated string which is the tuple to set.
* @param[in] flags - The flags to set tuple to.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_set_options(const int fd, const token_t token, const char *name, unsigned int flags);

/**
* @brief Declare a program to run when a given tuple changes value.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] flags - action_flag_t flags to control the activation.
* @param[in] subject - A null terminated string which is the name of the tuple.
* @param[in] function - An executable to call when the tuple changes value.
* @param[in] numparams - The number of arguments in the following char**.
* @param[in] params - A list of 0 or more parameters to use when calling the function.
* @param[out] async_id - On return, an id that can be used to cancel the callback.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*
* @note When the tuple changes value, the executable will be called with all parameters given.
* The value of parameters will be either: the exact string given as a parameter, or if the
* parameter begins with $ the return will be the current value of the trigger by that name.
* If the trigger does not exist then "NULL" will be used.
* For example, if the subject is trigger1, the function /bin/programA, and the parameter
* list is 3 params = trigger1, $trigger3, $trigger1. Assuming trigger3 has not yet been set,
* Then when trigger1 changes to "new_value", a process will be forked to
* call  /bin/programA  "trigger1" "NULL" "new_value".
*/
int sysevent_setcallback(const int fd, const token_t token, action_flag_t flags, char *subject, char *function, int numparams, char **params, async_id_t *async_id);

/**
* @brief Remove a callback/notification from a trigger.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] async_id - The async id to remove.
*
* @return Status of the operation.
* @retval 0 if async action is removed.
* @retval Non-zero on error.
*/
int sysevent_rmcallback(const int fd, const token_t token, async_id_t async_id);

/**
* @brief Request a notification message to be sent when a given tuple changes value.
*
* A notification can only be sent to a client which is still connected.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] subject - A null terminated string which is the name of the tuple.
* @param[out] async_id - On return, an id that can be used to cancel the notification.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*
* @note Notifications are asynchronous and should be sent to a client connection
* which is dedicated to asynchronous sysevent messages. In other words a
* connection which is not shared with a thread doing sets/gets etc.
*/
int sysevent_setnotification(const int fd, const token_t token, char *subject, async_id_t *async_id);

/**
* @brief Remove a callback/notification from a trigger.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] async_id - The async id to remove.
*
* @return Status of the operation.
* @retval 0 if async action is removed.
* @retval Non-zero on error.
*/
int sysevent_rmnotification(const int fd, const token_t token, async_id_t async_id);

/**
* @brief Wait for a notification and return the results when received.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[out] namebuf - A buffer to hold the name received.
* @param[in,out] namebytes - On input, the maximum length of the string not counting terminating null.
*                            On output, the actual length of the string not counting terminating null.
* @param[out] valbuf - A buffer to hold returned value.
* @param[in,out] valbytes - On input, the maximum number of bytes in valbuf.
*                           On output, the actual number of bytes in valbuf not counting the terminating null.
* @param[out] async_id - The async id of the action.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note If a buffer is not big enough to hold the reply value, then the value will
* be truncated to fit. An error of ERR_INSUFFICIENT_ROOM will be returned. The value
* will always be NULL terminated, so the buffer must contain enough bytes for the
* return value as well as the NULL byte. This will block
*/
int sysevent_getnotification (const int fd, const token_t token, char *namebuf, int *namebytes, char *valbuf, int *valbytes, async_id_t *async_id);

/**
* @brief Wait for a notification with binary data and return the results when received.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - A server generated opaque value.
* @param[out] namebuf - A buffer to hold the name received.
* @param[in,out] namebytes - On input, the maximum length of the string not counting terminating null.
*                            On output, the actual length of the string not counting terminating null.
* @param[out] valbuf - A buffer to hold returned binary value.
* @param[in,out] valbytes - On input, the maximum number of bytes in valbuf.
*                           On output, the actual number of bytes in valbuf.
* @param[out] async_id - The async id of the action.
*
* @return Status of the operation.
* @retval 0 if reply received.
* @retval Non-zero on error.
*
* @note If a buffer is not big enough to hold the reply value, then the value will
* be truncated to fit. An error of ERR_INSUFFICIENT_ROOM will be returned. The value
* will always be NULL terminated, so the buffer must contain enough bytes for the
* return value as well as the NULL byte. This will block
*/
int sysevent_getnotification_data (const int fd, const token_t token, char *namebuf, int *namebytes, char *valbuf, int *valbytes, async_id_t *async_id);

/**
* @brief Tell daemon to show all data elements.
*
* @param[in] fd - The connection descriptor.
* @param[in] token - The server provided opaque id of the client.
* @param[in] file - A null terminated string which is the file to write to.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval Non-zero on error.
*/
int sysevent_show (const int fd, const token_t token, const char *file);

/**
* @brief Set sysevent daemon debug level.
*
* @param[in] ip - The name or IP address of the sysevent daemon to send message to.
* @param[in] port - The port of the sysevent daemon to send to.
* @param[in] level - Debug level to set to.
*
* @return Status of the operation.
* @retval 0 if debug message sent.
* @retval Non-zero on error.
*/
int sysevent_debug (char *ip, unsigned short port, int level);

/**
* @brief Get the maximum size for binary message data.
*
* @return Maximum size in bytes for binary message data.
*/
unsigned int sysevent_get_binmsg_maxsize();

#ifdef __cplusplus
}
#endif


#endif   /* __LIB_SYSEVENT_H_ */
