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

#ifndef __LIB_SYSEVENT_INTERNAL
#define __LIB_SYSEVENT_INTERNAL

#include "sysevent.h"
/*
 * Given a *se_msg_hdr calculate the address of the body
 * of the message
*/

/* #define SE_MSG_HDR_2_BODY(a) ((char *)(a) + sizeof(se_msg_hdr)) */


/**
 * @brief Prints the content of a sysevent message for debugging purposes.
 *
 * @param[in] inmsg Pointer to the message body to print
 * @param[in] type The type of message.
 *
 * @return The status of the operation.
 * @retval 0 on success.
 */
int  SE_print_message(char *inmsg, int type);

/**
 * @brief Calculates the number of bytes required to hold a string in a se_msg_string structure.
 *
 * The calculation includes the string length, null terminator and alignment.
 *
 * @param[in] str The string to measure.
 *
 * @return The total number of bytes required for se_msg_string including overhead and alignment.
 * @retval The total number of bytes required for se_msg_string on success.
 * @retval 0 If str is NULL.
 */
unsigned int SE_string2size(const char *str);

/**
 * @brief Prints a sysevent message header and its body for debugging purposes.
 *
 * Print a message header and the message like delimiter,mbytes,mtype and sender.
 *
 * @param[in] hdr Pointer to the se_msg_hdr structure to print
 *
 * @return The status of the operation.
 * @retval 0 on success
 */
int  SE_print_message_hdr(char *hdr);

/**
 * @brief Adds a string to a sysevent message buffer as a se_msg_string structure.
 *
 * The function adds a string with its size field and ensures 32-bit alignment.
 *
 * @param[in,out] msg Pointer to the buffer where the string will be added
 * @param[in] size Maximum number of bytes available in the buffer
 * @param[in] str The null-terminated string to add (NULL allowed)
 *
 * @return Number of bytes added to the message buffer
 * @retval >0 Number of bytes added on success
 * @retval 0 Error, string not added
 *
 * @note If str is NULL then the added string will have a length of 0.
 */
int SE_msg_add_string(char *msg, unsigned int size, const char *str);

/**
 * @brief Calculates and updates the total message size in the se_msg_hdr structure.
 *
 * Examines the message type and calculates the total byte count including the header
 * and message-specific data structures. The result is stored in the mbytes field of
 * the se_msg_hdr.
 *
 * @param[in,out] hdr Pointer to a complete se_msg_hdr plus message body
 *
 * @return The status of the operation.
 * @retval 0 on success
 */
int  SE_msg_hdr_mbytes_fixup (se_msg_hdr *hdr);

/**
 * @brief Receives a sysevent message from a file descriptor with blocking.
 *
 * This function blocks until a complete message arrives on the file descriptor.
 *
 * @param[in] fd The file descriptor to receive from.
 * @param[out] replymsg Buffer to store the received message.
 * @param[in,out] replymsg_size On input: size of replymsg buffer.
 *                              On output: number of bytes received.
 * @param[out] who Pointer to receive the sender's token ID as known to the sysevent server.
 *
 * @return Message type received
 * @retval >0 The type of message received on success.
 * @retval SE_MSG_NONE Error occurred during receive.
 *
 * @note This call will block until a message arrives.
 */
int SE_msg_receive(int fd, char *replymsg, unsigned int *replymsg_size, token_t *who);

/**
 * @brief Receives a sysevent message from a file descriptor with minimal blocking.
 *
 * @param[in] fd The file descriptor to receive from.
 * @param[out] replymsg Buffer to store the received message
 * @param[in,out] replymsg_size On input: size of replymsg buffer.
 *                              On output: number of bytes received.
 * @param[out] who Pointer to receive the sender's token ID as known to the sysevent server
 *
 * @return Message type received
 * @retval >0 The type of message received on success.
 * @retval SE_MSG_NONE Error or no message available within timeout period.
 *
 * @note This call will return SE_MSG_NONE if there is not a message immediately there.
 */
int SE_minimal_blocking_msg_receive (int fd, char *replymsg, unsigned int *replymsg_size, token_t *who);

/**
 * @brief Sends a sysevent message to the sysevent daemon.
 *
 * @param[in] fd The file descriptor to send to
 * @param[in] sendmsg Pointer to the complete message including se_msg_hdr and body
 *
 * @return The status of the operation.
 * @retval 0 on success - message sent completely
 * @retval -1 Write failed after retries
 * @retval -2 Message too large for buffer
 * @retval Non-zero for other errors.
 */
int SE_msg_send (int fd, char *sendmsg);

/**
 * @brief Sends a sysevent message and waits for a reply with a timeout.
 *
 * @param[in] fd The file descriptor to send to and receive from
 * @param[in] sendmsg Pointer to the complete message to send including se_msg_hdr and body.
 * @param[out] replymsg Buffer to store the received reply message.
 * @param[in,out] replymsg_size On input: size of replymsg buffer.
 *                              On output: number of bytes received.
 *
 * @return Message type of the reply.
 * @retval >0 The type of reply message received on success.
 * @retval SE_MSG_NONE Error occurred or no reply within timeout.
 *
 * @note This function will NOT block until it receives a reply.
 */
int SE_msg_send_receive (int fd, char *sendmsg, char *replymsg, unsigned int *replymsg_size);

/**
 * @brief Initializes a sysevent message header in a buffer.
 *
 * This function create a sysevent message.
 *
 * @param[out] buf The message buffer in which to prepare the message
 * @param[in] bufsize The number of bytes available in buf
 * @param[in] mtype The type of message
 * @param[in] sender The token ID of the sender
 *
 * @return Pointer to the start of the message body.
 * @retval Non-NULL Pointer to the message body area after the se_msg_hdr on success.
 * @retval NULL Error - buf is NULL, bufsize too small, or mtype is 0.
 */
char *SE_msg_prepare(char *buf, const unsigned int bufsize, const int mtype, const token_t sender);

/**
 * @brief Extracts data from a se_msg_string structure in a message buffer.
 *
 * Retrieves the data pointer and size from a se_msg_string.
 *
 * @param[in] msg Pointer to the se_msg_string structure in the message buffer.
 * @param[out] size Pointer to store the data length in bytes.
 *
 * @return Pointer to the data within the se_msg_string.
 * @retval Non-NULL Pointer to the data immediately after the size field on success.
 * @retval NULL If msg is NULL or data length is 0.
 */
char *SE_msg_get_data(char *msg, int *size);

/**
 * @brief Sends a sysevent message containing binary data to the sysevent daemon.
 *
 * @param[in] fd The file descriptor to send to.
 * @param[in,out] sendmsg Pointer to the message buffer containing se_msg_hdr and data.
 * @param[in] msgsize Total size of the message in bytes.
 *
 * @return The status of the operation.
 * @retval 0  message sent successfully.
 * @retval -1 Write failed after retries.
 * @retval -2 Message size exceeds maximum binary message size.
 * @retval Non-zero for other errors.
 */
int SE_msg_send_data (int fd, char *sendmsg, unsigned int msgsize);

/**
 * @brief Adds binary data to a sysevent message buffer as a se_msg_string structure.
 *
 * @param[in,out] msg Pointer to the buffer where the data will be added
 * @param[in] size Maximum number of bytes available in the buffer
 * @param[in] data Pointer to the binary data to add
 * @param[in] data_length Length of the data in bytes
 *
 * @return Number of bytes added to the message buffer
 * @retval >0 Number of bytes added (equal to data_length) on success.
 * @retval 0 Error - msg is NULL, data is NULL, data_length is 0, or buffer too small
 */
int SE_msg_add_data(char *msg, unsigned int size, const char *data, const int data_length);

#endif   /* __LIB_SYSEVENT_INTERNAL */