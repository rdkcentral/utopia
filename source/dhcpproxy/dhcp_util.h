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

#ifndef _DHCP_UTIL_H_
#define _DHCP_UTIL_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "dhcp_msg.h"

/**
* @brief Send a DHCP message to the specified destination address.
*
* This function transmits the complete DHCP message to the destination.
*
* @param[in] s - Socket descriptor used to send the message.
* @param[in] msg - Pointer to the DHCP message data to send.
* @param[in] size - Size of the DHCP message in bytes.
* @param[in] dest_addr - Destination socket address for the message.
*
* @return None.
*
*/
void dhcp_send(int s, const unsigned char *msg, unsigned int size, struct sockaddr_in dest_addr);

/**
* @brief Insert an ARP record for a host.
*
* This function Insert ARP record, required if DHCP message is unicast to a host that has not finished IP initialization.
*
* @param[in] s - Socket descriptor used for the ioctl operation.
* @param[in] device_name - Pointer to the network device name string.
* @param[in] ip_addr - IP address to add to the ARP table.
* @param[in] htype - Hardware type.
* @param[in] hlen - Hardware address length in bytes.
* @param[in] chaddr - Pointer to the hardware address buffer.
*
* @return None.
*
*/
void insert_arp_record(int s, const char *device_name,
                       struct sockaddr_in ip_addr,
                       ui8 htype, ui8 hlen, ui8* chaddr);

/**
* @brief Create a DHCP socket and bind it to a port and device.
*
* This function opens a socket suitable for DHCP relay/server use and binds it to the given local port and interface.
*
* @param[in] port - Port number to bind the socket to.
* @param[in] device_name - Pointer to the network device name string to bind to.
*                       \n If NULL, the socket will not be bound to a specific device.
*
* @return The status of the operation.
* @retval The socket descriptor on success.
* @retval -1 on error.
*
*/
int dhcp_create_socket(int port, const char* device_name);

/**
* @brief Receive a packet from a DHCP socket with source and destination IP addresses.
*
* This function uses recvmsg to obtain the packet's destination IP in addition to the source address.
*
* @param[in] s - Socket descriptor to receive from.
* @param[out] buf - Pointer to the buffer to store received data.
* @param[in] len - Size of the buffer in bytes.
* @param[in] flags - Flags for the recvmsg operation.
* @param[out] from - Pointer to store the source address.
* @param[out] to - Pointer to store the destination IP address.
*
* @return The status of operation.
* @retval The number of bytes received on success.
* @retval -1 on error.
*
*/
int dhcp_recvfrom_to(int s, void *buf, size_t len, int flags,
                     struct sockaddr_in *from,
                     struct in_addr *to);


/**
* @brief Dump binary data in hexadecimal and ASCII format for diagnostic purposes.
*
* This function outputs the data in hexadecimal and ASCII format.
*
* @param[in] data - Pointer to the binary data buffer to dump.
* @param[in] size - Size of the data buffer in bytes.
*
* @return None.
*
*/
void dump_data(const unsigned char *data, size_t size);

/**
* @brief Dump binary data in short form showing hexadecimal and ASCII on a single line.
*
* This function displays the data in a short, one-line format suitable for inline logging.
*
* @param[in] data - Pointer to the binary data buffer to dump.
* @param[in] size - Size of the data buffer in bytes.
*
* @return None.
*
*/
void dump_data_short(const unsigned char *data, size_t size);

/**
* @brief Dump MAC address in standard colon-separated hexadecimal format.
*
* @param[in] param - Pointer to the 6-byte MAC address buffer.
*
* @return None.
*
*/
void dump_mac_addr(const void *param);

/**
* @brief Dump IP address in dotted-decimal notation.
*
* @param[in] param - Pointer to the 4-byte IP address buffer.
*
* @return None.
*
*/
void dump_ip_addr(const void *param);

/**
* @brief Dump a list of IP addresses in comma-separated dotted-decimal notation.
*
* @param[in] data - Pointer to the buffer containing IP addresses.
* @param[in] size - Size of the data buffer in bytes.
*
* @return None.
*
*/
void dump_ip_list(const unsigned char *data, size_t size);

/**
* @brief Dump a single DHCP option with formatted output based on option type.
*
* @param[in] p_option - Pointer to the DHCP option to dump.
*
* @return None.
*
*/
void dump_dhcp_option(const struct dhcp_option *p_option);

/**
* @brief Dump a linked list of DHCP options.
*
* @param[in] option_list - Pointer to the first DHCP option in the linked list.
*
* @return None.
*
*/
void dump_dhcp_option_list(const struct dhcp_option *option_list);

/**
* @brief Dump complete DHCP message including header fields and all options.
*
* @param[in] msg - Pointer to the DHCP message to dump.
* @param[in] opts - Pointer to the parsed DHCP option info.
*
* @return None.
*
*/
void dump_dhcp_msg(const struct dhcp_msg *msg, const struct dhcp_option_info *opts);

#endif // _DHCP_UTIL_H_