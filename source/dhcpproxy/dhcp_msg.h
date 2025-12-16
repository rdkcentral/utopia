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

#ifndef _DHCP_MSG_H_
#define _DHCP_MSG_H_

#include <netinet/in.h>

typedef unsigned char ui8;
typedef unsigned short ui16;
typedef unsigned int ui32;

/**
 * @brief DHCP Message header, exclude sname and file
 */
struct dhcp_msg_hdr
{
  ui8 op;
  ui8 htype;
  ui8 hlen;
  ui8 hops;
  ui32 xid;
  ui16 secs;
  ui16 flags;
  struct in_addr ciaddr;
  struct in_addr yiaddr;
  struct in_addr siaddr;
  struct in_addr giaddr;
  ui8 chaddr[16];
};

/**
 * @brief BOOTP Operation Type
 */
enum {
  BOOTREQUEST=1,
  BOOTREPLY=2
};
#define HTYPE_ETHERNET 1                   ///< htype = ethernet
#define BROADCAST_FLAG 0x8000              ///< Broadcast Flag

/**
 * @brief DHCP Message
 */
struct dhcp_msg
{
  struct dhcp_msg_hdr hdr;
  ui8 sname[64];
  ui8 file[128];
  ui32 cookie;
  ui8 option_data[];
};
#define DHCP_COOKIE 0x63825363             ///< DHCP Magic Cookie

/**
 * @brief DHCP option in TLV format
 */
struct dhcp_option
{
  ui8 code;
  ui8 len;
  ui8 *data;
  struct dhcp_option *next;
};

/**
 * @brief DHCP option code
 */
enum {
  OPTION_PAD=0,
  OPTION_ROUTER=3,
  OPTION_DNS=6,
  OPTION_HOSTNAME=12,
  OPTION_LEASETIME=51,
  OPTION_OVERLOAD=52,
  OPTION_MSGTYPE=53,
  OPTION_SERVERID=54,
  OPTION_CLIENTID=61,
  OPTION_END=255
};

/**
 * @brief Additional DHCP Message Info from options
 */
struct dhcp_option_info
{
   ui8 msgtype;                             ///< DHCP message type (option 53)
   int overload;                            ///< DHCP overload flag (option 52)
   struct in_addr server_ip;                ///< DHCP server IP (option 54)
   ui32 leasetime;                          ///< DHCP lease time (option 51)
   struct dhcp_option *opt_hostname;        ///< hostname (option  12)
   struct dhcp_option *opt_clientid;        ///< client ID (option 61)
   struct dhcp_option *opt_router;          ///< Routers (option 3)
   struct dhcp_option *opt_dns;             ///< DNS servers (option 6)
   struct dhcp_option *option_list;         ///< List of option in option field
   struct dhcp_option *file_option_list;    ///< List of option in file field
   struct dhcp_option *sname_option_list;  ///< List of option in sname field
};

#define OPTION_IN_FILE 0x01                ///< file field is used to store additional options
#define OPTION_IN_SNAME 0x02               ///< sname field is used to store additional options

/**
 * @brief DHCP message type (option 53)
 */
enum {
  DHCPDISCOVER=1,
  DHCPOFFER=2,
  DHCPREQUEST=3,
  DHCPDECLINE=4,
  DHCPACK=5,
  DHCPNAK=6,
  DHCPRELEASE=7,
  DHCPINFORM=8
};

#define INFINITE_LEASETIME 0xFFFFFFFF

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Compare two DHCP options.
*
* This function compares two DHCP option structures by their length and data.
*
* @param[in] opt1 - Pointer to the first DHCP option to compare.
* @param[in] opt2 - Pointer to the second DHCP option to compare.
*
* @return The comparison result.
* @retval 0 if two options are same.
* @retval -1 if opt1 is less than opt2.
* @retval 1 if opt1 is greater than opt2.
*
*/
int compare_option(const struct dhcp_option *opt1, const struct dhcp_option *opt2);

/**
* @brief Copy DHCP option and allocate new memory for data.
*
* This function performs copy of a DHCP option from src to dst.
*
* @param[in,out] dst - Pointer to the destination DHCP option structure.
* @param[in] src - Pointer to the source DHCP option structure to copy from.
*
* @return None.
*
*/
void dhcp_copy_option(struct dhcp_option *dst, const struct dhcp_option *src);

/**
* @brief Cleanup DHCP option by freeing allocated memory.
*
* This function can only be used to clean up copied DHCP options. DHCP options from message parsing contain pointers to option
* locations inside the DHCP message and cannot be cleaned using this function.This function does not free the option structure itself.
*
* @param[in,out] opt - Pointer to the DHCP option structure to cleanup.
*
* @return None.
*
*/
void dhcp_cleanup_option(struct dhcp_option *opt);

/**
* @brief Clear DHCP option info and free all associated option lists.
*
* This function releases all dynamically allocated option nodes and resets the structure to zero.
*
* @param[in,out] opt_info - Pointer to the DHCP option info structure to clear.
*
* @return None.
*
*/
void dhcp_clear_option_info(struct dhcp_option_info *opt_info);

/**
* @brief Parse a list of DHCP options from option data.
*
* @param[in,out] opt_info - Pointer to DHCP option info structure where parsed options will be stored.
*                           Overload flag will be set if found.
* @param[in] opt_data - Pointer to the option data buffer to parse.
* @param[in] size - Size of the option data buffer in bytes.
*
* @return A linked list of DHCP options.
*
*/
struct dhcp_option *dhcp_parse_options(struct dhcp_option_info *opt_info,
                                       ui8* opt_data, size_t size);

/**
* @brief Parse DHCP message including options in option field, file field, and sname field.
*
* @param[out] opt_info - Pointer to DHCP option info structure where parsed options will be stored.
* @param[in] msg - Pointer to the DHCP message to parse.
* @param[in] size - Total size of the DHCP message in bytes.
*
* @return None.
*
*/
void dhcp_parse_msg(struct dhcp_option_info *opt_info, struct dhcp_msg *msg, size_t size);

/**
* @brief Validate DHCP message by checking message type consistency with operation type.
*
* @param[in] msg - Pointer to the DHCP message to validate.
* @param[in] opt_info - Pointer to the DHCP option info containing parsed message type.
*
* @return The status of the operation.
* @retval 0 if the message is valid.
* @retval -1 if the message is invalid.
*
*/
int dhcp_validate_msg(const struct dhcp_msg *msg, const struct dhcp_option_info *opt_info);

/**
* @brief Add a single IP address option to the buffer.
*
* This function add a 4-byte IP address option into the provided buffer.
*
* @param[in] code - DHCP option code.
* @param[in] ipaddr - IP address to add.
* @param[out] buf - Pointer to the buffer where the option will be written.
* @param[in] bufsize - Size of the buffer in bytes.
*
* @return The number of bytes written to the buffer.
*
*/
size_t dhcp_add_ipaddr_option(ui8 code, struct in_addr ipaddr, ui8* buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif // _DHCP_MSG_H_