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

#ifndef _PACKET_UTIL_H_
#define _PACKET_UTIL_H_

#include <netpacket/packet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <sys/time.h>

/**
 * @brief Network interface
 */
struct packet_intf
{
   char ifname[IFNAMSIZ];
   int  ifindex;
   int  iftype;
};

#define MAC_ADDRESS_LEN 6

/**
 * @brief Ethernet MAC Header
 */
struct mac_header
{
   unsigned char dst[MAC_ADDRESS_LEN];
   unsigned char src[MAC_ADDRESS_LEN];
   unsigned short proto;
};

/**
 * @brief IP header, not including option field
 */
struct ip_header
{
   unsigned char vihl; // Version + IP header length
   unsigned char tos;
   unsigned short len;
   unsigned short id;
   unsigned short frag;
   unsigned char ttl;
   unsigned char proto;
   unsigned short cksum;
   unsigned int src;
   unsigned int dst;
};

/**
 * @brief UDP header
 */
struct udp_header
{
   unsigned short src;
   unsigned short dst;
   unsigned short len;
   unsigned short cksum;
};

#define MAC_HEADER_SIZE sizeof(struct mac_header)
#define MIN_IP_HEADER_SIZE sizeof(struct ip_header)
#define UDP_HEADER_SIZE sizeof(struct udp_header)

#define MF_FLAG 0x2000  // more fragment flag
#define DF_FLAG 0x4000  // don't fragment flag

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Create a packet socket for raw packet I/O.
*
* @return The status of the operation
* @retval The socket descriptor on success.
* @retval -1 on error.
*
*/
int packet_init_socket();

/**
* @brief Get the interface index by interface name.
*
* @param[in] device_name - Pointer to the network device name string.
*
* @return Interface index
* @return The interface index on success.
* @retval -1 on error.
*
*/
int get_ifindex(const char *device_name);

/**
* @brief Attach a socket filter to the packet socket.
*
* @param[in] filter - Pointer to the Berkeley Packet Filter (BPF) program array.
* @param[in] filter_len - Number of filter instructions in the filter array.
*
* @return The status of the operation.
* @return 0 on success.
* @retval -1 on error.
*
*/
int packet_attach_filter(struct sock_filter *filter, int filter_len);

/**
* @brief Add an IP interface to the packet socket interface list.
*
* @param[in] ifname - Pointer to the interface name string.
* @param[in] iftype - Interface type, opaque to packet utility.
*
* @return The status of the operation.
* @return 0 on success.
* @retval -1 if too many interfaces or invalid interface.
*
*/
int packet_add_interface(const char *ifname, int iftype);

/**
* @brief Bind the packet socket to IP protocol.
*
* @return The status of the operation.
* @return 0 on success.
* @retval -1 on error.
*
*/
int packet_bind_socket();

/**
* @brief Receive data from the packet socket.
*
* @param[out] buf - Pointer to the buffer provided by caller to store received data.
* @param[in] len - Size of the buffer in bytes.
* @param[in] flags - Flags for the recvfrom operation.
* @param[out] from_addr - Pointer to store the socket address.
* @param[out] from_intf - Pointer to store the interface from which data was received.
* @param[in] timeout - Pointer to optional timeout value.
*
* @return The size of data
* @retval size if data received successfully
* @retval -1 if error.
* @retval 0 if timeout.
*
*/
int packet_recvfrom(void *buf, size_t len, int flags,
                    struct sockaddr_ll *from_addr,
                    struct packet_intf **from_intf,
                    struct timeval *timeout);

/**
* @brief Send data to the packet socket.
*
* @param[in] ifindex - Interface index of the interface used to send packet.
* @param[in] buf - Pointer to the data buffer to be sent.
* @param[in] len - Size of the data in bytes.
* @param[in] flags - Flags for the sendto operation.
*
* @return The size of data sent.
* @retval The size of data sent on success.
* @retval -1 on error.
*
*/
int packet_sendto(int ifindex, const void *buf, size_t len, int flags);


/**
* @brief Get the IP header from an Ethernet packet.
*
* @param[in] mac_header - Pointer to the MAC header of the Ethernet packet.
* @param[in] size - Size of the ethernet packet in bytes.
*
* @return The IP header
* @retval Pointer to the IP header on success.
* @retval NULL if the packet is too small.
*
*/
static inline struct ip_header *get_ip_header(void *mac_header, unsigned int size)
{
   return size < sizeof(struct mac_header)+MIN_IP_HEADER_SIZE ? NULL :
         (struct ip_header*)(mac_header+sizeof(struct mac_header));
}

/**
* @brief Get the IP header size including options.
*
* @param[in] iph - Pointer to the IP header.
*
* @return The IP header size in bytes.
*
*/
static inline unsigned int get_ip_header_size(const struct ip_header *iph)
{
   return (iph->vihl&0xf)<<2;
}

/**
* @brief Get the IP payload pointer.
*
* @param[in] iph - Pointer to the IP header.
* @param[in] size - Size of the IP packet in bytes.
*
* @return The IP payload.
* @retval Pointer to the IP payload on success.
* @retval NULL if the header size is invalid.
*
*/
static inline void *get_ip_payload(struct ip_header *iph, unsigned int size)
{
   unsigned int iph_size = get_ip_header_size(iph);

   return (iph_size < MIN_IP_HEADER_SIZE) | (iph_size > size) ? NULL :
          (void*)iph + iph_size;
}

/**
* @brief Get the UDP header from an IP packet.
*
* @param[in] ip_hdr - Pointer to the IP header.
* @param[in] size - Size of the IP packet in bytes.
*
* @return The UDP header.
* @retval Pointer to the UDP header.
* @retval NULL if the packet is too small.
*
*/
static inline struct udp_header *get_udp_header(void *ip_hdr, unsigned int size)
{
   struct ip_header *iph = (struct ip_header*)ip_hdr;

   return get_ip_header_size(iph) + UDP_HEADER_SIZE > size ? NULL :
          (struct udp_header *)get_ip_payload(iph, size);
}

/**
* @brief Check if the IP packet is truncated.
*
* @param[in] iph - Pointer to the IP header.
* @param[in] size - Data size starting from the IP header in bytes.
*
* @return The truncation status.
* @retval 1 if IP packet is truncated.
* @retval 0 if IP packet is not truncated.
*
*/
static inline int is_packet_truncated(const struct ip_header *iph, unsigned int size)
{
   return size < ntohs(iph->len);
}

/**
* @brief Check if the IP packet is fragmented or incomplete.
*
* @param[in] iph - Pointer to the IP header.
* @param[in] udph - Pointer to the UDP header.
*
* @return The fragmentation status.
* @retval 1 if it is a fragmented packet or IP packet does not contain entire UDP packet.
* @retval 0 if the packet is not fragmented and complete.
*
*/
static inline int is_ip_fragmented(const struct ip_header *iph,
                     const struct udp_header *udph)
{
   return (MF_FLAG & ntohs(iph->frag)) ||
          ntohs(udph->len) + get_ip_header_size(iph) > ntohs(iph->len);
}

/**
* @brief Get the UDP payload pointer.
*
* @param[in] udp_hdr - Pointer to the UDP header.
*
* @return Pointer to the UDP payload.
*
*/
static inline void *get_udp_payload(void *udp_hdr)
{
   return udp_hdr + UDP_HEADER_SIZE;
}

/**
* @brief Validate and parse an Ethernet packet to extract header pointers.
*
* @param[in] packet - Pointer to the ethernet packet buffer.
* @param[in] size - Size of the ethernet packet in bytes.
* @param[out] machdr - Pointer to store the MAC header.
* @param[out] iphdr - Pointer to store the IP header.
* @param[out] udphdr - Pointer to store the UDP header.
* @param[out] udp_payload_size - Pointer to store the UDP payload size in bytes.
*
* @return The status of the operation.
* @return Pointer to the UDP payload on success.
* @retval NULL if parse/validation fails.
*
*/
void *parse_and_validate_ethernet_packet(void *packet, unsigned int size,
                                         struct mac_header **machdr,
                                         struct ip_header **iphdr,
                                         struct udp_header **udphdr,
                                         unsigned int *udp_payload_size);

#ifdef __cplusplus
}
#endif

#endif // _PACKET_UTIL_H_