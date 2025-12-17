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

#ifndef __UTAPI_UTIL_H__
#define __UTAPI_UTIL_H__

/*
 * Generic struct used to map between the various Enums and
 * their syscfg string representations
 */
typedef struct _EnumString_Map
{
    char* pszStr;
    int iEnum;
} EnumString_Map;

/*
 * Macros methods with automatic return on error
 * if you don't want automatic return, use the non-macro version
 */

#define UTOPIA_SET(ctx,name,value) \
                    if (0  == Utopia_Set((ctx),(name),(value))) { \
                        return (ERR_UTCTX_OP); \
                    } \

#define UTOPIA_SETINDEXED(ctx,name,index,value) \
                    if (0 == Utopia_SetIndexed((ctx),(name),(index),(value))) { \
                        return (ERR_UTCTX_OP); \
                    } \

#define UTOPIA_SETINDEXED_NORETURN(ctx,name,index,value) \
                    if (0 == Utopia_SetIndexed((ctx),(name),(index),(value))) { \
                        ulogf(ULOG_CONFIG, UL_UTAPI, "Error: Utopia_SetIndexed failed\n"); \
                    } \

#define UTOPIA_SETNAMED(ctx,name,prefix,value) \
                    if (0  == Utopia_SetNamed((ctx),(name),(prefix),(value))) { \
                        ulogf(ULOG_CONFIG, UL_UTAPI, "Error: setting %s_[%d] to %s", prefix, name, value); \
                        return (ERR_UTCTX_OP); \
                    } \



#define UTOPIA_SETIP(ctx,name,value) \
                    if (IsValid_IPAddr((value))) { \
                        UTOPIA_SET((ctx),(name),(value)) \
                    } else { \
                       return (ERR_INVALID_IP); \
                    } \


#define UTOPIA_VALIDATE_SET(ctx,name,value,validate_func,error) \
                    if (validate_func((value))) { \
                        UTOPIA_SET((ctx),(name),(value)) \
                    } else { \
                       return (error); \
                    } \

#define UTOPIA_UNSET(ctx,name) \
                    if (0  == Utopia_Unset((ctx),(name))) { \
                        return (ERR_UTCTX_OP); \
                    } \

#define UTOPIA_UNSETINDEXED(ctx,name,index) \
                    if (0 == Utopia_UnsetIndexed((ctx),(name),(index))) { \
                        return (ERR_UTCTX_OP); \
                    } \

#define UTOPIA_UNSETINDEXED_NORETURN(ctx,name,index) \
                    if (0 == Utopia_UnsetIndexed((ctx),(name),(index))) { \
                        ulogf(ULOG_CONFIG, UL_UTAPI, "Error: failed Utopia_UnsetIndexed\n"); \
                    } \

/*
 * Integer sets
 */
#define UTOPIA_SETINT(ctx,name,intvalue) \
                    { \
                        int err_rc = Utopia_SetInt((ctx),(name),(intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_SETINT_NORETURN(ctx,name,intvalue) \
                    { \
                        int err_rc = Utopia_SetInt((ctx),(name),(intvalue)); \
                        if (err_rc != SUCCESS) \
                            ulogf(ULOG_CONFIG, UL_UTAPI, "Error: failed Utopia_SetInt\n"); \
                    }

#define UTOPIA_SETINDEXEDINT(ctx,name,index,intvalue) \
                    { \
                        int err_rc = Utopia_SetIndexedInt((ctx),(name),(index),(intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_SETNAMEDINT(ctx,name,prefix,intvalue) \
                    { \
                        int err_rc = Utopia_SetNamedInt((ctx),(name),(prefix),(intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

/*
 * Boolean sets
 */
#define UTOPIA_SETBOOL(ctx,name,boolvalue) \
                    { \
                        int err_rc = Utopia_SetBool((ctx),(name),(boolvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_SETINDEXEDBOOL(ctx,name,index,boolvalue) \
                    { \
                        int err_rc = Utopia_SetIndexedBool((ctx),(name),(index),(boolvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_SETNAMEDBOOL(ctx,name,prefix,boolvalue) \
                    { \
                        int err_rc = Utopia_SetNamedBool((ctx),(name),(prefix),(boolvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

/*
 * GET macros are used ONLY on values that are always expected to be set
 * if a value is optional is syscfg, it is okay to ignore Utopia_Get method's
 * error status
 */
#define UTOPIA_GET(ctx,name,value,sz) \
                    if (0 == Utopia_Get((ctx),(name),(value),(sz))) { \
                        return (ERR_UTCTX_OP); \
                    } \

#define UTOPIA_GETINDEXED(ctx,name,index,out_value,size) \
                    if (0 == Utopia_GetIndexed((ctx),(name),(index),(out_value),(size))) { \
                        return (ERR_UTCTX_OP); \
                    } \

/*

#define UTOPIA_GETIP(ctx,name,value) \
                    if (IsValid_IPAddr((value))) { \
                        UTOPIA_GET((ctx),(name),(value)) \
                    } else { \
                       return (ERR_INVALID_IP); \
                    } \


#define UTOPIA_VALIDATE_GET(ctx,name,value,validate_func,error) \
                    if (validate_func((value))) { \
                        UTOPIA_GET((ctx),(name),(value)) \
                    } else { \
                       return (error); \
                    } \
*/

/*
 * Integer sets
 */

#define UTOPIA_GETINT(ctx,name,out_intvalue) \
                    { \
                        int err_rc = Utopia_GetInt((ctx),(name),(out_intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_GETINDEXEDINT(ctx,name,index,out_intvalue) \
                    { \
                        int err_rc = Utopia_GetIndexedInt((ctx),(name),(index),(out_intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_GETINDEXED2INT(ctx,name,index1,index2,out_value,size) \
                    { \
                        int err_rc = Utopia_GetIndexed2Int((ctx),(name),(index1),(index2),(out_intvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

/*
 * Integer sets
 */

#define UTOPIA_GETBOOL(ctx,name,out_boolvalue) \
                    { \
                        int err_rc = Utopia_GetBool((ctx),(name),(out_boolvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

#define UTOPIA_GETINDEXEDBOOL(ctx,name,index,out_boolvalue) \
                    { \
                        int err_rc = Utopia_GetIndexedBool((ctx),(name),(index),(out_boolvalue)); \
                        if (err_rc != SUCCESS) \
                            return err_rc; \
                    }

/*
 * Utility APIs
 */
/**
* @brief Convert an enumeration value to its corresponding string representation.
*
* @param[in] pMap  - Pointer to an EnumString_Map array for lookup.
* @param[in] iEnum - Enumeration value to convert.
*
* @return Pointer to the string representation of the enumeration.
* @retval Valid string pointer if converted successfully.
* @retval NULL if pMap is NULL or enumeration is not found.
*
*/
char* s_EnumToStr (EnumString_Map* pMap, int iEnum);

/**
* @brief Convert a string to its corresponding enumeration value.
*
* @param[in] pMap - Pointer to an EnumString_Map array for lookup.
* @param[in] iStr - Pointer to the string to convert.
*
* @return The enumeration value corresponding to the string.
* @retval Valid enumeration value if converted successfully.
* @retval -1 if pMap or iStr is NULL, or if the string is not found.
*
*/
int s_StrToEnum (EnumString_Map* pMap, const char *iStr);

/**
* @brief Validate if a string represents a valid IPv4 address.
*
* @param[in] ip - Pointer to the IP address string to validate.
*
* @return The validation result.
* @retval TRUE if the IP address is valid.
* @retval FALSE if the IP address is invalid or NULL.
*
*/
int IsValid_IPAddr (const char *ip);

/**
* @brief Validate if an integer represents a valid IPv4 address last octet.
*
* @param[in] ipoctet - Integer value of the last octet to validate.
*                      \n Valid range: 2 to 254.
*
* @return The validation result.
* @retval TRUE if the octet value is valid (greater than 1 and less than 255).
* @retval FALSE if the octet value is invalid.
*
*/
int IsValid_IPAddrLastOctet (int ipoctet);

/**
* @brief Validate if a string represents a valid netmask.
*
* @param[in] ip - Pointer to the netmask string to validate.
*
* @return The validation result.
* @retval TRUE if valid.
*
*/
int IsValid_Netmask (const char *ip);

/**
* @brief Validate if a string represents a valid MAC address.
*
* @param[in] mac - Pointer to the MAC address string to validate.
*
* @return The validation result.
* @retval TRUE if valid
*
*/
int IsValid_MACAddr (const char *mac);

/**
* @brief Validate if a string represents a valid ULA (Unique Local Address) IPv6 address.
*
* @param[in] address - Pointer to the IPv6 address string to validate.
*                      \n Format: "address/prefix_length" (e.g., "fc00::/7").
*                      \n ULA addresses have the first byte with (byte & 0xfe) == 0xfc.
*
* @return The validation result.
* @retval TRUE if the address is a valid ULA IPv6 address.
* @retval FALSE if the address is invalid, NULL, or not a ULA address.
*
*/
int IsValid_ULAAddress(const char *address);

/**
* @brief Check if a string contains only integer digits.
*
* @param[in] str - Pointer to the string to check.
*
* @return The validation result.
* @retval TRUE if the string contains only digits.
* @retval FALSE if the string contains non-digit characters.
*
*/
boolean_t IsInteger (const char *str);

/**
* @brief Check if two IPv4 addresses are on the same network.
*
* @param[in] addr1 - First IPv4 address in network byte order.
* @param[in] addr2 - Second IPv4 address in network byte order.
* @param[in] mask  - Network mask in network byte order.
*
* @return The comparison result.
* @retval 1 if addresses are on the same network.
* @retval 0 if addresses are not on the same network.
*
*/
int IsSameNetwork(unsigned long addr1, unsigned long addr2, unsigned long mask);

/**
* @brief Check if an IPv4 address is a loopback address.
*
* @param[in] addr - IPv4 address in network byte order.
*                   \n Loopback range: 127.0.0.0/8.
*
* @return The validation result.
* @retval 1 if the address is a loopback address.
* @retval 0 if the address is not a loopback address.
*
*/
int IsLoopback(unsigned long addr);

/**
* @brief Check if an IPv4 address is a multicast address.
*
* @param[in] addr - IPv4 address in network byte order.
*                   \n Multicast range: 224.0.0.0/4.
*
* @return The validation result.
* @retval 1 if the address is a multicast address.
* @retval 0 if the address is not a multicast address.
*
*/
int IsMulticast(unsigned long addr);

/**
* @brief Check if an IPv4 address is a broadcast address.
*
* @param[in] addr - IPv4 address in network byte order.
* @param[in] net  - Network address in network byte order.
* @param[in] mask - Network mask in network byte order.
*
* @return The validation result.
* @retval 1 if the address is a broadcast address (all ones, or subnet broadcast).
* @retval 0 if the address is not a broadcast address.
*
*/
int IsBroadcast(unsigned long addr, unsigned long net, unsigned long mask);

/**
* @brief Check if an IPv4 address is a network address.
*
* @param[in] addr - IPv4 address in network byte order.
* @param[in] net  - Network address in network byte order.
* @param[in] mask - Network mask in network byte order.
*
* @return The validation result.
* @retval 1 if the address is a network address (host bits are all zeros).
* @retval 0 if the address is not a network address.
*
*/
int IsNetworkAddr(unsigned long addr, unsigned long net, unsigned long mask);

/**
* @brief Validate if a netmask is valid (contiguous set bits).
*
* @param[in] netmask - Netmask value in network byte order.
*
* @return The validation result.
* @retval 1 if the netmask has contiguous set bits from left to right.
* @retval 0 if the netmask is invalid.
*
*/
int IsNetmaskValid(unsigned long netmask);

/**
* @brief Get the MAC address of a network interface.
*
* @param[in]  ifname  - Pointer to the interface name string.
* @param[out] out_buf - Pointer to the buffer where the MAC address string will be returned.
*                       \n Format: "xx:xx:xx:xx:xx:xx\n".
* @param[in]  bufsz   - Size of the output buffer.
*
* @return None.
*/
void s_get_interface_mac (char *ifname, char *out_buf, int bufsz);

/**
* @brief Connect to the sysevent daemon.
*
* @param[out] out_se_token - Pointer to a token_t where the sysevent token will be returned.
*
* @return The sysevent file descriptor.
* @retval >=0 Valid file descriptor if connection is successful.
* @retval <0 if connection fails.
*
*/
int s_sysevent_connect (token_t *out_se_token);

/**
* @brief Set an integer value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] value    - Integer value to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetInt (UtopiaContext *ctx, UtopiaValue ixUtopia, int value);

/**
* @brief Set a boolean value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] value    - Boolean value to be set (TRUE or FALSE).
*                       \n TRUE is stored as "1", FALSE as "0".
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetBool (UtopiaContext *ctx, UtopiaValue ixUtopia, boolean_t value);

/**
* @brief Set an indexed integer value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] iIndex   - Index for the value.
* @param[in] value    - Integer value to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetIndexedInt (UtopiaContext *ctx, UtopiaValue ixUtopia, int iIndex, int value);

/**
* @brief Set an indexed boolean value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] iIndex   - Index for the value.
* @param[in] value    - Boolean value to be set (TRUE or FALSE).
*                       \n TRUE is stored as "1", FALSE as "0".
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetIndexedBool (UtopiaContext *ctx, UtopiaValue ixUtopia, int iIndex, boolean_t value);

/**
* @brief Set a named integer value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] prefix   - Pointer to the name prefix string.
* @param[in] value    - Integer value to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetNamedInt (UtopiaContext *ctx, UtopiaValue ixUtopia, char *prefix, int value);

/**
* @brief Set a named boolean value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] prefix   - Pointer to the name prefix string.
* @param[in] value    - Boolean value to be set (TRUE or FALSE).
*                       \n TRUE is stored as "1", FALSE as "0".
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetNamedBool (UtopiaContext *ctx, UtopiaValue ixUtopia, char *prefix, boolean_t value);

/**
* @brief Set a named unsigned long value in the Utopia context.
*
* @param[in] ctx      - Pointer to the Utopia context.
* @param[in] ixUtopia - Utopia value identifier.
* @param[in] prefix   - Pointer to the name prefix string.
* @param[in] value    - Unsigned long value to be set.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_SetNamedLong (UtopiaContext *ctx, UtopiaValue ixUtopia, char *prefix, unsigned long value);

/**
* @brief Get an integer value from the Utopia context.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[out] out_int - Pointer to an integer where the value will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if the retrieved value is not a valid integer.
*
*/
int Utopia_GetInt (UtopiaContext *ctx, UtopiaValue ixUtopia, int *out_int);

/**
* @brief Get an indexed integer value from the Utopia context.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  index   - Index for the value.
* @param[out] out_int - Pointer to an integer where the value will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if the retrieved value is not a valid integer.
*
*/
int Utopia_GetIndexedInt (UtopiaContext *ctx, UtopiaValue ixUtopia, int index, int *out_int);

/**
* @brief Get a boolean value from the Utopia context.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[out] out_bool - Pointer to a boolean_t where the value will be returned.
*                        \n "1" is returned as TRUE, all other values as FALSE.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_GetBool (UtopiaContext *ctx, UtopiaValue ixUtopia, boolean_t *out_bool);

/**
* @brief Get an indexed boolean value from the Utopia context.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  index    - Index for the value.
* @param[out] out_bool - Pointer to a boolean_t where the value will be returned.
*                        \n "1" or "true" is returned as TRUE, all other values as FALSE.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_GetIndexedBool (UtopiaContext *ctx, UtopiaValue ixUtopia, int index, boolean_t *out_bool);

/**
* @brief Get a double-indexed integer value from the Utopia context.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  index1  - First index for the value.
* @param[in]  index2  - Second index for the value.
* @param[out] out_int - Pointer to an integer where the value will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if the retrieved value is not a valid integer.
*
*/
int Utopia_GetIndexed2Int (UtopiaContext *ctx, UtopiaValue ixUtopia, int index1, int index2, int *out_int);

/**
* @brief Get a double-indexed boolean value from the Utopia context.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  index1   - First index for the value.
* @param[in]  index2   - Second index for the value.
* @param[out] out_bool - Pointer to a boolean_t where the value will be returned.
*                        \n "1" is returned as TRUE, all other values as FALSE.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_GetIndexed2Bool (UtopiaContext *ctx, UtopiaValue ixUtopia, int index1, int index2, boolean_t *out_bool);

/**
* @brief Get a named boolean value from the Utopia context.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  name     - Pointer to the name string.
* @param[out] out_bool - Pointer to a boolean_t where the value will be returned.
*                        \n "1" is returned as TRUE, all other values as FALSE.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
*
*/
int Utopia_GetNamedBool (UtopiaContext *ctx, UtopiaValue ixUtopia, char *name, boolean_t *out_bool);

/**
* @brief Get a named integer value from the Utopia context.
*
* @param[in]  ctx     - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  name    - Pointer to the name string.
* @param[out] out_int - Pointer to an integer where the value will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if the retrieved value is not a valid integer.
*
*/
int Utopia_GetNamedInt (UtopiaContext *ctx, UtopiaValue ixUtopia,char *name, int *out_int);

/**
* @brief Get a named unsigned long value from the Utopia context.
*
* @param[in]  ctx      - Pointer to the Utopia context.
* @param[in]  ixUtopia - Utopia value identifier.
* @param[in]  name     - Pointer to the name string.
* @param[out] out_int  - Pointer to an unsigned long where the value will be returned.
*
* @return The status of the operation.
* @retval SUCCESS if the operation is successful.
* @retval ERR_UTCTX_OP if the Utopia context operation fails.
* @retval ERR_INVALID_INT_VALUE if the retrieved value is not a valid integer.
*
*/
int Utopia_GetNamedLong (UtopiaContext *ctx, UtopiaValue ixUtopia,char *name, unsigned long *out_int);

#endif // __UTAPI_UTIL_H__