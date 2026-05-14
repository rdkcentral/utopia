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

/**********************************************************************
 *    FileName:    pal_xml.h
 *      Author:    Barry Wang (bowan@cisco.com)
 *        Date:    2009-05-05
 * Description:    Header file of PAL XML abstract interfaces
 *****************************************************************************/
/*$Id: pal_xml.h,v 1.2 2009/05/19 07:41:12 bowan Exp $
 *
 *$Log: pal_xml.h,v $
 *Revision 1.2  2009/05/19 07:41:12  bowan
 *change some comments and data type as per common type definition
 *
 *Revision 1.1  2009/05/13 07:53:02  bowan
 *no message
 *
 *
 **/

#ifndef __PAL_XML_H__
#define __PAL_XML_H__

#include "pal_def.h"

#ifndef IN
	#define IN
#endif

#ifndef OUT
	#define OUT
#endif

#ifndef INOUT
	#define INOUT
#endif

#define PAL_XML_E_SUCCESS              0
#define PAL_XML_E_INVALID_PARAM        -1

typedef VOID  pal_xml_node;
typedef VOID  pal_xml_nodelist;
typedef VOID  pal_xml_top;


typedef struct{
    pal_xml_node *node;
    CHAR *tag_name;
}pal_xml_element;

/**
 * @brief Get a node list of all descendant elements with a given name and namespace.
 *
 * Returns a nodeList of all the descendant Elements with a given name and namespace in the order
 * in which they are encountered in a preorder traversal of the element tree.
 *
 * @param[in] top - The XML top tree to search elements from
 * @param[in] name - The target tag name to search for
 * @param[in] ns_url - The namespace URL of the tag to search for
 *
 * @return Pointer to pal_xml_nodelist containing all matched elements
 * @retval Non-NULL - A list of all matched elements
 * @retval NULL - No matching elements found
 */
 pal_xml_nodelist *PAL_xml_nodelist_GetbyName(IN pal_xml_top *top,
                                                IN const CHAR *name,
                                                IN const CHAR *ns_url);

/**
 * @brief Get the first node matching the given name and namespace.
 *
 * Returns the first node that matches the given name and namespace from the XML tree.
 *
 * @param[in] top - The XML top tree to search from
 * @param[in] name - The target tag name to search for
 * @param[in] ns_url - The namespace URL of the tag to search for
 *
 * @return Pointer to the matched element node
 * @retval Non-NULL - The first matched element node
 * @retval NULL - No matching element found
 */
 pal_xml_node *PAL_xml_node_GetFirstbyName(IN pal_xml_top *top,
                                                 IN const CHAR *name,
                                                 IN const CHAR *ns_url);

/**
 * @brief Get the node at the specified index in the node list.
 *
 * Returns the indexth item in the collection. If index is greater than or equal to the number
 * of nodes in the list, this returns NULL.
 *
 * @param[in] list - The node list to get the node from
 * @param[in] index - The index of the node to retrieve (zero-based)
 *
 * @return Pointer to the element node at the specified index
 * @retval Non-NULL - The matched element node at the given index
 * @retval NULL - Index out of range or list is empty
 */
 pal_xml_node *PAL_xml_nodelist_item (IN pal_xml_nodelist *list, IN ULONG index);

/**
 * @brief Get the first child node of the specified parent node.
 *
 * Returns the first child of the given node.
 *
 * @param[in] node - The parent node
 *
 * @return Pointer to the first child element node
 * @retval Non-NULL - The first child element node
 * @retval NULL - Node has no children
 */
 pal_xml_node *PAL_xml_node_GetFirstChild(IN pal_xml_node *node);

/**
 * @brief Get the text value of the specified node.
 *
 * Returns the value of the node by retrieving the text content from its first child text node.
 *
 * @param[in] node - The node to get the value from
 *
 * @return String value of the element
 * @retval Non-NULL - The text value of the element node
 * @retval NULL - Node has no value or is invalid
 */
 CHAR *PAL_xml_node_get_value(IN pal_xml_node *node);

/**
 * @brief Free a node list and release its resources.
 *
 * Frees the memory allocated for a pal_xml_nodelist structure.
 *
 * @param[in] list - The node list to be freed
 *
 * @return None
 */
 VOID PAL_xml_nodelist_free(IN pal_xml_nodelist *list);

/**
 * @brief Parse an XML document from a buffer.
 *
 * Parses the XML content stored in the buffer and creates a document tree structure.
 *
 * @param[in] buffer - The buffer containing the XML document content
 *
 * @return Pointer to the parsed XML document tree
 * @retval Non-NULL - Successfully parsed XML document tree
 * @retval NULL - Parsing failed or invalid buffer
 */
 pal_xml_top *PAL_xml_parse_buffer(IN const CHAR *buffer);

/**
 * @brief Get the number of nodes in the node list.
 *
 * Returns the number of nodes in the list. The range of valid child node indices is 0 to length-1 inclusive.
 *
 * @param[in] list - The node list to query
 *
 * @return The number of nodes in the list
 */
 ULONG PAL_xml_nodelist_length(IN pal_xml_nodelist *list);

/**
 * @brief Free the XML document tree and release its resources.
 *
 * Frees the memory allocated for the XML document tree.
 *
 * @param[in] top - The XML document tree to be freed
 *
 * @return None
 */
 VOID PAL_xml_top_free(IN pal_xml_top *top);

/**
 * @brief Print the DOM tree under the specified node.
 *
 * Converts the DOM tree structure under the given node to a formatted XML string representation
 * with whitespace formatting for readability.
 *
 * @param[in] node - The node to be printed
 *
 * @return Pointer to a string containing the formatted XML representation
 * @retval Non-NULL - A string containing the formatted XML tree
 * @retval NULL - Printing failed or invalid node
 */
 CHAR *PAL_xml_node_print(IN pal_xml_node *node);

/**
 * @brief Print the entire XML document with XML prolog.
 *
 * Prints the entire XML document, prepending the XML prolog first, with whitespace formatting
 * for readability.
 *
 * @param[in] top - The XML document tree to be printed
 *
 * @return Pointer to a string containing the formatted XML document
 * @retval Non-NULL - A string containing the complete formatted XML document with prolog
 * @retval NULL - Printing failed or invalid document
 */
 CHAR *PAL_xml_top_print(IN pal_xml_top *top);

/**
 * @brief Create a new XML document object.
 *
 * Creates a new XML document tree object with the nodeName set to "#document".
 *
 * @return Pointer to the newly created XML document object
 * @retval Non-NULL - A new XML document object
 * @retval NULL - Creation failed
 */
 pal_xml_top *PAL_xml_top_creat();

/**
 * @brief Create a new XML element with optional namespace.
 *
 * Creates a new XML element node with the specified tag name and optional namespace URI. If namespace
 * is provided, creates a namespaced element; otherwise creates a standard element.
 *
 * @param[in] top - The XML document object related to the element
 * @param[in] tag_name - The qualified name of the element to instantiate
 * @param[in] namespace - The namespace URI of the element to create
 *
 * @return Pointer to the newly created element object
 * @retval Non-NULL - The new element object successfully created
 * @retval NULL - Creation failed or invalid parameters
 */
pal_xml_element *PAL_xml_element_create (IN pal_xml_top * top,
                                         IN const CHAR* tag_name,
                                         IN const CHAR* namespace);

/**
 * @brief Set or update an attribute on an XML element.
 *
 * Adds a new attribute to the element. If an attribute with that name is already present in the element,
 * its value is changed to be that of the value parameter. If not, a new attribute is inserted into the element.
 *
 * @param[in] element - The XML element to modify
 * @param[in] name - The name of the attribute to create or alter
 * @param[in] value - The value to set in string form
 *
 * @return The status of the operation
 * @retval 0 - Success
 * @retval Non-zero - Failure code
 */
 INT32 PAL_xml_element_set_attr(IN pal_xml_element *element,
                              IN const CHAR *name,
                              IN const CHAR *value);

/**
 * @brief Append a child node to a parent node.
 *
 * Adds the node newChild to the end of the list of children of the parent node. If the newChild is
 * already in the tree, it is first removed before being appended.
 *
 * @param[in] node - The parent node
 * @param[in] newChild - The child node to add
 *
 * @return The status of the operation
 * @retval 0 - Success
 * @retval Non-zero - Failure code
 */
INT32 PAL_xml_node_append_child(IN pal_xml_node * node, IN pal_xml_node * newChild);

/**
 * @brief Add a child element with text value to a parent element.
 *
 * Creates a new child element with the specified tag name, sets its text content to the provided value,
 * and appends it to the parent element.
 *
 * @param[in] top - The related XML document object
 * @param[in] parent - The parent element to which the child will be added
 * @param[in] tag_name - The tag name of the child element to be added
 * @param[in] value - The text value of the child element
 *
 * @return None
 */
 VOID PAL_xml_top_AddElementTextValue(IN pal_xml_top *top,
                                    IN pal_xml_element *parent,
                                    IN CHAR *tag_name,
                                    IN CHAR *value);

/**
 * @brief Add a child element with INT32 value to a parent element.
 *
 * Creates a new child element with the specified tag name, converts the INT32 value to string format,
 * and appends it to the parent element.
 *
 * @param[in] top - The related XML document object
 * @param[in] parent - The parent element to which the child will be added
 * @param[in] tagname - The tag name of the child element to be added
 * @param[in] value - The INT32 value of the child element
 *
 * @return None
 */
 VOID PAL_xml_top_AddElementIntValue(IN pal_xml_top *top,
                                        IN pal_xml_element *parent,
                                        IN CHAR *tagname,
                                        IN INT32 value);

/**
 * @brief Add a child element with long long value to a parent element.
 *
 * Creates a new child element with the specified tag name, converts the long long value to string format,
 * and appends it to the parent element.
 *
 * @param[in] top - The related XML document object
 * @param[in] parent - The parent element to which the child will be added
 * @param[in] tagname - The tag name of the child element to be added
 * @param[in] value - The long long value of the child element
 *
 * @return None
 */
 VOID PAL_xml_top_AddElementLongValue(IN pal_xml_top *top,
                                         IN pal_xml_element *parent,
                                         IN CHAR *tagname,
                                         IN long long value);

/**
 * @brief Create a text node with the specified content.
 *
 * Creates a new text node with the provided text data, which is stored in the nodeValue field.
 *
 * @param[in] top - The related XML document object
 * @param[in] data - The text data for the text node
 *
 * @return Pointer to the newly created text node
 * @retval Non-NULL - The new text node successfully created
 * @retval NULL - Creation failed
 */
pal_xml_node *PAL_xml_top_create_textnode(IN pal_xml_top * top, IN const CHAR *data);

/**
 * @brief Escape special XML characters in a string.
 *
 * Converts special XML characters in the source string to their corresponding
 * XML entity representations. The conversion depends on whether the string is used as an attribute value.
 *
 * @param[in] src_str - The source string to be escaped
 * @param[in] attribute - Flag indicating whether this string is an attribute value (TRUE) or element content (FALSE)
 *
 * @return Pointer to the escaped string
 * @retval Non-NULL - The result escaped string with XML entities
 * @retval NULL - Escape operation failed
 */
CHAR *PAL_xml_escape(IN const CHAR *src_str, IN BOOL attribute);

#endif //__PAL_XML_H__