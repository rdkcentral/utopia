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
 *    FileName:    pal_xml2s.h
 *      Author:    Barry Wang (bowan@cisco.com)
 *        Date:    2009-05-05
 * Description:    Header file of PAL translator for XML to a data structure
 *****************************************************************************/
/*$Id: pal_xml2s.h,v 1.2 2009/05/19 07:41:12 bowan Exp $
 *
 *$Log: pal_xml2s.h,v $
 *Revision 1.2  2009/05/19 07:41:12  bowan
 *change some comments and data type as per common type definition
 *
 *Revision 1.1  2009/05/13 07:53:02  bowan
 *no message
 *
 *
 **/

#ifndef __PAL_XML2S_H__
#define __PAL_XML2S_H__

#include <stddef.h>
#include <stdlib.h>
#include "pal_def.h"
#include "pal_xml.h"

#ifndef IN
	#define IN
#endif

#ifndef OUT
	#define OUT
#endif

#ifndef INOUT
	#define INOUT
#endif

#ifndef XML2S_MSIZE
#define XML2S_MSIZE(st,mb) offsetof(st,mb)
#endif

typedef ULONG PAL_ARRAY_SIZE;
typedef ULONG PAL_XML2S_FDMSK;

#define PAL_XML2S_E_SUCCESS  0
#define PAL_XML2S_E_INVALID_ARG  -1
#define PAL_XML2S_E_OUTOF_MEM    -2
#define PAL_XML2S_E_TAG_MISSING  -3
#define PAL_XML2S_E_FORMAT       -4

#define XML2S_TABLE_END {NULL, 0, 0, NULL, 0}

#define PAL_XML2S_INT8      1
#define PAL_XML2S_INT16     2
#define PAL_XML2S_INT32     3
#define PAL_XML2S_UINT8     4
#define PAL_XML2S_UINT16    5
#define PAL_XML2S_UINT32    6
#define PAL_XML2S_STRING    7
#define PAL_XML2S_STRUCT    8
#define PAL_XML2S_MAX_BITS  0xFFFF

#define PAL_XML2S_ARRAY    (0x0001 << 16)  //array
#define PAL_XML2S_OPTIONAL (0x0010 << 16)  //optional element.

/*table struct for the translation from XML to designated data struct*/
typedef struct _pal_xml2s_table{

    CHAR *tag_name;        //got the node from xml dom tree by given name

    UINT32 type;     //the content type of the element

    UINT32 offset;         //member offset in a struct  --
                             //#define offsetof(s,m) (size_t)&(((s *)0)->m)

    struct _pal_xml2s_table *child_s;   //point to the child sturcture member (array also taken as a common structure)
    UINT32 mask_bit;   /*mask the sturcture's fieldmask once find the element
                              * NOTE: For a structure array, this field must be the size of the structure.
                              */

}PAL_XML2S_TABLE;

/**
 * @brief Translate an XML tree to a data structure according to translation rules.
 *
 * Translates the XML DOM tree to a given data structure according to the rules defined in the
 * translation table. The function processes both simple types and complex structures, including arrays. It recursively handles nested structures
 * and allocates memory for dynamic arrays. The data buffer must be pre-allocated by the caller.
 *
 * @param[in] xml - The XML DOM tree (node) to be translated
 * @param[in] trans_table - The translation table defining the mapping rules between XML elements and data structure fields
 * @param[in,out] data_buff - Data structure memory buffer where the translated data will be stored
 *
 * @return The status of the operation
 * @retval PAL_XML2S_E_SUCCESS (0) - Translation successful
 * @retval PAL_XML2S_E_INVALID_ARG (-1) - Invalid arguments provided
 * @retval PAL_XML2S_E_OUTOF_MEM (-2) - Out of memory during array allocation
 * @retval PAL_XML2S_E_TAG_MISSING (-3) - Required XML tag missing
 * @retval PAL_XML2S_E_FORMAT (-4) - Format error during translation
 */
 INT32 PAL_xml2s_process(IN pal_xml_top *xml,
                       IN PAL_XML2S_TABLE *trans_table,
                       INOUT VOID *data_buff);

/**
 * @brief Free all memory allocated during XML to structure translation.
 *
 * Frees all memory allocated during PAL_xml2s_process, including dynamically allocated arrays and strings.
 * The data_buff must have been populated by PAL_xml2s_process using the same translation table to ensure
 * proper memory deallocation. The function recursively frees nested structures and array elements.
 *
 * @param[in] data_buff - The data buffer to be freed, obtained from PAL_xml2s_process
 * @param[in] trans_table - The translation table used during PAL_xml2s_process
 *
 * @return None
 */
 VOID PAL_xml2s_free(IN VOID *data_buff, IN PAL_XML2S_TABLE *trans_table);

#endif //__PAL_XML2S_H__

