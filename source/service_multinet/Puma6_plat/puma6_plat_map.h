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
   Copyright [2015] [Cisco Systems, Inc.]

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
#ifndef P6_PLAT_MAP_H
#define P6_PLAT_MAP_H

typedef enum puma6entities {
    ENTITY_NP = 1,
    ENTITY_ISW,
    ENTITY_ESW,
    ENTITY_AP
} Puma6EntityID;

typedef enum puma6Hals {
    HAL_NOOP,
    HAL_WIFI,
    HAL_ESW,
    HAL_ISW,
    HAL_GRE,
    HAL_LINUX
} Puma6HalID;

/**
* @brief Generate a sysevent name from a string-based port ID.
*
* @param[in] portID  - Pointer to a string containing the port identifier.
*                    \n The function expects a string-based port ID.
* @param[out] stringbuf  - Pointer to a buffer where the generated sysevent name will be stored.
*                    \n The function formats the output as "if_<portID>-status"
* @param[in] bufsize  - The size of the stringbuf buffer.
*                    \n Specifies the maximum number of characters that can be written to stringbuf.
*
* @return The number of bytes required for the sysevent name .
* @retval >0 Number of bytes needed for the complete sysevent name string.
* @retval 0 If operation failed.
*
*/
int eventIDFromStringPortID (void* portID, char* stringbuf, int bufsize);

#define NUM_ENTITIES 4
#define NUM_HALS 6

#endif
