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
#ifndef P6_PLAT_SW_H
#define P6_PLAT_SW_H

#include "service_multinet_swfab.h"

#define SW_PORT_VENABLE_FORMAT(x) "sw_%s_venable", x->stringID
#define SW_PORT_UTVID_FORMAT(x) "sw_%s_ut_vid", x->stringID
#define SW_PORT_TVIDS_FORMAT(x) "sw_%s_t_vids", x->stringID
#define SW_PORT_TVIDS_DELIM ";"

typedef struct switchPortIDAndState {
    int portID;
    char* stringID;
    
    BOOL vidsLoaded;
    List taggingVids; // List of vids (ints)
    unsigned short untaggedVid;
    unsigned char bVlanEnabled;
} SwPortState, *PSwPortState;

int configVlan_ESW(PSWFabHALArg args, int numArgs, BOOL up);
int configVlan_ISW(PSWFabHALArg args, int numArgs, BOOL up);
int configVlan_WiFi(PSWFabHALArg args, int numArgs, BOOL up);

int stringIDIntSw (void* portID, char* stringbuf, int bufSize) ;
int stringIDExtSw (void* portID, char* stringbuf, int bufSize) ;

int eventIDSw (void* portID, char* stringbuf, int bufSize);

#endif
