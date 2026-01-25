/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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

#include <stdio.h>
#include "stackmode_log.h"

bool stackmode_log_init(void)
{
    if (rdk_logger_init(DEBUG_INI_PATH) != 0)
    {
        fprintf(stderr, "Warning: RDK logger initialization failed for %s\n", DEBUG_INI_PATH);
        return false;
    }
    
    STACKMODE_INFO("%s: Logging initialized successfully\n", __FUNCTION__);
    return true;
}

bool stackmode_log_deinit(void)
{
    STACKMODE_DEBUG("%s: Deinitializing logging\n", __FUNCTION__);
    
    if (rdk_logger_deinit() != 0)
    {
        fprintf(stderr, "Warning: RDK logger deinitialization failed\n");
        return false;
    }
    
    return true;
}
