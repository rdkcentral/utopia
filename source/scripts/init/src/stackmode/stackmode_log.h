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

#ifndef _STACKMODE_LOG_H_
#define _STACKMODE_LOG_H_

#include <stdbool.h>
#include <stdio.h>

#if defined (_CBR_PRODUCT_REQ_) || defined (_XB6_PRODUCT_REQ_)
#define STACKMODE_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
#define STACKMODE_LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define STACKMODE_LOG(level, fmt...) {\
   FILE *logfp = fopen(STACKMODE_LOG_FILE, "a+");\
   if (logfp)\
   {\
        fprintf(logfp, "[STACKMODE][%s] ", level);\
        fprintf(logfp, fmt);\
        fclose(logfp);\
   }\
}

#define STACKMODE_ERROR(...) STACKMODE_LOG("ERROR", __VA_ARGS__)
#define STACKMODE_WARN(...)  STACKMODE_LOG("WARN", __VA_ARGS__)
#define STACKMODE_INFO(...)  STACKMODE_LOG("INFO", __VA_ARGS__)
#define STACKMODE_DEBUG(...) STACKMODE_LOG("DEBUG", __VA_ARGS__)

/**
 * @brief Initialize StackMode logging
 * @return true on success, false on failure
 */
bool stackmode_log_init(void);

/**
 * @brief Deinitialize StackMode logging
 * @return true on success, false on failure
 */
bool stackmode_log_deinit(void);

#endif /* _STACKMODE_LOG_H_ */
