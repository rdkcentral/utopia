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
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "stackmode_log.h"

static FILE *log_fp = NULL;

void stackmode_log(const char *level, const char *format, ...)
{
    va_list args;
    time_t now;
    struct tm *timeinfo;
    char timestamp[64];
    
    // Get current time
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Open log file in append mode
    FILE *fp = fopen(STACKMODE_LOG_FILE, "a");
    if (fp)
    {
        fprintf(fp, "[%s] [%s] ", timestamp, level);
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
        fclose(fp);
    }
    
    // Also print to stderr for immediate visibility
    fprintf(stderr, "[STACKMODE][%s] ", level);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

bool stackmode_log_init(void)
{
    // Create/truncate log file
    log_fp = fopen(STACKMODE_LOG_FILE, "w");
    if (!log_fp)
    {
        fprintf(stderr, "Warning: Failed to create log file %s\n", STACKMODE_LOG_FILE);
        return false;
    }
    
    fprintf(log_fp, "=== StackMode Log Started ===\n");
    fclose(log_fp);
    log_fp = NULL;
    
    return true;
}

bool stackmode_log_deinit(void)
{
    FILE *fp = fopen(STACKMODE_LOG_FILE, "a");
    if (fp)
    {
        fprintf(fp, "=== StackMode Log Ended ===\n");
        fclose(fp);
    }
    
    return true;
}
