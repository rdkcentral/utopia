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

/*
===================================================================
    This library provide logging API and routines to filter logs
    based on defined component.subcomponent
===================================================================
*/

#ifndef _ULOG_H_
#define _ULOG_H_

#include <stdio.h>              // FILE
#include <sys/types.h>          // pid_t
#include <sys/syslog.h>

#define ULOG_STR_SIZE  64

typedef struct _sys_log_info{
    char         name[ULOG_STR_SIZE]; // process name
    pid_t        pid;                 // process ID
    int          gPrior;              // global log priority
    int          prior;               // log priority
    unsigned int enable;              // logging enabled
    FILE*        stream;              // stream of log file
}_sys_Log_Info;


#define ulog_LOG_Emerg(format, ...)   ulog_sys(LOG_EMERG, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Alert(format, ...)   ulog_sys(LOG_ALERT, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Crit(format, ...)    ulog_sys(LOG_CRIT, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Err(format, ...)     ulog_sys(LOG_ERR, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Warn(format, ...)    ulog_sys(LOG_WARNING, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Note(format, ...)    ulog_sys(LOG_NOTICE, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Info(format, ...)    ulog_sys(LOG_INFO, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define ulog_LOG_Dbg(format, ...)     ulog_sys(LOG_DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__)

/**
 * @brief Get the global log priority level.
 *
 * Retrieves the current global logging priority mask by querying the system's
 * log mask and finding the highest enabled priority level.
 *
 * @return The current global log priority level.
 * @retval LOG_EMERG to LOG_DEBUG - Valid priority level
 * @retval -1 - No valid priority found in mask
 *
 */
int ulog_GetGlobalPrior(void);

/**
 * @brief Set the global log priority level.
 *
 * Configures the global logging priority mask using setlogmask() to filter messages
 * at or below the specified priority level.
 *
 * @param[in] prior - Log priority level to set
 *                    \n Valid range: LOG_EMERG (0) to LOG_DEBUG (7)
 *
 * @return void.
 *
 */
void ulog_SetGlobalPrior(int prior);

/**
 * @brief Get the current process log priority level.
 *
 * Retrieves the logging priority level stored in the sys_Log_Info structure
 * for the current process.
 *
 * @return The current process log priority level.
 * @retval LOG_EMERG to LOG_DEBUG - Current priority level from sys_Log_Info.prior.
 *
 */
int ulog_GetPrior(void);

/**
 * @brief Set the current process log priority level.
 *
 * Configures the logging priority level for the current process by updating
 * the sys_Log_Info.prior field. Only accepts valid syslog priority values.
 *
 * @param[in] prior - Log priority level to set
 *                    \n Valid range: LOG_EMERG (0) to LOG_DEBUG (7)
 * @return void.
 *
 */
void ulog_SetPrior(int prior);

/**
 * @brief Get the current process name and ID.
 *
 * Retrieves the process name by reading /proc/[pid]/stat and obtains the process ID
 * via getpid(). Extracts the process name from the stat file's second field.
 *
 * @param[in] size - Maximum size of the name buffer
 *                   \n Must be greater than 0
 * @param[out] name - Buffer to store the extracted process name
 *                    \n Will be null-terminated
 *                    \n Receives name from /proc/[pid]/stat with trailing ')' removed
 * @param[out] pid - Pointer to store the process ID
 *                   \n Receives value from getpid()
 *
 * @return The status of the operation.
 * @retval 0 - Success, name and pid retrieved
 * @retval -1 - Invalid parameters or failed to read /proc/[pid]/stat
 *
 */
int ulog_GetProcId(size_t size, char *name, pid_t *pid);

/**
 * @brief Get the logging enabled state.
 *
 * Retrieves the current logging enable flag from the sys_Log_Info structure.
 *
 * @return The current logging enabled state.
 * @retval 1 - Logging is enabled
 * @retval 0 - Logging is disabled
 *
 */
unsigned int ulog_GetEnable(void);

/**
 * @brief Set the logging enabled state.
 *
 * Configures whether logging is enabled for the current process by updating
 * the sys_Log_Info.enable field.
 *
 * @param[in] enable - Logging enable flag
 *                     \n 1 = Enable logging
 *                     \n 0 = Disable logging
 *
 * @return void.
 *
 */
void ulog_SetEnable(unsigned int enable);

/**
 * @brief Log a system message with file location and timestamp.
 *
 * Logs a formatted message to syslog with the specified priority, including timestamp,
 * source file name, and line number. Formats the message with current date/time down to
 * microseconds.
 *
 * @param[in] prior - Syslog priority level
 *                    \n Valid range: LOG_EMERG (0) to LOG_DEBUG (7)
 * @param[in] fileName - Source file name where log is invoked
 *                       \n Typically __FILE__ macro
 * @param[in] line - Line number in source file
 *                   \n Typically __LINE__ macro
 * @param[in] format - Printf-style format string for the log message
 * @param[in] ... - Variable arguments corresponding to format specifiers
 *
 * @return void.
 *
 */
void ulog_sys(int prior, const char* fileName, int line, const char* format, ...);

typedef enum {
    ULOG_SYSTEM,
    ULOG_LAN,
    ULOG_WAN,
    ULOG_WLAN,
    ULOG_FIREWALL,
    ULOG_IGD,
    ULOG_CONFIG,
    ULOG_IPV6,
    ULOG_SERVICE,
    ULOG_ETHSWITCH,
} UCOMP;

typedef enum {
    /* GENERAL */
                UL_INFO,
                UL_STATUS,
    /* SYSTEM */
                UL_SYSEVENT,
                UL_SYSCFG,
                UL_UTCTX,
    /* LAN */
                UL_DHCPSERVER,
    /* WAN */
                UL_WMON,
                UL_PPPOE,
                UL_PPTP,
                UL_L2TP,
    /* WLAN */
                UL_WLANCFG,
    /* FIREWALL */
                UL_PKTDROP,
                UL_TRIGGER,
    /* CONFIG */
                UL_IGD,
                UL_WEBUI,
                UL_UTAPI,
    /* IPv6 */
                UL_MANAGER,
                UL_TUNNEL,
                UL_DHCP
} USUBCOMP;


/**
 * @brief Initialize the Utopia logging infrastructure for the current process.
 *
 * Per-process initialization of logging infrastructure. Opens connection to system logger
 * (syslog) using the ULOG_IDENT ("UTOPIA") prefix and LOG_LOCAL7 facility with LOG_NDELAY option.
 * Must be called before using other ulog functions.
 *
 * @return void.
 */
void ulog_init();

/**
 * @brief Log a general message to system logger with component categorization.
 *
 * Logs a simple string message at LOG_NOTICE priority level to syslog, prefixed with
 * component.subcomponent identifiers for categorization and filtering.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] mesg - Message string to log
 *
 * @return void.
 *
 * @note uses syslog LOCAL7.NOTICE facility
 */
void ulog (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
 * @brief Log a formatted message to system logger with variable arguments.
 *
 * Logs a printf-style formatted message at LOG_NOTICE priority level to syslog,
 * prefixed with component.subcomponent identifiers. Supports variable argument lists.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] fmt - Printf-style format string for the message
 * @param[in] ... - Variable arguments corresponding to format specifiers
 *
 * @return void
 *
 * @note uses syslog LOCAL7.NOTICE facility
 */
void ulogf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
 * @brief Log a debug message to system logger.
 *
 * Logs a debug-level string message at LOG_DEBUG priority to syslog, prefixed with
 * component.subcomponent identifiers. Intended for detailed debugging information.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] mesg - Debug message string to log
 *
 * @return void
 *
 * @note uses syslog LOCAL7.DEBUG facility
 */
void ulog_debug (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
 * @brief Log a formatted debug message to system logger with variable arguments.
 *
 * Logs a printf-style formatted debug message at LOG_DEBUG priority to syslog,
 * prefixed with component.subcomponent identifiers. Supports variable argument lists.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] fmt - Printf-style format string for the debug message
 * @param[in] ... - Variable arguments corresponding to format specifiers
 *
 * @return void
 *
 * @note uses syslog LOCAL7.DEBUG facility
 */
void ulog_debugf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
 * @brief Log an error message to system logger.
 *
 * Logs an error-level string message at LOG_ERR priority to syslog, prefixed with
 * component.subcomponent identifiers. Used for reporting error conditions.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] mesg - Error message string to log
 *
 * @return void
 *
 * @note uses syslog LOCAL7.ERROR facility
 */
void ulog_error (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
 * @brief Log a formatted error message to system logger with variable arguments.
 *
 * Logs a printf-style formatted error message at LOG_ERR priority to syslog,
 * prefixed with component.subcomponent identifiers. Supports variable argument lists.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] fmt - Printf-style format string for the error message
 * @param[in] ... - Variable arguments corresponding to format specifiers
 *
 * @return void
 *
 * @note uses syslog LOCAL7.ERROR facility
 */
void ulog_errorf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
 * @brief Retrieve logged messages for a given component.subcomponent.
 *
 * Retrieves previously logged messages from the system log that match the specified
 * component and subcomponent identifiers. The messages are stored in the provided buffer.
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[out] mesgbuf - Buffer to store retrieved message strings
 *                       \n Will be truncated and null-terminated
 * @param[in] size - Size of the mesgbuf buffer in bytes
 *
 * @return void
 *
 * @note mesgbuf will be truncated before mesgs are stored, and upto allowed size.
 */
void ulog_get_mesgs (UCOMP comp, USUBCOMP sub, char *mesgbuf, unsigned int size);

#if 0
/**
 * @brief Log and execute a command string.
 *
 * Logs the command string at LOG_NOTICE priority to syslog with component.subcomponent
 * prefix, then executes the command using system().
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] cmd - Command string to log and execute
 *
 * @return void.
 *
 * @note uses syslog LOCAL7.NOTICE facility
 */
void ulog_runcmd (UCOMP comp, USUBCOMP sub, const char *cmd);

/**
 * @brief Log and execute a formatted command string with variable arguments.
 *
 * Logs a printf-style formatted command at LOG_NOTICE priority to syslog with
 * component.subcomponent prefix, then executes the formatted command using system().
 *
 * @param[in] comp - Component identifier from UCOMP enumeration
 * @param[in] sub - Subcomponent identifier from USUBCOMP enumeration
 * @param[in] fmt - Printf-style format string for the command
 * @param[in] ... - Variable arguments corresponding to format specifiers
 *
 * @return The status of the command execution.
 * @retval Command exit status - Return value from system() call
 *
 * @note uses syslog LOCAL7.NOTICE facility
 */
int ulog_runcmdf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);
#endif

#endif /* _ULOG_H_ */
