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
* @return The global priority level.
* @retval priority level on success.
* @retval -1 if no priority level is set.
*/
int ulog_GetGlobalPrior(void);

/**
* @brief Set the global log priority level.
*
* Sets the log mask up to the specified priority level using setlogmask.
*
* @param[in] prior - Priority level to set.
*
* @return None.
*/
void ulog_SetGlobalPrior(int prior);

/**
* @brief Get the current log priority level.
*
* @return The current log priority level.
*/
int ulog_GetPrior(void);

/**
* @brief Set the current log priority level.
*
* @param[in] prior - Priority level to set. If priority is out of valid range,
*                    the function returns without setting.
*
* @return None.
*
*/
void ulog_SetPrior(int prior);

/**
* @brief Get the current process ID and name.
*
* Retrieves the process ID and process name by reading /proc/pid/stat file.
*
* @param[in] size - Size of the name buffer.
* @param[out] name - Buffer to store the process name.
* @param[out] pid - Pointer to store the process ID.
*
* @return Status of the operation.
* @retval 0 on success.
* @retval -1 if size is 0, name or pid is NULL, or unable to read process information.
*
*/
int ulog_GetProcId(size_t size, char *name, pid_t *pid);

/**
* @brief Get the logging enable status.
*
* @return The current logging enable status.
* @retval 1 if logging is enabled.
* @retval 0 if logging is disabled.
*/
unsigned int ulog_GetEnable(void);

/**
* @brief Set the logging enable status.
*
* @param[in] enable - Enable flag (1 to enable, 0 to disable).
*
* @return None.
*/
void ulog_SetEnable(unsigned int enable);

/**
* @brief Log a message to system logger with file and line information.
*
* Logs messages to syslog with timestamp, file name, and line number information.
*
* @param[in] prior - Priority level.
* @param[in] fileName - Source file name where log is generated.
* @param[in] line - Line number in source file where log is generated.
* @param[in] format - Printf-style format string.
* @param[in] ... - Variable arguments for format string.
*
* @return None.
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
* @brief Per process initialization of logging infrastructure.
*
* Opens connection to system logger and sets up a prefix string.
*
* @return None.
*
* @note Opens connect to system logget and sets up a prefix string.
* Current prefix string is "UTOPIA:"
*/
void ulog_init();

/**
* @brief Log a general message to system logger.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] mesg - Message string to log.
*
* @return None.
*
* @note uses syslog LOCAL7.NOTICE facility.
*/
void ulog (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
* @brief Log a message to system logger with variable arguments.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] fmt - Printf-style format string for message.
* @param[in] ... - Variable arguments for format string.
*
* @return None.
*
* @note uses syslog LOCAL7.NOTICE facility.
*/
void ulogf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
* @brief Log a debug message to system logger.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] mesg - Debug message string to log.
*
* @return None.
*
* @note uses syslog LOCAL7.DEBUG facility.
*/
void ulog_debug (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
* @brief Log a debug message to system logger with variable arguments.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] fmt - Printf-style format string for debug message.
* @param[in] ... - Variable arguments for format string.
*
* @return None.
*
* @note uses syslog LOCAL7.DEBUG facility.
*/
void ulog_debugf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
* @brief Log an error message to system logger.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] mesg - Error message string to log.
*
* @return None.
*
* @note uses syslog LOCAL7.ERROR facility.
*/
void ulog_error (UCOMP comp, USUBCOMP sub, const char *mesg);

/**
* @brief Log an error message to system logger with variable arguments.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] fmt - Printf-style format string for error message.
* @param[in] ... - Variable arguments for format string.
*
* @return None.
*
* @note uses syslog LOCAL7.ERROR facility.
*/
void ulog_errorf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);

/**
* @brief Retrieve messages for given component.subcomponent.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[out] mesgbuf - Buffer to hold retrieved message strings.
* @param[in] size - Size of the message buffer.
*
* @return None.
*
* @note  mesgbuf will be truncated before mesgs are stored, and upto allowed size.
*/
void ulog_get_mesgs (UCOMP comp, USUBCOMP sub, char *mesgbuf, unsigned int size);

#if 0
/**
* @brief Log and run command string.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] cmd - Command string to execute.
*
* @return None.
*
* @note uses syslog LOCAL7.NOTICE facility
*/
void ulog_runcmd (UCOMP comp, USUBCOMP sub, const char *cmd);

/**
* @brief Log and run command string with variable arguments.
*
* @param[in] comp - Component id.
* @param[in] sub - Subcomponent id.
* @param[in] fmt - Printf-style format string for command.
* @param[in] ... - Variable arguments for format string.
*
* @return Status of the command execution.
*
* @note uses syslog LOCAL7.NOTICE facility
*/
int ulog_runcmdf (UCOMP comp, USUBCOMP sub, const char *fmt, ...);
#endif

#endif /* _ULOG_H_ */
