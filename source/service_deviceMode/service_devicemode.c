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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sysevent/sysevent.h"
#include "syscfg/syscfg.h"
#include "util.h"
#include "errno.h"
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <regex.h>
#include <telemetry_busmessage_sender.h>
#include <stdint.h>
#include "ccsp_dm_api.h"
#include "ccsp_custom.h"
#include "ccsp_psm_helper.h"
#include <ccsp_base_api.h>
#include "ccsp_memory.h"

#ifdef FEATURE_SUPPORT_ONBOARD_LOGGING
#include <rdk_debug.h>
#define LOGGING_MODULE "Utopia"
#define OnboardLog(...)     rdk_log_onboard(LOGGING_MODULE, __VA_ARGS__)
#else
#define OnboardLog(...)
#endif
#include "print_uptime.h"

#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERROR
#define RETURN_ERROR   -1
#endif

#define USECS_IN_MSEC 1000
#define MSECS_IN_SEC  1000

#define COLLECT_WAIT_INTERVAL_MS 40
#define ROUTER_MODE_SERVICES_PATH_1 "/etc/utopia/svc_router/"
#define PSM_NAME_NETWORKING_DEVICE_MODE "dmsb.device.NetworkingMode"
#define CCSP_SUBSYS     "eRT."
#define PRIVLAN_L3INST 4
#define XHS_BRIDGE_NAME "brlan1"
#define XHS_L3INST 5
#define LNF_MULTINET_INSTANCE 6
#define PSM_L2_BRIDGENAME "dmsb.l2net.%d.Name"
typedef enum deviceMode
{
    DEVICE_MODE_ROUTER,
    DEVICE_MODE_EXTENDER
}deviceMode;

#include <time.h>
#define LOG_FILE "/tmp/Debug_devicemode.txt"
#define APPLY_PRINT(fmt ...) {\
FILE *logfp = fopen(LOG_FILE , "a+");\
if (logfp){\
time_t s = time(NULL);\
struct tm* current_time = localtime(&s);\
fprintf(logfp, "[%02d:%02d:%02d] ",\
current_time->tm_hour,\
current_time->tm_min,\
current_time->tm_sec);\
fprintf(logfp, fmt);\
fclose(logfp);\
}\
}\

static int            sysevent_fd = -1;
static char          *sysevent_name = "devicemode";
static token_t        sysevent_token;
static unsigned short sysevent_port;
static char           sysevent_ip[19];

static void* bus_handle = NULL;
static const char* const service_devicemode_component_id = "ccsp.devicemode";

#define PSM_VALUE_GET_STRING(name, str) PSM_Get_Record_Value2(bus_handle, CCSP_SUBSYS, name, NULL, &(str))
#define PSM_VALUE_SET_STRING(name, str) PSM_Set_Record_Value2(bus_handle, CCSP_SUBSYS, name, ccsp_string, str)
#define PSM_VALUE_GET_INS(name, pIns, ppInsArry) PsmGetNextLevelInstances(bus_handle, CCSP_SUBSYS, name, pIns, ppInsArry)


int InitBus( void )
{
    int ret = 0;
    char* pCfg = CCSP_MSG_BUS_CFG;

    if (bus_handle == NULL)
    {
#ifdef DBUS_INIT_SYNC_MODE
        ret = CCSP_Message_Bus_Init_Synced(service_devicemode_component_id,
                                           pCfg,
                                           &bus_handle,
                                           Ansc_AllocateMemory_Callback,
                                           Ansc_FreeMemory_Callback);
#else
        ret = CCSP_Message_Bus_Init((char *)service_devicemode_component_id,
                                    pCfg,
                                    &bus_handle,
                                    (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,
                                    Ansc_FreeMemory_Callback);
#endif

        if (ret == -1)
        {
            fprintf(stderr, "BUS connection error\n");
        }
    }
    return ret;
}

int syseventInit()
{
    snprintf(sysevent_ip, sizeof(sysevent_ip),"%s","127.0.0.1");
    sysevent_port = SE_SERVER_WELL_KNOWN_PORT;
    sysevent_fd =  sysevent_open(sysevent_ip, sysevent_port, SE_VERSION, sysevent_name, &sysevent_token);
    if (sysevent_fd < 0)
        return -1;
    return 0;
}

void syseventClose()
{
    if (0 <= sysevent_fd)
    {
        sysevent_close(sysevent_fd, sysevent_token);
    }
}
int service_close ()
{
   syseventClose();
   if (bus_handle != NULL) {
        CCSP_Message_Bus_Exit(bus_handle);
   }
   return 0;
}

int read_cmd_output(char *cmd, char *output_buf, int size_buf)
{
    FILE *f = NULL;
    char *pos = NULL;

    if (!cmd || (!output_buf) || (size_buf <= 0))
        return -1;

    f = popen(cmd,"r");
    if(f==NULL){
        return -1;
    }
    fgets(output_buf,size_buf,f);
    /* remove trailing newline */
    if((pos = strrchr(output_buf, '\n')) != NULL)
        *pos = '\0';
    pclose(f);
    return 0;
}

int runCommandInShell(char *command)
{
   int pid;

   printf("\n executing %s\n", command);
   pid = fork();
   if (pid == -1)
   {
      printf("\n fork failed! \n");
      return -1;
   }

   if (pid == 0)
   {
      /* this is the child */
      int i;
      char *argv[4];

      /* close all of the child's other fd's */
      for (i=3; i <= 50; i++)
      {
         close(i);
      }

      argv[0] = "sh";
      argv[1] = "-c";
      argv[2] = command;
      argv[3] = 0;
      execv("/bin/sh", argv);
      printf("\n Should not have reached here! \n");
      exit(127);
   }

   /* parent returns the pid */
   return pid;
}

int collectProcess(int pid, int timeout)
{
   int32_t rc, status, waitOption=0;
   int32_t requestedPid=-1;
   uint32_t timeoutRemaining=0;
   uint32_t sleepTime;
   int ret=RETURN_ERROR;

   requestedPid = pid;
   timeoutRemaining = timeout;

   if(timeoutRemaining > 0)
     waitOption = WNOHANG;

   timeoutRemaining = (timeoutRemaining <= 1) ?
                      (timeoutRemaining + 1) : timeoutRemaining;
   while (timeoutRemaining > 0)
   {
      rc = waitpid(requestedPid, &status, waitOption);
      if (rc == 0)
      {
         if (timeoutRemaining > 1)
         {
            sleepTime = (timeoutRemaining > COLLECT_WAIT_INTERVAL_MS) ?
                         COLLECT_WAIT_INTERVAL_MS : timeoutRemaining - 1;
            usleep(sleepTime * USECS_IN_MSEC);
            timeoutRemaining -= sleepTime;
         }
         else
         {
            timeoutRemaining = 0;
         }
      }
      else if (rc > 0)
      {
         pid = rc;
         timeoutRemaining = 0;
         ret = RETURN_OK;
      }
      else
      {
         if (errno == ECHILD)
         {
            printf("\nCould not collect child pid %d, possibly stolen by SIGCHLD handler?", requestedPid);
            ret = RETURN_ERROR;
         }
         else
         {
            printf("\nbad pid %d, errno=%d", requestedPid, errno);
            ret = RETURN_ERROR;
         }

         timeoutRemaining = 0;
      }
   }

   return ret;
}

int runCommandInShellBlocking(char *command)
{
   int processId;
   int timeout = 0;
   if ( command == 0 )
      return 1;

   if((processId = runCommandInShell(command) ) < 0)
   {
      return 1;
   }
   if(collectProcess(processId, timeout) != 0)
   {
      printf("\n Process collection failed\n");
      return -1;
   }
   return 0;
}

int service_stop(int mode)
{
    APPLY_PRINT("%s: Stopping services according to device mode %d\n", __FUNCTION__, mode);
    char buf[256];
    memset(buf,0,sizeof(buf));
    switch(mode)
    {
        case DEVICE_MODE_ROUTER:
        {
            APPLY_PRINT("%s: Stopping services for ROUTER mode\n", __FUNCTION__);
            sysevent_set(sysevent_fd, sysevent_token, "lan-stop", "", 0);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4-down", "5", 0);
#if defined (_COSA_BCM_ARM_)
            sysevent_set(sysevent_fd, sysevent_token, "wan-stop", "", 0);
#endif
             //lte-1312
             APPLY_PRINT("%s: Killing zebra process\n", __FUNCTION__);
            runCommandInShellBlocking("killall zebra");
            snprintf(buf,sizeof(buf),"execute_dir %s stop", ROUTER_MODE_SERVICES_PATH_1);
            runCommandInShellBlocking(buf);
            runCommandInShellBlocking("systemctl stop CcspLMLite.service");
        }
        break;
        case DEVICE_MODE_EXTENDER:
        {
#if defined (_COSA_BCM_ARM_)
            APPLY_PRINT("%s: Stopping WAN services\n", __FUNCTION__);
            sysevent_set(sysevent_fd, sysevent_token, "wan-stop", "", 0);
#endif
            APPLY_PRINT("%s: Stopping LAN services\n", __FUNCTION__);
            sysevent_set(sysevent_fd, sysevent_token, "lan-stop", "", 0);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4-down", "5", 0);
            runCommandInShellBlocking("systemctl stop CcspLMLite.service");
        }
        break;
        default:
        break;
    }

    return 0;
}

int GetL2InterfaceNameFromPsm(int instanceNumber, char *pName, int len)
{
    char paramName[256]={0};
    int rc = CCSP_SUCCESS;
    char *pStr = NULL;

    if (!pName || (len <= 0))
        return -1;

    if (NULL != bus_handle)
    {
        snprintf(paramName,sizeof(paramName), PSM_L2_BRIDGENAME, instanceNumber);
        rc = PSM_VALUE_GET_STRING(paramName, pStr);
    }
    else
    {
        return -1;
    }
    if(rc == CCSP_SUCCESS && pStr != NULL)
    {
        if (strlen(pStr) > 0)
        {
            strncpy(pName,pStr,len);
        }

        Ansc_FreeMemory_Callback(pStr);
    }
    else
    {
        return -1;
    }
    return 0;
}

int service_start(int mode)
{
    APPLY_PRINT("%s: Starting services according to device mode %d\n", __FUNCTION__, mode);
    char buf[256];
    memset(buf,0,sizeof(buf));
    int rc = -1;
    switch(mode)
    {
        case DEVICE_MODE_ROUTER:
        {
            APPLY_PRINT("%s: Starting services for ROUTER mode\n", __FUNCTION__);
            int bridgemode = 0;
            if( 0 == syscfg_get( NULL, "bridge_mode", buf, sizeof(buf) ) )
            {
                APPLY_PRINT("%s: bridge_mode is %s \n", __FUNCTION__, buf);
                bridgemode = atoi(buf);
                APPLY_PRINT("%s: bridge_mode value is %d \n", __FUNCTION__, bridgemode);
            }
            snprintf(buf,sizeof(buf),"execute_dir %s", ROUTER_MODE_SERVICES_PATH_1);
            runCommandInShellBlocking(buf);
            if (bridgemode == 0)
            {
                APPLY_PRINT("%s: Starting LAN services\n", __FUNCTION__);
                sysevent_set(sysevent_fd, sysevent_token, "lan-start", "", 0);
            }
            else
            {
                APPLY_PRINT("%s: Starting BRIDGE services in else case \n", __FUNCTION__);
                sysevent_set(sysevent_fd, sysevent_token, "bridge-start", "", 0);
            }

// Do wan start only in XB technicolor for xb->xb backup wan testing.
#if defined (_COSA_BCM_ARM_)
            APPLY_PRINT("%s: Starting WAN services\n", __FUNCTION__);
            sysevent_set(sysevent_fd, sysevent_token, "wan-start", "", 0);
#endif
            // start ipv4 for XHS 
            snprintf(buf,sizeof(buf),"%d", XHS_L3INST);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4-up", buf, 0);

            snprintf(buf,sizeof(buf),"%d", LNF_MULTINET_INSTANCE);
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
            char lnfEnabled[8] = {0};
            syscfg_get(NULL, "lost_and_found_enable", lnfEnabled, sizeof(lnfEnabled));
            if(strncmp(lnfEnabled, "false", 5) != 0)
            {
                 sysevent_set(sysevent_fd, sysevent_token, "lnf-setup", buf, 0);
	    } 
#else
             sysevent_set(sysevent_fd, sysevent_token, "lnf-setup", buf, 0);
#endif
            runCommandInShellBlocking("systemctl restart CcspLMLite.service");
            char lanStartVal[64] = {0};
            sysevent_get(sysevent_fd, sysevent_token, "lan-status", lanStartVal, sizeof(lanStartVal));
            APPLY_PRINT("%s: lan-status value: %s\n", __FUNCTION__, lanStartVal);
           // int res = sysevent_get(sysevent_fd, sysevent_token, "lan-status", lanStartVal, sizeof(lanStartVal));
          /*  if(res == 0)
            {
                APPLY_PRINT("%s: lan-status value: %s\n", __FUNCTION__, lanStartVal);
                if(strcmp(lanStartVal, "stopped") == 0)
                {
                    APPLY_PRINT("%s : Starting LAN here \n", __FUNCTION__);
                    sysevent_set(sysevent_fd, sysevent_token, "lan-status", "started", 0);
                    sysevent_get(sysevent_fd, sysevent_token, "lan-status", lanStartVal, sizeof(lanStartVal));
                    APPLY_PRINT("%s: lan-status value after set: %s\n", __FUNCTION__, lanStartVal);
                }
            } */
            if(strcmp(lanStartVal, "started") == 0)
            {
                APPLY_PRINT("%s: Restarting zebra service\n", __FUNCTION__);
               // sysevent_set(sysevent_fd, sysevent_token, "zebra-restart", "", 0);
                if (0 != sysevent_set(sysevent_fd, sysevent_token, "zebra-restart", "", 0)) {
                    APPLY_PRINT("%s: Failed to restart zebra service\n", __FUNCTION__);
                }
                else {
                    APPLY_PRINT("%s: Zebra service restarted successfully\n", __FUNCTION__);
                }
            }
        }
        break;
        case DEVICE_MODE_EXTENDER:
        {
            char tmpbuf[64] = {0};
            //lte-1312
            APPLY_PRINT("%s, killing zebra process when switching to extender mode \n", __FUNCTION__);
            runCommandInShellBlocking("killall zebra");
            sysevent_set(sysevent_fd, sysevent_token, "lan-start", "", 0);
            sysevent_set(sysevent_fd, sysevent_token, "lan_status-dhcp", "started", 0);
// Do wan start only in XB technicolor for xb->xb backup wan testing.
#if defined (_COSA_BCM_ARM_)
            sysevent_set(sysevent_fd, sysevent_token, "wan-start", "", 0);
#endif

            sleep(1);
            // Set private Lan ipv4 down
            snprintf(buf,sizeof(buf),"%d", PRIVLAN_L3INST);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4-down", buf, 0);

            // Set XHS ipv4 down
            snprintf(buf,sizeof(buf),"%d", XHS_L3INST);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4-down", buf, 0);

            rc = GetL2InterfaceNameFromPsm(LNF_MULTINET_INSTANCE,tmpbuf,sizeof(tmpbuf));
            if (0 == rc)
            {
                snprintf(buf,sizeof(buf),"ip addr flush %s", tmpbuf);
            }
            else
            {
                snprintf(buf,sizeof(buf),"ip addr flush %s", XHS_BRIDGE_NAME);
            }
            runCommandInShellBlocking(buf);
            runCommandInShellBlocking("systemctl restart CcspLMLite.service");

        }
        break;
        default:
        break;
    }

    // restart common services.
    sysevent_set(sysevent_fd, sysevent_token, "dhcp_server-restart", "", 0);
    sysevent_set(sysevent_fd, sysevent_token, "firewall-restart", "", 0);
    return 0;
}

char* get_mode(int mode)
{
    switch(mode)
    {
        case DEVICE_MODE_ROUTER:
            return "ROUTER";
        case DEVICE_MODE_EXTENDER:
            return "EXTENDER";
        default:
        break;
    }
    return "NONE";
}

int handleDeviceModeUpdate (int newMode)
{
    //stopping and starting the services in router and extender mode
    service_stop(!newMode);    
    service_start(newMode);    
    return 0;
}
/*  Syntax: service_devicemode arg1 arg2
 *  where,arg1 --> stop,start,DeviceMode
 *        arg2 --> Device Mode (0) Router, (1) extender
 *
 */
int main(int argc, char *argv[])
{
    int mode = -1;

    if ((argc < 3) || !argv) {
        return -1;
    }
    if (!argv[1] || !argv[2])
    {
        return -1;
    }
    if (strlen(argv[2]) <= 0)
    {
        return -1;
    }
    mode=atoi(argv[2]);
    printf ("\n service_devicemode arg1 %s arg2 %s\n",argv[1],get_mode(mode));
    
    if (syseventInit() < 0)
    {
        return -1;
    }   

    if (InitBus() != 0)
    {
        return -1;
    }

    if (strcmp(argv[1],"stop") == 0)
    {
        // stop the device mode received as input
        service_stop(mode);
    }
    else if (strcmp(argv[1],"start") == 0)
    {
        // start the device mode received as input
        service_start(mode);
    }
    else if (strcmp(argv[1],"DeviceMode") == 0)
    {
        // update the device mode into db received as input and restart mode handling.
        handleDeviceModeUpdate(mode);
    }
    service_close();
    return 0;
}
