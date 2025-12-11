/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

/**
* @brief Print and log system uptime with telemetry event reporting.
*
* This function logs the system uptime to a boot time log file and triggers telemetry 2.0 events
* for various system readiness milestones. The function prevents duplicate log entries
* by checking if the uptimeLog marker already exists in the file.
*
* @param[in] uptimeLog - Null-terminated string specifying the uptime log marker/event name.
*                    \n Used to identify the specific boot milestone being logged.
*                    \n Triggers corresponding telemetry 2.0 events.
* @param[in] bootfile - Null-terminated string specifying the path to the boot log file.
*                    \n Pass NULL to use the default file /rdklogs/logs/BootTime.log.
*                    \n If specified, this custom path will be used instead of the default.
* @param[in] uptime - Null-terminated string representation of uptime in seconds.
*                    \n Pass NULL to use the current system uptime from sysinfo().
*                    \n If provided, this value is used instead of querying the system.
*
* @return None.
*
*/
void print_uptime(char *uptimeLog, char *bootfile, char *uptime);

