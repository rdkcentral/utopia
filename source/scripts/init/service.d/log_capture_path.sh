#!/bin/sh

##################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

#source /etc/utopia/service.d/log_env_var.sh
LOG_PATH="/rdklogs/logs/"
CONSOLEFILE="${LOG_PATH}Consolelog.txt.0"
source /etc/log_timestamp.sh

if [ ! -d "$LOG_PATH" ]; then
    mkdir $LOG_PATH
fi

SCRIPT_TRACE_LOG="/tmp/script_execution_trace.log"
SCRIPT_TRACE_FIFO="/tmp/.script_execution_trace.$$"

rm -f "$SCRIPT_TRACE_FIFO"
mkfifo "$SCRIPT_TRACE_FIFO"
tee -a "$CONSOLEFILE" < "$SCRIPT_TRACE_FIFO" >> "$SCRIPT_TRACE_LOG" &
exec > "$SCRIPT_TRACE_FIFO" 2>&1
rm -f "$SCRIPT_TRACE_FIFO"
PS4='+ pid=$$ script=$0 line=$LINENO: '
set -x

