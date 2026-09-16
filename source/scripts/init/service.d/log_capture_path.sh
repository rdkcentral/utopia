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

source /etc/log_timestamp.sh

if [ "${SCRIPT_TRACE_ACTIVE}" != "1" ]; then
    SCRIPT_TRACE_ACTIVE=1
    export SCRIPT_TRACE_ACTIVE
    SCRIPT_TRACE_LOG="/tmp/script_execution_trace.log"

    exec >> "$SCRIPT_TRACE_LOG" 2>&1
    echo "$(date '+%Y-%m-%d %H:%M:%S') SCRIPT_START pid=$$ script=$0 args=$*"
    PS4='+ pid=$$ script=$0 line=$LINENO: '
    set -x
fi

