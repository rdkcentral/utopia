#!/bin/sh 
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

#------------------------------------------------------------------
# This script is used to start ssh daemon
# $1 is the calling event (sshd-restart, lan-status, wan-status, etc)
#------------------------------------------------------------------

# OpenSSH based SSH service for RDK POC

source /etc/utopia/service.d/ulog_functions.sh
source /etc/utopia/service.d/log_capture_path.sh

SERVICE_NAME="sshd"
SELF_NAME="`basename "$0"`"

SSHD="/usr/sbin/sshd"
SSHD_CONFIG="/etc/ssh/sshd_config_readonly"
PID_FILE="/var/run/sshd.pid"
KEY_DIR="/var/run/ssh"
PMON="/etc/utopia/service.d/pmon.sh"

generate_openssh_keys()
{
    mkdir -p "${KEY_DIR}"
    chmod 0755 "${KEY_DIR}"

    [ -f "${KEY_DIR}/ssh_host_rsa_key" ] || ssh-keygen -q -t rsa -N '' -C '' -f "${KEY_DIR}/ssh_host_rsa_key"
    [ -f "${KEY_DIR}/ssh_host_ecdsa_key" ] || ssh-keygen -q -t ecdsa -N '' -C '' -f "${KEY_DIR}/ssh_host_ecdsa_key"
    [ -f "${KEY_DIR}/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -C '' -f "${KEY_DIR}/ssh_host_ed25519_key"

    chmod 600 "${KEY_DIR}"/ssh_host_*_key 2>/dev/null || true
    chmod 644 "${KEY_DIR}"/ssh_host_*_key.pub 2>/dev/null || true
}

do_start()
{
    SSHD_PID=`pidof sshd`

    if [ "${SSHD_PID}" ]; then
        echo "${SSHD_PID}" | awk '{print $1}' > "${PID_FILE}"
        sysevent set ssh_daemon_state up
        echo_t "[utopia] OpenSSH already running. PID: `cat ${PID_FILE}`"
        return 0
    fi

    generate_openssh_keys

    mkdir -p /var/run/sshd
    chmod 0755 /var/run/sshd

    mkdir -p /var/empty
    chown root:root /var/empty
    chmod 700 /var/empty

    ${SSHD} -f "${SSHD_CONFIG}" -o PidFile="${PID_FILE}" 2>>${CONSOLEFILE}

    sleep 1

    if [ ! -f "${PID_FILE}" ]; then
        pidof sshd | awk '{print $1}' > "${PID_FILE}"
    fi

    if [ -f "${PID_FILE}" ] && [ -s "${PID_FILE}" ]; then
        echo_t "[utopia] OpenSSH started. PID: `cat ${PID_FILE}`"
        sysevent set ssh_daemon_state up
    else
        echo_t "[utopia] OpenSSH failed to start"
        rm -f "${PID_FILE}"
        sysevent set ssh_daemon_state down
    fi
}

do_stop()
{
    sysevent set ssh_daemon_state down

    if [ -f "${PID_FILE}" ] && [ -s "${PID_FILE}" ]; then
        kill "`cat ${PID_FILE}`" 2>/dev/null
        sleep 1
    fi

    if pidof sshd >/dev/null 2>&1; then
        killall sshd 2>/dev/null
    fi

    rm -f "${PID_FILE}"
}

service_start()
{
    echo_t "[utopia] starting ${SERVICE_NAME} service"
    ulog ${SERVICE_NAME} status "starting ${SERVICE_NAME} service"

    do_start
    #OpenSSH POC: PMON monitoring temporarily disabled.
    #if [ -f "${PID_FILE}" ] && [ -s "${PID_FILE}" ]; then
        # In this POC, service_opensshd.sh is installed as
        # /etc/utopia/service.d/service_sshd.sh during do_install.
        # Therefore PMON restart points to the active OpenSSH-aware
        # service wrapper, not the original Dropbear implementation.
    #    ${PMON} setproc ssh sshd "${PID_FILE}" "/etc/utopia/service.d/service_sshd.sh sshd-restart"
    #fi

    sysevent set ${SERVICE_NAME}-errinfo
    sysevent set ${SERVICE_NAME}-status "started"
}

service_stop()
{
    echo_t "[utopia] stopping ${SERVICE_NAME} service"
    ulog ${SERVICE_NAME} status "stopping ${SERVICE_NAME} service"

    do_stop

    ${PMON} unsetproc ssh

    sysevent set ${SERVICE_NAME}-errinfo
    sysevent set ${SERVICE_NAME}-status "stopped"
}

service_lanwan_status()
{
    CURRENT_LAN_STATE=`sysevent get lan-status`
    CURRENT_WAN_STATE=`sysevent get wan-status`

    if [ "stopped" = "${CURRENT_LAN_STATE}" ] && [ "stopped" = "${CURRENT_WAN_STATE}" ]; then
        service_stop
    else
        service_start
    fi
}

service_bridge_status()
{
    CURRENT_BRIDGE_STATE=`sysevent get bridge-status`

    if [ "stopped" = "${CURRENT_BRIDGE_STATE}" ]; then
        service_stop
    elif [ "started" = "${CURRENT_BRIDGE_STATE}" ]; then
        service_start
    fi
}

echo_t "[utopia] ${SERVICE_NAME} $1 received"

case "$1" in
  "${SERVICE_NAME}-start")
      service_start
      ;;
  "${SERVICE_NAME}-stop")
      service_stop
      ;;
  "${SERVICE_NAME}-restart"|"sshd-restart")
      service_stop
      service_start
      ;;
  lan-status|wan-status)
      service_lanwan_status
      ;;
  bridge-status)
      service_bridge_status
      ;;
  current_wan_ifname)
      service_stop
      service_start
      ;;
  *)
      echo "Usage: $SELF_NAME [${SERVICE_NAME}-start|${SERVICE_NAME}-stop|${SERVICE_NAME}-restart|sshd-restart|lan-status|wan-status|bridge-status|current_wan_ifname]" >&2
      exit 3
      ;;
esac
