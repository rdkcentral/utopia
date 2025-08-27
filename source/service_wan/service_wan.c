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

/**
 * C version of "service_wan" scripts:
 * service_wan.sh/dhcp_link.sh/dhcp_wan.sh/static_link.sh/static_wan.sh
 *
 * The reason to re-implement service_wan with C is for boot time,
 * shell scripts is too slow.
 */

/*
 * since this utility is event triggered (instead of daemon),
 * we have to use some global var to (sysevents) mark the states.
 * I prefer daemon, so that we can write state machine clearly.
 */

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
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include <telemetry_busmessage_sender.h>
#if PUMA6_OR_NEWER_SOC_TYPE
#include "asm-arm/arch-avalanche/generic/avalanche_pp_api.h"
#include "netutils.h"
#endif
#ifdef FEATURE_SUPPORT_ONBOARD_LOGGING
#include <rdk_debug.h>
#define LOGGING_MODULE "Utopia"
#define OnboardLog(...)     rdk_log_onboard(LOGGING_MODULE, __VA_ARGS__)
#else
#define OnboardLog(...)
#endif
#include "secure_wrapper.h"
#include "print_uptime.h"
#include "safec_lib_common.h"

#if defined (FEATURE_RDKB_LED_MANAGER_CAPTIVE_PORTAL) || (FEATURE_RDKB_LED_MANAGER_LEGACY_WAN)
#include <sysevent/sysevent.h>
#define SYSEVENT_LED_STATE    "led_event"
#define IPV4_UP_EVENT         "rdkb_ipv4_up"
#define LIMITED_OPERATIONAL   "rdkb_limited_operational"
#define WAN_LINK_UP	      "rdkb_wan_link_up"
int sysevent_led_fd = -1;
token_t sysevent_led_token;
#endif

#ifdef UNIT_TEST_DOCKER_SUPPORT
#define VENDOR_SPEC_FILE "udhcpc.txt"
#define RESOLV_CONF_FILE  "resolv.conf"
#define STATIC
#else
#define VENDOR_SPEC_FILE "/etc/udhcpc.vendor_specific"
#define RESOLV_CONF_FILE  "/etc/resolv.conf"
#define STATIC static
#endif

#if defined (_PROPOSED_BUG_FIX_)
#include <syslog.h>

/*eRouter events*/
#define EROUTER_EVT_ID                                      "eRouterEvents"
#define EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED            72003001
#define EVENTS_EROUTER_IPV4_ONLY                            72003002
#define EVENTS_EROUTER_IPV6_ONLY                            72003003
#define EVENTS_EROUTER_DS_ENABLED                           72003004
#define EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED_STR        "eRouter is administratively disabled"
#define EVENTS_EROUTER_IPV4_ONLY_STR                        "eRouter enabled as IPv4 only"
#define EVENTS_EROUTER_IPV6_ONLY_STR                        "eRouter enabled as IPv6 only"
#define EVENTS_EROUTER_DS_ENABLED_STR                       "eRouter enabled as Dual Stack"
#endif

#define PROG_NAME       "SERVICE-WAN"
#define ER_NETDEVNAME "erouter0"

char DHCPC_PID_FILE[100]="";

#define DHCPV6_PID_FILE 		"/var/run/erouter_dhcp6c.pid"
#define DHCP6C_PROGRESS_FILE 	"/tmp/dhcpv6c_inprogress"

#define POSTD_START_FILE "/tmp/.postd_started"
//this value is from erouter0 dhcp client(5*127+10*4)
#define SW_PROT_TIMO   675
#define SW_PROT_TIMO_MIN   120
//#define RESOLV_CONF_FILE  "/etc/resolv.conf"
#define ONEWIFI_ENABLED "/etc/onewifi_enabled"
#define OPENVSWITCH_LOADED "/sys/module/openvswitch"
#define WFO_ENABLED       "/etc/WFO_enabled"

#define WAN_STARTED "/var/wan_started"

//Network Connectivity check
#if defined(FEATURE_TAD_HEALTH_CHECK)
#define SYSEVENT_NET_CONNECTIVITY_CHECK "network_connectivity_check"
enum NetworkConnectivityCheck
{
    NET_CONNNECTIVITY_CHECK_DISABLED = 0,
    NET_CONNNECTIVITY_CHECK_ENABLED,
    NET_CONNNECTIVITY_CHECK_STARTING,
    NET_CONNNECTIVITY_CHECK_STOPPED,
    NET_CONNNECTIVITY_CHECK_STARTED,
};
#endif

enum wan_prot {
    WAN_PROT_DHCP,
    WAN_PROT_STATIC,
};

enum wan_mode {
    WAN_MODE_AUTO,
    WAN_MODE_ETHWAN,
    WAN_MODE_DOCSIS
};



#ifdef DSLITE_FEATURE_SUPPORT
// Dslite dhcpv6 option 64 response Maximum wait time in seconds
#define DSLITE_DHCPREPLY_MAX_TIME 60
#endif
/*
 * XXX:
 * no idea why COSA_DML_DEVICE_MODE_DeviceMode is 1, and 2, 3, 4 for IPv4/IPv6/DS
 * and sysevent last_erouter_mode use 0, 1, 2, 3 instead.
 * let's just follow the last_erouter_mode. :-(
 */
enum wan_rt_mod {
    WAN_RTMOD_UNKNOW,
    WAN_RTMOD_IPV4, // COSA_DML_DEVICE_MODE_Ipv4 - 1
    WAN_RTMOD_IPV6, // COSA_DML_DEVICE_MODE_Ipv6 - 1
    WAN_RTMOD_DS,   // COSA_DML_DEVICE_MODE_Dualstack - 1
};

struct serv_wan {
    int             sefd;
    int             setok;
    char            ifname[IFNAMSIZ];
    enum wan_rt_mod rtmod;
    enum wan_prot   prot;
    int             timo;
};

struct cmd_op {
    const char      *cmd;
    int             (*exec)(struct serv_wan *sw);
    const char      *desc;
};

STATIC int wan_start(struct serv_wan *sw);
STATIC int wan_stop(struct serv_wan *sw);
STATIC int wan_restart(struct serv_wan *sw);
STATIC int wan_iface_up(struct serv_wan *sw);
STATIC int wan_iface_down(struct serv_wan *sw);
STATIC int wan_addr_set(struct serv_wan *sw);
STATIC int wan_addr_unset(struct serv_wan *sw);

#if !defined (FEATURE_RDKB_DHCP_MANAGER)
STATIC int wan_dhcp_start(struct serv_wan *sw);
STATIC int wan_dhcp_stop(struct serv_wan *sw);
STATIC int wan_dhcp_restart(struct serv_wan *sw);
STATIC int wan_dhcp_release(struct serv_wan *sw);
STATIC int wan_dhcp_renew(struct serv_wan *sw);
#endif

#if !defined(_WAN_MANAGER_ENABLED_)
STATIC int wan_static_start(struct serv_wan *sw);
STATIC int wan_static_stop(struct serv_wan *sw);
#endif

STATIC int wan_static_start_v6(struct serv_wan *sw);
STATIC int wan_static_stop_v6(struct serv_wan *sw);

STATIC struct cmd_op cmd_ops[] = {
    {"start",       wan_start,      "start service wan"},
    {"stop",        wan_stop,       "stop service wan"},
    {"restart",     wan_restart,    "restart service wan"},
    {"iface-up",    wan_iface_up,   "bring interface up"},
    {"iface-down",  wan_iface_down, "tear interface down"},
    {"addr-set",    wan_addr_set,   "set IP address with specific protocol"},
    {"addr-unset",  wan_addr_unset, "unset IP address with specific protocol"},

#if !defined (FEATURE_RDKB_DHCP_MANAGER)
    /* protocol specific */
    {"dhcp-start",  wan_dhcp_start, "trigger DHCP procedure"},
    {"dhcp-stop",   wan_dhcp_stop,  "stop DHCP procedure"},
    {"dhcp-restart",wan_dhcp_restart, "restart DHCP procedure"},
    {"dhcp-release",wan_dhcp_release,"trigger DHCP release"},
    {"dhcp-renew",  wan_dhcp_renew, "trigger DHCP renew"},
#endif
};

#if !defined (FEATURE_RDKB_DHCP_MANAGER)
STATIC int Getdhcpcpidfile(char *pidfile,int size )
{
#if defined(_PLATFORM_IPQ_)
        strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);

#elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
      {


        char udhcpflag[10]="";
        syscfg_get( NULL, "UDHCPEnable_v2", udhcpflag, sizeof(udhcpflag));
        if( 0 == strcmp(udhcpflag,"true")){
                strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);
        }
        else
        {
                strncpy(pidfile,"/var/run/eRT_ti_udhcpc.pid",size);
        }
     }
#else
        strncpy(pidfile,"/tmp/udhcpc.erouter0.pid",size);
#endif
return 0;
}

STATIC int dhcp_stop(const char *ifname)
{
    FILE *fp;
    char pid_str[10];
    int pid = -1;

    Getdhcpcpidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) != NULL) {
        if (fgets(pid_str, sizeof(pid_str), fp) != NULL && atoi(pid_str) > 0)
            pid = atoi(pid_str);

        fclose(fp);
    }

    if (pid <= 0)
#if defined(_PLATFORM_IPQ_)
        pid = pid_of("udhcpc", ifname);
#elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
        {
        char udhcpflag[10]="";
        syscfg_get( NULL, "UDHCPEnable_v2", udhcpflag, sizeof(udhcpflag));
        if( 0 == strcmp(udhcpflag,"true")){
                pid = pid_of("udhcpc", ifname);
        }
        else
        {
                pid = pid_of("ti_udhcpc", ifname);
        }
        }
#else
        pid = pid_of("udhcpc", ifname);
#endif

    if (pid > 0) {
        kill(pid, SIGUSR2); // triger DHCP release
        sleep(1);
        kill(pid, SIGTERM); // terminate DHCP client

        /*
        sleep(1);
        if (pid_of("ti_udhcpc", ifname) == pid) {
            fprintf(stderr, "%s: ti_udhcpc is still exist ! kill -9 it\n", __FUNCTION__);
            kill(pid, SIGKILL);
        }
        */
#if defined (_PROPOSED_BUG_FIX_)
        syslog(LOG_INFO, "%u-%s", EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED, EVENTS_EROUTER_ADMINISTRATIVELY_DISABLED_STR);
#endif
    }
    unlink(DHCPC_PID_FILE);

    unlink("/tmp/udhcp.log");
    return 0;
}


//#define VENDOR_SPEC_FILE "/etc/udhcpc.vendor_specific"
#define VENDOR_OPTIONS_LENGTH 100

/***
 * Parses a file containing vendor specific options
 *
 * options:  buffer containing the returned parsed options
 * length:   length of options
 *
 * returns:  0 on successful parsing, else -1
 ***/
STATIC int dhcp_parse_vendor_info( char *options, const int length, char *ethWanMode )
{
    FILE *fp;
    char subopt_num[12] ={0}, subopt_value[64] = {0} , mode[8] = {0} ;
    int num_read;
    errno_t rc = -1;

    if ((fp = fopen(VENDOR_SPEC_FILE, "ra")) != NULL) {
        int opt_len = 0;   //Total characters read

        //Start the string off with "43:"
        rc =  sprintf_s(options, length, "43:");
        if(rc < EOK)
        {
           ERR_CHK(rc);
        }
        opt_len = rc;

        while ((num_read = fscanf(fp, "%7s %11s %63s", mode, subopt_num, subopt_value)) == 3) {
            char *ptr;

            if (length - opt_len < 6) {
                fprintf( stderr, "%s: Too many options\n", __FUNCTION__ );
                fclose(fp);   //CID 61631 : Resource leak
                return -1;
            }

#if defined (EROUTER_DHCP_OPTION_MTA)
            if ( ( strcmp(mode,"DOCSIS") == 0 ) && ( strcmp (ethWanMode,"true") == 0) )
            {
                continue;
            }

            if ( ( strcmp(mode,"ETHWAN") == 0 ) && ( strcmp (ethWanMode,"false") == 0) )
            {
                continue;
            }
#else
            if ((strcmp(mode,"ETHWAN") == 0))
            {
                continue;
            }
#endif

            //Print the option number
            if (strcmp(subopt_num, "SUBOPTION2") == 0) {
                rc = sprintf_s(options + opt_len, (length - opt_len), "02");
                if(rc < EOK)
                {
                   ERR_CHK(rc);
                }
                opt_len += rc;
            }
            else if (strcmp(subopt_num, "SUBOPTION3") == 0) {
                rc = sprintf_s(options + opt_len, (length - opt_len), "03");
                if(rc < EOK)
                {
                   ERR_CHK(rc);
                }
                opt_len += rc;
            }
            else {
                fprintf( stderr, "%s: Invalid suboption\n", __FUNCTION__ );
                fclose(fp);
                return -1;
            }

            //Print the length of the sub-option value
            rc = sprintf_s(options + opt_len, (length - opt_len), "%02zx", strlen(subopt_value));
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            opt_len += rc;

            //Print the sub-option value in hex
            for (ptr=subopt_value; (char)*ptr != (char)0; ptr++) {
                if (length - opt_len <= 2) {
                    fprintf( stderr, "%s: Too many options\n", __FUNCTION__ );
                    fclose(fp);
                    return -1;
                }
                rc = sprintf_s(options + opt_len, (length - opt_len), "%02x", *ptr);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
                opt_len += rc;
            }
        } //while

        fclose(fp);

        if ((num_read != EOF) && (num_read != 3)) {
            fprintf(stderr, "%s: Error parsing file\n", __FUNCTION__);
            return -1;
        }
    }
    else {
        fprintf(stderr, "%s: Cannot read %s\n", __FUNCTION__, VENDOR_SPEC_FILE);
        return -1;
    }

    return 0;
}


STATIC int dhcp_start(struct serv_wan *sw)
{
    char l_cErouter_Mode[16] = {0}, l_cWan_if_name[16] = {0}, cEthWanMode[8] = {0} ;
    int err = 0;
    char map_mode[16] = {0};

    sysevent_get(sw->sefd, sw->setok, "map_transport_mode", map_mode, sizeof(map_mode));
    if (strcmp(map_mode, "MAPT") == 0)
    {
        fprintf(stderr, "%s: Do not start dhcpv4 client when mapt is already configured\n", __FUNCTION__);
        return 0;
    }

    syscfg_get(NULL, "last_erouter_mode", l_cErouter_Mode, sizeof(l_cErouter_Mode));

    syscfg_get(NULL, "wan_physical_ifname", l_cWan_if_name, sizeof(l_cWan_if_name));

    syscfg_get(NULL, "eth_wan_enabled", cEthWanMode, sizeof(cEthWanMode));
    //if the syscfg is not giving any value hardcode it to erouter0
    Getdhcpcpidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if (0 == l_cWan_if_name[0])
    {
        strncpy(l_cWan_if_name, "erouter0", 8);
        l_cWan_if_name[8] = '\0';
    }
    if (sw->rtmod == WAN_RTMOD_IPV4 || sw->rtmod == WAN_RTMOD_DS)
    {

  /*TCHXB6 is configured to use udhcpc */
#if defined(_PLATFORM_IPQ_)
        err = v_secure_system("/sbin/udhcpc -t 5 -n -i %s -p %s -s /etc/udhcpc.script",sw->ifname, DHCPC_PID_FILE);

        /* DHCP client didn't able to get Ipv4 configurations */
        if ( -1 == access(DHCPC_PID_FILE, F_OK) )
        {
            printf("%s: WAN service not able to get IPv4 configuration"
                   " in 5 lease try\n", __func__);
        }
#elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
        {

            char udhcpflag[10]="";
            syscfg_get( NULL, "UDHCPEnable_v2", udhcpflag, sizeof(udhcpflag));

            if( 0 == strcmp(udhcpflag,"true"))
            {
                char options[VENDOR_OPTIONS_LENGTH];

                if ((err = dhcp_parse_vendor_info(options, VENDOR_OPTIONS_LENGTH,cEthWanMode)) == 0)
                {
                    err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone -O 125 -O 2 -x %s -s /etc/udhcpc.script", sw->ifname, DHCPC_PID_FILE, options);
                }
            }
            else
            {
//#if defined (INTEL_PUMA7)
    //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                err = v_secure_system("ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
                             "-H DocsisGateway -p %s -B -b 4",
                             sw->ifname, DHCPC_PID_FILE);

//#else
    /*err = vsystem("ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
                 "-H DocsisGateway -p %s -B -b 1",
                 sw->ifname, DHCPC_PID_FILE);*/
//#endif
           }
       }
#else

        char options[VENDOR_OPTIONS_LENGTH];

        if ((err = dhcp_parse_vendor_info(options, VENDOR_OPTIONS_LENGTH,cEthWanMode)) == 0)
        {
#if defined (_XB6_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_) // TCXB6 and TCXB7 only
        // tcxb6-6655, add "-b" option, so that, udhcpc forks to
        // background if lease cannot be immediately negotiated.

  // In ethwan mode send dhcp options part of dhcp-client to get the eMTA dhcp options

#if defined (EROUTER_DHCP_OPTION_MTA)
            if (strcmp(cEthWanMode, "true") == 0 )
                err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone -O 122 -O 125 -O 2 -x %s -x 125:0000118b0701027B7C7c0107 -s /etc/udhcpc.script", sw->ifname, DHCPC_PID_FILE, options);
            else
                err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone -O 125 -O 2 -x %s -s /etc/udhcpc.script", sw->ifname, DHCPC_PID_FILE, options);
#else
            {
                err = vsystem("/sbin/udhcpc -b -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone -O 125 -O 2 -x %s -s /etc/udhcpc.script", sw->ifname, DHCPC_PID_FILE, options);
            }
#endif /* EROUTER_DHCP_OPTION_MTA */
#else
#if !defined (_HUB4_PRODUCT_REQ_)
            err = vsystem("/sbin/udhcpc -i %s -p %s -V eRouter1.0 -O ntpsrv -O timezone -O 125 -O 2 -x %s -s /etc/udhcpc.script", sw->ifname, DHCPC_PID_FILE, options);
#endif /* ! _HUB4_PRODUCT_REQ_ */
#endif /* _XB6_PRODUCT_REQ_ && _COSA_BCM_ARM_ */
        }
#endif /* _PLATFORM_IPQ_ */

/*
	err = vsystem("strace -o /tmp/stracelog -f ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i %s "
              "-H DocsisGateway -p %s -B -b 1",
              ifname, DHCPC_PID_FILE);
*/
        if (err != 0)
            fprintf(stderr, "%s: fail to launch erouter plugin\n", __FUNCTION__);
    }
    return err == 0 ? 0 : -1;
}
#endif   /* FEATURE_RDKB_DHCP_MANAGER */

STATIC int route_config(const char *ifname)
{
    if (v_secure_system("ip rule add iif %s lookup all_lans && "
                "ip rule add oif %s lookup erouter ",
                ifname, ifname) != 0) {
    }

    return 0;
}

STATIC int route_deconfig(const char *ifname)
{
    if (v_secure_system("ip rule del iif %s lookup all_lans && "
                "ip rule del oif %s lookup erouter ",
                ifname, ifname) != 0) {
    }
    return 0;
}

STATIC int route_config_v6(const char *ifname)
{
    if (vsystem("ip -6 rule add iif %s lookup all_lans && "
                "ip -6 rule add oif %s lookup erouter ",
                ifname, ifname) != 0) {
    /*
     * NOTE : Not returning error, as vsystem() always returns -1
     */
    }

    return 0;
}

STATIC int route_deconfig_v6(const char *ifname)
{
    if (vsystem("ip -6 rule del iif %s lookup all_lans && "
                "ip -6 rule del oif %s lookup erouter ",
                ifname, ifname) != 0) {
    /*
     * NOTE : Not returning error, as vsystem() always returns -1
     */
    }

    return 0;
}

int checkFileExists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

#ifdef DSLITE_FEATURE_SUPPORT
STATIC int Is_Dslite_Dhcpv6option64_received(struct serv_wan *sw)
{
    char buf[8];
    char status[32];
    if (!sw)
        return -1;

    memset(buf,0,sizeof(buf));
    syscfg_get(NULL, "dslite_enable", buf, sizeof(buf));

    if (!strncmp(buf,"1",1))
    {
        if (sw->rtmod == WAN_RTMOD_IPV6 || sw->rtmod == WAN_RTMOD_DS)
        {
            char endpointname[256];
            memset(status,0,sizeof(status));
            sysevent_get(sw->sefd, sw->setok, "dslite_option64-status", status, sizeof(status));
            if (!strncmp(status,"received",strlen("received")))
            {
                memset(endpointname,0,sizeof(endpointname));
                sysevent_get(sw->sefd, sw->setok, "dslite_dhcpv6_endpointname", endpointname, sizeof(endpointname));
                fprintf(stderr, "DHCP DS-Lite Option 64 received ok value: %s\n",endpointname);
                //If dslite_addr_fqdn_1 is not set, dslite would have failed to start, adding a restart to create a tunnel
                v_secure_system("service_dslite restart &");
                return 1;
            }
            fprintf(stderr, "DHCP DS-Lite Option 64 Error\n");
        }
    }
    return 0;
}

/*The function start_dhcpv6_client() is not called anywhere when the macro DSLITE_FEATURE_SUPPORT is activated, resulting in a compilation error.
So this definition is being disabled at compile time, until it is used.
*/

#if 0
STATIC int start_dhcpv6_client(struct serv_wan *sw)
{
    char buf[8];
    if (!sw)
        return -1;

    memset(buf,0,sizeof(buf));
    syscfg_get(NULL, "dslite_enable", buf, sizeof(buf));
    if (!strncmp(buf,"1",1))
    {
        if (sw->rtmod == WAN_RTMOD_IPV6 || sw->rtmod == WAN_RTMOD_DS)
        {
            switch (sw->prot)
            {
                case WAN_PROT_DHCP:
                    sleep(5);
                    sysevent_set(sw->sefd, sw->setok, "wan-status", "starting", 0);
                    sysevent_set(sw->sefd, sw->setok, "dslite_option64-status", "", 0);
                    fprintf(stderr, "Starting DHCPv6 Client now\n");
#if defined (FEATURE_RDKB_DHCP_MANAGER)
                    system("dmcli eRT setv Device.DHCPv6.Client.1.Enable bool true");
                    //sysevent_set(sw->sefd, sw->setok, "dhcpv6_client-start", "", 0);
                    fprintf(stderr, "%s  Enabling DHCPv6 client using TR181\n",__func__);
#elif defined(CORE_NET_LIB)
                    system("/usr/bin/service_dhcpv6_client dhcpv6_client_service_enable");
                    fprintf(stderr, "%s  Calling service_dhcpv6_client.c with dhcpv6_client_service_enable from service_wan.c\n",__func__);
#else
                    system("/etc/utopia/service.d/service_dhcpv6_client.sh enable");
#endif
                    break;
                case WAN_PROT_STATIC:
                    break;
            }
        }
    }
    return 0;
}
#endif

STATIC int wait_till_dhcpv6_client_reply(struct serv_wan *sw)
{
    char status[32];
    char buf[8];
    int count = 0;
    char *ok_s = "received";
    char *nok_s = "not received";
     if (!sw)
        return -1;

    memset(buf,0,sizeof(buf));
    syscfg_get(NULL, "dslite_enable", buf, sizeof(buf));
    if (!strncmp(buf,"1",1))
    {
        if (sw->rtmod == WAN_RTMOD_IPV6 || sw->rtmod == WAN_RTMOD_DS)
        {
            memset(status,0,sizeof(status));

            for (count=0; count < DSLITE_DHCPREPLY_MAX_TIME; ++count)
            {
                fprintf(stderr, "Waiting for DHCP DS-Lite Option 64 reply\n");
                sysevent_get(sw->sefd, sw->setok, "dslite_option64-status", status, sizeof(status));
                if (!strncmp(status,ok_s,strlen(ok_s)) || !strncmp(status,nok_s,strlen(nok_s)))
                {
                    break;
                }
                sleep(1);
            }
        }
    }
    return 0;
}
#endif

STATIC int wan_start(struct serv_wan *sw)
{
#if defined (_BWG_PRODUCT_REQ_)
    char gw_ip[64];
#endif
    char buf[16] = {0};
    int ret;
    char uptime[24];
    struct sysinfo si;

    print_uptime("Wan_init_start", NULL, NULL);
    sysinfo(&si);
    OnboardLog("Wan_init_start:%ld\n", si.uptime);

#if defined(FEATURE_TAD_HEALTH_CHECK)
    char output[16] = {0};
    enum NetworkConnectivityCheck nConnCheck = 0;

    sysevent_get(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, sizeof(output));
    nConnCheck = atoi(output);
    if(!(nConnCheck & NET_CONNNECTIVITY_CHECK_ENABLED) && (nConnCheck != NET_CONNNECTIVITY_CHECK_DISABLED))
    {
        fprintf(stderr, "%s-%d: DNS Connectivity Check Enabled, wan-start is not from Wan Manager Policy, Ignore \n", __FUNCTION__, __LINE__);
        return 0;
    }
    if((nConnCheck) && (nConnCheck != NET_CONNNECTIVITY_CHECK_ENABLED))
    {
        memset(output, 0, 16);
        nConnCheck = nConnCheck & (~NET_CONNNECTIVITY_CHECK_ENABLED);
        sprintf(output, "%d", nConnCheck);
        sysevent_set(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, 0);
    }
    fprintf(stderr, "%s-%d: wan-start, Dns ConnectivityCheck State=%s \n", __FUNCTION__, __LINE__, output);
#endif

    #if defined (_BRIDGE_UTILS_BIN_)

    char ovs_enable[8] = {0};
    char bridge_mode[8] = {0};

    if( 0 == syscfg_get( NULL, "bridge_mode", bridge_mode, sizeof( bridge_mode ) ) )
    {
        if ( atoi(bridge_mode) != 0 )
        {
            if( 0 == syscfg_get( NULL, "mesh_ovs_enable", ovs_enable, sizeof( ovs_enable ) ) )
            {
                if ((strcmp(ovs_enable,"true") == 0) || (0 == access(OPENVSWITCH_LOADED, F_OK)))
                {
                    v_secure_system("/usr/bin/bridgeUtils add-port brlan0 llan0 &");
                }
            }
            else if (0 == access(OPENVSWITCH_LOADED, F_OK))
            {
                v_secure_system("/usr/bin/bridgeUtils add-port brlan0 llan0 &");
            }
        }
    }
    #endif
/*
 * Wan Interfaces are controlled by RdkWanManager As Part of Unification.
 */
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    fprintf(stderr, "%s-%d:Wan Interface Control Moved from Service Wan to RdkWanManager. \n", __FUNCTION__, __LINE__);
    return 0;
#endif

#if defined (INTEL_PUMA7)
	//Intel Proposed RDKB Generic Bug Fix from XB6 SDK
	int pid = 0;
#endif
#if !defined(FEATURE_TAD_HEALTH_CHECK)
    /* state check */
    char status[16];
    sysevent_get(sw->sefd, sw->setok, "wan_service-status", status, sizeof(status));
    if (strcmp(status, "starting") == 0 || strcmp(status, "started") == 0) {
        fprintf(stderr, "%s: service wan has already %s !\n", __FUNCTION__, status);
        return 0;
    } else if (strcmp(status, "stopping") == 0) {
        fprintf(stderr, "%s: cannot start in status %s !\n", __FUNCTION__, status);
        return -1;
    }
#endif
    /* do start */
    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "starting", 0);

#if (defined _COSA_INTEL_XB3_ARM_)
    /* For xb3 we have default route for both wan0 and erouter0,
       move wan0 to separate routing table, to make sure we are
       limiting wan0 traffic only on wan0 */

    /* we will come here when wan0 got ip,tftp,tod was completed before erouter0
       and brlan0 got ipv6 */
    char cmroute_isolation[8] = {0};
    int  cm_isolation_enbld = 0;

    if( 0 == syscfg_get( NULL, "CMRouteIsolation_Enable", cmroute_isolation, sizeof( cmroute_isolation ) ) )
    {
       if ( strcmp (cmroute_isolation,"true") == 0 ) {
           cm_isolation_enbld=1;
       }
    }

    if (cm_isolation_enbld) {
    	char buff[256] = {0};
        FILE *Fp;
        char *p;
        Fp = v_secure_popen("r","ip -6 addr show dev wan0 scope global \
		    		| awk '/inet/{print $2}' | cut -d '/' -f1");
        if (Fp == NULL)
        {
    	   fprintf(stderr, "<%s>:<%d> Error popen\n", __FUNCTION__, __LINE__);
        }
        else
        {
           if (fgets(buff, 50, Fp) != NULL)
           {
              if (buff[0] != 0)
              {
 	         if ((p = strchr(buff, '\n'))) {
                    *p = '\0';
                 }
  	         fprintf(stderr, "Configuring wan0 to route table cmwan\n");
	         if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra_table", "wan0", "1024") == 0)
	         {
	            /* accept_Ra_table accpets only integers, currently table name cmwan mapped with 1024
		     * in case, if changed make sure to update in etc/iproute2/rt_tables too*/
    	            v_secure_system("ip -6 rule add from %s lookup cmwan && "
                                    "ip -6 rule add from all oif wan0 table cmwan && "
                                    "ip -6 route del default dev wan0 && "
                                    "touch /tmp/wan0_configured ",buff);

		    /* check to ensure, we are properly configured, partial configuration
                     * may lead to indefinite behaviour,revert to original state*/
    		    if (access( "/tmp/wan0_configured", F_OK ) != 0)
    		    {
                       fprintf(stderr, "Configuring wan0 to route table cmwan failed, Reset to default state\n");
	               if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra_table", "wan0", "254") == 0)
	               {
	                  v_secure_system("ip -6 rule del lookup cmwan && "
					  "ip -6 rule del from all oif wan0 lookup cmwan && "
		    	                  "ip -6 route del default dev wan0 table cmwan ");
		       }
		       else
	                  fprintf(stderr, "Sysctl set failed,Unable to Reset Route table for wan0\n");
                    }
		 }
		 else
		    fprintf(stderr, "Sysctl set failed,unable to configure routing table cmwan\n");
	      }
              else
	         fprintf(stderr, "WAN0 IPv6 null,Unable to configure route table cmwan\n");
            }
            else
            {
                /* ??? we can't be empty, either the box management is ipv4 only or
                rare conditon of wan0 is empty. can't taken any action for now
                */
                fprintf(stderr, "WAN0 IPv6 empty,Unable to configure route table cmwan\n");
            }
            v_secure_pclose(Fp);
        }
     }
     else
	fprintf(stderr, "RFC disabled, Skip WAN0 CM Route Isolation\n");
#endif

    /*
     * If we are in routing mode and executing a wan-restart
     * sysevent last_erouter_mode will allow us to stop the
     * correct services before starting them
     */
    syscfg_get(NULL, "last_erouter_mode", buf, sizeof(buf));
    sysevent_set(sw->sefd, sw->setok, "last_erouter_mode", buf, 0);

#if !defined(_WAN_MANAGER_ENABLED_)
    if (wan_iface_up(sw) != 0) {
        fprintf(stderr, "%s: wan_iface_up error\n", __FUNCTION__);
        sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
        return -1;
    }

#endif /*_WAN_MANAGER_ENABLED_*/

     //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
    /* set current_wan_ifname at wan-start, for all erouter modes */
    if (sw->rtmod != WAN_RTMOD_UNKNOW) {
    	/* set sysevents and trigger for other modules */
#if defined(FEATURE_TAD_HEALTH_CHECK)
        if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
           (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
        {
            fprintf(stderr, "%s: current_wan_ifname=%s \n", __FUNCTION__, sw->ifname);
    	    sysevent_set(sw->sefd, sw->setok, "current_wan_ifname", sw->ifname, 0);
        }
    }

 #ifndef DSLITE_FEATURE_SUPPORT
    if (sw->rtmod == WAN_RTMOD_IPV4 || sw->rtmod == WAN_RTMOD_DS)
    {
            #if !defined(_WAN_MANAGER_ENABLED_)
                if (wan_addr_set(sw) != 0) {
                    fprintf(stderr, "%s: wan_addr_set error\n", __FUNCTION__);
                    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
                    return -1;
                }
            #endif /*_WAN_MANAGER_ENABLED_*/

#if defined (_BWG_PRODUCT_REQ_)
                /*Adding default gateway */
                memset(gw_ip, 0 ,sizeof(gw_ip));
                sysevent_get(sw->sefd, sw->setok, "default_router", gw_ip, sizeof(gw_ip));
                if (vsystem("route add default gw %s dev %s",gw_ip,sw->ifname)!=0){
                fprintf(stdout, "%s: adding default route without gateway IP=%s \n", __FUNCTION__,gw_ip);
                vsystem("route add default dev %s",sw->ifname);
                }
#endif
                if (route_config(sw->ifname) != 0) {
                    fprintf(stderr, "%s: route_config error\n", __FUNCTION__);
                    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
                    return -1;
                }

                /*
                 * Saving the WAN protocol configuration to the sysevent variable.
                 * It's value will specify the protocol configuration of the previously
                 * running WAN service, which will be used in case of WAN restart.
                 */
                if (sw->prot == WAN_PROT_DHCP) {
                       sysevent_set(sw->sefd, sw->setok, "last_wan_proto", "dhcp", 0);
                }else if (sw->prot == WAN_PROT_STATIC) {
                       sysevent_set(sw->sefd, sw->setok, "last_wan_proto", "static", 0);
                }
    }
#endif
    /*
     * IPV6 static and dhcp configurations
     */
    if (sw->rtmod == WAN_RTMOD_IPV6 || sw->rtmod == WAN_RTMOD_DS) {


            #if defined (_COSA_BCM_ARM_) || defined (_COSA_QCA_ARM_)
                // dibbler fails sometime with tentative link local address , adding 5 sec delay
                sleep(5);
            #endif

            switch (sw->prot) {
            case WAN_PROT_DHCP:
#ifdef DSLITE_FEATURE_SUPPORT
            memset(status,0,sizeof(status));
             syscfg_get(NULL, "dslite_enable", status, sizeof(status));
             if (!strncmp(status,"1",1))
             {
                 sysevent_set(sw->sefd, sw->setok, "dslite_option64-status", "", 0);
                 sleep (5);
             }
#endif

                   fprintf(stderr, "Starting DHCPv6 Client now\n");
                    /* In IPv6 or dual mode, raise wan-status event here */
                   sysevent_set(sw->sefd, sw->setok, "wan-status", "starting", 0);

#if defined(FEATURE_RDKB_LED_MANAGER_LEGACY_WAN)
		   sysevent_led_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "OperationalStateHandler", &sysevent_led_token);
		   if(sysevent_led_fd != -1)
		   {
			   sysevent_set(sysevent_led_fd, sysevent_led_token, SYSEVENT_LED_STATE, WAN_LINK_UP, 0);
 			   fprintf(stderr, "%s  Sent WAN_LINK_UP event to RdkLedManager for registration \n",__func__);
		   }
#endif

#if defined (FEATURE_RDKB_DHCP_MANAGER)
                    v_secure_system("dmcli eRT setv Device.DHCPv6.Client.1.Enable bool true");
                    //sysevent_set(sw->sefd, sw->setok, "dhcpv6_client-start", "", 0);
                    fprintf(stderr, "%s  Enabling DHCPv6 client using TR181\n",__func__);
#elif defined(CORE_NET_LIB)
                    v_secure_system("/usr/bin/service_dhcpv6_client dhcpv6_client_service_enable");
                    fprintf(stderr, "%s  Calling service_dhcpv6_client.c with dhcpv6_client_service_enable from service_wan.c\n",__func__);
#else
                    v_secure_system("/etc/utopia/service.d/service_dhcpv6_client.sh enable");
#endif

#ifdef DSLITE_FEATURE_SUPPORT
                   wait_till_dhcpv6_client_reply(sw);
#endif
                   break;
             case WAN_PROT_STATIC:
                   if (wan_static_start_v6(sw) != 0) {
                           fprintf(stderr, "%s: wan_static_start error\n", __FUNCTION__);
                           return -1;
                   }
                   break;
            default:
              fprintf(stderr, "%s: unknow wan protocol\n", __FUNCTION__);
       }

       if (route_config_v6(sw->ifname) != 0) {
               fprintf(stderr, "%s: route_config_v6 error\n", __FUNCTION__);
               sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
               return -1;
       }

    }

#ifdef DSLITE_FEATURE_SUPPORT
    if (0 == Is_Dslite_Dhcpv6option64_received(sw))
    {

 if (sw->rtmod == WAN_RTMOD_IPV4 || sw->rtmod == WAN_RTMOD_DS)
    {
            #if !defined(_WAN_MANAGER_ENABLED_)
                if (wan_addr_set(sw) != 0) {
                    fprintf(stderr, "%s: wan_addr_set error\n", __FUNCTION__);
                    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
                    return -1;
                }
            #endif /*_WAN_MANAGER_ENABLED_*/

                if (route_config(sw->ifname) != 0) {
                    fprintf(stderr, "%s: route_config error\n", __FUNCTION__);
                    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
                    return -1;
                }

                /*
                 * Saving the WAN protocol configuration to the sysevent variable.
                 * It's value will specify the protocol configuration of the previously
                 * running WAN service, which will be used in case of WAN restart.
                 */
                if (sw->prot == WAN_PROT_DHCP) {
                       sysevent_set(sw->sefd, sw->setok, "last_wan_proto", "dhcp", 0);
                }else if (sw->prot == WAN_PROT_STATIC) {
                       sysevent_set(sw->sefd, sw->setok, "last_wan_proto", "static", 0);
                }
    }
    }
#endif

    if (access(POSTD_START_FILE, F_OK) != 0)
    {
        fprintf(stderr, "[%s] Restarting post.d from service_wan\n", __FUNCTION__);
        v_secure_system("touch " POSTD_START_FILE "; execute_dir /etc/utopia/post.d/");
    }

#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
       (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
    {
        sysevent_set(sw->sefd, sw->setok, "wan-status", "started", 0);
    }
    else if ((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTING - 1))) ||
             (nConnCheck == NET_CONNNECTIVITY_CHECK_ENABLED) )
    {
        sysevent_set(sw->sefd, sw->setok, "wan-status", "standby", 0);
    }
#else
    sysevent_set(sw->sefd, sw->setok, "wan-status", "started", 0);
#endif

    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "started", 0);

#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
       (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
    {
        sysevent_set(sw->sefd, sw->setok, "current_wan_state", "up", 0);

#if defined (FEATURE_RDKB_LED_MANAGER_CAPTIVE_PORTAL)
        char redirFlag[10]={0};
        char captivePortalEnable[10]={0};

        if (!syscfg_get(NULL, "redirection_flag", redirFlag, sizeof(redirFlag)) && !syscfg_get(NULL, "CaptivePortal_Enable", captivePortalEnable, sizeof(captivePortalEnable))){
	    if (!strcmp(redirFlag,"true") && !strcmp(captivePortalEnable,"true"))
	    {
		    if(sysevent_led_fd != -1)
		    {
			    sysevent_set(sysevent_led_fd, sysevent_led_token, SYSEVENT_LED_STATE, LIMITED_OPERATIONAL, 0);
			    fprintf(stderr, "%s  Sent LIMITED_OPERATIONAL event to RdkLedManager\n",__func__);
		    }
	    }
	    else
	    {
		    if(sysevent_led_fd != -1)
                    {
                            sysevent_set(sysevent_led_fd, sysevent_led_token, SYSEVENT_LED_STATE, IPV4_UP_EVENT, 0);
                            fprintf(stderr, "%s  Sent IPV4_UP_EVENT to RdkLedManager\n",__func__);
                    }
	    }
        }
        if (sysevent_led_fd != -1)
	    sysevent_close(sysevent_led_fd, sysevent_led_token);
#endif

        fprintf(stderr, "[%s] start firewall fully\n", PROG_NAME);
        /*XB6 brlan0 comes up earlier so ned to find the way to restart the firewall
        IPv6 not yet supported so we can't restart in service routed  because of missing zebra.conf*/

	fprintf(stderr, "[%s] start firewall fully\n", PROG_NAME);
        printf("%s Triggering RDKB_FIREWALL_RESTART\n",__FUNCTION__);
        t2_event_d("SYS_SH_RDKB_FIREWALL_RESTART", 1);
        sysevent_set(sw->sefd, sw->setok, "firewall-restart", NULL, 0);

        sysinfo(&si);
        snprintf(uptime, sizeof(uptime), "%ld", si.uptime);
        OnboardLog("RDKB_FIREWALL_RESTART:%s\n", uptime);
        sysevent_set(sw->sefd, sw->setok, "wan_start_time", uptime, 0);

        printf("Network Response script called to capture network response\n ");
        /*Network Response captured ans stored in /var/tmp/network_response.txt*/

#if defined (INTEL_PUMA7)
        //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
        pid = pid_of("sh", "network_response.sh");
        if (pid > 0)
            kill(pid, SIGKILL);
#endif
        v_secure_system("sh /etc/network_response.sh &");

        ret = checkFileExists(WAN_STARTED);
        printf("Check wan started ret is %d\n",ret);
        if ( 0 == ret )
        {
	    v_secure_system("touch /var/wan_started");
	    print_uptime("boot_to_wan_uptime",NULL, NULL);
        }
        else
        {
            printf("%s wan_service-status is started again, upload logs\n",__FUNCTION__);
            t2_event_d("RF_ERROR_wan_restart", 1);
            v_secure_system("/rdklogger/uploadRDKBLogs.sh '' HTTP '' false ");
        }

        sysinfo(&si);
	print_uptime("Waninit_complete", NULL, NULL);
        snprintf(uptime, sizeof(uptime), "%ld", si.uptime);
        OnboardLog("Wan_init_complete:%s\n",uptime);
        t2_event_d("btime_waninit_split", (int) si.uptime);

        /* RDKB-24991 to handle snmpv3 based on wan-status event */
        v_secure_system("sh /lib/rdk/postwanstatusevent.sh &");
#if (defined _COSA_INTEL_XB3_ARM_)
        if (cm_isolation_enbld) {
            fprintf(stderr, "Dumping Route table cmwan and routing rules\n");
            v_secure_system("ip -6 route show table cmwan && "
                            "ip -6 rule show ");
        }
#endif
    }
    return 0;
}

STATIC int wan_stop(struct serv_wan *sw)
{
    char status[16];
    char buf[16] = {0};
#if defined(FEATURE_TAD_HEALTH_CHECK)
    char output[16] = {0};
    enum NetworkConnectivityCheck nConnCheck = 0;

    sysevent_get(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, sizeof(output));
    nConnCheck = atoi(output);
    if(!(nConnCheck & NET_CONNNECTIVITY_CHECK_ENABLED) && (nConnCheck != NET_CONNNECTIVITY_CHECK_DISABLED))
    {
        fprintf(stderr, "%s-%d: DNS Connectivity Check Enabled, wan-stop is not from Wan Manager Policy, Ignore \n", __FUNCTION__, __LINE__);
        return 0;
    }
    if((nConnCheck) && (nConnCheck != NET_CONNNECTIVITY_CHECK_ENABLED))
    {
        memset(output, 0, 16);
        nConnCheck = nConnCheck & (~NET_CONNNECTIVITY_CHECK_ENABLED);
        sprintf(output, "%d", nConnCheck);
        sysevent_set(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, 0);
    }
    fprintf(stderr, "%s-%d: wan-stop, Dns ConnectivityCheck State=%s \n", __FUNCTION__, __LINE__, output);
#endif

/*
 * Wan Interfaces are controlled by RdkWanManager As Part of Unification.
 */
#if defined(WAN_MANAGER_UNIFICATION_ENABLED)
    fprintf(stderr, "%s-%d:Wan Interface Control Moved from Service Wan to RdkWanManager. \n", __FUNCTION__, __LINE__);
    return 0;
#endif

#if !defined(FEATURE_TAD_HEALTH_CHECK)
    /* state check */
    sysevent_get(sw->sefd, sw->setok, "wan_service-status", status, sizeof(status));
    if (strcmp(status, "stopping") == 0 || strcmp(status, "stopped") == 0) {
        fprintf(stderr, "%s: service wan has already %s !\n", __FUNCTION__, status);
        return 0;
    } else if (strcmp(status, "starting") == 0) {
        fprintf(stderr, "%s: cannot start in status %s !\n", __FUNCTION__, status);
        return -1;
    }
#endif
    /* do stop */
    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "stopping", 0);
#if (defined _COSA_INTEL_XB3_ARM_)
    if (access( "/tmp/wan0_configured", F_OK ) == 0)
    {
        fprintf(stderr, "Reset Route table and routing rules for wan0\n");
	if (sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra_table", "wan0", "254") == 0)
	{
	   v_secure_system("ip -6 rule del from all oif wan0 lookup cmwan && "
                           "ip -6 rule del lookup cmwan && "
		    	   "ip -6 route del default dev wan0 table cmwan && "
                           "rm /tmp/wan0_configured ");
	}
	else
	   fprintf(stderr, "Sysctl set failed,Unable to Reset Route table for wan0\n");
    }
#endif


    /*
     * To facilitate mode switch between IPV4, IPv6 and Mix mode we set last_erouter_mode
     * to 1, 2, 3 respectively and do wan-restart, to stop the right set of services we
     * store the mode value in last_erouter_mode sysevent variable during wan start phase and
     * use it to reset the sw->rtmod here.
     * sysevent last_erouter_mode = 1 Last running ip mode was IPV4.
     *                                   = 2 Last running ip mode was IPv6.
     *                                   = 3 Last running ip mode was Dual stack.
     */
    sysevent_get(sw->sefd, sw->setok, "last_erouter_mode", buf, sizeof(buf));
    if ( '\0' == buf[0] )
    {
        memset(buf,0,sizeof(buf));
        syscfg_get(NULL, "last_erouter_mode", buf, sizeof(buf));
    }
    switch (atoi(buf)) {
    case 1:
        sw->rtmod = WAN_RTMOD_IPV4;
        break;
    case 2:
        sw->rtmod = WAN_RTMOD_IPV6;
        break;
    case 3:
        sw->rtmod = WAN_RTMOD_DS;
        break;
    default:
        if ( '\0' == buf[0] )
        {
            fprintf(stderr, "%s: received NULL as (last_erouter_mode), considering erouter mode as default (DS) \n", __FUNCTION__);
            sw->rtmod = WAN_RTMOD_DS;
        }
        else
        {
            fprintf(stderr, "%s: unknow RT mode (last_erouter_mode)\n", __FUNCTION__);
            sw->rtmod = WAN_RTMOD_UNKNOW;
        }
        break;
    }

    /*
     * Fetching the configuration of previously running WAN service.
     * last_wan_proto values:
     *                 dhcp   : Last running WAN service's protocol was dhcp.
     *                 static : Last running WAN service's protocol was static.
     */
     sysevent_get(sw->sefd, sw->setok, "last_wan_proto", status, sizeof(status));
     if (strcmp(status, "dhcp") == 0) {
       sw->prot = WAN_PROT_DHCP;
     } else if (strcmp(status, "static") == 0) {
       sw->prot = WAN_PROT_STATIC;
     }

    if (sw->rtmod == WAN_RTMOD_IPV6 || sw->rtmod == WAN_RTMOD_DS) {
       if (sw->prot == WAN_PROT_DHCP) {
#if defined(FEATURE_TAD_HEALTH_CHECK)
           if((nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) ||
              (nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STOPPED - 1))))
#endif
       {
               fprintf(stderr, "Disabling DHCPv6 Client\n");
#if defined (FEATURE_RDKB_DHCP_MANAGER)
                    v_secure_system("dmcli eRT setv Device.DHCPv6.Client.1.Enable bool false");
                    //sysevent_set(sw->sefd, sw->setok, "dhcpv6_client-stop", "", 0);
                    fprintf(stderr, "%s  Disabling DHCPv6 client using TR181\n",__func__);
#elif defined(CORE_NET_LIB)
                    v_secure_system("/usr/bin/service_dhcpv6_client dhcpv6_client_service_disable");
                    fprintf(stderr, "%s  Calling service_dhcpv6_client.c with dhcpv6_client_service_disable from service_wan.c\n",__func__);
#else
                    v_secure_system("/etc/utopia/service.d/service_dhcpv6_client.sh disable");
#endif
       }
       } else if (sw->prot == WAN_PROT_STATIC) {
#if defined(FEATURE_TAD_HEALTH_CHECK)
           if((nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) ||
              (nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STOPPED - 1))) )
#endif
           {
               if (wan_static_stop_v6(sw) != 0) {
                       fprintf(stderr, "%s: wan_static_stop_v6 error\n", __FUNCTION__);
                       return -1;
               }
           }
       }
        if (route_deconfig_v6(sw->ifname) != 0) {
               fprintf(stderr, "%s: route_deconfig_v6 error\n", __FUNCTION__);
               sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
               return -1;
        }
    }


#ifdef DSLITE_FEATURE_SUPPORT
    //reset dslite sysevent during wan-stop
    sysevent_set(sw->sefd, sw->setok, "dslite_dhcpv6_endpointname", "", 0);
    sysevent_set(sw->sefd, sw->setok, "dslite_option64-status", "", 0);
#endif

    if (sw->rtmod == WAN_RTMOD_IPV4 || sw->rtmod == WAN_RTMOD_DS) {
        if (route_deconfig(sw->ifname) != 0) {
            fprintf(stderr, "%s: route_deconfig error\n", __FUNCTION__);
            sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
            return -1;
        }

        if (wan_addr_unset(sw) != 0) {
            fprintf(stderr, "%s: wan_addr_unset error\n", __FUNCTION__);
            sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
            return -1;
        }
    }

#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) ||
       (nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STOPPED - 1))) )
#endif
    {
#if !defined(_PLATFORM_IPQ_) && !defined(_WAN_MANAGER_ENABLED_) && !defined(_PROPOSED_BUG_FIX_)
        if (wan_iface_down(sw) != 0) {
            fprintf(stderr, "%s: wan_iface_down error\n", __FUNCTION__);
            sysevent_set(sw->sefd, sw->setok, "wan_service-status", "error", 0);
            return -1;
        }
#endif  /*_PLATFORM_IPQ_ && _WAN_MANAGER_ENABLED_*/
    }
    v_secure_system("rm -rf /tmp/ipv4_renew_dnsserver_restart");
    v_secure_system("rm -rf /tmp/ipv6_renew_dnsserver_restart");
    printf("%s wan_service-status is stopped, take log back up\n",__FUNCTION__);
    t2_event_d("RF_ERROR_Wan_down", 1);
    sysevent_set(sw->sefd, sw->setok, "wan_service-status", "stopped", 0);
#if defined (_XB6_PRODUCT_REQ_)
    v_secure_system("sh /etc/network_response.sh OnlyForNoRf &");
#endif
    v_secure_system("/rdklogger/backupLogs.sh false '' wan-stopped");
    return 0;
}

STATIC int wan_restart(struct serv_wan *sw)
{
    int err = 0;

    sysevent_set(sw->sefd, sw->setok, "wan-restarting", "1", 0);

    if (wan_stop(sw) != 0)
        fprintf(stderr, "%s: wan_stop error\n", __FUNCTION__);


    //Intel Proposed RDKB Bug Fix
    /* Do not try to start WAN if mode is unknown */
    if (sw->rtmod != WAN_RTMOD_UNKNOW) {
        if ((err = wan_start(sw)) != 0)
            fprintf(stderr, "%s: wan_start error\n", __FUNCTION__);
    }

    sysevent_set(sw->sefd, sw->setok, "wan-restarting", "0", 0);
    return err;
}
#if PUMA6_OR_NEWER_SOC_TYPE
int SendIoctlToPpDev( unsigned int cmd, void* data)
{
   int rc;
   int pp_fd;

   printf(" Entry %s \n", __FUNCTION__);

    if ( ( pp_fd = open ( "/dev/pp" , O_RDWR ) ) < 0 )
    {
        printf(" Error in open PP driver %d\n", pp_fd);
        close(pp_fd);
        return -1;
    }

    /* Send Command to PP driver */
    if ((rc = ioctl(pp_fd, cmd, data)) != 0)
    {
        printf(" Error ioctl %d return with %d\n", cmd, rc);
        close(pp_fd);
        return -1;
    }

    close(pp_fd);
    return 0;

}
#endif
STATIC int wan_iface_up(struct serv_wan *sw)
{
// XXX: MOVE these code to IPv6 scripts, why put them in IPv4 service wan ??
    char proven[64];
    char mtu[16];

#if defined(FEATURE_TAD_HEALTH_CHECK)
    char output[16] = {0};
    enum NetworkConnectivityCheck nConnCheck = 0;

    sysevent_get(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, sizeof(output));
    nConnCheck = atoi(output);


#endif

    switch (sw->rtmod) {
    case WAN_RTMOD_IPV6:
    case WAN_RTMOD_DS:
#if defined(FEATURE_TAD_HEALTH_CHECK)
        if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
           (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
        {
            syscfg_get(NULL, "router_adv_provisioning_enable", proven, sizeof(proven));
            if (atoi(proven) == 1) {
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", sw->ifname, "1");
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra", sw->ifname, "2");
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra_defrtr", sw->ifname, "1");
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra_pinfo", sw->ifname, "0");
#if !defined(INTEL_PUMA7) /* On Puma 7 autoconf enables SLAAC not link-local address */
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/autoconf", sw->ifname, "1");
#endif
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", sw->ifname, "0");
            } else {
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/accept_ra", sw->ifname, "0");
                sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/autoconf", sw->ifname, "0");
            }

            sysctl_iface_set("/proc/sys/net/ipv6/conf/all/forwarding", NULL, "1");
            sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/forwarding", sw->ifname, "1");
            sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/forwarding", "wan0", "0");
            sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/forwarding", "mta0", "0");
        }
        break;
    default:
        sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/disable_ipv6", sw->ifname, "1");
        sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/autoconf", sw->ifname, "0");
        break;
    }


    syscfg_get(NULL, "wan_mtu", mtu, sizeof(mtu));
#ifdef INTEL_PUMA7
#if !defined(DOCSIS_EXTENDED_MTU_SUPPORT)
    if(atoi(mtu) > 1500)
    {
	snprintf(mtu, sizeof(mtu), "1500");
	syscfg_set(NULL, "wan_mtu", mtu);
    }
#endif
    if (atoi(mtu) > 0)
        v_secure_system("ip -4 link set %s mtu %s", sw->ifname, mtu);
#else
    if (atoi(mtu) < 1500 && atoi(mtu) > 0)
        v_secure_system("ip -4 link set %s mtu %s", sw->ifname, mtu);
#endif

    sysctl_iface_set("/proc/sys/net/ipv4/conf/%s/arp_announce", sw->ifname, "1");
    v_secure_system("ip -4 link set %s up", sw->ifname);
#if PUMA6_OR_NEWER_SOC_TYPE

    if(0 == strncmp(sw->ifname,ER_NETDEVNAME,strlen(ER_NETDEVNAME)))
    {
        avalanche_pp_local_dev_addr_ioctl_params_t pp_gwErtMacAddr;
        NETUTILS_GET_MACADDR(ER_NETDEVNAME, (macaddr_t *)&pp_gwErtMacAddr.u.mac_addr);
        pp_gwErtMacAddr.op_type = ADD_ADDR;
        pp_gwErtMacAddr.addr_type = GW_MAC_ADDR;
        SendIoctlToPpDev(PP_DRIVER_SET_LOCAL_DEV_ADDR,&pp_gwErtMacAddr);
    }
    {// send IOCTL for l2sd0
        avalanche_pp_local_dev_addr_ioctl_params_t pp_gwL2Sd0MacAddr;
        NETUTILS_GET_MACADDR("l2sd0", (macaddr_t *)&pp_gwL2Sd0MacAddr.u.mac_addr);
        pp_gwL2Sd0MacAddr.op_type = ADD_ADDR;
        pp_gwL2Sd0MacAddr.addr_type = RND_MAC_ADDR;
        SendIoctlToPpDev(PP_DRIVER_SET_LOCAL_DEV_ADDR,&pp_gwL2Sd0MacAddr);
    }
#endif
    return 0;
}

STATIC int wan_iface_down(struct serv_wan *sw)
{
    int err = 0;
#if !defined(_PLATFORM_RASPBERRYPI_)  && !defined(_PLATFORM_BANANAPI_R4_)
    err = v_secure_system("ip -4 link set %s down", sw->ifname);
#endif
#if PUMA6_OR_NEWER_SOC_TYPE

    if(0 == strncmp(sw->ifname,ER_NETDEVNAME,strlen(ER_NETDEVNAME)))
    {
        avalanche_pp_local_dev_addr_ioctl_params_t pp_gwErtMacAddr;
        NETUTILS_GET_MACADDR(ER_NETDEVNAME, (macaddr_t *)&pp_gwErtMacAddr.u.mac_addr);
        pp_gwErtMacAddr.op_type = FLUSH_LIST;
        pp_gwErtMacAddr.addr_type = GW_MAC_ADDR;
        SendIoctlToPpDev(PP_DRIVER_SET_LOCAL_DEV_ADDR,&pp_gwErtMacAddr);
    }
#endif

    return err == 0 ? 0 : -1;
}

STATIC int wan_addr_set(struct serv_wan *sw)
{
    char val[64];
#if !defined(_COSA_BCM_MIPS_)
    char mischandler_ready[10] ={0};
#endif
#if !defined(_PLATFORM_IPQ_) && !defined(_WAN_MANAGER_ENABLED_) && !defined(_PROPOSED_BUG_FIX_)
    char state[16];
    int timo = 0;
#endif
    int count=0;
    //FILE *fp;
    char ipaddr[16];
    char lanstatus[10] = {0};
    char brmode[4] = {0};

#if defined(FEATURE_TAD_HEALTH_CHECK)
    char output[16] = {0};
    enum NetworkConnectivityCheck nConnCheck = 0;

    sysevent_get(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, sizeof(output));
    nConnCheck = atoi(output);
#endif

    sysevent_set(sw->sefd, sw->setok, "wan-status", "starting", 0);

    sysevent_set(sw->sefd, sw->setok, "wan-errinfo", NULL, 0);

#if !defined(_WAN_MANAGER_ENABLED_)
    switch (sw->prot) {
    case WAN_PROT_DHCP:
        #if !defined (FEATURE_RDKB_DHCP_MANAGER)
        if (wan_dhcp_start(sw) != 0) {
            fprintf(stderr, "%s: wan_dhcp_start error\n", __FUNCTION__);
            return -1;
        }
        #else
        //sysevent_set(sw->sefd, sw->setok, "dhcp_client-start", "", 0);
        v_secure_system("dmcli eRT setv Device.DHCPv4.Client.1.Enable bool true");
        fprintf(stderr, "%s  Enabling DHCPv4 client using TR181\n", __FUNCTION__);
        #endif

        break;
    case WAN_PROT_STATIC:
        if (wan_static_start(sw) != 0) {
            fprintf(stderr, "%s: wan_static_start error\n", __FUNCTION__);
            return -1;
        }

        break;
    default:
        fprintf(stderr, "%s: unknow wan protocol\n", __FUNCTION__);
        return -1;
    }
#endif /*_WAN_MANAGER_ENABLED_*/

#if !defined(_PLATFORM_IPQ_) && !defined(_WAN_MANAGER_ENABLED_) && !defined(_PROPOSED_BUG_FIX_)
    /*
     * The trigger of 'current_ipv4_link_state' to 'up' is moved to WAN service
     * from Gateway provisioning App. This is done to save the delay in getting
     * the configuration done, and to support the WAN restart functionality.
     */
#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
       (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
    {
        fprintf(stderr, "[%s] start waiting for protocol ...\n", PROG_NAME);
        for (timo = sw->timo; timo > 0; timo--) {
            sysevent_get(sw->sefd, sw->setok, "current_ipv4_link_state", state, sizeof(state));
            if (strcmp(state, "up") == 0)
                break;
            sleep(1);
        }
        if (timo == 0)
            fprintf(stderr, "[%s] wait for protocol TIMEOUT !\n", PROG_NAME);
        else
            fprintf(stderr, "[%s] wait for protocol SUCCESS !\n", PROG_NAME);
    }
#endif /*_PLATFORM_IPQ_ && _WAN_MANAGER_ENABLED_*/

#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
       (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
    {
        memset(val, 0 ,sizeof(val));
        sysevent_get(sw->sefd, sw->setok, "ipv4_wan_subnet", val, sizeof(val));
        if (strlen(val))
            sysevent_set(sw->sefd, sw->setok, "current_wan_subnet", val, 0);
        else
        {
            do
            {
                count++;
                sleep(2);
                sysevent_get(sw->sefd, sw->setok, "ipv4_wan_subnet", val, sizeof(val));
                if ( '\0' == val[0] )
                    printf("ipv4_wan_subnet is NULL, retry count is %d\n",count);
                else
                    printf("ipv4_wan_subnet value is %s, count is %d\n",val,count);
            }while ( 0 == strlen(val) && count < 3 );
            count=0;
    	    if (strlen(val))
                sysevent_set(sw->sefd, sw->setok, "current_wan_subnet", val, 0);
            else
                sysevent_set(sw->sefd, sw->setok, "current_wan_subnet", "255.255.255.0", 0);
        }
        memset(val, 0 ,sizeof(val));
        sysevent_get(sw->sefd, sw->setok, "ipv4_wan_ipaddr", val, sizeof(val));
        if (strlen(val)){
            printf("Setting current_wan_ipaddr  %s\n",val);
            sysevent_set(sw->sefd, sw->setok, "current_wan_ipaddr", val, 0);
        }
        else
        {
            printf("Wait for ipv4_wan_ipaddr to get valid ip \n");
            do
            {
                count++;
                sleep(2);
                sysevent_get(sw->sefd, sw->setok, "ipv4_wan_ipaddr", val, sizeof(val));
                if ( '\0' == val[0] )
                    printf("ipv4_wan_ipaddr is NULL, retry count is %d\n",count);
                else
                    printf("ipv4_wan_ipaddr value is %s, count is %d\n",val,count);
            } while ( 0 == strlen(val) && count < 3 );
            count=0;
            printf("Setting current_wan_ipaddr  %s\n",val);
   	    if (strlen(val))
            {
                sysevent_set(sw->sefd, sw->setok, "current_wan_ipaddr", val, 0);
            }
            else
            {
#ifdef WAN_FAILOVER_SUPPORTED
                char bkup_wan_status[16] = {0};
                unsigned int uiNeedstoAvoidIPConfig = 0;

                sysevent_get(sw->sefd, sw->setok, "backup-wan-status", bkup_wan_status, sizeof(bkup_wan_status));

                if(( bkup_wan_status[0] != '\0' ) &&
                   ( strlen(bkup_wan_status) > 0 ) &&
                   ( strcmp(bkup_wan_status,"started") == 0 ))
                {
                    uiNeedstoAvoidIPConfig = 1;
                }

                if( 0 == uiNeedstoAvoidIPConfig )
#endif /* * WAN_FAILOVER_SUPPORTED */
                {
                    sysevent_set(sw->sefd, sw->setok, "current_wan_ipaddr", "0.0.0.0", 0);
                }
            }
        }
    }

#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STARTED - 1))) ||
       (nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) )
#endif
    {
        memset(val, 0 ,sizeof(val));
        syscfg_get(NULL, "dhcp_server_propagate_wan_domain", val, sizeof(val));
        if (atoi(val) != 1)
            syscfg_get(NULL, "dhcp_server_propagate_wan_nameserver", val, sizeof(val));

        if (atoi(val) == 1) {
            //if ((fp = fopen("/var/tmp/lan_not_restart", "wb")) != NULL)
                //fclose(fp);
            sysevent_set(sw->sefd, sw->setok, "dhcp_server-restart", "lan_not_restart", 0);
        }
#if 1
        /* wan-status triggers service_routed, which will restart firewall
         * this logic are really strange, it means whan lan is ok but "start-misc" is not,
         * do not start firewall fully. but "start-misc" means ?
         * why not use "lan-status" ?
         * It not good idea to trigger other module here, firewall itself should register
         * "lan-status" and "wan-status" and determine which part should be launched.
        */
        memset(val, 0 ,sizeof(val));
        sysevent_get(sw->sefd, sw->setok, "start-misc", val, sizeof(val));
        sysevent_get(sw->sefd, sw->setok, "current_lan_ipaddr", ipaddr, sizeof(ipaddr));

        sysevent_get(sw->sefd, sw->setok,"bridge_mode", brmode, sizeof(brmode));
        sysevent_get(sw->sefd, sw->setok,"lan-status", lanstatus, sizeof(lanstatus));

        if (strcmp(val, "ready") != 0 && strlen(ipaddr) && strcmp(ipaddr, "0.0.0.0") != 0)
        {
            fprintf(stderr, "%s: start-misc: %s current_lan_ipaddr %s\n", __FUNCTION__, val, ipaddr);
            fprintf(stderr, "[%s] start firewall partially\n", PROG_NAME);
            sysevent_get(sw->sefd, sw->setok, "parcon_nfq_status", val, sizeof(val));
            if (strcmp(val, "started") != 0)
            {
                iface_get_hwaddr(sw->ifname, val, sizeof(val));
                vsystem("((nfq_handler 4 %s &)&)", val);
                sysevent_set(sw->sefd, sw->setok, "parcon_nfq_status", "started", 0);
            }
    	    /* Should not be executed before wan_service-status is set to started for _PLATFORM_IPQ_ */

#if !defined(_PLATFORM_IPQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_)
#if defined (_XB6_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_)
            v_secure_system("firewall");
#else
            // TODO : gw_lan_refresh to be removed from here once udhcpc is made generic to all platforms
            v_secure_system("firewall && gw_lan_refresh");
#endif
#endif
        }
        else
        {
#if !defined(_COSA_BCM_MIPS_)
    	sysevent_get(sw->sefd, sw->setok, "misc-ready-from-mischandler",mischandler_ready, sizeof(mischandler_ready));
    	if(strcmp(mischandler_ready,"true") == 0)
    	{
    		//only for first time
    #if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_TURRIS_)  && !defined(_PLATFORM_BANANAPI_R4_)
    		fprintf(stderr, "[%s] ready is set from misc handler. Doing gw_lan_refresh\n", PROG_NAME);
            #if defined (_XB6_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_)
                v_secure_system("firewall");
#else
                // TODO : gw_lan_refresh to be removed from here once udhcpc is made generic to all platforms
                v_secure_system("firewall && gw_lan_refresh");
#endif
#endif
                sysevent_set(sw->sefd, sw->setok, "misc-ready-from-mischandler", "false", 0);
    	    }
#endif

        }
#endif
        sysctl_iface_set("/proc/sys/net/ipv4/ip_forward", NULL, "1");
        sysevent_set(sw->sefd, sw->setok, "firewall_flush_conntrack", "1", 0);
#if !defined(_WAN_MANAGER_ENABLED_)
        fprintf(stderr, "[%s] Synching DNS to ATOM...\n", PROG_NAME);
        v_secure_system("/etc/utopia/service.d/service_wan/dns_sync.sh &");
#endif /*_WAN_MANAGER_ENABLED_*/
    }

    return 0;
}

STATIC int wan_addr_unset(struct serv_wan *sw)
{
    struct sysinfo si;
#ifdef WAN_FAILOVER_SUPPORTED
    char bkup_wan_status[16] = {0};
    unsigned int uiNeedstoAvoidIPConfig = 0;
#endif /* * WAN_FAILOVER_SUPPORTED */

#if defined(FEATURE_TAD_HEALTH_CHECK)
    char output[16] = {0};
    enum NetworkConnectivityCheck nConnCheck = 0;

    sysevent_get(sw->sefd, sw->setok, SYSEVENT_NET_CONNECTIVITY_CHECK, output, sizeof(output));
    nConnCheck = atoi(output);
#endif
    sysevent_set(sw->sefd, sw->setok, "wan-status", "stopping", 0);
    sysevent_set(sw->sefd, sw->setok, "wan-errinfo", NULL, 0);
    char prev_ip[100];
    sysevent_get(sw->sefd, sw->setok, "current_wan_ipaddr",prev_ip, sizeof(prev_ip));
    sysevent_set(sw->sefd, sw->setok, "previous_wan_ipaddr", prev_ip, sizeof(prev_ip));

#ifdef WAN_FAILOVER_SUPPORTED
    sysevent_get(sw->sefd, sw->setok, "backup-wan-status", bkup_wan_status, sizeof(bkup_wan_status));

    if(( bkup_wan_status[0] != '\0' ) &&
       ( strlen(bkup_wan_status) > 0 ) &&
       ( strcmp(bkup_wan_status,"started") == 0 ))
    {
        uiNeedstoAvoidIPConfig = 1;
    }

    if( 0 == uiNeedstoAvoidIPConfig )
#endif /* * WAN_FAILOVER_SUPPORTED */
    {
       sysevent_set(sw->sefd, sw->setok, "current_wan_ipaddr", "0.0.0.0", 0);
    }

    sysevent_set(sw->sefd, sw->setok, "current_wan_subnet", "0.0.0.0", 0);
    sysevent_set(sw->sefd, sw->setok, "current_wan_state", "down", 0);

#if defined (EROUTER_DHCP_OPTION_MTA)
    sysevent_set(sw->sefd, sw->setok, "MTA_DHCPv4_PrimaryAddress", NULL, 0);
    sysevent_set(sw->sefd, sw->setok, "MTA_DHCPv4_SecondaryAddress", NULL, 0);
    sysevent_set(sw->sefd, sw->setok, "MTA_DHCPv6_PrimaryAddress", NULL, 0);
    sysevent_set(sw->sefd, sw->setok, "MTA_DHCPv6_SecondaryAddress", NULL, 0);
    sysevent_set(sw->sefd, sw->setok, "MTA_IP_PREF", NULL, 0);
    sysevent_set(sw->sefd, sw->setok, "dhcp_mta_option", NULL, 0);
#endif


#if defined(FEATURE_TAD_HEALTH_CHECK)
    if((nConnCheck == NET_CONNNECTIVITY_CHECK_DISABLED) ||
       (nConnCheck & (1 << (NET_CONNNECTIVITY_CHECK_STOPPED - 1))) )
#endif
    {
#if !defined(_WAN_MANAGER_ENABLED_)
        switch (sw->prot) {
        case WAN_PROT_DHCP:
#if !defined (FEATURE_RDKB_DHCP_MANAGER)
            if (wan_dhcp_stop(sw) != 0) {
                fprintf(stderr, "%s: wan_dhcp_stop error\n", __FUNCTION__);
                return -1;
            }
#else
            //sysevent_set(sw->sefd, sw->setok, "dhcp_client-stop", "", 0);
            v_secure_system("dmcli eRT setv Device.DHCPv4.Client.1.Enable bool false");
            fprintf(stderr, "%s  Disabling DHCPv4 client using TR181\n", __FUNCTION__);
#endif
        break;
        case WAN_PROT_STATIC:
            if (wan_static_stop(sw) != 0) {
                fprintf(stderr, "%s: wan_static_stop error\n", __FUNCTION__);
                return -1;
            }
        break;
        default:
            fprintf(stderr, "%s: unknow wan protocol\n", __FUNCTION__);
            return -1;
        }
        v_secure_system("ip -4 addr flush dev %s", sw->ifname);
#endif /*_WAN_MANAGER_ENABLED_*/
    }
    printf("%s Triggering RDKB_FIREWALL_RESTART\n",__FUNCTION__);
    t2_event_d("SYS_SH_RDKB_FIREWALL_RESTART", 1);
    sysevent_set(sw->sefd, sw->setok, "firewall-restart", NULL, 0);

    sysinfo(&si);
    OnboardLog("RDKB_FIREWALL_RESTART:%ld", si.uptime);

    v_secure_system("killall -q dns_sync.sh");
    sysevent_set(sw->sefd, sw->setok, "wan-status", "stopped", 0);
    return 0;
}

#if !defined (FEATURE_RDKB_DHCP_MANAGER)
STATIC int wan_dhcp_start(struct serv_wan *sw)
{
    int pid;
    int has_pid_file = 0;
#if defined(_PLATFORM_IPQ_)
    int ret = -1;
#endif

# if defined(_PLATFORM_IPQ_)
        pid = pid_of("udhcpc", sw->ifname);
#elif (defined _COSA_INTEL_XB3_ARM_) || (defined INTEL_PUMA7)
       {
        char udhcpflag[10]="";
        syscfg_get( NULL, "UDHCPEnable_v2", udhcpflag, sizeof(udhcpflag));
        if( 0 == strcmp(udhcpflag,"true")){
                pid = pid_of("udhcpc", sw->ifname);
        }
        else
        {
                pid = pid_of("ti_udhcpc", sw->ifname);
        }
      }
#else
        pid = pid_of("udhcpc", sw->ifname);
#endif

    Getdhcpcpidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if (access(DHCPC_PID_FILE, F_OK) == 0)
        has_pid_file = 1;

    if (pid > 0 && has_pid_file) {
        fprintf(stderr, "%s: DHCP client has already running as PID %d\n", __FUNCTION__, pid);
        return 0;
    }

    if (pid > 0 && !has_pid_file)
        kill(pid, SIGKILL);
    else if (pid <= 0 && has_pid_file)
        dhcp_stop(sw->ifname);

#if defined(_PLATFORM_IPQ_)
    /*
     * Setting few sysevent parameters which were previously getting set
     * in Gateway provisioning App. This is done to save the delay
     * in configuration and to support WAN restart functionality.
     */
    if ( 0 != (ret = dhcp_start(sw)) )
    {
       return ret;
    }

    system("sysevent set current_ipv4_link_state up");
    system("sysevent set ipv4_wan_ipaddr `ifconfig erouter0 \
                   | grep \"inet addr\" | cut -d':' -f2 | awk '{print$1}'`");
    system("sysevent set ipv4_wan_subnet `ifconfig erouter0 \
                   | grep \"inet addr\" | cut -d':' -f4 | awk '{print$1}'`");
    return 0;
#else
    return dhcp_start(sw);
#endif
}

STATIC int wan_dhcp_stop(struct serv_wan *sw)
{
    return dhcp_stop(sw->ifname);
}

STATIC int wan_dhcp_restart(struct serv_wan *sw)
{
    if (dhcp_stop(sw->ifname) != 0)
        fprintf(stderr, "%s: dhcp_stop error\n", __FUNCTION__);

    return dhcp_start(sw);
}

STATIC int wan_dhcp_release(struct serv_wan *sw)
{
    FILE *fp;
    char pid[10];

    Getdhcpcpidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) == NULL)
        return -1;

    if (fgets(pid, sizeof(pid), fp) != NULL && atoi(pid) > 0)
        kill(atoi(pid), SIGUSR2); // triger DHCP release

    fclose(fp);

    vsystem("ip -4 addr flush dev %s", sw->ifname);
    return 0;
}

STATIC int wan_dhcp_renew(struct serv_wan *sw)
{
    FILE *fp;
    char pid[10];
    char uptime[24];
    struct sysinfo si;

    Getdhcpcpidfile(DHCPC_PID_FILE,sizeof(DHCPC_PID_FILE));
    if ((fp = fopen(DHCPC_PID_FILE, "rb")) == NULL)
        return dhcp_start(sw);

    if (fgets(pid, sizeof(pid), fp) != NULL && atoi(pid) > 0)
        kill(atoi(pid), SIGUSR1); // triger DHCP release

    fclose(fp);
    sysevent_set(sw->sefd, sw->setok, "current_wan_state", "up", 0);

    sysinfo(&si);
    snprintf(uptime, sizeof(uptime), "%ld", si.uptime);
    sysevent_set(sw->sefd, sw->setok, "wan_start_time", uptime, 0);

    return 0;
}
#endif    /* FEATURE_RDKB_DHCP_MANAGER */

#if !defined(_WAN_MANAGER_ENABLED_)
STATIC int resolv_static_config(struct serv_wan *sw)
{
    FILE *fp = NULL;
    char wan_domain[64] = {0};
    char name_server[3][32] = {{0}};
    int i = 0;
    char name_str[16] = {0};

    if((fp = fopen(RESOLV_CONF_FILE, "w+")) == NULL)
    {
        fprintf(stderr, "%s: Open %s error!\n", __FUNCTION__, RESOLV_CONF_FILE);
        return -1;
    }

    syscfg_get(NULL, "wan_domain", wan_domain, sizeof(wan_domain));
    if(wan_domain[0] != '\0') {
        fprintf(fp, "search %s\n", wan_domain);
        sysevent_set(sw->sefd, sw->setok, "dhcp_domain", wan_domain, 0);
    }

    memset(name_server, 0, sizeof(name_server));
    for(; i < 3; i++) {
        snprintf(name_str, sizeof(name_str), "nameserver%d", i+1);
        syscfg_get(NULL, name_str, name_server[i], sizeof(name_server[i]));
        if(name_server[i][0] != '\0' && strcmp(name_server[i], "0.0.0.0")) {
            printf("nameserver%d:%s\n", i+1, name_server[i]);
            fprintf(fp, "nameserver %s\n", name_server[i]);
        }
    }

    fclose(fp);
    return 0;
}

STATIC int resolv_static_deconfig(struct serv_wan *sw)
{
    FILE *fp = NULL;

    if((fp = fopen(RESOLV_CONF_FILE, "w+")) == NULL) {
        fprintf(stderr, "%s: Open %s error!\n", __FUNCTION__, RESOLV_CONF_FILE);
        return -1;
    }

    fclose(fp);
    return 0;
}

STATIC int wan_static_start(struct serv_wan *sw)
{
    char wan_ipaddr[16] = {0};
    char wan_netmask[16] = {0};
    char wan_default_gw[16] = {0};

    if(resolv_static_config(sw) != 0) {
        fprintf(stderr, "%s: Config resolv file failed!\n", __FUNCTION__);
    }

    /*get static config*/
    syscfg_get(NULL, "wan_ipaddr", wan_ipaddr, sizeof(wan_ipaddr));
    syscfg_get(NULL, "wan_netmask", wan_netmask, sizeof(wan_netmask));
    syscfg_get(NULL, "wan_default_gateway", wan_default_gw, sizeof(wan_default_gw));

    if(v_secure_system("ip -4 addr add %s/%s broadcast + dev %s", wan_ipaddr, wan_netmask, sw->ifname) != 0) {
        fprintf(stderr, "%s: Add address to interface %s failed!\n", __FUNCTION__, sw->ifname);
	return -1;
    }

    if(v_secure_system("ip -4 link set %s up", sw->ifname) != 0) {
        fprintf(stderr, "%s: Set interface %s up failed!\n", __FUNCTION__, sw->ifname);
	return -1;
    }

    if(v_secure_system("ip -4 route add table erouter default dev %s via %s && "
                "ip rule add from %s lookup erouter", sw->ifname, wan_default_gw, wan_ipaddr) != 0)
    {
        fprintf(stderr, "%s: router related config failed!\n", __FUNCTION__);
	return -1;
    }

    /*set related sysevent*/
    sysevent_set(sw->sefd, sw->setok, "default_router", wan_default_gw, 0);
    sysevent_set(sw->sefd, sw->setok, "ipv4_wan_ipaddr", wan_ipaddr, 0);
    sysevent_set(sw->sefd, sw->setok, "ipv4_wan_subnet", wan_netmask, 0);
    sysevent_set(sw->sefd, sw->setok, "current_ipv4_link_state", "up", 0);
    sysevent_set(sw->sefd, sw->setok, "dhcp_server-restart", NULL, 0);

    return 0;
}

STATIC int wan_static_stop(struct serv_wan *sw)
{
    char wan_ipaddr[16] = {0};

    if(resolv_static_deconfig(sw) != 0) {
        fprintf(stderr, "%s: deconfig resolv file failed!\n", __FUNCTION__);
    }

    sysevent_set(sw->sefd, sw->setok, "ipv4_wan_ipaddr", "0.0.0.0", 0);
    sysevent_set(sw->sefd, sw->setok, "ipv4_wan_subnet", "0.0.0.0", 0);

    sysevent_set(sw->sefd, sw->setok, "default_router", NULL, 0);
    syscfg_get(NULL, "wan_ipaddr", wan_ipaddr, sizeof(wan_ipaddr));
    v_secure_system("ip rule del from %s lookup erouter", wan_ipaddr);
    v_secure_system("ip -4 route del table erouter default dev %s", sw->ifname);

    sysevent_set(sw->sefd, sw->setok, "current_ipv4_link_state", "down", 0);

    return 0;
}
#endif

STATIC int wan_static_start_v6(struct serv_wan *sw)
{
    unsigned char wan_ipaddr_v6[16] = {0};
    unsigned char wan_prefix_v6[16] = {0};
    unsigned char wan_default_gw_v6[16] = {0};

    /* get static ipv6 config */
    syscfg_get(NULL, "wan_ipv6addr", wan_ipaddr_v6, sizeof(wan_ipaddr_v6));
    syscfg_get(NULL, "wan_ipv6_prefix", wan_prefix_v6, sizeof(wan_prefix_v6));
    syscfg_get(NULL, "wan_ipv6_default_gateway", wan_default_gw_v6, sizeof(wan_default_gw_v6));

    /*
     * NOTE : Not checking for return, as it always returns -1
     */
    vsystem("ip -6 addr add %s/%s dev %s", wan_ipaddr_v6, wan_prefix_v6, sw->ifname);

    vsystem("ip -6 route add table erouter default dev %s via %s && "
                "ip -6 rule add from %s lookup erouter", sw->ifname, wan_default_gw_v6, wan_ipaddr_v6);

    if (sw->rtmod == WAN_RTMOD_IPV6)
       sysevent_set(sw->sefd, sw->setok, "wan-status", "started", 0);

    return 0;
}

STATIC int wan_static_stop_v6(struct serv_wan *sw)
{
    unsigned char wan_ipaddr_v6[16] = {0};
    unsigned char wan_prefix_v6[16] = {0};
    unsigned char wan_default_gw_v6[16] = {0};

    /* get static ipv6 config */
    syscfg_get(NULL, "wan_ipv6addr", wan_ipaddr_v6, sizeof(wan_ipaddr_v6));
    syscfg_get(NULL, "wan_ipv6_prefix", wan_prefix_v6, sizeof(wan_prefix_v6));
    syscfg_get(NULL, "wan_ipv6_default_gateway", wan_default_gw_v6, sizeof(wan_default_gw_v6));

    /*
     * NOTE : Not checking for return, as it always returns -1
     */
    vsystem("ip -6 addr del %s/%s dev %s", wan_ipaddr_v6, wan_prefix_v6, sw->ifname);

    vsystem("ip -6 route del table erouter default dev %s via %s && "
                "ip -6 rule del from %s lookup erouter", sw->ifname, wan_default_gw_v6, wan_ipaddr_v6);

    if (sw->rtmod == WAN_RTMOD_IPV6)
       sysevent_set(sw->sefd, sw->setok, "wan-status", "stopped", 0);

    return 0;
}

STATIC int serv_wan_init(struct serv_wan *sw, const char *ifname, const char *prot)
{
    char buf[32];

    memset(buf,0,sizeof(buf));

    if ((sw->sefd = sysevent_open(SE_SERV, SE_SERVER_WELL_KNOWN_PORT,
                    SE_VERSION, PROG_NAME, &sw->setok)) < 0) {
        fprintf(stderr, "%s: fail to open sysevent\n", __FUNCTION__);
        return -1;
    }

    if (ifname)
        snprintf(sw->ifname, sizeof(sw->ifname), "%s", ifname);
    else
        syscfg_get(NULL, "wan_physical_ifname", sw->ifname, sizeof(sw->ifname));

    if (!strlen(sw->ifname)) {
        fprintf(stderr, "%s: fail to get ifname\n", __FUNCTION__);
        return -1;
    }

    if (prot)
        snprintf(buf, sizeof(buf), "%s", prot);
    else
        syscfg_get(NULL, "wan_proto", buf, sizeof(buf));

    /* IPQ Platform : For WAN stop, protocol field will be modified in
     * the WAN stop functionality */
    if (strcasecmp(buf, "dhcp") == 0)
        sw->prot = WAN_PROT_DHCP;
    else if (strcasecmp(buf, "static") == 0)
        sw->prot = WAN_PROT_STATIC;
    else {
        fprintf(stderr, "%s: fail to get wan protocol\n", __FUNCTION__);
        return -1;
    }

#if defined (_PROPOSED_BUG_FIX_)
    openlog(EROUTER_EVT_ID, LOG_NDELAY, LOG_LOCAL4);
#endif
    memset(buf,0,sizeof(buf));

    syscfg_get(NULL, "last_erouter_mode", buf, sizeof(buf));
    switch (atoi(buf)) {
    case 1:
        sw->rtmod = WAN_RTMOD_IPV4;
#if defined (_PROPOSED_BUG_FIX_)
        syslog(LOG_INFO, "%u-%s", EVENTS_EROUTER_IPV4_ONLY, EVENTS_EROUTER_IPV4_ONLY_STR);
#endif
        break;
    case 2:
        sw->rtmod = WAN_RTMOD_IPV6;
#if defined (_PROPOSED_BUG_FIX_)
        syslog(LOG_INFO, "%u-%s", EVENTS_EROUTER_IPV6_ONLY, EVENTS_EROUTER_IPV6_ONLY_STR);
#endif
        break;
    case 3:
        sw->rtmod = WAN_RTMOD_DS;
#if defined (_PROPOSED_BUG_FIX_)
        syslog(LOG_INFO, "%u-%s", EVENTS_EROUTER_DS_ENABLED, EVENTS_EROUTER_DS_ENABLED_STR);
#endif
        break;
    default:
        fprintf(stderr, "%s: unknow RT mode (last_erouter_mode)\n", __FUNCTION__);
        sw->rtmod = WAN_RTMOD_UNKNOW;
        break;
    }

#ifdef FEATURE_RDKB_WAN_MANAGER
    memset(buf,0,sizeof(buf));
    syscfg_get(NULL, "selected_wan_mode", buf, sizeof(buf));
    if (strlen(buf))
    {
        int wanmode = atoi(buf);
        if (wanmode == WAN_MODE_AUTO)
        {
            sw->timo = SW_PROT_TIMO_MIN;
        }
        else
        {
            sw->timo = SW_PROT_TIMO;
        }
    }
    else
    {
        sw->timo = SW_PROT_TIMO;
    }
    fprintf(stderr, "proto timeout value: [%d]  wan_mode:%s \n",sw->timo, buf);
    printf("proto timeout value: [%d]  wan_mode:%s \n",sw->timo, buf);
#else
    sw->timo = SW_PROT_TIMO;
#endif

    return 0;
}

STATIC int serv_wan_term(struct serv_wan *sw)
{
    sysevent_close(sw->sefd, sw->setok);

#if defined (_PROPOSED_BUG_FIX_)
    closelog();
#endif

    return 0;
}

STATIC void usage(void)
{
    int i;

    fprintf(stderr, "USAGE\n");
    fprintf(stderr, "    %s COMMAND [ INTERFACE [ PROTOCOL ] ]\n", PROG_NAME);
    fprintf(stderr, "COMMANDS\n");
    for (i = 0; i < NELEMS(cmd_ops); i++)
        fprintf(stderr, "    %-20s%s\n", cmd_ops[i].cmd, cmd_ops[i].desc);
    fprintf(stderr, "PROTOCOLS\n");
        fprintf(stderr, "    dhcp, static\n");
}

int service_wan_main(int argc, char *argv[])
{
    int i;
    struct serv_wan sw;

    fprintf(stderr, "[%s] -- IN\n", PROG_NAME);

	/* When syseventd use the system() API internally, these calls were returning -1.
	 * Reason: system() expects to get the SIGCHLD event when the forked process finishes,
	 * but syseventd disables the SIGCHLD process. This setting propagates to the event handlers,
	 * because they are child processes of syseventd or syseventd_fork_helper.
	 * Workaround: On setting SIGCHLD back to SIG_DFL,
	 * system() function calls returns success on successful command execution.*/
	/* Default handling of SIGCHLD signals */
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
    {
        fprintf(stderr, "ERROR: Couldn't set SIGCHLD handler!\n");
		return EXIT_FAILURE;
    }

    if (argc < 2) {
        usage();
        exit(1);
    }

    if (serv_wan_init(&sw, (argc > 2 ? argv[2] : NULL), (argc > 3 ? argv[3] : NULL)) != 0)
        exit(1);

    /* execute commands */
    for (i = 0; i < NELEMS(cmd_ops); i++) {
        if (strcmp(argv[1], cmd_ops[i].cmd) != 0 || !cmd_ops[i].exec)
            continue;

        fprintf(stderr, "[%s] exec: %s\n", PROG_NAME, cmd_ops[i].cmd);

        if (cmd_ops[i].exec(&sw) != 0)
            fprintf(stderr, "[%s]: fail to exec `%s'\n", PROG_NAME, cmd_ops[i].cmd);

        break;
    }
    if (i == NELEMS(cmd_ops))
        fprintf(stderr, "[%s] unknown command: %s\n", PROG_NAME, argv[1]);

    if (serv_wan_term(&sw) != 0)
        exit(1);

    fprintf(stderr, "[%s] -- OUT\n", PROG_NAME);
    exit(0);
}
