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
   Copyright [2015] [Cisco Systems, Inc.]
 
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

#include "service_multinet_lib.h" 
#include "service_multinet_nv.h"
#include "service_multinet_ev.h"
#include "service_multinet_ep.h"
#include "service_multinet_handler.h"
#include "service_multinet_plat.h"
#include <unistd.h>
#ifdef MULTILAN_FEATURE
#include "syscfg/syscfg.h"
#include <net/if.h>
#include <dirent.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "errno.h"
#include "secure_wrapper.h"
//#include "nethelper.h"
#include "util.h"

#define LOCAL_BRLAN1UP_FILE "/tmp/brlan1_up"
#if defined(MOCA_HOME_ISOLATION)
#define LOCAL_MOCABR_UP_FILE "/tmp/MoCABridge_up"
#define MOCA_BRIDGE_IP "169.254.30.1"
#endif
#include "safec_lib_common.h"

#ifdef MULTILAN_FEATURE
/* Syscfg keys used for calculating mac addresses of local interfaces and bridges */
#define BASE_MAC_SYSCFG_KEY                  "base_mac_address"
/* Offset at which LAN bridge mac addresses will start */
#define BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY    "base_mac_bridge_offset"
#define BRIDGE_IFACE_PATH                    "/sys/class/net/%s/brif/%s"
#define CMD_STRING_LEN 255
#define MAC_ADDRESS_OCTET_MAX 0x100
#define MAC_ADDRESS_LOCAL_MASK 0x02
/* Using 1111 11xx bit mask to derive unique bridge mac addresses */
#define BIT_MASK 0xFC
#endif

#if defined (INTEL_PUMA7) || defined(MULTILAN_FEATURE)
//Intel Proposed RDKB Bug Fix
#define LAN_CONFIG_FILE "/etc/lan.cfg"
#define LAN_PORT_MAP_FILE "/var/tmp/map/mapping_table.txt"
#define BASE_IF_NAME_KEY "BaseInterface"
#define SW_TYPE_KEY "Type=SW"
#endif

#if defined (INTEL_PUMA7)
/* Command for clearing CPE table on Puma 7 */
#define CLEAR_CPE_TABLE_COMMAND "ncpu_exec -e service_bridge.sh clear_cpe_table"
#elif defined (_COSA_INTEL_XB3_ARM_)
/* Command for clearing CPE table on Puma 6 */
#define CLEAR_CPE_TABLE_COMMAND "echo 'LearnFrom=CPE_DYNAMIC' > /proc/net/dbrctl/delalt"
#endif

#if defined MULTILAN_FEATURE && defined(MESH_ETH_BHAUL)
#define MESHETHBHAUL_IPV4_CIDR "169.254.85.1/24"
#endif

 /* The service_multinet library provides service fuctions for manipulating the lifecycle 
 * and live configuration of system bridges and their device specific interface members. 
 * Authoritative configuration is considered to be held in nonvol storage, so most functions
 * will take this external configuration as input. 
 */

unsigned char isDaemon;
char* executableName;

static int add_members(PL2Net network, PMember interfaceBuf, int numMembers);
static int remove_members(PL2Net network, PMember live_members, int numLiveMembers);
static SERVICE_STATUS check_status(PMember live_members, int numLiveMembers);
static int resolve_member_diff(PL2Net network, PMember members, int* numMembers, PMember live_members, int* numLiveMembers, PMember keep_members, int* numKeepMembers); 
static int isMemberEqual(PMember a, PMember b);

#if defined (INTEL_PUMA7) || defined(MULTILAN_FEATURE)
//Intel Proposed RDKB Bug Fix
/* Get the interface name from the port name
 * ifName would be the real interface name if it's not switch port.
 * Otherwise, ifName would be same as port name */
int getIfName(char *ifName, char *port)
{
    char line[MAX_BUF_SIZE] = {0};
    char *buff = NULL;
    char *token = NULL;
    char *token1 = NULL;
    char *token2 = NULL;
    char *c;
    char *saveptr1, *saveptr2;
    FILE *file = NULL;

    if((STATUS_NOK == access(LAN_CONFIG_FILE, F_OK )))
    {
        /* Use backward compatibility method*/
        MNET_DEBUG("Static conf file %s is not available, try backward compatibility\n" COMMA LAN_CONFIG_FILE);
        return STATUS_NOK;
    }

    file = fopen(LAN_PORT_MAP_FILE, "r");
    if(!file)
    {
        MNET_DEBUG("ERROR: failed to open file %s\n" COMMA LAN_PORT_MAP_FILE);
        return STATUS_NOK;
    }

    /* Parsing map file */
    while(fgets(line, sizeof(line), file) != NULL)
    {
        /* Skip the line if it's commented or blank line */
        if('#' == line[0] || '\n' == line[0])
        {
            continue;
        }
        /* Skip if it's a switch port */
        if(!strstr(line, port) || strstr(line, SW_TYPE_KEY))
        {
            continue;
        }

        buff = line;
        for(token = strtok_r(buff, " ", &saveptr1); token != NULL; token = strtok_r(NULL, " ", &saveptr1))
        {
            /* Parse parameters and get values, e.g. token="LogicalPort=1", token1="LogicalPort", token2="1" */
            token1 = strtok_r(token, "=", &saveptr2);
            if(!strcmp(token1, BASE_IF_NAME_KEY))
            {
                token2 = strtok_r(NULL, "=", &saveptr2);
                if(token2 == NULL)
                {
                        MNET_DEBUG("ERROR: Null pointer\n");
                        fclose(file);
                        return STATUS_NOK;
                }
                if((c = strchr(token2, '\n')))
                {
                        /* Removing new line character */
                        *c = '\0';
                }
                strncpy(ifName, token2, MAX_IFNAME_SIZE);
                MNET_DEBUG("%s inner: ifName=%s, portName=%s\n" COMMA __func__ COMMA ifName COMMA port);
                fclose(file);
                return STATUS_OK;
            }
        }
    }
    /* port is switch port */
    strncpy(ifName, port, MAX_IFNAME_SIZE);
    MNET_DEBUG("%s outer: ifName=%s, portName=%s\n" COMMA __func__ COMMA ifName COMMA port);
    fclose(file);
    return STATUS_OK;
}
#endif

//TODO Move these to a common lib
#ifndef MULTILAN_FEATURE
static int nethelper_bridgeCreate(char* brname) {
    
    MNET_DEBUG("SYSTEM CALL: brctl addbr %s; ifconfig %s up" COMMA brname COMMA brname); 
    v_secure_system("brctl addbr %s; ifconfig %s up", brname, brname);
    return 0;
}
#endif
#ifdef MULTILAN_FEATURE
/* nethelper_bridgeCreateUniqueMac
 *
 * Creates a bridge with a unique and consistent mac address.
 * The mac address is calculated by starting with the base mac address taken from
 * the syscfg key defined in BASE_MAC_SYSCFG_KEY and adding 1 to the least-significant octet.
 * Then the bridge instance number is used with 1111 11xx (0xFC) bit mask and bit shift by 0x2
 * If the resulting octet is larger than MAC_ADDRESS_OCTET_MAX, the value becomes the remainder
 * of the intermediate value divided by MAC_ADDRESS_OCTET_MAX. This is to allow roll-over in the
 * resulting mac address octet. Finally, the Universal/Local bit (found in MAC_ADDRESS_LOCAL_MASK)
 * is set on the resulting mac address to specify that this is NOT a globally-unique mac address.
*/
static int nethelper_bridgeCreateUniqueMac(char* brname, int id) {
    char cmdBuff[CMD_STRING_LEN];
    int result = 0;
    int mac_offset = 0;
    int mac[6];
    int got_base_mac = 0;

    /* Create bridge */
    MNET_DEBUG("SYSTEM CALL: brctl addbr %s" COMMA brname);
    v_secure_system("brctl addbr %s", brname);

    if (!syscfg_get(NULL, BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY, cmdBuff, sizeof(cmdBuff)))
    {
        MNET_DEBUG("Got %s = %s from syscfg" COMMA BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY COMMA cmdBuff);
        mac_offset = atoi(cmdBuff);

        if (!syscfg_get(NULL, BASE_MAC_SYSCFG_KEY, cmdBuff, sizeof(cmdBuff)))
        {
            MNET_DEBUG("Got %s = %s from syscfg" COMMA BASE_MAC_SYSCFG_KEY COMMA cmdBuff);

            got_base_mac = 1;

            if (sscanf(cmdBuff, "%x:%x:%x:%x:%x:%x",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]
                ) == 6)
            {
                /* Add offset+1 to least significant octet */
                mac[5] += (mac_offset + 1);
                /* Handle roll-over */
                mac[5] %= MAC_ADDRESS_OCTET_MAX;
                /* Set as a local mac address using combination of BIT_MASK and MAC_ADDRESS_LOCAL_MASK */
                mac[0] = (mac[0] & ~BIT_MASK) | (id << MAC_ADDRESS_LOCAL_MASK) | MAC_ADDRESS_LOCAL_MASK;
                /* Set the newly-generated mac address to the bridge */
                MNET_DEBUG("SYSTEM CALL: ifconfig %s hw ether %02x:%02x:%02x:%02x:%02x:%02x" COMMA
                    brname COMMA mac[0] COMMA mac[1] COMMA mac[2] COMMA mac[3] COMMA mac[4] COMMA mac[5]);
                v_secure_system("ifconfig %s hw ether %02x:%02x:%02x:%02x:%02x:%02x",
                    brname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
        }
        else
        {
            MNET_DEBUG("Couldn't get %s from syscfg" COMMA BASE_MAC_SYSCFG_KEY);
        }
    }
    else
    {
        MNET_DEBUG("Couldn't get %s from syscfg" COMMA BASE_MAC_BRIDGE_OFFSET_SYSCFG_KEY);
    }

    /* Workaround, Linux will not generate a link-local address if no switch ports connected */
    if (got_base_mac)
    {
        v_secure_system("ip link add tmp%d type dummy", id);
        v_secure_system("echo 1 > /proc/sys/net/ipv6/conf/tmp%d/disable_ipv6", id);
        v_secure_system("ifconfig tmp%d up", id);
        v_secure_system("brctl addif %s tmp%d", brname, id);
    }

    /* Bring bridge up */
    MNET_DEBUG("SYSTEM CALL: ifconfig %s up" COMMA brname);
    v_secure_system("ifconfig %s up", brname);

    if (got_base_mac)
    {
        v_secure_system("ip link del tmp%d", id);
    }

    return result;
}
#endif
static int nethelper_bridgeDestroy(char* brname) {
    
    v_secure_system("ifconfig %s down; brctl delbr %s", brname, brname);
    return 0;
}
#if defined(MOCA_HOME_ISOLATION)
void ConfigureMoCABridge(L2Net l2net)
{
    v_secure_system("ip link set %s allmulticast on; ifconfig %s "MOCA_BRIDGE_IP ";ip link set %s up",l2net.name, l2net.name,l2net.name);
    sysctl_iface_set("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", NULL, "0");
    sysctl_iface_set("/proc/sys/net/ipv4/conf/all/arp_announce", NULL, "3");
    v_secure_system("ip rule add from all iif brlan10 lookup all_lans");

#if defined(MULTILAN_FEATURE)
    sysctl_iface_set("/proc/sys/net/ipv4/conf/brlan10/rp_filter", NULL, "0");
#if defined(INTEL_PUMA7)
    v_secure_system("ip rule add from 169.254.0.0/16 iif brlan0 lookup moca");
#else
    v_secure_system("ip rule add from all iif brlan0 lookup moca");
#endif
#else
    v_secure_system("ip rule add from all iif brlan0 lookup moca");
#endif

}
#endif
/* Public interface section */

/* multinet_bridgeUp
 * 
 * Uses the network instance ID to load the stored configuration and initialize 
 * the bridge network. 
 * 
 * Intended to only be called once for a given bridge.
 */
int multinet_bridgeUp(PL2Net network, int bFirewallRestart){
    Member memberBuf[MAX_MEMBERS];
    NetInterface interfaceBuf[MAX_MEMBERS];
    IFType ifTypeBuf[MAX_MEMBERS];
    int numMembers = 0, i;
    
    memset(memberBuf,0, sizeof(memberBuf));
    memset(interfaceBuf,0, sizeof(interfaceBuf));
    memset(ifTypeBuf,0, sizeof(ifTypeBuf));
    for (i = 0; i < MAX_MEMBERS; ++i) {
        memberBuf[i].interface = interfaceBuf + i;
        interfaceBuf[i].type = ifTypeBuf +i;
    }
    
    //Load members from nv
    numMembers = nv_get_members(network, memberBuf, sizeof(memberBuf)/sizeof(*memberBuf));
    MNET_DEBUG("Get members for %d complete. \n" COMMA network->inst)
    numMembers += plat_addImplicitMembers(network, memberBuf+numMembers);
    MNET_DEBUG("plat_addImplicitMembers for %d complete. \n" COMMA network->inst)
    
    //create bridge
#ifdef MULTILAN_FEATURE
    nethelper_bridgeCreateUniqueMac(network->name, network->inst);
#else
    nethelper_bridgeCreate(network->name);
#endif
    
    ep_set_bridge(network);
    
    ev_set_netStatus(network, STATUS_PARTIAL); //NOTE bring back if routing issue can be solved
    
    MNET_DEBUG("Bridge create for %d complete. \n" COMMA network->inst)
    
    add_members(network, memberBuf, numMembers);
    
    MNET_DEBUG("add_members for %d complete. \n" COMMA network->inst)
    
    ep_set_allMembers(network, memberBuf, numMembers);
    
    MNET_DEBUG("ep_set_allMembers for %d complete. \n" COMMA network->inst)
    
    
    ev_set_netStatus(network, check_status(memberBuf, numMembers)); 
    
    MNET_DEBUG("Status send for %d complete. \n" COMMA network->inst)
    
    //ep_set_info(network);
    ep_add_active_net(network);
    
    
    MNET_DEBUG("ep_set_bridge for %d complete. \n" COMMA network->inst)
    
    if (bFirewallRestart)
        ev_firewall_restart(); 
    
    return 0;
}
int multinet_bridgeUpInst(int l2netInst, int bFirewallRestart){
    L2Net l2net;
    int fd = 0;/*RDKB-12965 & CID:- 34240*/
	memset(&l2net,0,sizeof(l2net)); /*RDKB-12965 & CID:-33815*/
    if(!ep_netIsStarted(l2netInst)) {
        MNET_DEBUG("Found %d is not started. Starting.\n" COMMA l2netInst)
        nv_get_bridge(l2netInst, &l2net);
        MNET_DEBUG("nv fetch complete for %d. Name: %s, Vid: %d\n" COMMA l2netInst COMMA l2net.name COMMA l2net.vid)
        multinet_bridgeUp(&l2net, bFirewallRestart);
        MNET_DEBUG("multinet_bridgeUp for %d complete. \n" COMMA l2netInst)
#if defined(MULTILAN_FEATURE)
        if (1 == l2netInst)
        {
           MNET_DEBUG("brlan0 up: disabling multicast_snooping\n")
           sysctl_iface_set("/sys/devices/virtual/net/brlan0/bridge/multicast_snooping", NULL, "0");
           sysctl_iface_set("/proc/sys/net/ipv4/conf/all/rp_filter", NULL, "0");
           sysctl_iface_set("/proc/sys/net/ipv4/conf/brlan0/rp_filter", NULL, "0");
        }

#endif
		// For brlan1 case create a temp file so that cosa_start_rem.sh execution can continue.
        if (2 == l2netInst)
        {
            MNET_DEBUG("brlan1 case creating %s file \n" COMMA LOCAL_BRLAN1UP_FILE)
            if((fd = creat(LOCAL_BRLAN1UP_FILE, S_IRUSR | S_IWUSR)) == -1) /*RDKB-12965 & CID:- 34240*/
            {
                MNET_DEBUG("%s file creation failed with error:%d\n" COMMA LOCAL_BRLAN1UP_FILE COMMA errno)
            }
            else
            {
                MNET_DEBUG("%s file creation is successful \n" COMMA LOCAL_BRLAN1UP_FILE)
		close(fd); /*RDKB-12965 & CID:- 34240*/
            }
        }
#if defined(MOCA_HOME_ISOLATION)
	if(9 == l2netInst)
	{
	    ConfigureMoCABridge(l2net);
            MNET_DEBUG("MoCA Bridge case creating %s file \n" COMMA LOCAL_MOCABR_UP_FILE)
            if((fd = creat(LOCAL_MOCABR_UP_FILE, S_IRUSR | S_IWUSR)) == -1) //CID: 74549
            {
                MNET_DEBUG("%s file creation failed with error:%d\n" COMMA LOCAL_MOCABR_UP_FILE COMMA errno)
            }
            else
            {
                MNET_DEBUG("%s file creation is successful \n" COMMA LOCAL_MOCABR_UP_FILE)
		close(fd); //CID: 74549
            }

	}
#endif
    }
#if defined (CLEAR_CPE_TABLE_COMMAND)
    //If this is the primary instance and bridge mode is enabled, clear CPE table
    if (l2netInst == nv_get_primary_l2_inst() && ep_get_bridge_mode() != 0)
        v_secure_system(CLEAR_CPE_TABLE_COMMAND); 
#endif

    return 0;
}



int multinet_bridgeDown(PL2Net network){
    Member memberBuf[MAX_MEMBERS];
    NetInterface interfaceBuf[MAX_MEMBERS];
    IFType ifTypeBuf[MAX_MEMBERS];
    int numMembers = 0, i;
    
    memset(memberBuf,0, sizeof(memberBuf));
    memset(interfaceBuf,0, sizeof(interfaceBuf));
    memset(ifTypeBuf,0, sizeof(ifTypeBuf));
    
    for (i = 0; i < MAX_MEMBERS; ++i) {
        memberBuf[i].interface = interfaceBuf + i;
        interfaceBuf[i].type = ifTypeBuf +i;
    }
    
    //read ep ready memebers
    numMembers = ep_get_allMembers(network, memberBuf, sizeof(memberBuf)/sizeof(*memberBuf));
    MNET_DEBUG("multinet_bridgeDown, ep_get_allMembers returned\n")
    //delete vlans
    remove_members(network, memberBuf, numMembers);
    MNET_DEBUG("remove_members, ep_get_allMembers returned\n")
    
    //delete bridge
    nethelper_bridgeDestroy(network->name);
    
    //clear info and status
    ev_set_netStatus(network, STATUS_STOPPED); 
    
    ep_clear(network);
    ep_rem_active_net(network);
    return 0;
}
int multinet_bridgeDownInst(int l2netInst){
    L2Net l2net;
    if(ep_netIsStarted(l2netInst)) {
        nv_get_bridge(l2netInst, &l2net);
        multinet_bridgeDown(&l2net);
    }
    return 0;
}

int multinet_Sync(PL2Net network, PMember members, int numMembers){
    int i;
    
    Member live_members[MAX_MEMBERS];
    NetInterface interfaceBuf[MAX_MEMBERS];
    IFType ifTypeBuf[MAX_MEMBERS];
    
    memset(live_members,0, sizeof(live_members));
    memset(interfaceBuf,0, sizeof(interfaceBuf));
    memset(ifTypeBuf,0, sizeof(ifTypeBuf));
    
    for (i = 0; i < MAX_MEMBERS; ++i) {
        live_members[i].interface = interfaceBuf + i;
        interfaceBuf[i].type = ifTypeBuf +i;
    }
    
    Member keep_members[MAX_MEMBERS];
    NetInterface interfaceBuf2[MAX_MEMBERS];
    IFType ifTypeBuf2[MAX_MEMBERS];
    
    memset(live_members,0, sizeof(live_members));
    memset(interfaceBuf2,0, sizeof(interfaceBuf2));
    memset(ifTypeBuf2,0, sizeof(ifTypeBuf2));
    
    for (i = 0; i < MAX_MEMBERS; ++i) {
        live_members[i].interface = interfaceBuf2 + i;
        interfaceBuf2[i].type = ifTypeBuf2 +i;
    }
    
    int numKeepMembers = 0;
    int numLiveMembers;
    //L2Net nv_net;
    L2Net live_net;
    
    
    //Don't re-sync members of networks that are not up
    if(!ep_netIsStarted(network->inst)) {
        return -1;
    }
    
    //nv_get_bridge(network->inst, &nv_net);
    ep_get_bridge(network->inst, &live_net);
    
    //Check disabled
    if (!network->bEnabled) {
        multinet_bridgeDown(network);
        return 0;
    }
    
    numLiveMembers = ep_get_allMembers(&live_net, live_members, sizeof(live_members)/sizeof(*live_members));
    //numNvMembers = nv_get_members(&nv_net, nv_members, sizeof(nv_members));
    
    //Sync vlan
    //Only pare down add/remove lists if there is no vlan change. If the vlan is different, 
    //  all interfaces must have the old vlan deleted, and the new vlan must be added. 
    if (live_net.vid == network->vid) {
        resolve_member_diff(network, members, &numMembers, live_members, &numLiveMembers, keep_members, &numKeepMembers); //Modifies buffers into new and remove lists
    }
    
    MNET_DEBUG("Resolved member diff. %d add, %d keep, %d remove\n" COMMA numMembers COMMA numKeepMembers COMMA numLiveMembers)
    
    //Sync members
    remove_members(network, live_members, numLiveMembers);
    
    add_members(network, members, numMembers);
    
    //numLiveMembers = ep_get_allMembers(&live_net, live_members, sizeof(live_members)/sizeof(*live_members));
    
#ifdef MULTILAN_FEATURE
    //Interfaces to keep will have status already started
    for (i = 0; i < numKeepMembers; ++i) {
        keep_members[i].bReady = STATUS_STARTED;
    }
#endif

    for (i = 0; i < numMembers; ++i) {
        keep_members[numKeepMembers++] = members[i];
    }
    
    ep_set_allMembers(network, keep_members, numKeepMembers);
    
    ep_set_bridge(network);
    
    ev_set_netStatus(network, check_status(keep_members, numKeepMembers)); 
    
    //Sync name TODO Deferred!
    
    return 0;
}
int multinet_SyncInst(int l2netInst){
    L2Net nv_net;
    Member nv_members[MAX_MEMBERS];
    NetInterface interfaceBuf[MAX_MEMBERS];
    IFType ifTypeBuf[MAX_MEMBERS];
    int i;
    int result = 0;
    
    memset(nv_members,0,sizeof(nv_members));
    memset(interfaceBuf,0,sizeof(interfaceBuf));
    memset(ifTypeBuf,0,sizeof(ifTypeBuf));
    for (i = 0; i < MAX_MEMBERS; ++i) {
        nv_members[i].interface = interfaceBuf + i;
        interfaceBuf[i].type = ifTypeBuf +i;
    }
    
    int numNvMembers;
    
    nv_net.inst = l2netInst;
    if (ep_netIsStarted(l2netInst)) {
        nv_get_bridge(l2netInst, &nv_net);
        numNvMembers = nv_get_members(&nv_net, nv_members, sizeof(nv_members)/sizeof(*nv_members));
        numNvMembers += plat_addImplicitMembers(&nv_net, nv_members+numNvMembers);
        result = multinet_Sync(&nv_net, nv_members, numNvMembers);
    }

#if defined (CLEAR_CPE_TABLE_COMMAND)
    //If this is the primary instance and bridge mode is enabled, clear CPE table
    if (l2netInst == nv_get_primary_l2_inst() && ep_get_bridge_mode() != 0)
        v_secure_system(CLEAR_CPE_TABLE_COMMAND); 
#endif

    return result;
}

int multinet_bridgesSync(){
    //TODO: compare nonvol instances to running instances, and stop instances that no longer exist.
    return 0;
}

//TODO: This should only take in an "NetInterface" and search the member list for
//relevant members. 
int multinet_ifStatusUpdate(PL2Net network, PMember interface, IF_STATUS status){
    int i;
    Member live_members[MAX_MEMBERS];
    NetInterface interfaceBuf[MAX_MEMBERS];
    IFType ifTypeBuf[MAX_MEMBERS];
    
    memset(live_members,0, sizeof(live_members));
    memset(interfaceBuf,0, sizeof(interfaceBuf));
    memset(ifTypeBuf,0, sizeof(ifTypeBuf));
    
    for (i = 0; i < MAX_MEMBERS; ++i) {
        live_members[i].interface = interfaceBuf + i;
        interfaceBuf[i].type = ifTypeBuf +i;
    }
    int numLiveMembers;
    
    interface->bReady = status;
    
    if (status == IF_STATUS_UP) {
        add_vlan_for_members(network, interface, 1);
        MNET_DEBUG("multinet_ifStatusUpdate: finished with add_vlan_for_members\n")
//         if (interface->bLocal) {
//             nethelper_bridgeAddIf(network->name, interface->name);
//         }
    } //FIXME should remove vlans for down ports, even if it's a no-op
    
    //ep_set_memberStatus(network, interface);
    
    numLiveMembers = ep_get_allMembers(network, live_members, sizeof(live_members)/sizeof(*live_members));
    MNET_DEBUG("multinet_ifStatusUpdate: finished with ep_get_allMembers\n")
    for ( i = 0; i < numLiveMembers; ++i) {
        if (isMemberEqual(interface, live_members + i)) {
            live_members[i].bReady = status;
        }
    }
    MNET_DEBUG("multinet_ifStatusUpdate: finished setting ready bits\n")
    ep_set_allMembers(network, live_members,numLiveMembers);
    MNET_DEBUG("multinet_ifStatusUpdate: finished set all members\n")
    
    ev_set_netStatus(network, check_status(live_members, numLiveMembers));
    MNET_DEBUG("multinet_ifStatusUpdate: exit\n")
    return 0;
}
int multinet_ifStatusUpdate_ids(int l2netInst, char* ifname, char* ifType, char* status, char* tagging){ 
    IFType type = {{0},NULL};
    NetInterface iface = {0};
    Member member = {0};
    L2Net net = {0};
    errno_t  rc = -1;
    IF_STATUS ifStatus;
    rc = strcpy_s(type.name, sizeof(type.name), ifType);
    ERR_CHK(rc);
    rc = strcpy_s(iface.name, sizeof(iface.name), ifname);
    ERR_CHK(rc);
    iface.type = &type;
    member.interface = &iface;
    
    nv_get_bridge(l2netInst, &net);
    ev_string_to_status(status, (SERVICE_STATUS *)&ifStatus);
    
    
    member.bTagging = strcmp("tag", tagging) ? 0 : 1;
    
    return multinet_ifStatusUpdate(&net, &member, ifStatus);
    
}

int multinet_lib_init(BOOL daemon, char* exeName) { 
    int retval;
    isDaemon = daemon;
    
    retval = ev_init();
    
    if (retval) return retval; // Failed to initialize the library
    
    MNET_DEBUG("Setting executableName: %s\n" COMMA exeName)
    
    executableName = strdup(exeName);
    
    handlerInit();
    
    return 0;
}

/* Internal interface section */

static int add_members(PL2Net network, PMember interfaceBuf, int numMembers) 
{          
    //register for member status
    create_and_register_if(network, interfaceBuf, numMembers);
    
    //add vlans for ready members
    add_vlan_for_members(network, interfaceBuf, numMembers);
    return 0;
}

static int remove_members(PL2Net network, PMember live_members, int numLiveMembers) 
{
    unregister_if(network, live_members, numLiveMembers);
    remove_vlan_for_members(network, live_members, numLiveMembers);
    return 0; 
}

static SERVICE_STATUS check_status(PMember live_members, int numLiveMembers) {
    int i;
    
    int all = 1;
    
    for (i = 0; i < numLiveMembers; ++i ) {
        if ((live_members[i].interface->map == NULL) || !live_members[i].interface->dynamic || live_members[i].bReady) {
        } else {
            all = 0;
        }
    }
    
    if (all)
        return STATUS_STARTED;
    else
        return STATUS_PARTIAL;
}

static int isMemberEqual(PMember a, PMember b) {
 
    MNET_DEBUG("Comparing interfaces, %s:%s-%s, %s:%s-%s\n" COMMA a->interface->type->name COMMA a->interface->name COMMA a->bTagging ? "t" : "ut" COMMA b->interface->type->name COMMA b->interface->name COMMA b->bTagging ? "t" : "ut")
    if (strncmp(a->interface->name, b->interface->name, sizeof(a->interface->name)))
        return 0;
    if (strncmp(a->interface->type->name, b->interface->type->name, sizeof(a->interface->type->name)))
        return 0;
    if (a->bTagging != b->bTagging)
        return 0;
    
    MNET_DEBUG("Returning match\n")
    
    return 1;
}

static inline void deleteFromMemberArray(PMember memberArray, int index, int* numMembers) {
    MNET_DEBUG("Deleting %s-%s\n" COMMA memberArray[index].interface->type->name COMMA memberArray[index].bTagging ? "t" : "ut")
    if (*numMembers > 1)
        memberArray[index] = memberArray[*numMembers - 1];
    
    (*numMembers)--;
}

static int resolve_member_diff(PL2Net network, 
                               PMember members, int* numMembers, 
                               PMember live_members, int* numLiveMembers,
                               PMember keep_members, int* numKeepMembers) {
    int i, j; 

#if defined(MULTILAN_FEATURE)
    int len = 0;
    char br_if_path[CMD_STRING_LEN] = {0};
    char temp_ifname[MAX_IFNAME_SIZE] = {0};
#endif

    for (i = 0; i < *numMembers; ++i ) {
        for (j = 0; j < *numLiveMembers; ++j) {

#if defined (MULTILAN_FEATURE)
            memset(temp_ifname, 0, sizeof(temp_ifname));
            if(!strstr(live_members[j].interface->name, "sw_") ||
                  (STATUS_OK != getIfName(temp_ifname, live_members[j].interface->name)))
            {
                /* if port is not sw_x or getIfName() returns failure then use port name as the interface name */
                strncpy(temp_ifname, live_members[j].interface->name, sizeof(temp_ifname));
            }
                  len = snprintf(br_if_path, CMD_STRING_LEN, BRIDGE_IFACE_PATH, network->name, temp_ifname);

            if (live_members[i].bTagging) {
                snprintf(br_if_path+len, CMD_STRING_LEN-len, ".%d", network->vid);
            }
            if (isMemberEqual(members + i, live_members + j) && (access(br_if_path, F_OK) == 0)) {       /* Added check: if previously added interfaces are connected to bridge */
#else
            if (isMemberEqual(members + i, live_members + j)) {
#endif
                keep_members[*numKeepMembers] = members[i];
                deleteFromMemberArray(members, i, numMembers);
                deleteFromMemberArray(live_members, j, numLiveMembers);
                
                (*numKeepMembers)++;
                --i;
                break;
            }
        }
    }
    
    return 0;
}

#if defined(MULTILAN_FEATURE)
// Assign an address in CIDR format to a bridge instance
int multinet_assignBridgeCIDR(int l2netInst, char *CIDR, int IPVersion) {
    L2Net l2net;

    memset(&l2net,0,sizeof(l2net));

    // Get bridge details from nv
    nv_get_bridge(l2netInst, &l2net);

    // Assign IP address in CIDR form to the bridge's network interface
    if (strnlen(l2net.name, IFNAMSIZ) > 0)
    {
        MNET_DEBUG("About to assign CIDR address %s to instance %d. Name: %s\n" COMMA CIDR COMMA l2netInst COMMA l2net.name);
        if (IPVersion == 4 || IPVersion == 6) {
            v_secure_system("ip -%d addr change %s dev %s", IPVersion, CIDR, l2net.name);

        }
        else {
            MNET_DEBUG("Unknown IP version %d\n" COMMA IPVersion);
            return -1;
        }
    }
    else
    {
        MNET_DEBUG("nv fetch failed for instance %d.\n" COMMA l2netInst);
        return -1;
    }
    return 0;
}
#endif

#if defined(MESH_ETH_BHAUL)
int toggle_ethbhaul_ports(BOOL onOff)
{
    int retVal = 0;
    char eb_enable[20] = {0};

    /* Determine if Ethernet Backhaul is enabled */
    if (0 == syscfg_get(NULL, "eb_enable", eb_enable, sizeof(eb_enable)))
    {
        if(0 == strncmp(eb_enable, "false", sizeof(eb_enable)))
        {
            /* RFC Not Enabled So Exit */
            return retVal;
        }
    }
    else
    {
        MNET_DEBUG("Error: %s syscfg_get for eb_enable failed!\n" COMMA __FUNCTION__);
        return retVal;
    }

    if(1 == onOff)
    {
       multinet_bridgeUpInst(11, 0);
    }
    else if(0 == onOff)
    {
       multinet_bridgeDownInst(11);
    }

    multinet_assignBridgeCIDR(11, MESHETHBHAUL_IPV4_CIDR, 4);
    v_secure_system("sysevent set firewall-restart");

    retVal = nv_toggle_ethbhaul_ports(onOff);

    return retVal;
}
#endif

//TODO:Deferred BRIDGES SYNC!!!
//TODO: inspect differences from script
//TODO: use utplat defines

