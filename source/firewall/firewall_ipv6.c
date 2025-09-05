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
 ============================================================================

 Introduction to IPv6 Firewall
 -------------------------------
 
 The firewall is based on iptables. It uses the mangle, nat, and filters tables,
 and for each of these, it add several subtables.

 The reason for using subtables is that a subtable represents a block of rules
 which can be erased (using -F), and reconstituted using syscfg and sysevent, 
 without affecting the rest of the firewall. That makes its easier to organize
 a complex firewall into smaller functional groups. 

 The main tables, INPUT OUTPUT, and FORWARD, contain jumps to subtables that better represent
 a Utopia firewall: wan2self, lan2self, lan2wan, wan2wan. Each of these subtables
 further specifies the order of rules and jumps to further subtables. 
 
 As mentioned earlier, the firewall is iptables based. There are two ways to use iptables:
 iptables-restore using an input file, or issuing a series of iptables commands. Using iptables-restore
 disrupts netfilters connection tracking which causes established connections to appear to be invalid.
 Using iptables is slower, and it requires that Utopia firewall table structure already exists. This means
 that it cannot be used to initially structure the firewall. 

 The behavior of firewall.c is to check whether the iptables file (/tmp/.ipt)
 exists. If it doesn't exist, then a new one is created and instantiated via iptables-restore.
 On the other hand if .ipt already exists, then all subtables are flushed and reconstituted
 using iptables rules. 

 Here is a list of subtables and how each subtable is populated:
 Note that some syscfg/sysevent tuples are used to populate more than one subtable
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "firewall.h"

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <ctype.h>
#include <ulog/ulog.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/mman.h>
#include "secure_wrapper.h"
#include "util.h"
#if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#endif

void* bus_handle ;
int sysevent_fd;
char sysevent_ip[19];
unsigned short sysevent_port;


// Global variables used in both files
char current_wan_ifname[50];
char wan6_ifname[50];
char ecm_wan_ifname[20];
char lan_ifname[50];
char cmdiag_ifname[20];
char emta_wan_ifname[20];
token_t sysevent_token;
int syslog_level;
char firewall_levelv6[20];
int isWanPingDisableV6;
int isHttpBlockedV6;
int isP2pBlockedV6;
int isIdentBlockedV6;
int isMulticastBlockedV6;
int isFirewallEnabled;
int isBridgeMode;
int isWanServiceReady;
int isDevelopmentOverride;
int isRawTableUsed;
int isContainerEnabled;
int isComcastImage;
bool bEthWANEnable = FALSE;
int isCmDiagEnabled;
char iot_ifName[50];       // IOT interface
int isDmzEnabled;
int isPingBlockedV6;
#if defined (INTEL_PUMA7)
bool erouterSSHEnable = FALSE;
#else
bool erouterSSHEnable = TRUE;
#endif
int ecm_wan_ipv6_num;
char ecm_wan_ipv6[IF_IPV6ADDR_MAX][40];
bool bAmenityEnabled = FALSE;
int isNatReady;

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
BOOL isMAPTReady = 0;
#endif

#if defined(SPEED_BOOST_SUPPORTED)
char speedboostports[32];
BOOL isPvDEnable = FALSE;
#if defined(SPEED_BOOST_SUPPORTED_V6)
char speedboostportsv6[32];
#endif
#endif

#ifdef WAN_FAILOVER_SUPPORTED

#define PSM_MESH_WAN_IFNAME "dmsb.Mesh.WAN.Interface.Name"
int mesh_wan_ipv6_num = 0;
char mesh_wan_ifname[32];
char mesh_wan_ipv6addr[IF_IPV6ADDR_MAX][40];
char dev_type[20];
#endif

char current_wan_ipv6[IF_IPV6ADDR_MAX][40];
char lan_local_ipv6[IF_IPV6ADDR_MAX][40];
bool isDefHttpPortUsed = FALSE;
char devicePartnerId[255] = {'\0'};

//Hardcoded support for cm and erouter should be generalized.
#if defined(_HUB4_PRODUCT_REQ_) || defined(_TELCO_PRODUCT_REQ_)
char * ifnames[] = { wan6_ifname, lan_ifname};
#else
char * ifnames[] = { wan6_ifname, ecm_wan_ifname, emta_wan_ifname, lan_ifname};
#endif /* * _HUB4_PRODUCT_REQ_ */
int numifs = sizeof(ifnames) / sizeof(*ifnames);


#define V6_BLOCKFRAGIPPKT   "v6_BlockFragIPPkts"
#define V6_PORTSCANPROTECT  "v6_PortScanProtect"
#define V6_IPFLOODDETECT    "v6_IPFloodDetect"

/*
 ****************************************************************
 *               IPv6 Firewall                                  *
 ****************************************************************
 */

/*
 *  Procedure     : prepare_ipv6_firewall
 *  Purpose       : prepare the ip6tables-restore file that establishes all
 *                  ipv6 firewall rules
 *  Paramenters   :
 *    fw_file        : The name of the file to which the firewall rules are written
 * Return Values  :
 *    0              : Success
 *   -1              : Bad input parameters
 *   -2              : Could not open firewall file
 * Notes          :
 *   If the fw_file exists it will be overwritten.
 *   The syscfg subsystem must be initialized prior to calling this function
 *   The sysevent subsytem must be initializaed prior to calling this function
 */
int prepare_ipv6_firewall(const char *fw_file)
{
 FIREWALL_DEBUG("Inside prepare_ipv6_firewall \n");
   if (NULL == fw_file) {
      return(-1);
   }
   FILE *fp = fopen(fw_file, "w");
   if (NULL == fp) {
      return(-2);
   }
   sysevent_get(sysevent_fd, sysevent_token, "current_wan_ipv6_interface", wan6_ifname, sizeof(wan6_ifname));
   
   errno_t safec_rc = -1;
   if (wan6_ifname[0] == '\0'){
       safec_rc = strcpy_s(wan6_ifname, sizeof(wan6_ifname),current_wan_ifname);
       ERR_CHK(safec_rc);
    }

	int ret=0;
	FILE *raw_fp=NULL;
	FILE *mangle_fp=NULL;
	FILE *filter_fp=NULL;
	FILE *nat_fp=NULL;
   char string[MAX_QUERY]={0};
	char *strp=NULL;
    /*
    * We use 4 files to store the intermediary firewall statements.
    * One file is for raw, another is for mangle, another is for 
    * nat tables statements, and the other is for filter statements.
    */
	pid_t ourpid = getpid();
	char  fname[50];
	
	snprintf(fname, sizeof(fname), "/tmp/raw6_%x", ourpid);
	raw_fp = fopen(fname, "w+");
	if (NULL == raw_fp) {
		ret=-2;
		goto clean_up_files;
	}
	
	snprintf(fname, sizeof(fname), "/tmp/mangle6_%x", ourpid);
	mangle_fp = fopen(fname, "w+");
	if (NULL == mangle_fp) {
		ret=-2;
		goto clean_up_files;
	}
	snprintf(fname, sizeof(fname), "/tmp/filter6_%x", ourpid);
	filter_fp = fopen(fname, "w+");
	if (NULL == filter_fp) {
		ret=-2;
		goto clean_up_files;
	}
	snprintf(fname, sizeof(fname), "/tmp/nat6_%x", ourpid);
	nat_fp = fopen(fname, "w+");
	if (NULL == nat_fp) {
		ret=-2;
		goto clean_up_files;
	}
        
       
   #ifdef RDKB_EXTENDER_ENABLED  

   if (isExtProfile() == 0)
   {
      prepare_ipv6_rule_ex_mode(raw_fp, mangle_fp, nat_fp, filter_fp);
   }
   else
   {
   #endif
      #ifdef INTEL_PUMA7
         fprintf(raw_fp, "*raw\n");
         do_raw_table_puma7(raw_fp);
      #endif
         
      do_ipv6_sn_filter(mangle_fp);
      #if !defined(_PLATFORM_IPQ_)
         do_ipv6_nat_table(nat_fp);
      #endif

  	if ( bEthWANEnable )
  	{
      	  ethwan_mso_gui_acess_rules(NULL,mangle_fp);                      
  	}
    do_ipv6_UIoverWAN_filter(mangle_fp);

#if defined(_COSA_BCM_MIPS_) // RDKB-35063
	ethwan_mso_gui_acess_rules(NULL,mangle_fp);
#endif
	
        do_ipv6_filter_table(filter_fp);

	do_wpad_isatap_blockv6(filter_fp);

#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
        prepare_rabid_rules(filter_fp, mangle_fp, IP_V6);
#else
        prepare_rabid_rules_v2020Q3B(filter_fp, mangle_fp, IP_V6);
#endif
	do_parental_control(filter_fp,nat_fp, 6);
#if defined(SPEED_BOOST_SUPPORTED) && defined(SPEED_BOOST_SUPPORTED_V6)
	WAN_FAILOVER_SUPPORT_CHECK
	if(isWanServiceReady && !isBridgeMode)
		do_speedboost_port_rules(mangle_fp,nat_fp , 6);
	WAN_FAILOVER_SUPPORT_CHECk_END
#endif
        prepare_lnf_internet_rules(mangle_fp,6);
        if (isContainerEnabled) {
            do_container_allow(filter_fp, mangle_fp, nat_fp, AF_INET6);
        }

       do_blockfragippktsv6(filter_fp);
       do_portscanprotectv6(filter_fp);
       do_ipflooddetectv6(filter_fp);
	
	/* XDNS - route dns req though dnsmasq */
#ifdef XDNS_ENABLE
    do_dns_route(nat_fp, 6);
#endif
#ifdef INTEL_PUMA7
    prepare_multinet_mangle_v6(mangle_fp);
#endif 
//#if defined(MOCA_HOME_ISOLATION)
  //      prepare_MoCA_bridge_firewall(raw_fp, mangle_fp, nat_fp, filter_fp);
//#endif
//
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
   /* bypass IPv6 firewall, let IPv4 firewall handle MAP-T packets */
    do_mapt_rules_v6(filter_fp);
#endif //FEATURE_MAPT

#if defined(_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      do_hub4_voice_rules_v6(filter_fp, mangle_fp);
      if (do_hub4_dns_rule_v6(mangle_fp) == 0)
      {
         FIREWALL_DEBUG("INFO: Firewall rule addition success for IPv6 DNS CHECKSUM \n");
      }
      else
      {
         FIREWALL_DEBUG("INFO: Firewall rule addition failed for IPv6 DNS CHECKSUM \n");
      }
   }
#if defined(HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   char syscfg_value[64] = { 0 };
   int get_ret = 0;
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      do_hub4_bfd_rules_v6(filter_fp, mangle_fp);
   }
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED

#ifdef HUB4_QOS_MARK_ENABLED
      do_qos_output_marking_v6(mangle_fp);
#endif

#ifdef HUB4_SELFHEAL_FEATURE_ENABLED
      do_self_heal_rules_v6(mangle_fp);
#endif
#endif //_HUB4_PRODUCT_REQ_ || _RDKB_GLOBAL_PRODUCT_REQ_
   #ifdef RDKB_EXTENDER_ENABLED  
   }
   #endif

   #ifdef WAN_FAILOVER_SUPPORTED
#ifdef FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE
        if(strcmp(current_wan_ifname, mesh_wan_ifname ) == 0)
#else
         if ( strcmp(current_wan_ifname,default_wan_ifname) != 0 )
#endif
         {
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -i %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -o %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I FORWARD -o %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
            fprintf(filter_fp, "-I OUTPUT -o %s -p tcp --tcp-flags RST RST -j DROP\n",current_wan_ifname);
            fprintf(filter_fp, "-I OUTPUT -o %s -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT\n",current_wan_ifname);
         }
         fprintf(filter_fp, "-I FORWARD -o %s -m state --state INVALID -j DROP\n",current_wan_ifname);
#ifdef NAT46_KERNEL_SUPPORT
         fprintf(filter_fp, "-I FORWARD -o %s -p gre -j ACCEPT\n",current_wan_ifname);
#endif

         int retval = 0;
         char tmpsysQuery[MAX_QUERY];
         memset(tmpsysQuery, 0, sizeof(tmpsysQuery));
         retval = syscfg_get(NULL, "ipv6_hopbyhop_hdr_accept", tmpsysQuery, sizeof(tmpsysQuery));
         if ((retval == 0) && (!strcmp(tmpsysQuery,"true")))
         {
            /* These rules are needed to accept IPv6 traffic with HBH extension header and No-Next-Header option */
            /* To enable ipv6header module support need to set CONFIG_IP6_NF_MATCH_IPV6HEADER=m kernel config */
             fprintf(filter_fp,"-I FORWARD 1 -o erouter0 -m ipv6header --soft --header hop-by-hop -j ACCEPT\n");
             fprintf(filter_fp,"-I FORWARD 1 -o erouter0 -m ipv6header --soft --header hop-by-hop -j LOG --log-prefix \"UTOPIA: FW.IPv6 FORWARD Hop-by-Hop\" --log-level 6\n");
         }

   #endif

	/*add rules before this*/
#if !defined(_BWG_PRODUCT_REQ_)
	fprintf(raw_fp, "COMMIT\n");
#endif


	fprintf(mangle_fp, "COMMIT\n");
#if !defined(_PLATFORM_IPQ_)
	fprintf(nat_fp, "COMMIT\n");
#endif
	fprintf(filter_fp, "COMMIT\n");
	
   	fflush(raw_fp);
   	fflush(mangle_fp);
   	fflush(nat_fp);
   	fflush(filter_fp);
	rewind(raw_fp);
	rewind(mangle_fp);
	rewind(nat_fp);
	rewind(filter_fp);
	/*
	* The raw table is before conntracking and is thus expensive
	* So we dont set it up unless we actually used it
	*/
#if !defined(_BWG_PRODUCT_REQ_)
	if (isRawTableUsed) {
		while (NULL != (strp = fgets(string, MAX_QUERY, raw_fp)) ) {
		   fprintf(fp, "%s", string);
		}
	} else {
		fprintf(fp, "*raw\n-F\nCOMMIT\n");
	}
#endif

	while (NULL != (strp = fgets(string, MAX_QUERY, mangle_fp)) ) {
		fprintf(fp, "%s", string);
	}
	while (NULL != (strp = fgets(string, MAX_QUERY, nat_fp)) ) {
		fprintf(fp, "%s", string);
	}
	while (NULL != (strp = fgets(string, MAX_QUERY, filter_fp)) ) {
		fprintf(fp, "%s", string);
	}

clean_up_files:	 
	if(fp){
   		fflush(fp);
		fclose(fp);
	}
	if(raw_fp) {
		fclose(raw_fp);
		snprintf(fname, sizeof(fname), "/tmp/raw6_%x", ourpid);
	 	unlink(fname);
	}
	if(mangle_fp) {
		fclose(mangle_fp);
		snprintf(fname, sizeof(fname), "/tmp/mangle6_%x", ourpid);
	 	unlink(fname);
	}
	if(nat_fp) {
		fclose(nat_fp);
		snprintf(fname, sizeof(fname), "/tmp/filter6_%x", ourpid);
	 	unlink(fname);
	}
	if(filter_fp) {
		fclose(filter_fp);
		snprintf(fname, sizeof(fname), "/tmp/nat6_%x", ourpid);
		unlink(fname);
	}
	FIREWALL_DEBUG("Exiting prepare_ipv6_firewall \n"); 
	return ret;
}

void do_ipv6_filter_table(FILE *fp){
	FIREWALL_DEBUG("Inside do_ipv6_filter_table \n");
   int inf_num = 0;
   
#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_)
   FILE *f = NULL;
   char request[256], response[256], cm_ipv6addr[40];
   unsigned int a[16] = {0};
#endif
	
   fprintf(fp, "*filter\n");
   fprintf(fp, ":INPUT ACCEPT [0:0]\n");
   fprintf(fp, ":FORWARD ACCEPT [0:0]\n");
   fprintf(fp, ":OUTPUT ACCEPT [0:0]\n");
   fprintf(fp, ":lan2wan - [0:0]\n");
   fprintf(fp, ":lan2wan_misc_ipv6 - [0:0]\n");
   fprintf(fp, ":lan2wan_pc_device - [0:0]\n");
   fprintf(fp, ":lan2wan_pc_site - [0:0]\n");
   fprintf(fp, ":lan2wan_pc_service - [0:0]\n");
   fprintf(fp, ":wan2lan - [0:0]\n");

#if defined (_HUB4_PRODUCT_REQ_) || defined (_RDKB_GLOBAL_PRODUCT_REQ_)
#if defined (HUB4_BFD_FEATURE_ENABLED) || defined (IHC_FEATURE_ENABLED)
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
   char syscfg_value[64] = { 0 };
   int get_ret = 0;
   get_ret = syscfg_get(NULL, "ConnectivityCheckType", syscfg_value, sizeof(syscfg_value));
   if ((get_ret == 0) && atoi(syscfg_value) == 1)
   {
        fprintf(fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
        fprintf(fp, "-I INPUT -j %s\n", IPOE_HEALTHCHECK);
   }
#else
    fprintf(fp, ":%s - [0:0]\n", IPOE_HEALTHCHECK);
    fprintf(fp, "-I INPUT -j %s\n", IPOE_HEALTHCHECK);
#endif //_RDKB_GLOBAL_PRODUCT_REQ_
#endif //HUB4_BFD_FEATURE_ENABLED || IHC_FEATURE_ENABLED
#endif //_HUB4_PRODUCT_REQ_
   //>>DOS
#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(fp, ":%s - [0:0]\n", "wandosattack");
   fprintf(fp, ":%s - [0:0]\n", "mtadosattack");
#endif
   //<<DOS

#if defined (INTEL_PUMA7)
   fprintf(fp, "-I FORWARD -m conntrack --ctdir original -m connbytes --connbytes 0:15 --connbytes-dir original --connbytes-mode packets -j GWMETA --dis-pp\n");
   fprintf(fp, "-I FORWARD -m conntrack --ctdir reply -m connbytes --connbytes 0:15 --connbytes-dir reply --connbytes-mode packets -j GWMETA --dis-pp\n");
#endif

#ifdef INTEL_PUMA7
   //Avoid blocking packets at the Intel NIL layer
   fprintf(fp, "-A FORWARD -i a-mux -j ACCEPT\n");
#endif

   fprintf(fp, ":%s - [0:0]\n", "LOG_INPUT_DROP");
   fprintf(fp, ":%s - [0:0]\n", "LOG_FORWARD_DROP");
   if(isComcastImage) {
       //tr69 chains for logging and filtering
       fprintf(fp, ":%s - [0:0]\n", "LOG_TR69_DROP");
       fprintf(fp, ":%s - [0:0]\n", "tr69_filter");
       fprintf(fp, "-A INPUT -p tcp -m tcp --dport 7547 -j tr69_filter\n");
       fprintf(fp, "-A LOG_TR69_DROP -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"TR-069 ACS Server Blocked:\"\n",syslog_level);
       fprintf(fp, "-A LOG_TR69_DROP -j DROP\n");
   }

#ifdef _COSA_INTEL_XB3_ARM_
   fprintf(fp, "-I INPUT -i wan0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j wandosattack\n");
   fprintf(fp, "-I INPUT -i wan0 -p udp -m udp -j wandosattack\n");
   fprintf(fp, "-I INPUT -i mta0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j mtadosattack\n");
   fprintf(fp, "-I INPUT -i mta0 -p udp -m udp -j mtadosattack\n");
   fprintf(fp, "-A wandosattack -p tcp -m tcp --dport 22 -m limit --limit 25/sec --limit-burst 80 -j RETURN\n");
   fprintf(fp, "-A wandosattack -m limit --limit 25/sec --limit-burst 80 -j ACCEPT\n");
   fprintf(fp, "-A wandosattack -j DROP\n");
   fprintf(fp, "-A mtadosattack -m limit --limit 200/sec --limit-burst 100 -j ACCEPT\n");
   fprintf(fp, "-A mtadosattack -j DROP\n");
#endif

   do_block_ports(fp);	
   fprintf(fp, ":%s - [0:0]\n", "LOG_SSH_DROP");
   fprintf(fp, ":%s - [0:0]\n", "SSH_FILTER");
   if(bEthWANEnable)
   {
   fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n",current_wan_ifname);
   }
   else if (erouterSSHEnable)
   {
   fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n",current_wan_ifname);
   fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", ecm_wan_ifname);
   }
   else
   {
       if (strcmp(current_wan_ifname,default_wan_ifname ) == 0)
       {
        fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", ecm_wan_ifname);
       }
       else
       {
        fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 22 -j SSH_FILTER\n", current_wan_ifname);
       }
      
   }
   
   fprintf(fp, "-A LOG_SSH_DROP -j LOG --log-prefix \"SSH Connection Blocked: \" --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute --limit-burst 1\n", syslog_level); 
   fprintf(fp, "-A LOG_SSH_DROP -j DROP\n");

//SNMPv3 chains for logging and filtering
   fprintf(fp, ":%s - [0:0]\n", "SNMPDROPLOG");
   fprintf(fp, ":%s - [0:0]\n", "SNMP_FILTER");
   fprintf(fp, "-A INPUT -p udp -m udp --match multiport --dports 10161,10163 -j SNMP_FILTER\n");
   fprintf(fp, "-A SNMPDROPLOG -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"SNMP Connection Blocked:\"\n",syslog_level);
   fprintf(fp, "-A SNMPDROPLOG -j DROP\n");

   //DROP incoming  NTP packets on erouter interface
   fprintf(fp, "-A INPUT -i %s -m state --state ESTABLISHED,RELATED -p udp --dport 123 -j ACCEPT \n", get_current_wan_ifname());
   fprintf(fp, "-A INPUT -i %s  -m state --state NEW -p udp --dport 123 -j DROP \n",get_current_wan_ifname());

   /* RDKB-57186 SNMP drop to XHS and LnF */
   fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 161 -j DROP\n", XHS_IF_NAME);
   fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 161 -j DROP\n", LNF_IF_NAME);

   // Video Analytics Firewall rule to allow port 58081 only from LAN interface
   do_OpenVideoAnalyticsPort (fp);

#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_)
   /* To avoid open ssh connection to CM IP TCXB6-2879*/
   snprintf(request, 256, "snmpget -cpub -v2c -Ov %s %s", CM_SNMP_AGENT, kOID_cmRemoteIpv6Address);

   if ((f = popen(request, "r")) != NULL)
   {
      fgets(response, 255, f);
      sscanf(response, "Hex-STRING: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &a[8], &a[9], &a[10], &a[11], &a[12], &a[13], &a[14], &a[15]);
      sprintf(cm_ipv6addr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);

      if (!(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0
         && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0
         && a[8] == 0 && a[9] == 0 && a[10] == 0 && a[11] == 0
         && a[12] == 0 && a[13] == 0 && a[14] == 0 && a[15] == 0))
         {
            fprintf(fp, "-I FORWARD -d %s -i %s  -j DROP\n", cm_ipv6addr, lan_ifname);
            fprintf(fp, "-I FORWARD -d %s -i brlan1  -j DROP\n", cm_ipv6addr);
	    fprintf(fp, "-I FORWARD -d %s -i br106  -j DROP\n", cm_ipv6addr);
         }

         pclose(f);
   }
#endif

   // Create iptable chain to ratelimit remote management packets
   do_webui_rate_limit(fp);
   // Rate limiting the webui-access lan side
   if(isBridgeMode)
   {
       lan_access_set_proto(fp, "80",cmdiag_ifname);
       lan_access_set_proto(fp, "443",cmdiag_ifname);
   }
   else
   {
       lan_access_set_proto(fp, "80",lan_ifname);
       lan_access_set_proto(fp, "443",lan_ifname);
   }
   // Blocking webui access to unnecessary interfaces
   fprintf(fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",lan_ifname);
   fprintf(fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",ecm_wan_ifname);
   if (isCmDiagEnabled)
   {
      fprintf(fp, "-A INPUT -p tcp -i %s --match multiport --dport 80,443 -j ACCEPT\n",cmdiag_ifname);
   }
   #if defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
        #if !defined(_CBR_PRODUCT_REQ_) && !defined (_BWG_PRODUCT_REQ_) && !defined (_CBR2_PRODUCT_REQ_)
           fprintf(fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",XHS_IF_NAME);
           fprintf(fp, "-A FORWARD -i %s -o privbr -p tcp -m multiport --dport 22,23,80,443 -j DROP\n",LNF_IF_NAME);
	   /* RDKB-57186 SNMP drop to XHS and LnF */
           fprintf(fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(fp, "-A FORWARD -i %s -o privbr -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
	   fprintf(fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",LNF_IF_NAME);
           fprintf(fp, "-A FORWARD -i %s -o brlan113 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
           fprintf(fp, "-A FORWARD -i %s -o brlan112 -p udp --dport 161 -j DROP\n",XHS_IF_NAME);
       #endif
       fprintf(fp, "-A INPUT -p tcp -i privbr --match multiport  --dport 80,443 -j ACCEPT\n");
       
       fprintf(fp, "-A FORWARD -i brlan1 -o erouter0 -p tcp -m multiport --dport 22,8080,8181 -j DROP\n");
       fprintf(fp, "-A FORWARD -i br106 -o erouter0 -p tcp -m multiport --dport 22,8080,8181 -j DROP\n");
   #endif
   if ( !bEthWANEnable )
   {
      fprintf(fp,"-A INPUT -p tcp --match multiport  --dport 80,443 -j DROP\n");
   }
   fprintf(fp,"-A INPUT -p tcp -i brlan1 --dport 22 -j DROP\n");
   fprintf(fp,"-A INPUT -p tcp -i br106 --dport 22 -j DROP\n");
   int retval = 0;
   char tmpsysQuery[MAX_QUERY];
   memset(tmpsysQuery, 0, sizeof(tmpsysQuery));
   #if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
      retval = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpsysQuery, sizeof(tmpsysQuery));
   #else
      retval = syscfg_get(NULL, "mgmt_wan_httpaccess", tmpsysQuery, sizeof(tmpsysQuery));
   #endif
   if ((retval == 0) && atoi(tmpsysQuery) == 1)
   {
      fprintf(fp,"-A INPUT -p tcp ! -i %s --dport 8080 -j DROP\n",current_wan_ifname);
   }
   else
   {
      fprintf(fp,"-A INPUT -p tcp  --dport 8080 -j DROP\n");
   }
   memset(tmpsysQuery, 0, sizeof(tmpsysQuery));
   retval =  syscfg_get(NULL, "mgmt_wan_httpsaccess", tmpsysQuery, sizeof(tmpsysQuery));
   if ((retval == 0) && atoi(tmpsysQuery) == 1)
   {
      fprintf(fp,"-A INPUT -i  brlan0 -p tcp --dport 8181 -j ACCEPT\n");
      fprintf(fp,"-A INPUT -p tcp ! -i %s --dport 8181 -j DROP\n",current_wan_ifname);
   }
   else
   {
      fprintf(fp,"-A INPUT -p tcp --dport 8181 -j DROP\n");
   }

   if (!isFirewallEnabled || isBridgeMode || !isWanServiceReady) {
       if(isBridgeMode || isWanServiceReady)
       {
	       WAN_FAILOVER_SUPPORT_CHECK
               do_remote_access_control(NULL, fp, AF_INET6);
	       WAN_FAILOVER_SUPPORT_CHECk_END
       }

#if defined(_CBR_PRODUCT_REQ_)
       if (isBridgeMode) {
           //TCCBR-2674 - Technicolor CBR Telnet port exposed to Public internet
           fprintf(fp, "-A INPUT -i erouter0 -p tcp -m tcp --dport 23 -j DROP\n" );
       }
#endif

       lan_telnet_ssh(fp, AF_INET6);
       do_ssh_IpAccessTable(fp, "22", AF_INET6, ecm_wan_ifname);
       do_snmp_IpAccessTable(fp, AF_INET6);
       if(isComcastImage) {
          do_tr69_whitelistTable(fp, AF_INET6);
       }
#if defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isMAPTReady)
      {
         fprintf(fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", wan6_ifname, NAT46_INTERFACE);
         fprintf(fp, "-I FORWARD -i %s -o %s -j ACCEPT\n", NAT46_INTERFACE, wan6_ifname);
      }
#endif
       goto end_of_ipv6_firewall;
   }

   do_openPorts(fp);

   fprintf(fp, "-A LOG_INPUT_DROP -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"UTOPIA: FW.IPv6 INPUT drop\"\n",syslog_level);
   fprintf(fp, "-A LOG_FORWARD_DROP -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"UTOPIA: FW.IPv6 FORWARD drop\"\n",syslog_level);
   fprintf(fp, "-A LOG_INPUT_DROP -j DROP\n"); 
#ifdef FEATURE_464XLAT
    //464xlat remove the rule
#else
    fprintf(fp, "-A LOG_FORWARD_DROP -j DROP\n");
#endif
   fprintf(fp, ":%s - [0:0]\n", "PING_FLOOD");
   fprintf(fp, "-A PING_FLOOD -m limit --limit 5/sec  --limit-burst 60 -j ACCEPT\n");
   fprintf(fp, "-A PING_FLOOD -m limit --limit 1/minute -j LOG --log-level %d --log-prefix \"UTOPIA: IPv6 PING FLOOD Drop\"\n",syslog_level);
   fprintf(fp, "-A PING_FLOOD -j DROP\n");

#ifdef MULTILAN_FEATURE
   prepare_multinet_filter_forward_v6(fp);
   prepare_multinet_filter_output_v6(fp);
#endif
#if defined (INTEL_PUMA7)
   //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
   fprintf(fp, "-A FORWARD -i brlan2 -j ACCEPT\n");
   fprintf(fp, "-A FORWARD -i brlan3 -j ACCEPT\n");
#endif

   //ban telnet and ssh from lan side
   lan_telnet_ssh(fp, AF_INET6);

	char Interface[MAX_NO_IPV6_INF][MAX_LEN_IPV6_INF];
    getIpv6Interfaces(Interface,&inf_num);
   if (isFirewallEnabled) {
      // Get the current WAN IPv6 interface (which differs from the IPv4 in case of tunnels)
      char query[10],port[10],tmpQuery[10];
#ifdef _COSA_FOR_BCI_
      char wanIPv6[64];
#endif
      int rc, ret;
      errno_t safec_rc = -1;

      
      // not sure if this is the right thing to do, but if there is no current_wan_ipv6_interface several iptables statements fail
      if ('\0' == wan6_ifname[0]) {
         snprintf(wan6_ifname, sizeof(wan6_ifname), "%s", current_wan_ifname);
      }
      query[0] = '\0';
      port[0] = '\0';
      rc = syscfg_get(NULL, "mgmt_wan_httpaccess", query, sizeof(query));
#if defined(CONFIG_CCSP_WAN_MGMT_ACCESS)
      tmpQuery[0] = '\0';
      ret = syscfg_get(NULL, "mgmt_wan_httpaccess_ert", tmpQuery, sizeof(tmpQuery));
      if(ret == 0){
          safec_rc = strcpy_s(query, sizeof(query),tmpQuery);
          ERR_CHK(safec_rc);
      }
#endif
      if (0 == rc && '\0' != query[0] && (0 !=  strncmp(query, "0", sizeof(query))) ) {

          rc = syscfg_get(NULL, "mgmt_wan_httpport", port, sizeof(port));
#if defined(CONFIG_CCSP_WAN_MGMT_PORT)
          tmpQuery[0] = '\0';
          ret = syscfg_get(NULL, "mgmt_wan_httpport_ert", tmpQuery, sizeof(tmpQuery));
          if(ret == 0){
              safec_rc = strcpy_s(port, sizeof(port),tmpQuery);
              ERR_CHK(safec_rc);
          }
#endif

          if (0 != rc || '\0' == port[0]) {
            snprintf(port, sizeof(port), "%d", 8080);
         }
      }

      // Accept everything from localhost
      fprintf(fp, "-A INPUT -i lo -j ACCEPT\n");

#if !defined(_PLATFORM_IPQ_)
      // Block the evil routing header type 0
      fprintf(fp, "-A INPUT -m rt --rt-type 0 -j DROP\n");
#endif
      prepare_hotspot_gre_ipv6_rule(fp);
      fprintf(fp, "-A INPUT -m state --state INVALID -j LOG_INPUT_DROP\n");

      if(isComcastImage) {
          do_tr69_whitelistTable(fp, AF_INET6);
      }

#if defined(_COSA_BCM_MIPS_)
      fprintf(fp, "-A INPUT -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
      fprintf(fp, "-A INPUT -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
#endif
      // Allow cfgserv through 
      //fprintf(fp, "-A INPUT -p udp -d ff80::114/64 --dport 5555 -j ACCEPT\n");
      //fprintf(fp, "-A INPUT -p tcp --dport 3005 -j ACCEPT\n");

      // Block all packet whose source is mcast
      fprintf(fp, "-A INPUT -s ff00::/8  -j DROP\n");
     
#ifdef _COSA_FOR_BCI_ 
      if(isWanPingDisableV6 == 1)
      {
             syscfg_get(NULL, "wanIPv6Address", wanIPv6, sizeof(wanIPv6));
             if(0 != strcmp(wanIPv6,""))
             {
                 fprintf(fp, "-A INPUT -i brlan0 -d %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j DROP\n", wanIPv6); // Echo request
                 fprintf(fp, "-A INPUT -i brlan0 -d %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m state --state NEW,INVALID,RELATED -j DROP\n", wanIPv6); // Echo reply
             }
      }
#endif
     
      // Should include --limit 10/second for most of ICMP
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 1/0 -m limit --limit 10/sec -j ACCEPT\n"); // No route
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 2 -m limit --limit 10/sec -j ACCEPT\n"); // Packet too big
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 3 -m limit --limit 10/sec -j ACCEPT\n"); // Time exceeded
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 4/1 -m limit --limit 10/sec -j ACCEPT\n"); // Unknown header type
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 4/2 -m limit --limit 10/sec -j ACCEPT\n"); // Unknown option

      //ping is allowed for cm and emta regardless whatever firewall level is

#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", ecm_wan_ifname); // Echo request
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", ecm_wan_ifname); // Echo reply

      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", emta_wan_ifname); // Echo request
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", emta_wan_ifname); // Echo reply
   }
#endif /*_HUB4_PRODUCT_REQ_*/

    #if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(_CBR_PRODUCT_REQ_)
      /*Add a simple logic here to make traffic allowed for lan interfaces
       * exclude primary lan*/
      prepare_ipv6_multinet(fp);
    #endif
    #if !defined(_XER5_PRODUCT_REQ_) && !defined (_SCER11BEL_PRODUCT_REQ_) //wan0 is not applicable for XER5
      /* not allow ping wan0 from brlan0 */
      int i;
      for(i = 0; i < ecm_wan_ipv6_num; i++){
         fprintf(fp, "-A INPUT -i %s -d %s -p icmpv6 -m icmp6 --icmpv6-type 128  -j LOG_INPUT_DROP\n", lan_ifname, ecm_wan_ipv6[i]);
      }
    #endif
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", lan_ifname); // Echo request
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname); // Echo reply
      if(inf_num!= 0)
	  {
	    int cnt =0;
		for(cnt = 0;cnt < inf_num;cnt++)
		{
			fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", Interface[cnt]); // Echo request
      		fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", Interface[cnt]); // Echo reply
		}
	  }

      if (isWanPingDisableV6 == 1)
      {
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j DROP\n", current_wan_ifname); // Echo request
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m state --state NEW,INVALID,RELATED -j DROP\n", current_wan_ifname); // Echo reply

      }
      else if (strncasecmp(firewall_levelv6, "None", strlen("None")) != 0 && (isWanPingDisableV6 == 0))
      {
      #if defined(CONFIG_CCSP_DROP_ICMP_PING)
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j DROP\n", current_wan_ifname); // Echo request
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m state --state NEW,INVALID,RELATED -j DROP\n", current_wan_ifname); // Echo reply
      #else
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", current_wan_ifname); // Echo request
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", current_wan_ifname); // Echo reply
      #endif
      }
      else
      {
          //fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 128 -m limit --limit 10/sec -j ACCEPT\n"); // Echo request
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", current_wan_ifname); // Echo request
          fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", current_wan_ifname); // Echo reply
      }

      // Should only come from LINK LOCAL addresses, rate limited except 100/second for NA/NS and RS
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 135 -m limit --limit 100/sec -j ACCEPT\n"); // Allow NS from any type source address
      fprintf(fp, "-A INPUT -p icmpv6 -m icmp6 --icmpv6-type 136 -m limit --limit 100/sec -j ACCEPT\n"); // NA

      //fprintf(fp, "-A INPUT -s fe80::/64 -d ff02::1/128 -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", current_wan_ifname); // periodic RA
      fprintf(fp, "-A INPUT -s fe80::/64 -d ff02::1/128 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname); // periodic RA

      if (strcmp(current_wan_ifname, wan6_ifname)) // Also accept from wan6_ifname in case of tunnel
         fprintf(fp, "-A INPUT -s fe80::/64 -d ff02::1/128 -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", wan6_ifname); // periodic RA

      //fprintf(fp, "-A INPUT -s fe80::/64 -d fe80::/64 -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", current_wan_ifname); // sollicited RA
      fprintf(fp, "-A INPUT -s fe80::/64 -d fe80::/64 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname); // sollicited RA

      if (strcmp(current_wan_ifname, wan6_ifname)) // Also accept from wan6_ifname in case of tunnel
         fprintf(fp, "-A INPUT -s fe80::/64 -d fe80::/64 -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", wan6_ifname); // sollicited RA

      fprintf(fp, "-A INPUT -s fe80::/64 -i %s -p icmpv6 -m icmp6 --icmpv6-type 133 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname); //RS
      if(inf_num!= 0)
	  {
		int cnt =0;
		for(cnt = 0;cnt < inf_num;cnt++)
		{
		fprintf(fp, "-A INPUT -s fe80::/64 -d ff02::1/128 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", Interface[cnt]); // periodic RA
      		fprintf(fp, "-A INPUT -s fe80::/64 -d fe80::/64 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", Interface[cnt]); // sollicited RA
		fprintf(fp, "-A INPUT -s fe80::/64 -i %s -p icmpv6 -m icmp6 --icmpv6-type 133 -m limit --limit 100/sec -j ACCEPT\n", Interface[cnt]); //RS
		}
	  }
      // But can also come from UNSPECIFIED addresses, rate limited 100/second for NS (for DAD) and MLD
      fprintf(fp, "-A INPUT -s ::/128 -p icmpv6 -m icmp6 --icmpv6-type 135 -m limit --limit 100/sec -j ACCEPT\n"); // NS
      fprintf(fp, "-A INPUT -s ::/128 -p icmpv6 -m icmp6 --icmpv6-type 143 -m limit --limit 100/sec -j ACCEPT\n"); // MLD

      // IPV6 Multicast traffic
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 130 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 131 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 132 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 143 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 151 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 152 -m limit --limit 10/sec -j ACCEPT\n");
      fprintf(fp, "-A INPUT -s fe80::/64 -p icmpv6 -m icmp6 --icmpv6-type 153 -m limit --limit 10/sec -j ACCEPT\n");
      
      // Allow SSDP 
      fprintf(fp, "-A INPUT -i %s -p udp --dport 1900 -j ACCEPT\n", lan_ifname);
      
      // Normal ports for Management interface
      do_lan2self_by_wanip6(fp);
      fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec -j ACCEPT\n", lan_ifname);
      fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec -j ACCEPT\n", lan_ifname);
      //if (port[0])
      //   fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport %s --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec -j ACCEPT\n", wan6_ifname,port);
      if(inf_num!= 0)
	  {
		int cnt =0;
		for(cnt = 0;cnt < inf_num;cnt++)
		{
		fprintf(fp, "-A INPUT -i %s -p udp --dport 1900 -j ACCEPT\n", Interface[cnt]);
	      	fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 80 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec -j ACCEPT\n", Interface[cnt]);
	      	fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec -j ACCEPT\n", Interface[cnt]);
		}
	  }
        WAN_FAILOVER_SUPPORT_CHECK
        do_remote_access_control(NULL, fp, AF_INET6);
	WAN_FAILOVER_SUPPORT_CHECk_END
      /* if(isProdImage) {
          do_ssh_IpAccessTable(fp, "22", AF_INET6, ecm_wan_ifname);
      } else {
          fprintf(fp, "-A SSH_FILTER -j ACCEPT\n");
      } */
      do_ssh_IpAccessTable(fp, "22", AF_INET6, ecm_wan_ifname);

       do_snmp_IpAccessTable(fp, AF_INET6);


      // Development override
      if (isDevelopmentOverride) {
        fprintf(fp, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n");
        fprintf(fp, "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n");
        fprintf(fp, "-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n");
        fprintf(fp, "-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\n");
      }

      // established communication from anywhere is accepted
      fprintf(fp, "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n");

#if defined(_COSA_BCM_MIPS_)
      fprintf(fp, "-A INPUT -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
      fprintf(fp, "-A INPUT -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
#endif

#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      // for tftp software download to work
      fprintf(fp, "-A INPUT -i %s -p udp --dport 53 -j DROP\n", ecm_wan_ifname);
      fprintf(fp, "-A INPUT -i %s -p udp --dport 67 -j DROP\n", ecm_wan_ifname);
      fprintf(fp, "-A INPUT -i %s -p udp --dport 514 -j DROP\n", ecm_wan_ifname);
      fprintf(fp, "-A INPUT -i %s -j ACCEPT\n", ecm_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/

      // Return traffic. The equivalent of IOS 'established'
      fprintf(fp, "-A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT\n");

      //Captive Portal 
      // Commenting out DROP 53 part as it will create confusion to end user
      //if(isInCaptivePortal()==1)
      //{
           //fprintf(fp, "-I INPUT -i %s -p udp -m udp --dport 53 -j DROP\n", lan_ifname);
           //fprintf(fp, "-I INPUT -i %s -p tcp -m tcp --dport 53 -j DROP\n", lan_ifname);
      //}
      //else
      //{
           // DNS resolver request from client
           // DNS server replies from Internet servers
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
   {
      // Remove burst limit on Hub4 IPv6 DNS requests
      fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -j ACCEPT\n", lan_ifname);
      fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 53 -j ACCEPT\n", lan_ifname);
      fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -j ACCEPT\n", lan_ifname);
   }
   else
   {
      fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname);
      //fprintf(fp, "-A INPUT -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", wan6_ifname);
      fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname); 
   }
#elif !defined(_HUB4_PRODUCT_REQ_)
           fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname);
           //fprintf(fp, "-A INPUT -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", wan6_ifname);
           fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname);
#else
            // Remove burst limit on Hub4 IPv6 DNS requests
           fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -j ACCEPT\n", lan_ifname);
           fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 53 -j ACCEPT\n", lan_ifname);
           fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -j ACCEPT\n", lan_ifname);
#endif
      //}
      if(inf_num!= 0)
	  {
		int cnt =0;
		for(cnt = 0;cnt < inf_num;cnt++)
		{
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
         if( 0 == strncmp( devicePartnerId, "sky-", 4 ) )
         {
               // Remove burst limit on Hub4 IPv6 DNS requests
            fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -j ACCEPT\n", Interface[cnt]);
            fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 53 -j ACCEPT\n", Interface[cnt]);
            fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -j ACCEPT\n", Interface[cnt]);
         }
         else
         {
            fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -m limit --limit 100/sec -j ACCEPT\n", Interface[cnt]);
            fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", Interface[cnt]);
         }
#elif !defined(_HUB4_PRODUCT_REQ_)            
		   fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -m limit --limit 100/sec -j ACCEPT\n", Interface[cnt]);
		   fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -m limit --limit 100/sec -j ACCEPT\n", Interface[cnt]);
#else
            // Remove burst limit on Hub4 IPv6 DNS requests
		   fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 53 -j ACCEPT\n", Interface[cnt]);
           fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 53 -j ACCEPT\n", Interface[cnt]);
		   fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 53 -j ACCEPT\n", Interface[cnt]);
#endif           
		}
	  }

      // NTP request from client
      // NTP server replies from Internet servers
      fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 123 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname);
      //fprintf(fp, "-A INPUT -i %s -p udp -m udp --sport 123 -m limit --limit 10/sec -j ACCEPT\n", wan6_ifname);
      fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --sport 123 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname);

      // DHCPv6 from inside clients (high rate in case of global reboot)
      fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 547 -m limit --limit 100/sec -j ACCEPT\n", lan_ifname);

      // DHCPv6 from outside server (low rate as only a couple of potential DHCP servers)
      //fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 546 -m limit --limit 10/sec -j ACCEPT\n", current_wan_ifname);
      //fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 546 -m limit --limit 10/sec -j ACCEPT\n", wan6_ifname);
      fprintf(fp, "-A INPUT ! -i %s -p udp -m udp --dport 546 -m limit --limit 10/sec -j ACCEPT\n", lan_ifname);

      // IPv4 in IPv6 (for DS-lite)
      fprintf(fp, "-A INPUT -i %s -p 4 -j ACCEPT\n", wan6_ifname);

      //SNMP
      //fprintf(fp, "-A INPUT -i %s -p udp --dport 161 -j ACCEPT\n", ecm_wan_ifname);
      fprintf(fp, "-A INPUT -i %s -p udp --dport 161 -j DROP\n", current_wan_ifname);
      fprintf(fp, "-A INPUT ! -i %s -p udp --dport 161 -j ACCEPT\n", lan_ifname);
#if (defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_) ) && !defined(MODEM_ONLY_SUPPORT)
	  //SSH and HTTP port open for IPv6
	  fprintf(fp, "-I INPUT 42 -p tcp -i privbr --dport 22 -j ACCEPT\n");
	  fprintf(fp, "-I INPUT 43 -p tcp -i privbr --dport 80 -j ACCEPT\n");
	  fprintf(fp, "-I INPUT 42 -p tcp -i privbr --dport 443 -j ACCEPT\n");
#endif
      // add user created rules from syscfg
      int  idx;
      char rule_query[MAX_QUERY];
      char in_rule[MAX_QUERY];
      char subst[MAX_QUERY];
      int  count;

      rule_query[0] = '\0';
      in_rule[0] = '\0'; //TODO addto 1.5.1
      syscfg_get(NULL, "v6GeneralPurposeFirewallRuleCount", in_rule, sizeof(in_rule));
      if ('\0' == in_rule[0]) {
         goto v6GPFirewallRuleNext;
      } else {
         count = atoi(in_rule);
         if (0 == count) {
            goto v6GPFirewallRuleNext;
         }
         if (MAX_SYSCFG_ENTRIES < count) {
            count = MAX_SYSCFG_ENTRIES;
         }
      }

      memset(in_rule, 0, sizeof(in_rule));
      for (idx=1; idx<=count; idx++) {
         snprintf(rule_query, sizeof(rule_query), "v6GeneralPurposeFirewallRule_%d", idx);
         syscfg_get(NULL, rule_query, in_rule, sizeof(in_rule));
         if ('\0' != in_rule[0]) {
            /*
             * the rule we just got could contain variables that we need to substitute
             * for runtime/configuration values
             */
            fprintf(fp,"%s\n", make_substitutions(in_rule, subst, sizeof(subst)));
         }
         memset(in_rule, 0, sizeof(in_rule));
      }

v6GPFirewallRuleNext:

{};// this statement is just to keep the compiler happy. otherwise it has  a problem with the label:
   // add rules from sysevent
      unsigned int iterator;
      char         name[MAX_QUERY];

      iterator = SYSEVENT_NULL_ITERATOR;
      do {
         name[0] = rule_query[0] = '\0';
         sysevent_get_unique(sysevent_fd, sysevent_token,
                                     "v6GeneralPurposeFirewallRule", &iterator,
                                     name, sizeof(name), rule_query, sizeof(rule_query));
         if ('\0' != rule_query[0]) {
            fprintf(fp, "%s\n", rule_query);
         }

      } while (SYSEVENT_NULL_ITERATOR != iterator);

      //fprintf(fp, "-A INPUT -m limit --limit 10/sec -j REJECT --reject-with icmp6-adm-prohibited\n");

      // Open destination port 12368 on wan0 to allow dbus communication between tpg and cns 
      //fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 12368 -j ACCEPT\n", wan6_ifname);
      //fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 12368 -j ACCEPT\n", wan6_ifname);

      // Open destination port 36367 on wan0 to allow sysevent communication between tpg and cns 
      //fprintf(fp, "-A INPUT -i %s -p tcp -m tcp --dport 36367 -j ACCEPT\n", wan6_ifname);
      // Adding rule for HOTSPOT interface
      fprintf(fp, "-A INPUT -i brlan2 -j ACCEPT \n");
      fprintf(fp, "-A INPUT -i brlan3 -j ACCEPT \n");
      fprintf(fp, "-A INPUT -i brlan4 -j ACCEPT \n");
      fprintf(fp, "-A INPUT -i brlan5 -j ACCEPT \n");
      fprintf(fp, "-A INPUT -i brpublic -j ACCEPT \n");
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
      fprintf(fp, "-A INPUT -i bropen6g -j ACCEPT \n");
      fprintf(fp, "-A INPUT -i brsecure6g -j ACCEPT \n");
#endif
      // Logging and rejecting politely (rate limiting anyway)
      fprintf(fp, "-A INPUT -j LOG_INPUT_DROP \n");

      do_forwardPorts(fp);

      //Adding rule for XB6 ARRISXB6-3348 and TCXB6-2262
#if defined(INTEL_PUMA7) || defined(_COSA_BCM_ARM_) || defined(_PLATFORM_TURRIS_) || defined(_COSA_QCA_ARM_) || defined(_PLATFORM_BANANAPI_R4_)
      fprintf(fp, "-A FORWARD -i brlan0 -o brlan0 -j lan2wan \n");
#endif

#if !defined(_PLATFORM_IPQ_)
      // Block the evil routing header type 0
      fprintf(fp, "-A FORWARD -m rt --rt-type 0 -j LOG_FORWARD_DROP \n");
#endif
#if defined(_COSA_BCM_MIPS_)
      fprintf(fp, "-A FORWARD -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
      fprintf(fp, "-A FORWARD -m physdev --physdev-out %s -j ACCEPT\n", emta_wan_ifname);
#endif
      fprintf(fp, "-A FORWARD -i brlan2 -o brlan2 -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -i brlan3 -o brlan3 -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -i brlan4 -o brlan4 -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -i brlan5 -o brlan5 -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -i brpublic -o brpublic -j ACCEPT\n");
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
      fprintf(fp, "-A FORWARD -i bropen6g -o bropen6g -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -i brsecure6g -o brsecure6g -j ACCEPT\n");
#endif
#if defined (AMENITIES_NETWORK_ENABLED)
      if (TRUE == bAmenityEnabled)
      {
         updateAmenityNetworkRules(fp , NULL , AF_INET6 );
      }
#endif
      // Link local should never be forwarded
      fprintf(fp, "-A FORWARD -s fe80::/64 -j LOG_FORWARD_DROP\n");
      fprintf(fp, "-A FORWARD -d fe80::/64 -j LOG_FORWARD_DROP\n");

      // Block all packet whose source is mcast
      fprintf(fp, "-A FORWARD -s ff00::/8  -j LOG_FORWARD_DROP\n");

      // Block all packet whose destination is mcast with organization scope
      fprintf(fp, "-A FORWARD -d ff08::/16  -j LOG_FORWARD_DROP\n");

      // Block all packet whose source or destination is the deprecated site local
      fprintf(fp, "-A FORWARD -s ec00::/10  -j LOG_FORWARD_DROP\n");
      fprintf(fp, "-A FORWARD -d ec00::/10  -j LOG_FORWARD_DROP\n");
      // Block all packet whose source or destination is IPv4 compatible address
      fprintf(fp, "-A FORWARD -s 0::/96  -j LOG_FORWARD_DROP\n");
      fprintf(fp, "-A FORWARD -d 0::/96  -j LOG_FORWARD_DROP\n");

      // Basic RPF check on the egress & ingress traffic
      char prefix[129];
      prefix[0] = 0;
      #ifdef WAN_FAILOVER_SUPPORTED
      if (0 == checkIfULAEnabled())
      {
         sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix_ula", prefix, sizeof(prefix));
      }  
      else
      {
         sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix", prefix, sizeof(prefix));
      }
      #else
         sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix", prefix, sizeof(prefix));
      #endif
      if ( '\0' != prefix[0] ) {
         //fprintf(fp, "-A FORWARD ! -s %s -i %s -m limit --limit 10/sec -j LOG --log-level %d --log-prefix \"UTOPIA: FW. IPv6 FORWARD anti-spoofing\"\n", prefix, lan_ifname,syslog_level);
         //fprintf(fp, "-A FORWARD ! -s %s -i %s -m limit --limit 10/sec -j REJECT --reject-with icmp6-adm-prohibited\n", prefix, lan_ifname);
#ifdef _COSA_FOR_BCI_
         /* adding forward rule for PD traffic */
         fprintf(fp, "-A FORWARD -s %s -i %s -j ACCEPT\n", prefix, lan_ifname);
         if (strncasecmp(firewall_levelv6, "Custom", strlen("Custom")) == 0)
         {
            if(isMulticastBlockedV6 || isP2pBlockedV6 || isPingBlockedV6 || isIdentBlockedV6 || isHttpBlockedV6)
            {
               fprintf(fp, "-A FORWARD -d %s -o %s -j wan2lan\n", prefix, lan_ifname);
            }
            else{
               fprintf(fp, "-A FORWARD -d %s -o %s -j ACCEPT\n", prefix, lan_ifname);
            }
         }
#endif
         fprintf(fp, "-A FORWARD ! -s %s -i %s -j LOG_FORWARD_DROP\n", prefix, lan_ifname);
         fprintf(fp, "-A FORWARD -s %s -i %s -j LOG_FORWARD_DROP\n", prefix, wan6_ifname);
      }

/* From community: utopia/generic */
      unsigned char sysevent_query[MAX_QUERY];
      unsigned char lan_prefix[MAX_QUERY];

      snprintf(sysevent_query, sizeof(sysevent_query), "ipv6_%s-prefix", lan_ifname);
      lan_prefix[0] = 0;
      sysevent_get(sysevent_fd, sysevent_token, sysevent_query, lan_prefix, sizeof(lan_prefix));

      if ( '\0' != lan_prefix[0] ) {
         // Block unicast WAN to LAN traffic from going to this bridge if the destination address is not within this bridge's allocated prefix
         fprintf(fp, "-A FORWARD -i %s -o %s -m pkttype --pkt-type unicast ! -d %s -j LOG_FORWARD_DROP\n", wan6_ifname, lan_ifname, lan_prefix);
         // Block unicast LAN to WAN traffic from being sent from this bridge if the source address is not within this bridge's allocated prefix
         fprintf(fp, "-A FORWARD -i %s -o %s -m pkttype --pkt-type unicast ! -s %s -j LOG_FORWARD_DROP\n", lan_ifname, wan6_ifname, lan_prefix);
      }

#if defined(_COSA_BCM_ARM_) && (defined(_CBR_PRODUCT_REQ_) || defined(_XB6_PRODUCT_REQ_)) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_XER5_PRODUCT_REQ_)
      if (isNatReady)
      {
          FILE *f = NULL;
          char request[256], response[256], cm_ipv6addr[40];
          unsigned int a[16] = {0};

          snprintf(request, 256, "snmpget -cpub -v2c -Ov %s %s", CM_SNMP_AGENT, kOID_cmRemoteIpv6Address);

          if ((f = popen(request, "r")) != NULL)
          {
              fgets(response, 255, f);
              sscanf(response, "Hex-STRING: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &a[8], &a[9], &a[10], &a[11], &a[12], &a[13], &a[14], &a[15]);
              sprintf(cm_ipv6addr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);

              if (!(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 
                 && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0 
                 && a[8] == 0 && a[9] == 0 && a[10] == 0 && a[11] == 0 
                 && a[12] == 0 && a[13] == 0 && a[14] == 0 && a[15] == 0))
              {
                  fprintf(fp, "-I lan2wan -d %s -p icmpv6 -m icmpv6 --icmpv6-type 8 -j DROP\n", cm_ipv6addr);
                  fprintf(fp, "-I lan2wan -d %s -p tcp -m tcp --dport 80 -j DROP\n", cm_ipv6addr);
              }

              pclose(f);
          }
      }
#endif

      fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", lan_ifname, lan_ifname);
      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", lan_ifname, wan6_ifname);
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined(IVI_KERNEL_SUPPORT)
      fprintf(fp, "-I FORWARD -i %s -o %s -j lan2wan\n", ETH_MESH_BRIDGE, wan6_ifname);
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isMAPTReady)
      {
         fprintf(fp, "-I FORWARD -i %s -o %s -j lan2wan\n", NAT46_INTERFACE, wan6_ifname);
         fprintf(fp, "-I FORWARD -i %s -o %s -j lan2wan\n", ETH_MESH_BRIDGE, wan6_ifname);
      }
#endif //IVI_KERNEL_SUPPORT
#endif //FEATURE_MAPT

#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
   if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
   {
      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", lan_ifname, ecm_wan_ifname);
      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", lan_ifname, emta_wan_ifname);
   }
#endif /*_HUB4_PRODUCT_REQ_*/
      if(inf_num!= 0)
	  {
		int cnt =0;
		int EvoStreamEnable = 0; 
		char lan_prefix[MAX_BUFF_LEN];
		char inf_prefix[MAX_BUFF_LEN];
		char inf_sysevent[MAX_BUFF_LEN];
		int rc;
        char buffer[64] = {'\0'};

		rc = syscfg_get(NULL, "EvoStreamDirectConnect", buffer, sizeof(buffer));
 		if((rc == 0) && (buffer[0] != '\0'))
		{
		    if (strcmp(buffer, "true") == 0)
                       EvoStreamEnable = TRUE;
                    else
                       EvoStreamEnable = FALSE;
		} 
		lan_prefix[0] = 0;
      #ifdef WAN_FAILOVER_SUPPORTED

      if (0 == checkIfULAEnabled())
      {
         sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix_ula", lan_prefix, sizeof(lan_prefix));
      }
      else
      {
         sysevent_get(sysevent_fd, sysevent_token, "lan_prefix", lan_prefix, sizeof(lan_prefix));
      }

      #else
            sysevent_get(sysevent_fd, sysevent_token, "lan_prefix", lan_prefix, sizeof(lan_prefix));
      #endif
		for(cnt = 0;cnt < inf_num;cnt++)
		{
			if(EvoStreamEnable)
			{
		    		if(strcmp(iot_ifName,Interface[cnt]) != 0) // not to add forward rule for LnF
				{	

                  #ifdef WAN_FAILOVER_SUPPORTED
                  if (0 == checkIfULAEnabled())
                  {
                     snprintf(inf_sysevent, sizeof(inf_sysevent), "%s_ipaddr_v6_ula",Interface[cnt]);
                  }
                  else
                  {
                     snprintf(inf_sysevent, sizeof(inf_sysevent), "%s_ipaddr_v6",Interface[cnt]);
                  }
                  #else
                     snprintf(inf_sysevent, sizeof(inf_sysevent), "%s_ipaddr_v6",Interface[cnt]);
                  #endif
					inf_prefix[0] = 0;
                			sysevent_get(sysevent_fd, sysevent_token, inf_sysevent, inf_prefix, sizeof(inf_prefix));
					if((inf_prefix[0] != '\0') && (lan_prefix[0] != '\0'))
					{
		      			fprintf(fp, "-A FORWARD -d %s -i %s -o %s -j ACCEPT\n",inf_prefix ,lan_ifname, Interface[cnt]);
		      			fprintf(fp, "-A FORWARD -d %s -i %s -o %s -j ACCEPT\n",lan_prefix , Interface[cnt],lan_ifname);
					}
				}
			}	
		      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", Interface[cnt], wan6_ifname);
#ifndef _HUB4_PRODUCT_REQ_
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
         if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
         {
            fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", Interface[cnt], ecm_wan_ifname);
		      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", Interface[cnt], emta_wan_ifname);  
         }
#endif
		}
	  }


      fprintf(fp, "-A lan2wan -j lan2wan_pc_device\n");
      fprintf(fp, "-A lan2wan -j lan2wan_pc_site\n");
      fprintf(fp, "-A lan2wan -j lan2wan_pc_service\n");

#ifdef CONFIG_CISCO_PARCON_WALLED_GARDEN
      fprintf(fp, ":%s - [0:0]\n", "wan2lan_dnsr_nfqueue");
      fprintf(fp, "-A FORWARD -i %s -p udp --sport 53 -j wan2lan_dnsr_nfqueue\n", wan6_ifname);
#endif


      if (strncasecmp(firewall_levelv6, "High", strlen("High")) == 0)
      {
         /* The following rules are the same as IPv4
         fprintf(fp, "-A lan2wan -p tcp --dport 80   -j ACCEPT\n"); // HTTP
         fprintf(fp, "-A lan2wan -p tcp --dport 443  -j ACCEPT\n"); // HTTPS
         fprintf(fp, "-A lan2wan -p udp --dport 53   -j ACCEPT\n"); // DNS
         fprintf(fp, "-A lan2wan -p tcp --dport 53   -j ACCEPT\n"); // DNS
         fprintf(fp, "-A lan2wan -p tcp --dport 119  -j ACCEPT\n"); // NTP
         fprintf(fp, "-A lan2wan -p tcp --dport 123  -j ACCEPT\n"); // NTP
         fprintf(fp, "-A lan2wan -p tcp --dport 25   -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 110  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 143  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 465  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 587  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 993  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p tcp --dport 995  -j ACCEPT\n"); // EMAIL
         fprintf(fp, "-A lan2wan -p gre              -j ACCEPT\n"); // GRE
         fprintf(fp, "-A lan2wan -p udp --dport 500  -j ACCEPT\n"); // VPN
         fprintf(fp, "-A lan2wan -p tcp --dport 1723 -j ACCEPT\n"); // VPN
         fprintf(fp, "-A lan2wan -p tcp --dport 3689 -j ACCEPT\n"); // ITUNES
         fprintf(fp, "-A lan2wan -m limit --limit 100/sec -j LOG --log-level %d --log-prefix \"UTOPIA: FW.IPv6 lan2wan drop\"\n",syslog_level);
         fprintf(fp, "-A lan2wan -j DROP\n");
         */

         //Changed GUI and IPv6 firewall now allows all lan2wan traffic
         fprintf(fp, "-A lan2wan -j ACCEPT\n");
      }
      else
      {
         // Everything from inside to Internet is allowed
         fprintf(fp, "-A lan2wan -j ACCEPT\n");
      }

      // established communication from WAN is accepted
      fprintf(fp, "-A FORWARD -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT\n", wan6_ifname);
#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
      if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
      {
         fprintf(fp, "-A FORWARD -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT\n", ecm_wan_ifname);
         fprintf(fp, "-A FORWARD -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT\n", emta_wan_ifname);
      }
#endif /*_HUB4_PRODUCT_REQ_*/

      // ICMP varies and are rate limited anyway
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 1/0 -m limit --limit 100/sec -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 2 -m state --state INVALID,NEW -j DROP\n");
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 2 -m limit --limit 100/sec -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 3 -m limit --limit 100/sec -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 4 -m limit --limit 100/sec -j ACCEPT\n");

      // ICMP messages for MIPv6 (assuming mobile node on the inside)
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 145 -m limit --limit 100/sec -j ACCEPT\n");
      fprintf(fp, "-A FORWARD -p icmpv6 -m icmp6 --icmpv6-type 147 -m limit --limit 100/sec -j ACCEPT\n");

      // Traffic WAN to LAN

      fprintf(fp, "-A wan2lan -m state --state INVALID -j LOG_FORWARD_DROP\n");

      fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, lan_ifname);
#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined(IVI_KERNEL_SUPPORT)
      fprintf(fp, "-I FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, ETH_MESH_BRIDGE);
#elif defined(NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
      if (isMAPTReady)
      {
         fprintf(fp, "-I FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, NAT46_INTERFACE);
         fprintf(fp, "-I FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, ETH_MESH_BRIDGE);
      }
#endif //IVI_KERNEL_SUPPORT
#endif //FEATURE_MAPT

#if !defined(_HUB4_PRODUCT_REQ_)
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
      if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
      {
         fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", ecm_wan_ifname, lan_ifname);
         fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", emta_wan_ifname, lan_ifname);
      }
#endif /*_HUB4_PRODUCT_REQ_*/
      if(inf_num!= 0)
	  {
		int cnt =0;
		for(cnt = 0;cnt < inf_num;cnt++)
		{
		      fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, Interface[cnt]);
#ifndef _HUB4_PRODUCT_REQ_
#if defined (_RDKB_GLOBAL_PRODUCT_REQ_)
      if( 0 != strncmp( devicePartnerId, "sky-", 4 ) )
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
      {
		      fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", ecm_wan_ifname, Interface[cnt]);
		      fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", emta_wan_ifname, Interface[cnt]);
      }
#endif
		}
	  }
      //in IPv6, the DMZ and port forwarding just overwrite the wan2lan rule.
      if(isDmzEnabled) {
		  int rc;
          char ipv6host[64] = {'\0'};

          if (!syscfg_get(NULL, "dmz_dst_ip_addrv6", ipv6host, sizeof(ipv6host))) {
			  rc = IsValidIPv6Addr(ipv6host);
			  if(rc != 0){
           #if defined(SPEED_BOOST_SUPPORTED_V6)
           if (speedboostportsv6[0] != '\0' && (isPvDEnable)) {
               fprintf(fp, "-A wan2lan -d %s -p tcp -m multiport ! --dports %s -j ACCEPT\n", ipv6host , speedboostportsv6);
               fprintf(fp, "-A wan2lan -d %s -p udp -m multiport ! --dports %s -j ACCEPT\n", ipv6host , speedboostportsv6);
           }
           else
           #endif
				  fprintf(fp, "-A wan2lan -d %s -j ACCEPT\n", ipv6host);
			  }
			}
		}
        WAN_FAILOVER_SUPPORT_CHECK
        do_single_port_forwarding(NULL, NULL, AF_INET6, fp);
        do_port_range_forwarding(NULL, NULL, AF_INET6, fp);
	WAN_FAILOVER_SUPPORT_CHECk_END

      if (strncasecmp(firewall_levelv6, "High", strlen("High")) == 0)
      {
         fprintf(fp, "-A wan2lan -j RETURN\n");
      }
      else if (strncasecmp(firewall_levelv6, "Medium", strlen("Medium")) == 0)
      {
         fprintf(fp, "-A wan2lan -p tcp --dport 113 -j RETURN\n"); // IDENT
         fprintf(fp, "-A wan2lan -p icmpv6 --icmpv6-type 128 -j RETURN\n"); // ICMP PING

         fprintf(fp, "-A wan2lan -p tcp --dport 1214 -j RETURN\n"); // Kazaa
         fprintf(fp, "-A wan2lan -p udp --dport 1214 -j RETURN\n"); // Kazaa
         fprintf(fp, "-A wan2lan -p tcp --dport 6881:6999 -j RETURN\n"); // Bittorrent
         fprintf(fp, "-A wan2lan -p tcp --dport 6346 -j RETURN\n"); // Gnutella
         fprintf(fp, "-A wan2lan -p udp --dport 6346 -j RETURN\n"); // Gnutella
         fprintf(fp, "-A wan2lan -p tcp --dport 49152:65534 -j RETURN\n"); // Vuze
         fprintf(fp, "-A wan2lan -j ACCEPT\n");
      }
      else if (strncasecmp(firewall_levelv6, "Low", strlen("Low")) == 0)
      {
         fprintf(fp, "-A wan2lan -p tcp --dport 113 -j RETURN\n"); // IDENT
         fprintf(fp, "-A wan2lan -j ACCEPT\n");
      }
      else if (strncasecmp(firewall_levelv6, "Custom", strlen("Custom")) == 0)
      {
         if (isHttpBlockedV6)
         {
            fprintf(fp, "-A wan2lan -p tcp --dport 80 -j RETURN\n"); // HTTP
            fprintf(fp, "-A wan2lan -p tcp --dport 443 -j RETURN\n"); // HTTPS
         }
         if (isIdentBlockedV6)
         {
            fprintf(fp, "-A wan2lan -p tcp --dport 113 -j RETURN\n"); // IDENT
         }
         if (isPingBlockedV6)
         {
            fprintf(fp, "-A wan2lan -p icmpv6 --icmpv6-type 128 -j RETURN\n"); // ICMP PING
         }
         if (isP2pBlockedV6)
         {
            fprintf(fp, "-A wan2lan -p tcp --dport 1214 -j RETURN\n"); // Kazaa
            fprintf(fp, "-A wan2lan -p udp --dport 1214 -j RETURN\n"); // Kazaa
            fprintf(fp, "-A wan2lan -p tcp --dport 6881:6999 -j RETURN\n"); // Bittorrent
            fprintf(fp, "-A wan2lan -p tcp --dport 6346 -j RETURN\n"); // Gnutella
            fprintf(fp, "-A wan2lan -p udp --dport 6346 -j RETURN\n"); // Gnutella
            fprintf(fp, "-A wan2lan -p tcp --dport 49152:65534 -j RETURN\n"); // Vuze
         }

         if(isMulticastBlockedV6) {
            fprintf(fp, "-A wan2lan -p 2 -j RETURN\n"); // IGMP
         }

         fprintf(fp, "-A wan2lan -j ACCEPT\n");
      }
      else if (strncasecmp(firewall_levelv6, "None", strlen("None")) == 0)
      {
         fprintf(fp, "-A wan2lan -j ACCEPT\n");
      }

      // Accept TCP return traffic (stateless a la IOS 'established')
      // Useless as this kernel has ip6tables with statefull inspection (see ESTABLISHED above)
      //fprintf(fp, "-A FORWARD -i %s -o %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT\n", wan6_ifname, lan_ifname);
#if 0
      // Accept UDP traffic blindly... to port greater than 1024 in a vain attempt to protect the inside
      fprintf(fp, "-A FORWARD -i %s -o %s -p udp -m udp --dport 1025:65535 -j ACCEPT\n", wan6_ifname, lan_ifname);

      // Accept NTP traffic
      fprintf(fp, "-A FORWARD -i %s -o %s -p udp -m udp --dport 123 -j ACCEPT\n", wan6_ifname, lan_ifname);
#endif

      // Accept blindly ESP/AH/SCTP
      fprintf(fp, "-A FORWARD -i %s -o %s -p esp -j ACCEPT\n", wan6_ifname, lan_ifname);
//temp changes for CBR until brcm fixauthentication Head issue on brlan0 for v6
#if !defined(_CBR_PRODUCT_REQ_) && !defined (_PLATFORM_IPQ_)
      fprintf(fp, "-A FORWARD -i %s -o %s -m ah -j ACCEPT\n", wan6_ifname, lan_ifname);
#endif
      fprintf(fp, "-A FORWARD -i %s -o %s -p 132 -j ACCEPT\n", wan6_ifname, lan_ifname);

      // Everything else is logged and declined
      //fprintf(fp, "-A FORWARD -m limit --limit 10/sec -j REJECT --reject-with icmp6-adm-prohibited\n");
      fprintf(fp, "-A FORWARD -j LOG_FORWARD_DROP\n");

      // Accept everything from localhost
      fprintf(fp, "-A OUTPUT -o lo -j ACCEPT\n");
      // And accept everything anyway as we trust ourself
      fprintf(fp, "-A OUTPUT -j ACCEPT\n");

#if defined(_COSA_BCM_MIPS_)
      fprintf(fp, "-A OUTPUT -m physdev --physdev-in %s -j ACCEPT\n", emta_wan_ifname);
#endif

   }

#if defined(CONFIG_CCSP_VPN_PASSTHROUGH)

    char queryv6[10] = {'\0'};
    if((0 == syscfg_get(NULL, "blockipsec::result", queryv6 , sizeof(queryv6))) && strcmp(queryv6,"DROP") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 500  -j DROP\n");
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 4500  -j DROP\n");
    }
    else if(strcmp(queryv6,"ACCEPT") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 500  -j ACCEPT\n");
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 4500  -j ACCEPT\n");
    }
    char sites_enabled[MAX_QUERY];
    sites_enabled[0] = '\0';
    syscfg_get(NULL, "managedsites_enabled", sites_enabled, sizeof(sites_enabled));
    if (sites_enabled[0] != '\0' && sites_enabled[0] == '0') // managed site list enabled
    {
        queryv6[0] = '\0';

        if((0 == syscfg_get(NULL, "blockssl::result", queryv6, sizeof(queryv6))) && strcmp(queryv6,"DROP") == 0){
            fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 443  -j DROP\n");
            fprintf(fp, "-A lan2wan_misc_ipv6 -p tcp --dport 443  -j DROP\n");
        }
        else if(strcmp(queryv6,"ACCEPT") == 0){
            fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 443  -j ACCEPT\n");
            fprintf(fp, "-A lan2wan_misc_ipv6 -p tcp --dport 443  -j ACCEPT\n");
        }
    }
    queryv6[0] = '\0';

    if((0 == syscfg_get(NULL, "blockl2tp::result", queryv6, sizeof(queryv6))) && strcmp(queryv6,"DROP") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 1701  -j DROP\n");
    }
    else if(strcmp(queryv6,"ACCEPT") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p udp --dport 1701  -j ACCEPT\n");
    }
    queryv6[0] = '\0';

    if((0 == syscfg_get(NULL, "blockpptp::result", queryv6, sizeof(queryv6))) && strcmp(queryv6,"DROP") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p tcp --dport 1723  -j DROP\n");
    }
    else if(strcmp(queryv6,"ACCEPT") == 0){
        fprintf(fp, "-A lan2wan_misc_ipv6 -p tcp --dport 1723  -j ACCEPT\n");
    }
    fprintf(fp, "-I lan2wan -j lan2wan_misc_ipv6\n");
#endif

end_of_ipv6_firewall:

      FIREWALL_DEBUG("Exiting prepare_ipv6_firewall \n");
}

#if defined(CISCO_CONFIG_DHCPV6_PREFIX_DELEGATION) && ! defined(_CBR_PRODUCT_REQ_) 
static int prepare_ipv6_multinet(FILE *fp)
{    
    char active_insts[32] = {0};
    char lan_pd_if[128] = {0};
    char *p = NULL;
    char iface_name[16] = {0};
    //char iface_ipv6addr[48] = {0};
    char buf[64] = {0};

    syscfg_get(NULL, "lan_pd_interfaces", lan_pd_if, sizeof(lan_pd_if));
    if (lan_pd_if[0] == '\0') {
        return -1;
    }

    sysevent_get(sysevent_fd, sysevent_token, "multinet-instances", active_insts, sizeof(active_insts));
    p = strtok(active_insts, " ");

    do {
        snprintf(buf, sizeof(buf), "multinet_%s-name", p);
        sysevent_get(sysevent_fd, sysevent_token, buf, iface_name, sizeof(iface_name));
        if (strcmp(iface_name, lan_ifname) == 0) /*if primary lan, skip*/
            continue;

        if (strstr(lan_pd_if, iface_name)) { /*active interface and also ipv6 enable*/
            /*
            snprintf(buf, sizeof(buf), "ipv6_%s-addr", iface_name);
            sysevent_get(sysevent_fd, sysevent_token, buf, iface_ipv6addr, sizeof(iface_ipv6addr));
            */

            fprintf(fp, "-A INPUT -i %s -j ACCEPT\n", iface_name);
            fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", iface_name, current_wan_ifname);
            fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", iface_name, ecm_wan_ifname);
            fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", current_wan_ifname, iface_name);
            fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", ecm_wan_ifname, iface_name);
        }

    } while ((p = strtok(NULL, " ")) != NULL);

    return 0;

}
#endif

void prepare_hotspot_gre_ipv6_rule(FILE *filter_fp) {
   char fw_rule[MAX_QUERY] = {0};

   FIREWALL_DEBUG("Entering prepare_hotspot_gre_ipv6_rule\n");
   sysevent_get(sysevent_fd, sysevent_token, "gre_ipv6_fw_rule", fw_rule, sizeof(fw_rule));
   if (strlen(fw_rule))
       fprintf(filter_fp, "%s\n", fw_rule);
}

#ifdef MULTILAN_FEATURE
/*
 *  Procedure     : prepare_multinet_prerouting_nat_v6
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv6 firewall rules pertaining to traffic
 *                  which will be evaluated by NAT table before routing
 *  Parameters    :
 *    fp          : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
int prepare_multinet_prerouting_nat_v6 (FILE *fp)
{
   unsigned char *tok;
   unsigned char sysevent_query[MAX_QUERY];
   unsigned char inst_resp[MAX_QUERY];
   unsigned char multinet_ifname[MAX_QUERY];

   inst_resp[0] = 0;
   sysevent_get(sysevent_fd, sysevent_token, "ipv6_active_inst", inst_resp, sizeof(inst_resp));

   tok = strtok(inst_resp, " ");

   if(tok) do {
      snprintf(sysevent_query, sizeof(sysevent_query), "multinet_%s-name", tok);
      multinet_ifname[0] = 0;
      sysevent_get(sysevent_fd, sysevent_token, sysevent_query, multinet_ifname, sizeof(multinet_ifname));

      // Ignoring Primary lan interface.
      if(strcmp(lan_ifname, multinet_ifname) == 0)
         continue;

      // Support blocked devices
      fprintf(fp, "-A PREROUTING -i %s -j prerouting_devices\n", multinet_ifname);

   }while ((tok = strtok(NULL, " ")) != NULL);

   return 0;
}

/*
 *  Procedure     : prepare_multinet_filter_output_v6
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv6 firewall rules pertaining to traffic
 *                  which will be sent from local host to LAN
 *  Parameters    :
 *    fp          : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
int prepare_multinet_filter_output_v6 (FILE *fp)
{
   unsigned char *tok;
   unsigned char sysevent_query[MAX_QUERY];
   unsigned char inst_resp[MAX_QUERY];
   unsigned char multinet_ifname[MAX_QUERY];

   inst_resp[0] = 0;
   sysevent_get(sysevent_fd, sysevent_token, "ipv6_active_inst", inst_resp, sizeof(inst_resp));

   tok = strtok(inst_resp, " ");

   if(tok) do {
      snprintf(sysevent_query, sizeof(sysevent_query), "multinet_%s-name", tok);
      multinet_ifname[0] = 0;
      sysevent_get(sysevent_fd, sysevent_token, sysevent_query, multinet_ifname, sizeof(multinet_ifname));

      // Skip primary LAN instance, it is handled as a special case
      if(strcmp(lan_ifname, multinet_ifname) == 0)
         continue;

      // Allow output towards LAN clients
      fprintf(fp, "-A OUTPUT -o %s -j ACCEPT\n", multinet_ifname);

   }while ((tok = strtok(NULL, " ")) != NULL);

   return 0;
}

/*
 *  Procedure     : prepare_multinet_filter_forward_v6
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv6 firewall rules pertaining to traffic
 *                  which will be either forwarded or received locally
 *  Parameters    :
 *    fp          : An open file to write rules to
 * Return Values  :
 *    0           : Success
 */
int prepare_multinet_filter_forward_v6 (FILE *fp)
{
   unsigned char *tok;
   unsigned char sysevent_query[MAX_QUERY];
   unsigned char inst_resp[MAX_QUERY];
   unsigned char multinet_ifname[MAX_QUERY];
   unsigned char lan_prefix[MAX_QUERY];

   inst_resp[0] = 0;
   sysevent_get(sysevent_fd, sysevent_token, "ipv6_active_inst", inst_resp, sizeof(inst_resp));

   tok = strtok(inst_resp, " ");

   if(tok) do {
      snprintf(sysevent_query, sizeof(sysevent_query), "multinet_%s-name", tok);
      multinet_ifname[0] = 0;
      sysevent_get(sysevent_fd, sysevent_token, sysevent_query, multinet_ifname, sizeof(multinet_ifname));

      // Skip primary LAN instance, it is handled as a special case
      if(strcmp(lan_ifname, multinet_ifname) == 0)
         continue;

      // Query the IPv6 prefix currently allocated to this bridge from sysevent
      snprintf(sysevent_query, sizeof(sysevent_query), "ipv6_%s-prefix", multinet_ifname);
      lan_prefix[0] = 0;
      sysevent_get(sysevent_fd, sysevent_token, sysevent_query, lan_prefix, sizeof(lan_prefix));

      // Allow DHCPv6 from LAN clients
      fprintf(fp, "-A INPUT -i %s -p udp -m udp --dport 547 -m limit --limit 100/sec -j ACCEPT\n", multinet_ifname);

      // Allow echo request and reply
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 128 -j PING_FLOOD\n", multinet_ifname);
      fprintf(fp, "-A INPUT -i %s -p icmpv6 -m icmp6 --icmpv6-type 129 -m limit --limit 10/sec -j ACCEPT\n", multinet_ifname);

      // Allow router solicitation and advertisement
      fprintf(fp, "-A INPUT -s fe80::/64 -d ff02::1/128 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", multinet_ifname);
      fprintf(fp, "-A INPUT -s fe80::/64 -d fe80::/64 ! -i %s -p icmpv6 -m icmp6 --icmpv6-type 134 -m limit --limit 10/sec -j ACCEPT\n", multinet_ifname);
      fprintf(fp, "-A INPUT -s fe80::/64 -i %s -p icmpv6 -m icmp6 --icmpv6-type 133 -m limit --limit 100/sec -j ACCEPT\n", multinet_ifname);

      // Block unicast WAN to LAN traffic from going to this bridge if the destination address is not within this bridge's allocated prefix
      fprintf(fp, "-A FORWARD -i %s -o %s -m pkttype --pkt-type unicast ! -d %s -j LOG_FORWARD_DROP\n", wan6_ifname, multinet_ifname, lan_prefix);
      // Block unicast LAN to WAN traffic from being sent from this bridge if the source address is not within this bridge's allocated prefix
      fprintf(fp, "-A FORWARD -i %s -o %s -m pkttype --pkt-type unicast ! -s %s -j LOG_FORWARD_DROP\n", multinet_ifname, wan6_ifname, lan_prefix);

      // Allow lan2wan and wan2lan traffic
      fprintf(fp, "-A FORWARD -i %s -o %s -j wan2lan\n", wan6_ifname, multinet_ifname);
      fprintf(fp, "-A FORWARD -i %s -o %s -j lan2wan\n", multinet_ifname, wan6_ifname);

      // Added this rule to allow any ipv6 traffic local to the bridge
      fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", multinet_ifname, multinet_ifname);

   }while ((tok = strtok(NULL, " ")) != NULL);

   return 0;
}

#endif

void do_ipv6_UIoverWAN_filter(FILE* fp) {
 FIREWALL_DEBUG("Inside do_ipv6_UIoverWAN_filter \n"); 
 if(strlen(current_wan_ipv6[0]) > 0)
      {
        if(!isDefHttpPortUsed)
            fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 80 -j DROP\n", lan_ifname,(char *)current_wan_ipv6);
        
        if(!isDefHttpPortUsed)
            fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 443 -j DROP\n", lan_ifname,(char *)current_wan_ipv6);
        int rc = 0;
        char buf[16] ;
        memset(buf,0,sizeof(buf));
        rc = syscfg_get(NULL, "mgmt_wan_httpaccess", buf, sizeof(buf));
        if ( rc == 0 && atoi(buf) == 0 )
        {
            memset(buf,0,sizeof(buf));
            rc = syscfg_get(NULL, "mgmt_wan_httpport", buf, sizeof(buf));
            if ( rc == 0 && buf[0] != '\0' )
            {
                fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport %s -j DROP\n", lan_ifname,(char *)current_wan_ipv6,buf);
            }

        }
        memset(buf,0,sizeof(buf));
        rc = syscfg_get(NULL, "mgmt_wan_httpsaccess", buf, sizeof(buf));
        if ( rc == 0 && atoi(buf) == 0 )
        {
            memset(buf,0,sizeof(buf));
            rc = syscfg_get(NULL, "mgmt_wan_httpsport", buf, sizeof(buf));
            if ( rc == 0 && buf[0] != '\0' )
            {
                fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport %s -j DROP\n", lan_ifname,(char *)current_wan_ipv6,buf);
            }

        }
        #ifdef WAN_FAILOVER_SUPPORTED
        /* Blocking UI access on Backup WAN or in case ULA addressing */
         if (0 == checkIfULAEnabled())
         {
            int i ;
            for(i = 0; i < mesh_wan_ipv6_num; i++)
            {
               if(mesh_wan_ipv6addr[i][0] != '\0' )
               {
                  fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 80 -j DROP\n", current_wan_ifname,(char *)mesh_wan_ipv6addr[i]);
                  fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 443 -j DROP\n", current_wan_ifname,(char *)mesh_wan_ipv6addr[i]);
                  fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m tcp --dport 8080 -j DROP\n", current_wan_ifname,(char *)mesh_wan_ipv6addr[i]);
               }
            }
         }
        #endif
      }

        FIREWALL_DEBUG("Exiting do_ipv6_UIoverWAN_filter \n"); 
}
/*-----*/
void do_ipv6_sn_filter(FILE* fp) {
 FIREWALL_DEBUG("Inside do_ipv6_sn_filter \n"); 
    int i;
    char mcastAddrStr[64];
    char ifIpv6AddrKey[64];
    fprintf(fp, "*mangle\n");
    
   fprintf(fp, ":%s - [0:0]\n", "postrouting_qos");
 
   #ifdef RDKB_EXTENDER_ENABLED
      add_if_mss_clamping(fp,AF_INET6);
   #endif

    for (i = 0; i < numifs; ++i) {
        snprintf(ifIpv6AddrKey, sizeof(ifIpv6AddrKey), "ipv6_%s_dhcp_solicNodeAddr", ifnames[i]);
        sysevent_get(sysevent_fd, sysevent_token, ifIpv6AddrKey, mcastAddrStr, sizeof(mcastAddrStr));
        if (mcastAddrStr[0] != '\0')
            fprintf(fp, "-A PREROUTING -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT\n", ifnames[i], mcastAddrStr);
        
        snprintf(ifIpv6AddrKey, sizeof(ifIpv6AddrKey), "ipv6_%s_ll_solicNodeAddr", ifnames[i]);
        sysevent_get(sysevent_fd, sysevent_token, ifIpv6AddrKey, mcastAddrStr, sizeof(mcastAddrStr));
        if (mcastAddrStr[0] != '\0')
            fprintf(fp, "-A PREROUTING -i %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT\n", ifnames[i], mcastAddrStr);
        /* NS Throttling rules for WAN and LAN */
        fprintf(fp, "-A PREROUTING -i %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m limit --limit 20/sec -j ACCEPT\n", ifnames[i]);
        fprintf(fp, "-A PREROUTING -i %s -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j DROP\n", ifnames[i]);
    }

    //RDKB-10248: IPv6 Entries issue in ip neigh show 1. drop the NS
	FILE *fp1;
	char ip[128]="";
	char buf[256]="";
        fp1=fopen("/proc/net/if_inet6", "r");
        if(fp1) {
	   while(fgets(buf, sizeof(buf), fp1)) {
                 if(!strstr(buf, current_wan_ifname))
          	    continue;
        	 if(strlen(buf)<35)
                    continue;
        	 strncpy(ip, "ff02::1:ff", sizeof(ip));
        	 ip[10]=buf[26];  ip[11]=buf[27];  ip[12]=':';  ip[13]=buf[28];  ip[14]=buf[29];  ip[15]=buf[30];  ip[16]=buf[31];  ip[17]=0;
        	 fprintf(fp, "-A PREROUTING -d %s -j ACCEPT\n", ip);
       	   }
           fprintf(fp, "-A PREROUTING -p icmpv6 --icmpv6-type neighbor-solicitation -i %s -d ff02::1:ff00:0/104 -j DROP\n", current_wan_ifname);
           fclose(fp1);
	}
	//RDKB-10248: IPv6 Entries issue in ip neigh show 2. Bring back TOS mirroring 

#if !defined(_PLATFORM_IPQ_)
	prepare_lld_dscp_rules(fp);
	prepare_dscp_rules_to_prioritized_clnt(fp);
	prepare_dscp_rule_for_host_mngt_traffic(fp);
	prepare_xconf_rules(fp);
#endif

#ifdef _COSA_INTEL_XB3_ARM_
        fprintf(fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",current_wan_ifname);
        fprintf(fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",ecm_wan_ifname);
        fprintf(fp, "-A PREROUTING -i %s -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP\n",emta_wan_ifname);
#endif
     FIREWALL_DEBUG("Exiting do_ipv6_sn_filter \n"); 
}

#if defined  (WAN_FAILOVER_SUPPORTED) && !defined(RDKB_EXTENDER_ENABLED)
typedef enum{
    GLOBAL_IPV6 = 0,
    ULA_IPV6
}ipv6_type;

void applyRoutingRules(FILE* fp,ipv6_type type)
{
       FIREWALL_DEBUG("Entering applyRoutingRules, ipv6_type is %d \n" COMMA type);
         char prefix[64] ;
         memset(prefix,0,sizeof(prefix));
         int i ;
         if ( ULA_IPV6 == type)
            sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix_ula", prefix, sizeof(prefix));
         else
            sysevent_get(sysevent_fd, sysevent_token, "ipv6_prefix", prefix, sizeof(prefix));
   if (strlen(prefix) != 0 )
         {
      char *token_pref =NULL;
         token_pref = strtok(prefix,"/");
                  for(i = 0; i < mesh_wan_ipv6_num; i++)
                  {
                  if(mesh_wan_ipv6addr[i][0] != '\0' )
                     {
                           if ( ULA_IPV6 == type)
                              fprintf(fp, "-A PREROUTING -i %s -d %s -j DNAT --to-destination %s1\n",current_wan_ifname,(char *)mesh_wan_ipv6addr[i],token_pref);
                           fprintf(fp, "-A POSTROUTING -o %s -s %s1/64 -j SNAT --to-source %s\n",current_wan_ifname,token_pref,(char *)mesh_wan_ipv6addr[i]);
                     }
                  }
               char cmd[100];
               char out[100];
               char interface_name[32] = {0};
               char *token = NULL; 
               char *pt;
               char pref_rx[16];
               int pref_len = 0;
               errno_t  rc = -1;
               memset(out,0,sizeof(out));
               memset(pref_rx,0,sizeof(pref_rx));
               sysevent_get(sysevent_fd, sysevent_token,"lan_prefix_v6", pref_rx, sizeof(pref_rx));
               syscfg_get(NULL, "IPv6subPrefix", out, sizeof(out));
               pref_len = atoi(pref_rx);
               if(pref_len < 64)
               {
                  if(!strncmp(out,"true",strlen(out)))
                  {
                           memset(out,0,sizeof(out));
                        memset(cmd,0,sizeof(cmd));
                           memset(prefix,0,sizeof(prefix));
                           syscfg_get(NULL, "IPv6_Interface", out, sizeof(out));
                           pt = out;
                           while((token = strtok_r(pt, ",", &pt)))
                           {
                              memset(interface_name,0,sizeof(interface_name));
                              strncpy(interface_name,token,sizeof(interface_name)-1);
                              if ( ULA_IPV6 == type)
                                    rc = sprintf_s(cmd, sizeof(cmd), "%s%s",interface_name,"_ipaddr_v6_ula");
                              else
                                    rc = sprintf_s(cmd, sizeof(cmd), "%s%s",interface_name,"_ipaddr_v6");
                              
               if(rc < EOK)
                              {
                                    ERR_CHK(rc);
                              }
                              memset(prefix,0,sizeof(prefix));
                              sysevent_get(sysevent_fd, sysevent_token, cmd, prefix, sizeof(prefix));
                              token_pref= NULL;
                              if (prefix[0] != '\0' && strlen(prefix) != 0 )
                              {
                                       token_pref = strtok(prefix,"/");
                                       for(i = 0; i < mesh_wan_ipv6_num; i++)
                                       {
                                          if(mesh_wan_ipv6addr[i][0] != '\0' )
                                          {
                                                if ( ULA_IPV6 == type)
                                                      fprintf(fp, "-A PREROUTING -i %s -d %s -j DNAT --to-destination %s1\n",current_wan_ifname,(char *)mesh_wan_ipv6addr[i],token_pref);
                                                fprintf(fp, "-A POSTROUTING -o %s -s %s1/64 -j SNAT --to-source %s\n",current_wan_ifname,token_pref,(char *)mesh_wan_ipv6addr[i]);
                                          }
                                       }
                              }
                           }
                  }
               }
      }
      FIREWALL_DEBUG("Exiting applyRoutingRules \n");
}
#endif

#if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
int checkIfULAEnabled()
{
    // temp check , need to replace with CurrInterface Name or if device is XLE
        char buf[16]={0};
    sysevent_get(sysevent_fd, sysevent_token, "ula_ipv6_enabled", buf, sizeof(buf));
    if ( strlen(buf) != 0 )
    {   
        int ulaIpv6Status = atoi(buf);
        if (ulaIpv6Status)
        {
            return 0 ;
        }
        else
        {
            return -1 ;
        }
    }   
      return -1;
}

void applyIpv6ULARules(FILE* fp)
{
   #if defined  (RDKB_EXTENDER_ENABLED)
      if(strlen(current_wan_ipv6[0]) > 0)
      {
	  FIREWALL_DEBUG("Source natting all traffic on %s interface to %s address\n" COMMA current_wan_ifname COMMA current_wan_ipv6); 
	  fprintf(fp, "-A POSTROUTING -o %s -j MASQUERADE\n",current_wan_ifname);
      }
   #else
      FIREWALL_DEBUG("Applying applyIpv6ULARules \n");
      applyRoutingRules(fp,GLOBAL_IPV6);
      applyRoutingRules(fp,ULA_IPV6);

   #endif
}

void applyHotspotIpv6PostRoutingRules(FILE *fp)
{
    FIREWALL_DEBUG("60736: Entering applyHotspotIpv6PostRoutingRules \n");
    int rc;
    char *pStr = NULL;
    errno_t  safec_rc  = -1;
    char hotspot_wan_ifname[32];
    memset(hotspot_wan_ifname,0,sizeof(hotspot_wan_ifname));
    rc = PSM_VALUE_GET_STRING(PSM_HOTSPOT_WAN_IFNAME, pStr);
    if(rc == CCSP_SUCCESS && pStr != NULL){
        FIREWALL_DEBUG("HotSpot wan interface fetched \n");
        safec_rc = strcpy_s(hotspot_wan_ifname, sizeof(hotspot_wan_ifname),pStr);
        ERR_CHK(safec_rc);
        Ansc_FreeMemory_Callback(pStr);
        pStr = NULL;
    }
    FIREWALL_DEBUG(" line:%d current_wan_ifname:%s  hotspot_wan_ifname %s \n" COMMA __LINE__ COMMA current_wan_ifname COMMA hotspot_wan_ifname);
    memset(current_wan_ip6_addr, 0, sizeof(current_wan_ip6_addr));
    sysevent_get(sysevent_fd, sysevent_token, "tr_brww0_dhcpv6_client_v6addr", current_wan_ip6_addr, sizeof(current_wan_ip6_addr));

    if(strncmp(current_wan_ifname, hotspot_wan_ifname, strlen(current_wan_ifname) ) == 0)
    {
	FIREWALL_DEBUG("Source natting all traffic on %s interface to %s address\n" COMMA current_wan_ifname COMMA current_wan_ip6_addr); 
        fprintf(fp, "-t nat -I POSTROUTING -o %s -j SNAT --to-source %s\n" COMMA current_wan_ifname COMMA current_wan_ip6_addr);
        fprintf(fp, "-A INPUT -s %s -i %s -p ipv6-icmp -m icmp6 --icmpv6-type 133 -m limit --limit 100/sec -j ACCEPT\n" , current_wan_ip6_addr , current_wan_ifname);
    }
    FIREWALL_DEBUG("60736: Exiting applyHotspotIpv6PostRoutingRules \n");
}

#endif 
void do_ipv6_nat_table(FILE* fp)
{
    FIREWALL_DEBUG("Entering do_ipv6_nat_table \n");
    char IPv6[INET6_ADDRSTRLEN] = "0";
    fprintf(fp, "*nat\n");
	fprintf(fp, ":%s - [0:0]\n", "prerouting_devices");
	fprintf(fp, ":%s - [0:0]\n", "prerouting_redirect");

#ifdef WAN_FAILOVER_SUPPORTED
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
      redirect_dns_to_extender(fp,AF_INET6);
#endif //_PLATFORM_RASPBERRYPI_ && _PLATFORM_BANANAPI_R4_
#endif 

#if defined(_WNXL11BWL_PRODUCT_REQ_) 
   proxy_dns(fp,AF_INET6);
#endif

#ifdef MULTILAN_FEATURE
   prepare_multinet_prerouting_nat_v6(fp);
#endif

#ifdef MULTILAN_FEATURE
   prepare_multinet_prerouting_nat_v6(fp);
#endif
/*
#ifdef WAN_FAILOVER_SUPPORTED
   if (0 == checkIfULAEnabled())
   {
         applyIpv6ULARules(fp);
   }
#endif*/
   
   //zqiu: RDKB-7639: block device broken for IPv6
   fprintf(fp, "-A PREROUTING -i %s -j prerouting_devices\n", lan_ifname);  

   memset(IPv6, 0, INET6_ADDRSTRLEN);
   sysevent_get(sysevent_fd, sysevent_token, "lan_ipaddr_v6", IPv6, sizeof(IPv6));

#if defined (_XB6_PRODUCT_REQ_)
   if(rfstatus == 1)
   {
      fprintf(fp, ":%s - [0:0]\n", "prerouting_noRFCP_redirect");
      fprintf(fp, "-I PREROUTING 1 -i %s -j prerouting_noRFCP_redirect\n", lan_ifname);
      fprintf(fp, "-I prerouting_noRFCP_redirect -p udp ! --dport 53 -j DNAT --to-destination [%s]:80\n",IPv6);
      fprintf(fp, "-I prerouting_noRFCP_redirect -p tcp -j DNAT --to-destination [%s]:80\n",IPv6);
      fprintf(fp, "-I prerouting_noRFCP_redirect -i %s -p udp --dport 53 -j DNAT --to-destination [%s]:80\n",lan_ifname, IPv6);   
      fprintf(fp, "-I prerouting_noRFCP_redirect -i %s -p tcp --dport 53 -j DNAT --to-destination [%s]:80\n",lan_ifname, IPv6);
   }
#endif
   // RDKB-25069 - Lan Admin page should able to access from connected clients.
   if (strlen(IPv6) > 0)
   {
       fprintf(fp, "-A prerouting_redirect -i %s -p tcp --dport 80 -d %s -j DNAT --to-destination %s\n",lan_ifname,IPv6,IPv6);
       fprintf(fp, "-A prerouting_redirect -i %s -p tcp --dport 443 -d %s -j DNAT --to-destination %s\n",lan_ifname,IPv6,IPv6);
   }

   if ((lan_local_ipv6_num == 1) && strlen(lan_local_ipv6[0]) > 0)
   {
       fprintf(fp, "-A prerouting_redirect -i %s -p tcp --dport 80 -d %s -j DNAT --to-destination %s\n",lan_ifname,lan_local_ipv6[0],lan_local_ipv6[0]);
       fprintf(fp, "-A prerouting_redirect -i %s -p tcp --dport 443 -d %s -j DNAT --to-destination %s\n",lan_ifname,lan_local_ipv6[0],lan_local_ipv6[0]);
   }

   fprintf(fp, "-A prerouting_redirect -p tcp --dport 80 -j DNAT --to-destination [%s]:21515\n",IPv6);
 	
   fprintf(fp, "-A prerouting_redirect -p tcp --dport 443 -j DNAT --to-destination [%s]:21515\n",IPv6);
      
   fprintf(fp, "-A prerouting_redirect -p tcp -j DNAT --to-destination [%s]:21515\n",IPv6);
   fprintf(fp, "-A prerouting_redirect -p udp ! --dport 53 -j DNAT --to-destination [%s]:21515\n",IPv6);
   #if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
   if (0 == checkIfULAEnabled())
   {
         applyIpv6ULARules(fp);
   }
   #endif
   //RDKB-19893
   //Intel Proposed RDKB Generic Bug Fix from XB6 SDK
   if(isDmzEnabled) {
	   int rc;
       char ipv6host[64] = {'\0'};
	   
       if (!syscfg_get(NULL, "dmz_dst_ip_addrv6", ipv6host, sizeof(ipv6host))) {
			rc = IsValidIPv6Addr(ipv6host);
			  if(rc != 0 && strlen(current_wan_ipv6[0]) > 0) {
           #if defined(SPEED_BOOST_SUPPORTED_V6)
           if (speedboostportsv6[0] != '\0' && (isPvDEnable)) {
              fprintf(fp, "-A PREROUTING -i %s -d %s -p tcp -m multiport ! --dports %s -j DNAT --to-destination %s \n", wan6_ifname, (char *)current_wan_ipv6, speedboostportsv6 , ipv6host);
              fprintf(fp, "-A PREROUTING -i %s -d %s -p udp -m multiport ! --dports %s -j DNAT --to-destination %s \n", wan6_ifname, (char *)current_wan_ipv6, speedboostportsv6 , ipv6host);
           }
           else
           #endif
				  fprintf(fp, "-A PREROUTING -i %s -d %s -j DNAT --to-destination %s \n", wan6_ifname, (char *)current_wan_ipv6, ipv6host);
			}
		}
   }
#ifdef _PLATFORM_RASPBERRYPI_
   fprintf(fp, "-A POSTROUTING -o %s -j MASQUERADE\n", current_wan_ifname);
#endif

#ifdef _PLATFORM_BANANAPI_R4_
   fprintf(fp, "-A POSTROUTING -o %s -j MASQUERADE\n", current_wan_ifname);
#endif

   #if defined  (WAN_FAILOVER_SUPPORTED)
   if (0 == checkIfULAEnabled())
   {
       applyHotspotIpv6PostRoutingRules(fp);
   }
   #endif
    FIREWALL_DEBUG("Exiting do_ipv6_nat_table \n");
}

void getIpv6Interfaces(char Interface[MAX_NO_IPV6_INF][MAX_LEN_IPV6_INF],int *len)
{
char *token = NULL;char *pt;
char buf[MAX_BUFF_LEN];

char str[MAX_BUFF_LEN],prefixlen[MAX_BUFF_LEN];
int i =0, ret;
errno_t safec_rc = -1;
 FIREWALL_DEBUG("Inside getIpv6Interfaces \n");
          ret = syscfg_get(NULL, "IPv6subPrefix", buf, sizeof(buf));
          if(ret == 0)
		{
			if(!strncmp(buf,"true",4))
			{
				sysevent_get(sysevent_fd, sysevent_token, "lan_prefix_v6", prefixlen, sizeof(prefixlen));
     				if ( '\0' != prefixlen[0] ) 
				{
					if(atoi(prefixlen) < 64)
					{
						 syscfg_get(NULL, "IPv6_Interface", str, sizeof(str));
					}
					else
					{
						*len = 0;
						return;
					}
						
				}
            			#if defined  (WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
               			else if (0 == checkIfULAEnabled())
               			{
                  			syscfg_get(NULL, "IPv6_Interface", str, sizeof(str));
               			}
            			#endif
			}
			else
			{
				*len = 0;
				return;
			}
		}
		else
			{
				*len = 0;
				return;
			}

    pt = str;

    while((token = strtok_r(pt, ",", &pt))) {
	safec_rc = strcpy_s(Interface[i], MAX_LEN_IPV6_INF,token);
	ERR_CHK(safec_rc);
	i++;
	if(i > MAX_NO_IPV6_INF)
	break;
   }
*len = i;
}

/*
 * Function to add IP Table rules regarding Fragmented Packets
 */
int do_blockfragippktsv6(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};
    syscfg_get(NULL, V6_BLOCKFRAGIPPKT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        /* Creating New Chain */
        fprintf(fp, "-N FRAG_DROP\n");
        fprintf(fp, "-F FRAG_DROP\n");
        /*Adding rules in new chain */
        fprintf(fp, "-I FORWARD -m frag --fragmore --fragid 0x0:0xffffffff -j FRAG_DROP\n");
        fprintf(fp, "-I INPUT -m frag --fragmore --fragid 0x0:0xffffffff -j FRAG_DROP\n");
        fprintf(fp, "-A FRAG_DROP -j DROP\n");
    }
    return 0;
}

/*
 * Function to add IP Table rules against Ports scanning
 */
int do_portscanprotectv6(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};

    syscfg_get(NULL, V6_PORTSCANPROTECT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        /* Creating New Chain */
        fprintf(fp,"-N %s\n",PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-F %s\n",PORT_SCAN_CHECK_CHAIN);
        /*Adding rules in new chain */
        fprintf(fp,"-A INPUT -j %s\n", PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-A FORWARD -j %s\n", PORT_SCAN_CHECK_CHAIN);
        fprintf(fp,"-A %s -i %s -j RETURN\n", PORT_SCAN_CHECK_CHAIN,current_wan_ifname);
        fprintf(fp,"-A %s -i lo -j RETURN\n", PORT_SCAN_CHECK_CHAIN);
    }
    return 0;
}

/*
 * Function to add IP Table rules against IPV6 Flooding
 */
int do_ipflooddetectv6(FILE *fp)
{
    int enable=0;
    char query[MAX_QUERY]={0};

    syscfg_get(NULL, V6_IPFLOODDETECT, query, sizeof(query));
    if (query[0] != '\0')
    {
        enable = atoi(query);
    }
    if (enable)
    {
        /* Creating New Chain */
        fprintf(fp, "-N DOS\n");
        fprintf(fp, "-N DOS_FWD\n");
        fprintf(fp, "-N DOS_TCP\n");
        fprintf(fp, "-N DOS_UDP\n");
        fprintf(fp, "-N DOS_ICMP\n");
        fprintf(fp, "-N DOS_ICMP_REQUEST\n");
        fprintf(fp, "-N DOS_ICMP_REPLY\n");
        fprintf(fp, "-N DOS_ICMP_OTHER\n");
        fprintf(fp, "-N DOS_DROP\n");

        fprintf(fp, "-F DOS\n");
        fprintf(fp, "-F DOS_FWD\n");
        fprintf(fp, "-F DOS_TCP\n");
        fprintf(fp, "-F DOS_UDP\n");
        fprintf(fp, "-F DOS_ICMP\n");
        fprintf(fp, "-F DOS_ICMP_REQUEST\n");
        fprintf(fp, "-F DOS_ICMP_REPLY\n");
        fprintf(fp, "-F DOS_ICMP_OTHER\n");
        fprintf(fp, "-F DOS_DROP\n");
        /*Adding Rules in new chain */
        fprintf(fp, "-A DOS -i lo -j RETURN\n");
        fprintf(fp, "-A DOS -p tcp --syn -j DOS_TCP\n");
        fprintf(fp, "-A DOS -p udp -m state --state NEW -j DOS_UDP\n");
        fprintf(fp, "-A DOS -p ipv6-icmp -j DOS_ICMP\n");
        fprintf(fp, "-A DOS_TCP -p tcp --syn -m limit --limit 20/s --limit-burst 40 -j RETURN\n");
        fprintf(fp, "-A DOS_TCP -j DOS_DROP\n");
        fprintf(fp, "-A DOS_UDP -p udp -m limit --limit 20/s --limit-burst 40 -j RETURN\n");
        fprintf(fp, "-A DOS_UDP -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_REQUEST\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_REPLY\n");
        fprintf(fp, "-A DOS_ICMP -j DOS_ICMP_OTHER\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -p ipv6-icmp ! --icmpv6-type echo-request -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -m frag --fragmore --fragid 0x0:0xffffffff -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -m frag --fraglast --fragid 0x0:0xffffffff -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REQUEST -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -p ipv6-icmp ! --icmpv6-type echo-reply -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -p ipv6-icmp --icmpv6-type echo-reply -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -m frag --fragmore --fragid 0x0:0xffffffff -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -m frag --fraglast --fragid 0x0:0xffffffff -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_REPLY -j DOS_DROP\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p ipv6-icmp --icmpv6-type echo-request -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p ipv6-icmp --icmpv6-type echo-reply -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -p ipv6-icmp -m limit --limit 5/s --limit-burst 60 -j RETURN\n");
        fprintf(fp, "-A DOS_ICMP_OTHER -j DOS_DROP\n");
        fprintf(fp, "-A DOS_DROP -j DROP\n");
        fprintf(fp, "-A DOS_FWD -j DOS\n");
        fprintf(fp, "-A FORWARD -j DOS_FWD\n");
        fprintf(fp, "-A INPUT -j DOS\n");
    }
    return 0;
}
