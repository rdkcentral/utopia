/*
* If not stated otherwise in this file or this component's Licenses.txt file the
* following copyright and licenses apply:
*
* Copyright 2025 RDK Management
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

#ifdef RDKB_EXTENDER_ENABLED

#include "firewall.h"
#include "firewall_custom.h"

#define DEVICE_RECOVERY_INTERFACE "eth0"
#include<errno.h> 


#define IPV4_TOTAL_HEADER_SIZE 40
#define IPV6_TOTAL_HEADER_SIZE 60

#define MTU_SIZE 1500

extern int  sysevent_fd ;
extern token_t        sysevent_token;

extern char cellular_ifname[32] ;
static char cellular_ipaddr[32] ;

extern char mesh_wan_ifname[32];
static char mesh_wan_ipaddr[32];

extern int mesh_wan_ipv6_num ;
extern char mesh_wan_ipv6addr[IF_IPV6ADDR_MAX][40];

#if 0
int cellular_wan_ipv6_num = 0;
char cellular_wan_ipv6addr[IF_IPV6ADDR_MAX][40];
#endif

#define SYSEVENT_IPV4_MTU_SIZE "ipv4_%s_mtu"

int isExtProfile()
{
      if ( ( EXTENDER_MODE == Get_Device_Mode() ) )
      {
         return 0;
      }
      return -1;
}  

void add_if_mss_clamping(FILE *mangle_fp,int family)
{
   char mtu_event_name[128] = {0}, mtu_val[8] = {0};
   memset(mtu_event_name,0,sizeof(mtu_event_name));
   memset(mtu_val,0,sizeof(mtu_val));
   int iMtuVal=0 ,  mss_clamp_val = 0;
   snprintf(mtu_event_name,sizeof(mtu_event_name),SYSEVENT_IPV4_MTU_SIZE,cellular_ifname);

   sysevent_get(sysevent_fd, sysevent_token, mtu_event_name, mtu_val, sizeof(mtu_val));

   if(mtu_val[0] != '\0' && strlen(mtu_val) != 0 )
   {
      iMtuVal = atoi(mtu_val) ;
      if ( iMtuVal !=0 && iMtuVal != MTU_SIZE )
      {
         if(family == AF_INET)
            mss_clamp_val= iMtuVal - IPV4_TOTAL_HEADER_SIZE ;
         else if (family == AF_INET6)
            mss_clamp_val= iMtuVal - IPV6_TOTAL_HEADER_SIZE ;
         else
            return;

         fprintf(mangle_fp, "add rule ip filter FORWARD oifname %s tcp flags & (syn|rst) == syn counter tcp option maxseg size set %d\n",cellular_ifname,mss_clamp_val); 
         fprintf(mangle_fp, "add rule ip filter POSTROUTING oifname %s tcp flags & (syn|rst) == syn counter tcp option maxseg size set %d\n",cellular_ifname,mss_clamp_val); 
         if ( 0 == isExtProfile())
         {
            fprintf(mangle_fp, "add rule ip filter FORWARD oifname %s tcp flags & (syn|rst) == syn counter tcp option maxseg size set %d\n",mesh_wan_ifname,mss_clamp_val); 
            fprintf(mangle_fp, "add rule ip filter POSTROUTING oifname %s tcp flags & (syn|rst) == syn counter tcp option maxseg size set %d\n",mesh_wan_ifname,mss_clamp_val);      
         }

      }

   }

   return ;
}
/*
 *  Procedure     : prepare_subtables
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules with the table/subtable structure
 *  Parameters    :
 *    raw_fp         : An open file for raw subtables
 *    mangle_fp      : An open file for mangle subtables
 *    nat_fp         : An open file for nat subtables
 *    filter_fp      : An open file for filter subtables
 * Return Values  :
 *    0              : Success
 */

static int prepare_subtables_ext_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering prepare_subtables \n"); 
   
   /*
    * raw
   */
   fprintf(filter_fp, "add table ip raw\n");


   /*
    * mangle
    */
   fprintf(filter_fp, "add table ip mangle\n");


      /*
    * nat
    */
   fprintf(filter_fp, "add table ip nat\n");

      /*
    * filter
    */
   fprintf(filter_fp, "add table ip filter\n");
   fprintf(filter_fp, "add chain ip filter %s { type route hook output priority -150; policy accept; }\n","INPUT");
   fprintf(filter_fp, "add chain ip filter %s { type route hook output priority -150; policy accept; }\n","OUTPUT");
   fprintf(filter_fp, "add chain ip filter %s { type route hook output priority -150; policy accept; }\n","FORWARD");
   fprintf(filter_fp, "add chain ip filter %s\n", "wanattack");
   fprintf(filter_fp, "add chain ip filter %s\n", "xlog_drop_wanattack");
   fprintf(filter_fp, "add chain ip filter %s\n", "xlog_accept_wan2lan");
   fprintf(filter_fp, "add chain ip filter %s\n", "LOG_SSH_DROP");
   fprintf(filter_fp, "add chain ip filter %s\n", "SSH_FILTER");
   return 0;
}  
/*
 *  Procedure     : prepare_ipv4_rule_ex_mode
 *  Purpose       : prepare ipv4 firewall
 *  Parameters    :
 *   raw_fp         : An open file for raw subtables
 *   mangle_fp      : an open file for writing mangle statements
 *   nat_fp         : an open file for writing nat statements
 *   filter_fp      : an open file for writing filter statements
 */
int prepare_ipv4_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering prepare_ipv4_rule_ex_mode \n"); 
   prepare_subtables_ext_mode(raw_fp, mangle_fp, nat_fp, filter_fp);

   fprintf(nat_fp, "add rule ip nat POSTROUTING oifname %s counter masquerade\n",cellular_ifname);

   add_if_mss_clamping(mangle_fp,AF_INET);
   if (strlen(mesh_wan_ipaddr) != 0 )
   {
      fprintf(nat_fp, "add rule ip nat PREROUTING iifname %s udp dport 53 counter dnat to %s\n",mesh_wan_ifname,mesh_wan_ipaddr);
      fprintf(nat_fp, "add rule ip nat PREROUTING iifname %s tcp dport 53 counter dnat to %s\n",mesh_wan_ifname,mesh_wan_ipaddr);      
   }

   fprintf(filter_fp, "add rule ip filter INPUT iifname lo udp dport 53 counter drop \n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname lo tcp dport 53 counter drop \n");

   fprintf(filter_fp, "add rule ip filter INPUT iifname %s counter jump wanattack\n", cellular_ifname);

   do_wan2self_attack(filter_fp,cellular_ipaddr);

   fprintf(filter_fp, "add rule ip filter INPUT iifname %s tcp dport 22 counter jump SSH_FILTER\n",cellular_ifname);
#if defined(_WNXL11BWL_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_)
   fprintf(filter_fp, "add rule ip filter INPUT iifname brlan112 ip daddr 169.254.70.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname brlan112 pkttype != unicast counter accept\n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname brlan113 ip daddr 169.254.71.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname brlan113 pkttype != unicast counter jump ACCEPT\n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname brebhaul ip daddr 169.254.85.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter INPUT iifname brebhaul pkttype != unicast counter accept\n");
#endif

   do_ssh_IpAccessTable(filter_fp, "22", AF_INET, cellular_ifname);

   fprintf(filter_fp, "add rule ip filter xlog_accept_wan2lan counter accept\n");

   // allow mesh wan and mesh bridge private ip range
   fprintf(filter_fp, "add rule ip filter INPUT ip saddr 192.168.245.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter FORWARD ip saddr 192.168.245.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter OUTPUT ip saddr 192.168.245.0/24 counter accept\n");

   fprintf(filter_fp, "add rule ip filter INPUT ip saddr 192.168.246.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter FORWARD ip saddr 192.168.246.0/24 counter accept\n");
   fprintf(filter_fp, "add rule ip filter OUTPUT ip saddr 192.168.246.0/24 counter accept\n");

   fprintf(filter_fp, "add rule ip filter INPUT iifname %s ip saddr 192.168.1.0/28 counter accept\n",DEVICE_RECOVERY_INTERFACE);
   fprintf(filter_fp, "add rule ip filter OUTPUT oifname %s ip saddr 192.168.1.0/28 counter accept\n",DEVICE_RECOVERY_INTERFACE);

// Dropping packets from private ip range 
   fprintf(filter_fp, "add rule ip filter INPUT ip saddr 10.0.0.0/8 counter drop\n");
   fprintf(filter_fp, "add rule ip filter FORWARD ip saddr 10.0.0.0/8 counter drop\n");
   fprintf(filter_fp, "add rule ip filter OUTPUT ip saddr 10.0.0.0/8 counter drop\n");

   fprintf(filter_fp, "add rule ip filter INPUT ip saddr 192.168.0.0/16 counter drop\n");
   fprintf(filter_fp, "add rule ip filter FORWARD ip saddr 192.168.0.0/16 counter drop\n");
   fprintf(filter_fp, "add rule ip filter OUTPUT ip saddr 192.168.0.0/16 counter drop\n");

   for (int i=16;i<=31 ;i++)
   {
      fprintf(filter_fp, "add rule ip filter INPUT ip saddr 172.%d.0.0/16 counter drop\n",i);
      fprintf(filter_fp, "add rule ip filter FORWARD ip saddr 172.%d.0.0/16 counter drop\n",i);
      fprintf(filter_fp, "add rule ip filter OUTPUT ip saddr 172.%d.0.0/16 counter drop\n",i);
   }

   fprintf(filter_fp, "add rule ip filter FORWARD iifname %s oifname %s counter accept\n",mesh_wan_ifname,cellular_ifname);
   fprintf(filter_fp, "add rule ip filter FORWARD iifname %s oifname %s counter accept\n",cellular_ifname,mesh_wan_ifname);

 //  do_logs(filter_fp);

   fprintf(filter_fp, "insert rule ip filter FORWARD oifname %s ct state invalid  counter drop\n",cellular_ifname);

   FIREWALL_DEBUG("Exiting prepare_enabled_ipv4_firewall \n"); 

   return 0;
}

int filter_ipv6_icmp_limit_rules(FILE *fp)
{
      FIREWALL_DEBUG("Entering filter_ipv6_icmp_limit_rules \n"); 


      // Should include --limit 10/second for most of ICMP
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type 1/0 limit rate 10/second burst 5 packets counter accept\n"); // No route
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type packet-too-big limit rate 10/second burst 5 packets counter accept\n"); // Packet too big
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type time-exceeded limit rate 10/second burst 5 packets counter accept\n"); // Time exceeded
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type 4/1 limit rate 10/second burst 5 packets counter accept\n"); // Unknown header type
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type 4/2 limit rate 10/second burst 5 packets counter accept\n"); // Unknown option

      fprintf(fp, "add rule ip6 filter INPUT iifname %s meta l4proto ipv6-icmp icmpv6 type echo-request counter jump PING_FLOOD\n", cellular_ifname); // Echo request
      fprintf(fp, "add rule ip6 filter INPUT iifname %s meta l4proto ipv6-icmp icmpv6 type echo-reply limit rate 10/second burst 5 packets counter accept\n", cellular_ifname); // Echo reply

      // Should only come from LINK LOCAL addresses, rate limited except 100/second for NA/NS and RS
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit limit rate 100/second burst 5 packets counter accept\n"); // Allow NS from any type source address
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert limit rate 100/second burst 5 packets counter accept\n"); // NA

      // But can also come from UNSPECIFIED addresses, rate limited 100/second for NS (for DAD) and MLD
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit limit rate 100/second burst 5 packets counter accept\n"); // NS
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp icmpv6 type 143 limit rate 100/second burst 5 packets counter accept\n"); // MLD

      // IPV6 Multicast traffic
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 130 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 131 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 132 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 143 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 151 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type 152 limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter INPUT meta l4proto ipv6-icmp ip6 saddr fe80::/64 icmpv6 type  153 limit rate 10/second burst 5 packets counter accept\n");

      // ICMP varies and are rate limited anyway
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type destination-unreachable limit rate 100/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type packet-too-big limit rate 100/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type time-exceeded limit rate 100/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type parameter-problem limit rate 100/second burst 5 packets counter accept\n");


      // ICMP messages for MIPv6 (assuming mobile node on the inside)
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type 145 limit rate 100/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter FORWARD meta l4proto ipv6-icmp icmpv6 type 147 limit rate 100/second burst 5 packets counter accept\n");

      fprintf(fp, "add rule ip6 filter PING_FLOOD limit rate 10/second burst 5 packets counter accept\n");
      fprintf(fp, "add rule ip6 filter PING_FLOOD counter drop\n");

      FIREWALL_DEBUG("Exiting filter_ipv6_icmp_limit_rules \n"); 

      return 0;
}
/*

 *  Procedure     : prepare_ipv6_rule_ex_mode
 *  Purpose       : prepare ipv4 firewall
 *  Parameters    :
 *   raw_fp         : An open file for raw subtables
 *   mangle_fp      : an open file for writing mangle statements
 *   nat_fp         : an open file for writing nat statements
 *   filter_fp      : an open file for writing filter statements
 * */
int prepare_ipv6_rule_ex_mode(FILE *raw_fp, FILE *mangle_fp, FILE *nat_fp, FILE *filter_fp)
{
   FIREWALL_DEBUG("Entering prepare_ipv4_rule_ex_mode \n"); 
 //  prepare_subtables_ext_mode(raw_fp, mangle_fp, nat_fp, filter_fp);

   /*
    * raw
   */
   fprintf(filter_fp, "add table ip6 raw\n");


   /*
    * mangle
    */
   fprintf(filter_fp, "add table ip6 mangle\n");


      /*
    * nat
    */
   fprintf(filter_fp, "add table ip6 nat\n");

      /*
    * filter
    */

   add_if_mss_clamping(mangle_fp,AF_INET6);

   int i ;
    for(i = 0; i < mesh_wan_ipv6_num; i++){

      if(mesh_wan_ipv6addr[i][0] != '\0' )
      {
         fprintf(nat_fp, "add rule ip6 nat PREROUTING iifname %s udp dport 53 counter dnat to %s\n",mesh_wan_ifname,mesh_wan_ipv6addr[i]);
         fprintf(nat_fp, "add rule ip6 nat PREROUTING iifname %s tcp dport 53 counter dnat to %s\n",mesh_wan_ifname,mesh_wan_ipv6addr[i]);  
      }
    }

   #if 0
   memset(cellular_wan_ipv6addr,0,sizeof(cellular_wan_ipv6addr));
   get_ip6address(cellular_ifname, cellular_wan_ipv6addr, &cellular_wan_ipv6_num,IPV6_ADDR_SCOPE_GLOBAL);
   #endif

   fprintf(nat_fp, "add rule ip6 nat POSTROUTING oifname %s counter masquerade\n",cellular_ifname);
   fprintf(filter_fp, "add table ip6 filter\n");
   fprintf(filter_fp, "add chain ip6 filter %s\n", "LOG_SSH_DROP");
   fprintf(filter_fp, "add chain ip6 filter %s\n", "SSH_FILTER");
   fprintf(filter_fp, "add chain ip6 filter %s\n", "PING_FLOOD");

   fprintf(filter_fp, "add rule ip6 filter INPUT iifname lo udp dport 53 counter drop\n");
   fprintf(filter_fp, "add rule ip6 filter INPUT iifname lo tcp dport 53 counter drop\n");
   
   fprintf(filter_fp, "add rule ip6 filter INPUT iifname %s tcp dport 22 counter jump SSH_FILTER\n",cellular_ifname);

   filter_ipv6_icmp_limit_rules(filter_fp);
   do_ssh_IpAccessTable(filter_fp, "22", AF_INET6, cellular_ifname);

   fprintf(filter_fp, "add rule ip6 filter FORWARD iifname %s oifname %s counter accept\n",mesh_wan_ifname,cellular_ifname);
   fprintf(filter_fp, "add rule ip6 filter FORWARD iifname %s oifname %s counter accept\n",cellular_ifname,mesh_wan_ifname);
   fprintf(filter_fp, "insert rule ip6 filter FORWARD oifname %s ct state invalid  counter drop\n",cellular_ifname);

   return 0;
}

/*
 * Name           :  service_start_ext_mode
 * Purpose        :  Start firewall service on extender 
 * Parameters     :
 *    None        :
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int service_start_ext_mode ()
{
   char *filename1 = "/tmp/.nft_ext";
   char *filename2 = "/tmp/.nft_v6_ext";

   memset(cellular_ipaddr,0,sizeof(cellular_ipaddr));
   memset(mesh_wan_ipaddr,0,sizeof(mesh_wan_ipaddr));
   
   errno_t safec_rc = -1;

   safec_rc = strcpy_s(mesh_wan_ipaddr, sizeof(mesh_wan_ipaddr),get_iface_ipaddr(mesh_wan_ifname));
   ERR_CHK(safec_rc);

   safec_rc = strcpy_s(cellular_ipaddr, sizeof(cellular_ipaddr),get_iface_ipaddr(cellular_ifname));
   ERR_CHK(safec_rc);


   //pthread_mutex_lock(&firewall_check);
   FIREWALL_DEBUG("Inside firewall service_start()\n");

   /*  ipv4 */
   prepare_ipv4_firewall(filename1);
   v_secure_system("nft -f /tmp/.ipt_ext 2> /tmp/.nftv4table_ext_error");


   prepare_ipv6_firewall(filename2);
   v_secure_system("nft -f /tmp/.nft_v6 2> /tmp/.nftv6table_ext_error");

   FIREWALL_DEBUG("Exiting firewall service_start()\n");
    return 0;
}

#endif
