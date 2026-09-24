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
 * Custom Functions
 */
#include <stdio.h>
#include "firewall_custom.h"

void do_device_based_pp_disabled_appendrule(FILE *fp, const char *ins_num, const char *lan_ifname, const char *query)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
    fprintf(fp, "add chain ip filter pp_disabled_%s\n", ins_num);
    fprintf(fp, "add rule ip filter pp_disabled jump pp_disabled_%s\n", ins_num);
    fprintf(fp, "add rule ip filter pp_disabled iifname %s ether saddr %s tcp dport { 80, 443 } ct state established connbytes 0-5 packets counter jump GWMETA comment \"dis-pp\"\n", lan_ifname, query);
#endif
}

void do_device_based_pp_disabled_ip_appendrule(FILE *fp, const char *ins_num, const char *ipAddr)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
    fprintf(fp, "add rule ip filter pp_disabled_%s dst %s tcp sport { 80, 443 } ct state established connbytes 0-5 packets counter jump GWMETA comment \"dis-pp\"\n", ins_num, ipAddr);
#endif
}

int do_parcon_mgmt_lan2wan_pc_site_appendrule(FILE *fp)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
fprintf(fp, "add rule ip filter lan2wan_pc_site tcp dport { 80, 443, 8080 } ct state established connbytes 0-5 packets counter jump GWMETA comment \"dis-pp\"\n");
#endif
	return 1;
}

void do_parcon_mgmt_lan2wan_pc_site_insertrule(FILE *fp, int index, char *nstdPort)
{
#if !defined(_PLATFORM_RASPBERRYPI_)
fprintf(fp, "insert rule ip filter lan2wan_pc_site %d tcp dport %s ct state established connbytes 0-5 packets counter jump GWMETA comment \"dis-pp\"\n", index, nstdPort);
#endif
}

