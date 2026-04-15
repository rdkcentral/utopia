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

#include "firewall.h"

/**
 * @brief Validate if a port number string is valid.
 *
 * @param[in] port_num - Pointer to the port number string.
 *
 * @return The status of the operation.
 * @retval 0 if port is valid (1-65535).
 * @retval -1 if port is invalid.
 */
int validate_port(const char* port_num)
{
    int port = atoi(port_num);
    if (port <= 0 || port > MAX_PORT)
        return -1;
    return 0;
}

/**
 * @brief Apply SSL blocking rules based on managed sites/services configuration.
 *
 * Checks if managed sites or managed services (with port 443) are enabled,
 * and emits appropriate SSL blocking (DROP/ACCEPT) rules for port 443.
 * Rules are skipped per protocol if managed services already covers that
 * protocol on port 443.
 *
 *
 * @param[in] fp         - Pointer to the FILE stream for writing firewall rules.
 * @param[in] chain_name - The iptables chain name (e.g., "lan2wan_misc" or "lan2wan_misc_ipv6").
 */
void do_ssl_blocking_rules(FILE *fp, const char *chain_name)
{
    int ms_has_tcp_443 = 0;
    int ms_has_udp_443 = 0;
    char sites_enabled[MAX_QUERY] = {0};
    char services_enabled[MAX_QUERY] = {0};

    syscfg_get(NULL, "managedsites_enabled", sites_enabled, sizeof(sites_enabled));

    /* If managed sites is enabled, skip SSL blocking entirely */
    if (sites_enabled[0] != '\0' && sites_enabled[0] != '0') {
        ms_has_tcp_443 = 1;
        ms_has_udp_443 = 1;
    } else {
        /* Check managed services for port 443 */
        syscfg_get(NULL, "managedservices_enabled", services_enabled, sizeof(services_enabled));
        if (services_enabled[0] != '\0' && services_enabled[0] != '0') {
            char ms_count_str[MAX_QUERY] = {0};
            int ms_count = 0;
            syscfg_get(NULL, "ManagedServiceBlockCount", ms_count_str, sizeof(ms_count_str));
            if (ms_count_str[0] != '\0') {
                ms_count = atoi(ms_count_str);
            }
            if (ms_count < 0) {
                ms_count = 0;
            } else if (ms_count > MAX_SYSCFG_ENTRIES) {
                ms_count = MAX_SYSCFG_ENTRIES;
            }
            for (int i = 1; i <= ms_count && !(ms_has_tcp_443 && ms_has_udp_443); i++) {
                char ns[MAX_QUERY], prot[10];
                char ms_namespace_key[MAX_QUERY];

                snprintf(ms_namespace_key, sizeof(ms_namespace_key), "ManagedServiceBlock_%d", i);
                syscfg_get(NULL, ms_namespace_key, ns, sizeof(ns));
                if (ns[0] == '\0')
                    continue;

                /* Get protocol to check if we can skip this entry */
                syscfg_get(ns, "proto", prot, sizeof(prot));

                /* Skip if this protocol is already covered */
                if ((strncasecmp("tcp", prot, 3) == 0 && ms_has_tcp_443) ||
                    (strncasecmp("udp", prot, 3) == 0 && ms_has_udp_443)) {
                    continue;
                }

                /* Check port range */
                char start_port[16], end_port[16];
                syscfg_get(ns, "start_port", start_port, sizeof(start_port));
                if (start_port[0] == '\0' || validate_port(start_port) != 0) {
                    continue;
                }
                syscfg_get(ns, "end_port", end_port, sizeof(end_port));
                if (end_port[0] == '\0' || validate_port(end_port) != 0) {
                    continue;
                }

                int sp = atoi(start_port);
                int ep = atoi(end_port);
                if (sp > 443 || ep < 443) continue;  /* Port 443 not in range */

                /* Set flags based on protocol */
                if (prot[0] == '\0' || strncasecmp("both", prot, 4) == 0) {
                    ms_has_tcp_443 = ms_has_udp_443 = 1;
                    break;
                } else if (strncasecmp("tcp", prot, 3) == 0) {
                    ms_has_tcp_443 = 1;
                } else if (strncasecmp("udp", prot, 3) == 0) {
                    ms_has_udp_443 = 1;
                }
            }
        }
    }

    /* Emit SSL blocking rules for protocols not covered by managed services */
    if (!(ms_has_tcp_443 && ms_has_udp_443)) {
        char query[MAX_QUERY] = {0};
        if (0 == syscfg_get(NULL, "blockssl::result", query, sizeof(query))) {
            if (strcmp(query, "DROP") == 0 || strcmp(query, "ACCEPT") == 0) {
                if (!ms_has_udp_443) {
                    fprintf(fp, "-A %s -p udp --dport 443  -j %s\n", chain_name, query);
                }
                if (!ms_has_tcp_443) {
                    fprintf(fp, "-A %s -p tcp --dport 443  -j %s\n", chain_name, query);
                }
            }
        }
    }
}
