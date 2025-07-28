/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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
 * Copyright 2023 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
**********************************************************************/
#ifndef _APPLY_SYSTEM_DEFAULTS_HELPER_H_ 
#define _APPLY_SYSTEM_DEFAULTS_HELPER_H_

#define APPLY_DEFAULTS_FACTORY_RESET  "/tmp/.apply_defaults_factory_reset"

int get_PartnerID( char *PartnerID);
int parse_command_line(int argc, char **argv);
int set_defaults(void);
int set_syscfg_partner_values (char *pValue, char *param);
int compare_partner_json_param (char *partner_nvram_bs_obj, char *partner_etc_obj, char *PartnerID);
int apply_partnerId_default_values (char *data, char *PartnerID);
char *json_file_parse (char *path);
int init_bootstrap_json (char *partner_nvram_obj, char *partner_etc_obj, char *PartnerID);
void getPartnerIdWithRetry(char* buf, char* PartnerID);
/* Function - dbus initialization  */
int dbusInit(void);
/* Function - PSM SET API*/
int set_psm_record(char *name,char *str);

#endif /* _APPLY_SYSTEM_DEFAULTS_HELPER_H_ */
