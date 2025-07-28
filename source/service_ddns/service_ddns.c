/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include "syscfg/syscfg.h"
#include "sysevent/sysevent.h"
#include "util.h"

#define PROG_NAME "SERVICE-DDNS"
#define TRACE_FILE "/tmp/ddns-general.trace"
// #define DEBUG 1

enum ddns_client_status
{
    CLIENT_CONNECTING = 1,
    CLIENT_AUTHENTICATING = 2,
    CLIENT_UPDATED = 3,
    CLIENT_ERROR_MISCONFIGURED = 4,
    CLIENT_ERROR = 5,
    CLIENT_DISABLED = 6,
};

enum ddns_client_lasterror
{
    NO_ERROR = 1,
    MISCONFIGURATION_ERROR = 2,
    DNS_ERROR = 3,
    CONNECTION_ERROR = 4,
    AUTHENTICATION_ERROR = 5,
    TIMEOUT_ERROR = 6,
    PROTOCOL_ERROR = 7,
};

enum ddns_hostname_status
{
    HOST_REGISTERED = 1,
    HOST_UPDATE_NEEDED = 2,
    HOST_UPDATING = 3,
    HOST_ERROR = 4,
    HOST_DISABLED = 5,
};

enum ddns_client_connection
{
    SUCCESS = 1,
    FAILURE = 2,
};

struct ddns_server
{
    char name[16];
    int enable;
    int syscfg_index;
    int array_index;
    int retry_interval;
    int check_interval;
    int max_retries;
};

struct ddns_client
{
    int  enable;
    char username[64];
    char password[64];
    char connection_msg[16];
    enum ddns_client_connection  connection_status;
    enum ddns_client_status status;
    enum ddns_client_lasterror lasterror;
};

struct ddns_hostname
{
    int enable;
    char name[64];
    enum ddns_hostname_status status;
};

struct wan_config
{
    char wan_ipaddr[24];
    int  dslite_enable;
};

struct serv_ddns
{
    int sefd;
    token_t setok;
    int ddns_enable;
    long last_updated_time;
    int retry_enable;
    int max_retry_count;
    struct wan_config  wan_conf;
    struct ddns_server server;
    struct ddns_client client;
    struct ddns_hostname hostname;
};

struct cmd_op
{
    const char *cmd;
    int (*exec)(struct serv_ddns *sdd);
    const char *desc;
};

/* This enum and supported_servers array are in one-to-one mapping */
enum
{
    CHANGEIP = 0,
    NOIP,
    DYNDNS,
    DUCKDNS,
    AFRAID,
    SERVICE_LIMIT
};

static char *supported_servers[][8] = {
    // name, register success, update success, hostname error, username error, password error, general error, token error
    {"changeip", "Successful Update", "Successful Update", "Hostname pattern does not exist", "badauth", "badauth", "", ""},
    {"no-ip", "good", "nochg", "nohost", "badauth", "badauth", "", ""},
    {"dyndns", "good", "nochg", "nohost", "badauth", "badauth", "", ""},
    {"duckdns", "OK", "", "", "", "", "KO", ""},
    {"afraid", "Updated", "has not changed", "", "", "", "Unable to locate this record", ""},
};

static int ddns_update_server(struct serv_ddns *sdd);
static int ddns_update_server_if_needed(struct serv_ddns *sdd);
static int ddns_check_interval(struct serv_ddns *sdd);
static int ddns_retry_interval(struct serv_ddns *sdd);

static const struct cmd_op cmd_ops[] = {
    {"restart",    ddns_update_server, "restart service ddns"},
    {"wan-status", ddns_update_server_if_needed, "restart service ddns if wan-status changes"},
    {"current_wan_ipaddr", ddns_update_server_if_needed, "restart service ddns if current wan IP address changes"},
    {"ddns-check", ddns_check_interval, "restart service ddns based on based on check interval param"},
    {"ddns-retry", ddns_retry_interval, "restart service ddns based on retry interval param "},
};

static void add_ddns_retryinterval_to_cron(struct serv_ddns *sdd)
{
    int quotient, modulus;
    char buff[256];
    FILE *cron_fp;
    FILE *cron_tmp_fp;
    int match = 0;

    if (sdd->server.retry_interval <= 60)
        quotient = 1;
    else if (sdd->server.retry_interval >= 3600)
        quotient = 59;
    else
    {
        modulus = sdd->server.retry_interval % 60;
        quotient = sdd->server.retry_interval / 60;
        if (modulus >= 30)
            quotient += 1;
    }

    cron_fp = fopen("/var/spool/cron/crontabs/root", "a+");
    cron_tmp_fp = fopen("/var/spool/cron/crontabs/ddns_tmp_root", "w");
    if (cron_fp == NULL || cron_tmp_fp == NULL)
    {
        if (cron_fp)
        {
            fclose(cron_fp);
        }
        if (cron_tmp_fp)
        {
            fclose(cron_tmp_fp);
        }
    }
    else
    {
        while (fgets(buff, sizeof(buff), cron_fp))
        {
            if (strstr(buff, "#DDNS_RETRY_INTERVAL"))
            {
                match = 1;
                fprintf(cron_tmp_fp, "*/%d * * * * /usr/bin/service_ddns ddns-retry & #DDNS_RETRY_INTERVAL\n", quotient);
            }
            else
            {
                fprintf(cron_tmp_fp, "%s", buff);
            }
        }
        if(!match)
        {
            fprintf(cron_tmp_fp, "*/%d * * * * /usr/bin/service_ddns ddns-retry & #DDNS_RETRY_INTERVAL\n", quotient);
        }
        fclose(cron_fp);
        fclose(cron_tmp_fp);

        if (rename("/var/spool/cron/crontabs/ddns_tmp_root", "/var/spool/cron/crontabs/root") == -1)
        {
            fprintf(stderr, "%s: rename() call failed. Reason : %s\n", __FUNCTION__, strerror(errno));
        }
        else
        {
            sysevent_set(sdd->sefd, sdd->setok, "crond-restart", "1", 0);
        }
    }
}

static void add_ddns_checkinterval_to_cron(struct serv_ddns *sdd)
{
    FILE *cron_fp;
    FILE *cron_tmp_fp;
    int match = 0;
    char buff[256];

    cron_fp = fopen("/var/spool/cron/crontabs/root", "a+");
    cron_tmp_fp = fopen("/var/spool/cron/crontabs/ddns_tmp_root", "w");
    if (cron_fp == NULL || cron_tmp_fp == NULL)
    {
        if (cron_fp)
        {
            fclose(cron_fp);
        }
        if (cron_tmp_fp)
        {
            fclose(cron_tmp_fp);
        }
    }
    else
    {
        while (fgets(buff, sizeof(buff), cron_fp))
        {
            if (strstr(buff, "#DDNS_CHECK_INTERVAL"))
            {
                match = 1;
                fprintf(cron_tmp_fp, "* * * * * /usr/bin/service_ddns ddns-check & #DDNS_CHECK_INTERVAL\n");
            }
            else
            {
                fprintf(cron_tmp_fp, "%s", buff);
            }
        }
        if(!match)
        {
            fprintf(cron_tmp_fp, "* * * * * /usr/bin/service_ddns ddns-check & #DDNS_CHECK_INTERVAL\n");
        }
        fclose(cron_fp);
        fclose(cron_tmp_fp);

        if (rename("/var/spool/cron/crontabs/ddns_tmp_root", "/var/spool/cron/crontabs/root") == -1)
        {
            fprintf(stderr, "%s: rename() call failed. Reason : %s\n", __FUNCTION__, strerror(errno));
        }
        else
        {
            sysevent_set(sdd->sefd, sdd->setok, "crond-restart", "1", 0);
        }
    }
}

static void serv_ddns_write_status(struct serv_ddns *sdd)
{
    char command[256];
    struct timeval tv;
    time_t t;
    struct tm *info;

#ifdef DEBUG
    fprintf(stdout, "sdd->wan_conf.wan_ipaddr       : %s\n", sdd->wan_conf.wan_ipaddr);
    fprintf(stdout, "sdd->wan_conf.dslite_enable    : %d\n", sdd->wan_conf.dslite_enable);
    fprintf(stdout, "sdd->ddns_enable               : %d\n", sdd->ddns_enable);
    fprintf(stdout, "sdd->server.enable             : %d\n", sdd->server.enable);
    fprintf(stdout, "sdd->server.name               : %s\n", sdd->server.name);
    fprintf(stdout, "sdd->server.array_index        : %d\n", sdd->server.array_index);
    fprintf(stdout, "sdd->server.syscfg_index       : %d\n", sdd->server.syscfg_index);
    fprintf(stdout, "sdd->server.retry_interval     : %d\n", sdd->server.retry_interval);
    fprintf(stdout, "sdd->server.check_interval     : %d\n", sdd->server.check_interval);
    fprintf(stdout, "sdd->server.max_retries        : %d\n", sdd->server.max_retries);
    fprintf(stdout, "sdd->client.enable             : %d\n", sdd->client.enable);
    fprintf(stdout, "sdd->client.username           : %s\n", sdd->client.username);
    fprintf(stdout, "sdd->client.password           : %s\n", sdd->client.password);
    fprintf(stdout, "sdd->client.status             : %d\n", sdd->client.status);
    fprintf(stdout, "sdd->client.lasterror          : %d\n", sdd->client.lasterror);
    fprintf(stdout, "sdd->client.connection_status  : %d\n", sdd->client.connection_status);
    fprintf(stdout, "sdd->client.connection_msg     : %s\n", sdd->client.connection_msg);;
    fprintf(stdout, "sdd->hostname.enable           : %d\n", sdd->hostname.enable);
    fprintf(stdout, "sdd->hostname.name             : %s\n", sdd->hostname.name);
    fprintf(stdout, "sdd->hostname.status           : %d\n", sdd->hostname.status);
#endif


    syscfg_set_u(NULL, "ddns_client_Status", sdd->client.status);
    syscfg_set_u(NULL, "ddns_client_Lasterror", sdd->client.lasterror);
    syscfg_set_u(NULL, "ddns_host_status_1", sdd->hostname.status);

    snprintf(command, sizeof(command), "ddns_return_status%d", sdd->server.syscfg_index);
    sysevent_set(sdd->sefd, sdd->setok, command, sdd->client.connection_msg, 0);
    sysevent_set(sdd->sefd, sdd->setok, "ddns_return_status", sdd->client.connection_msg, 0);

    gettimeofday(&tv, NULL);
    t = tv.tv_sec;
    info = localtime(&t);
    strftime(command, sizeof(command), "%Y-%m-%d %H:%M:%S", info);   // format : 2024-10-11T14:00:20Z

    if(sdd->client.connection_status == SUCCESS)
    {

        sysevent_set(sdd->sefd, sdd->setok, "ddns_failure_time", "0", 0);
        syscfg_set(NULL, "ddns_host_lastupdate_1", command);
        snprintf(command, sizeof(command), "%ld", tv.tv_sec);
        sysevent_set(sdd->sefd, sdd->setok, "ddns_updated_time", command, 0);
    }
    else
    {
        sysevent_set(sdd->sefd, sdd->setok, "ddns_failure_time", command, 0);
        sysevent_set(sdd->sefd, sdd->setok, "ddns_updated_time", "0", 0);
    }
}

static int serv_ddns_init(struct serv_ddns *sdd)
{
    char command[256];
    int ret = 0;

    sdd->client.status = CLIENT_ERROR;
    sdd->client.lasterror = DNS_ERROR;
    sdd->hostname.status = HOST_ERROR;

    if ((sdd->sefd = sysevent_open(SE_SERV, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, PROG_NAME, &sdd->setok)) < 0)
    {
        return -1;
    }

    strcpy(sdd->wan_conf.wan_ipaddr, "0.0.0.0");
    sysevent_get(sdd->sefd, sdd->setok, "current_wan_ipaddr", sdd->wan_conf.wan_ipaddr, sizeof(sdd->wan_conf.wan_ipaddr));
    if (strcmp(sdd->wan_conf.wan_ipaddr, "0.0.0.0") == 0)
    {
        fprintf(stderr, "%s: FAILED because wan_ipaddr is %s\n", __FUNCTION__, sdd->wan_conf.wan_ipaddr);
        sdd->client.status = CLIENT_DISABLED;
        sdd->client.lasterror = MISCONFIGURATION_ERROR;
        ret = -1;
        goto OUT;
    }

    syscfg_get(NULL, "dslite_enable", command, sizeof(command));
    sdd->wan_conf.dslite_enable = atoi(command);
    syscfg_get(NULL, "dynamic_dns_enable", command, sizeof(command));
    sdd->ddns_enable = atoi(command);
    syscfg_get("arddnsclient_1", "Server", command, sizeof(command));
    sscanf(command, "Device.DynamicDNS.Server.%d", &(sdd->server.syscfg_index));
    snprintf(command, sizeof(command), "ddns_server_enable_%d", sdd->server.syscfg_index);
    syscfg_get(NULL, command, command, sizeof(command));
    sdd->server.enable = atoi(command);
    snprintf(command, sizeof(command), "ddns_server_servicename_%d", sdd->server.syscfg_index);
    syscfg_get(NULL, command, sdd->server.name, sizeof(sdd->server.name));
    syscfg_get("arddnsclient_1", "enable", command, sizeof(command));
    sdd->client.enable = atoi(command);
    syscfg_get(NULL, "ddns_host_enable_1", command, sizeof(command));
    sdd->hostname.enable = atoi(command);
    strncpy(sdd->client.connection_msg, "error", sizeof(sdd->client.connection_msg));

    if (sdd->wan_conf.dslite_enable != 0 || !sdd->ddns_enable || !sdd->server.syscfg_index || !sdd->server.enable || !sdd->client.enable || !sdd->hostname.enable)
    {
        fprintf(stderr, "%s: FAILED because either dslite is enabled or one of ddns param is disabled\n", __FUNCTION__);
        sdd->client.status = CLIENT_DISABLED;
        sdd->client.lasterror = MISCONFIGURATION_ERROR;
        ret = -1;
        goto OUT;
    }

    sdd->server.array_index = -1;
    for (int i = 0; i < SERVICE_LIMIT; i++)
    {
        if (strcmp(sdd->server.name, supported_servers[i][0]) == 0)
        {
            sdd->server.array_index = i;
            break;
        }
    }
    if (sdd->server.array_index == -1)
    {
        fprintf(stderr, "%s: FAILED couldn't find the servername %s in supported_servers array\n", __FUNCTION__, sdd->server.name);
        sdd->client.status = CLIENT_ERROR_MISCONFIGURED;
        sdd->client.lasterror = MISCONFIGURATION_ERROR;
        ret = -1;
        goto OUT;
    }

    snprintf(command, sizeof(command), "ddns_server_checkinterval_%d", sdd->server.syscfg_index);
    syscfg_get(NULL, command, command, sizeof(command));
    sdd->server.check_interval = atoi(command);

OUT:
    if(ret == -1)
        serv_ddns_write_status(sdd);

    return ret;
}

static int serv_ddns_term(struct serv_ddns *sdd)
{
    sysevent_close(sdd->sefd, sdd->setok);
    return 0;
}

static char bin2hex(unsigned int a)
{
    a &= 0x0F;

    if ((a >= 0) && (a <= 9))
        return '0' + a;
    if ((a >= 10) && (a <= 15))
        return 'a' + (a - 10);
}

static void urlencoder(char *d, char *s, size_t n)
{
    char inch;
    int space_available = n - 1;

    // https://www.urlencoder.io/

    while (1)
    {
        if ((inch = *s++) == 0)
            break;

        if ((!((inch >= '0') && (inch <= '9'))) &&
            (!((inch >= 'a') && (inch <= 'z'))) &&
            (!((inch >= 'A') && (inch <= 'Z'))) &&
            (inch != '-') &&
            (inch != '_') &&
            (inch != '.') &&
            (inch != '~'))
        {
            if (space_available < 3)
                break;
            *d++ = '%';
            *d++ = bin2hex(inch >> 4);
            *d++ = bin2hex(inch & 0x0F);
            space_available -= 3;
        }
        else
        {
            if (space_available < 1)
                break;
            *d++ = inch;
            space_available -= 1;
        }
    }

    *d = 0;
}

static int ddns_update_server(struct serv_ddns *sdd)
{
    char buf[64];
    char command[572];
    char *cmd;
    int ret;
    int fd;
    char client_password[64 * 3]; /* raw value from syscfg may expand upto 3x if URL encoded */
    FILE *output_file;

    fd = open("/var/run/updating_ddns_server.txt", O_CREAT, 0644);

    syscfg_set(NULL, "wan_last_ipaddr", sdd->wan_conf.wan_ipaddr);

    if( fd == -1)
    {
        fprintf(stderr, "%s: Unable to create file. Error : %s \n", __FUNCTION__, strerror(errno));
        goto EXIT;
    }
    close(fd);

    syscfg_get("arddnsclient_1", "Username", sdd->client.username, sizeof(sdd->client.username));
    if (sdd->client.username[0] == 0)
    {
        fprintf(stderr, "%s: FAILED because client_username %s\n", __FUNCTION__, "undefined");
        sdd->client.lasterror = AUTHENTICATION_ERROR;
        strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
        goto EXIT;
    }

    syscfg_get(NULL, "ddns_host_name_1", sdd->hostname.name, sizeof(sdd->hostname.name));
    if (sdd->hostname.name[0] == 0)
    {
        fprintf(stderr, "%s: FAILED because hostname %s\n", __FUNCTION__, "undefined");
        goto EXIT;
    }

    /* Read and encode password (except for duckdns, which does not use a password) */
    if (sdd->server.array_index != DUCKDNS)
    {
        syscfg_get("arddnsclient_1", "Password", sdd->client.password, sizeof(sdd->client.password));
        if (sdd->client.password[0] == 0)
        {
            fprintf(stderr, "%s: FAILED client_password %s\n", __FUNCTION__, "undefined");
            sdd->client.lasterror = AUTHENTICATION_ERROR;
            strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            goto EXIT;
        }
        urlencoder(client_password, sdd->client.password, sizeof(client_password));
    }

    /* create the curl command to update IP address */
    cmd = command;
    sprintf(buf, "/var/tmp/ipupdate.%s", sdd->server.name);
    cmd += sprintf(cmd, "/usr/bin/curl --interface erouter0 -o %s ", buf);

    if (sdd->server.array_index == CHANGEIP)
        cmd += sprintf(cmd, "--url 'http://nic.changeip.com/nic/update?u=%s&p=%s&hostname=%s&ip=%s'", sdd->client.username, client_password, sdd->hostname.name, sdd->wan_conf.wan_ipaddr);
    else if (sdd->server.array_index == NOIP)
    {
        char username_encoded[64 * 3]; /* raw value from syscfg may expand upto 3x if URL encoded */
        urlencoder(username_encoded, sdd->client.username, sizeof(username_encoded));
        cmd += sprintf(cmd, "--url 'http://%s:%s@dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s'", username_encoded, client_password, sdd->hostname.name, sdd->wan_conf.wan_ipaddr);
    }
    else if (sdd->server.array_index == DYNDNS)
        cmd += sprintf(cmd, "--user %s:%s --url 'http://members.dyndns.org/nic/update?hostname=%s&myip=%s'", sdd->client.username, client_password, sdd->hostname.name, sdd->wan_conf.wan_ipaddr);
    else if (sdd->server.array_index == DUCKDNS)
        cmd += sprintf(cmd, "-g --insecure --url 'https://www.duckdns.org/update?domains=%s&token=%s&ip=%s&verbose=true'", sdd->hostname.name, sdd->client.username, sdd->wan_conf.wan_ipaddr);
    else if (sdd->server.array_index == AFRAID)
        cmd += sprintf(cmd, "--user %s:%s --insecure --url 'https://freedns.afraid.org/nic/update?hostname=%s&myip=%s'", sdd->client.username, client_password, sdd->hostname.name, sdd->wan_conf.wan_ipaddr);
    else
        goto EXIT;

    cmd += sprintf(cmd, " --trace-ascii %s >/dev/null 2>&1", TRACE_FILE);

    fprintf(stdout, "%s: command %s\n", __FUNCTION__, command);

    /* Remove output file, execute command + analyze result and
       set syscfg ddns_client_Lasterror / sysevent ddns_return_status here
       based on the error etc */
    unlink(buf);
    ret = system(command);
    fprintf(stdout, "%s: curl status for service %s is %s\n", __FUNCTION__, sdd->server.name, (ret == 0) ? "succeeded" : "failed");

    if (ret == 0)
    {
        output_file = fopen(buf, "r");
        if (output_file == NULL)
        {
            fprintf(stderr, "%s: failed to open %s\n", __FUNCTION__, buf);
            goto EXIT;
        }

        char *register_success = supported_servers[sdd->server.array_index][1];
        char *update_success = supported_servers[sdd->server.array_index][2];
        char *hostname_error = supported_servers[sdd->server.array_index][3];
        char *username_error = supported_servers[sdd->server.array_index][4];
        char *password_error = supported_servers[sdd->server.array_index][5];
        char *general_error = supported_servers[sdd->server.array_index][6];
        char *token_error = supported_servers[sdd->server.array_index][7];

        while (fgets(command, sizeof(command), output_file) != NULL)
        {

            if (register_success[0] && strstr(command, register_success))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "register_success", buf);
                sdd->client.connection_status = SUCCESS;
                break;
            }
            else if (update_success[0] && strstr(command, update_success))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "update_success", buf);
                sdd->client.connection_status = SUCCESS;
                break;
            }
            else if (hostname_error[0] && strstr(command, hostname_error))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "hostname_error", buf);
                sdd->client.lasterror = MISCONFIGURATION_ERROR;
            }
            else if (username_error[0] && strstr(command, username_error))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "username_error", buf);
                sdd->client.lasterror = AUTHENTICATION_ERROR;
                strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            }
            else if (password_error[0] && strstr(command, password_error))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "password_error", buf);
                sdd->client.lasterror = AUTHENTICATION_ERROR;
                strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            }
            else if (general_error[0] && strstr(command, general_error))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "general_error", buf);
                sdd->client.lasterror = AUTHENTICATION_ERROR;
                strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            }
            else if (token_error[0] && strstr(command, token_error))
            {
                fprintf(stderr, "%s: found %s in %s\n", __FUNCTION__, "token_error", buf);
                sdd->client.lasterror = AUTHENTICATION_ERROR;
                strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            }
            else
            {
                fprintf(stderr, "%s: didn't find expected result in %s\n", __FUNCTION__, buf);
                sdd->client.lasterror = AUTHENTICATION_ERROR;
                strncpy(sdd->client.connection_msg, "error-auth", sizeof(sdd->client.connection_msg));
            }
        }

        fclose(output_file);
    }
    else
    {
        output_file = fopen(TRACE_FILE, "r");
        if (output_file == NULL)
        {
            fprintf(stderr, "%s: failed to open %s\n", __FUNCTION__, TRACE_FILE);
            goto EXIT;
        }

        while (fgets(command, sizeof(command), output_file) != NULL)
        {

            if (strstr(command, "Failed to connect to"))
            {
                fprintf(stderr, "%s: found '%s' error in %s\n", __FUNCTION__, "Failed to connect to", TRACE_FILE);
                sdd->client.lasterror = CONNECTION_ERROR;
                strncpy(sdd->client.connection_msg, "error-connect", sizeof(sdd->client.connection_msg));
            }
            else if (strstr(command, "connect fail"))
            {
                fprintf(stderr, "%s: found '%s' error in %s\n", __FUNCTION__, "connect fail", TRACE_FILE);
                sdd->client.lasterror = CONNECTION_ERROR;
                strncpy(sdd->client.connection_msg, "error-connect", sizeof(sdd->client.connection_msg));
            }
            else if (strstr(command, "Couldn't resolve host"))
            {
                fprintf(stderr, "%s: found '%s' error in %s\n", __FUNCTION__, "Couldn't resolve host", TRACE_FILE);
                sdd->client.lasterror = CONNECTION_ERROR;
            }
            else
            {
                fprintf(stderr, "%s: no error keywords found in %s\n", __FUNCTION__, TRACE_FILE);
                sdd->client.lasterror = CONNECTION_ERROR;
            }
        }

        fclose(output_file);
    }

    if (sdd->client.connection_status == SUCCESS)
    {
        sdd->client.status = CLIENT_UPDATED;
        sdd->client.lasterror = NO_ERROR;
        sdd->hostname.status = HOST_REGISTERED;
        strncpy(sdd->client.connection_msg, "success", sizeof(sdd->client.connection_msg));

        if (sdd->server.check_interval != 0)
            add_ddns_checkinterval_to_cron(sdd);

        /* Remove retry check if update is successful */
        syscfg_set(NULL, "ddns_retry_enable", "0");
        system("sed -i '/#DDNS_RETRY_INTERVAL/d' /var/spool/cron/crontabs/root");

        fprintf(stdout, "%s: return 0 because everything looks good\n", __FUNCTION__);
        ret = 0;
    }
    else
    {
        if (!strcmp(sdd->client.connection_msg, "error-connect"))
        {
            syscfg_get(NULL, "ddns_retry_enable", buf, sizeof(buf));
            sdd->retry_enable = atoi(buf);

            if (sdd->retry_enable != 1)
            {
                sprintf(command, "ddns_server_retryinterval_%d", sdd->server.syscfg_index);
                syscfg_get(NULL, command, buf, sizeof(buf));
                sdd->server.retry_interval = atoi(buf);

                sprintf(command, "ddns_server_maxretries_%d", sdd->server.syscfg_index);
                syscfg_get(NULL, command, buf, sizeof(buf));
                sdd->server.max_retries = atoi(buf);

                if ((sdd->server.retry_interval != 0) && (sdd->server.max_retries != 0))
                {
                    syscfg_set_u(NULL, "ddns_max_retry_count", sdd->server.max_retries);
                    syscfg_set(NULL, "ddns_retry_enable", "1");
                    add_ddns_retryinterval_to_cron(sdd);
                }
            }
        }
        else
        {
            /* Remove retry entry if error is not error-connect */
            syscfg_set(NULL, "ddns_retry_enable", "0");
            system("sed -i '/#DDNS_RETRY_INTERVAL/d' /var/spool/cron/crontabs/root");
        }

        fprintf(stderr, "%s: return -1 because either curl returned non zero or update api returned error\n", __FUNCTION__);
        ret = -1;
    }

    if (unlink("/var/run/updating_ddns_server.txt") != 0)
        ret = -1;

EXIT:
    serv_ddns_write_status(sdd);
    syscfg_commit();

    return ret;
}

static int check_and_update_ddns_service(struct serv_ddns *sdd)
{
    int count = 5;
    int ret = -1;

    while (count > 0)
    {
        if (!access("/var/run/updating_ddns_server.txt", F_OK))
        {
            fprintf(stdout, "Already ddnsupdate is in progress.\n");
            sleep(2);
            count--;
        }
        else
        {
            fprintf(stdout, "Restart DDNS service\n");
            ret = ddns_update_server(sdd);
            break;
        }
    }

    return ret;
}

static int ddns_update_server_if_needed(struct serv_ddns *sdd)
{
    char current_status[8];
    char prev_wan_ipaddr[64];
    int ret = -1;

    current_status[0] = 0;
    sysevent_get(sdd->sefd, sdd->setok, "wan-status", current_status, sizeof(current_status));
    if (strcmp(current_status, "started") != 0)
        return 0;

    syscfg_get(NULL, "wan_last_ipaddr", prev_wan_ipaddr, sizeof(prev_wan_ipaddr));
    if (strcmp(sdd->wan_conf.wan_ipaddr, prev_wan_ipaddr) != 0)
    {
        fprintf(stdout, "Erouter IP changed\n");
        ret = check_and_update_ddns_service(sdd);
    }

    return ret;
}

static int ddns_retry_interval(struct serv_ddns *sdd)
{
    char buf[20];
    int ret = -1;

    syscfg_get(NULL, "ddns_max_retry_count", buf, sizeof(buf));
    sdd->max_retry_count = atoi(buf);

    if (sdd->max_retry_count > 0)
    {
        sdd->max_retry_count--;
        syscfg_set_u(NULL, "ddns_max_retry_count", sdd->max_retry_count);
        ret = check_and_update_ddns_service(sdd);
    }
    else
    {
        syscfg_set_commit(NULL, "ddns_retry_enable", "0");
        system("sed -i '/#DDNS_RETRY_INTERVAL/d' /var/spool/cron/crontabs/root");
    }

    return ret;
}

static int ddns_check_interval(struct serv_ddns *sdd)
{
    int ret = -1;

    if (sdd->client.enable)
    {
        char buf[50];
        struct timeval current_time;
        long time_diff;

        gettimeofday(&current_time, NULL);

        buf[0] = 0;
        sysevent_get(sdd->sefd, sdd->setok, "ddns_updated_time", buf, sizeof(buf));
        sdd->last_updated_time = atol(buf);
        time_diff = current_time.tv_sec - sdd->last_updated_time;

        if ((sdd->server.check_interval != 0) && (time_diff > sdd->server.check_interval))
        {
            ret = ddns_update_server_if_needed(sdd);
        }
    }

    return ret;
}

static void usage(void)
{
    int i;

    fprintf(stderr, "USAGE\n");
    fprintf(stderr, "    %s COMMAND \n", PROG_NAME);
    fprintf(stderr, "COMMANDS\n");

    for (i = 0; i < NELEMS(cmd_ops); i++)
    {
        fprintf(stderr, "    %-20s%s\n", cmd_ops[i].cmd, cmd_ops[i].desc);
    }
}

int main(int argc, char *argv[])
{
    int i = 0;
    struct serv_ddns sdd;

    if (argc < 2)
    {
        usage();
        exit(1);
    }

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
        exit(1);
    }

    for (i = 0; i < NELEMS(cmd_ops); i++)
    {
        if (strcmp(argv[1], cmd_ops[i].cmd) == 0)
        {
            break;
        }
    }

    if (i == NELEMS(cmd_ops))
    {
        fprintf(stderr, "[%s] unknown command: %s\n", PROG_NAME, argv[1]);
        exit(1);
    }

    memset(&sdd, 0, sizeof(sdd));
    if (serv_ddns_init(&sdd) != 0)
    {
        syscfg_set_commit(NULL, "ddns_retry_enable", "0");
        system("sed -i '/#DDNS_RETRY_INTERVAL/d' /var/spool/cron/crontabs/root");
        exit(1);
    }

    if (cmd_ops[i].exec(&sdd) != 0)
    {
        fprintf(stderr, "[%s]: fail to exec `%s'\n", PROG_NAME, cmd_ops[i].cmd);
    }

    if (serv_ddns_term(&sdd) != 0)
    {
        exit(1);
    }

    return 0;
}
