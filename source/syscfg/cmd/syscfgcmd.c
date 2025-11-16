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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscfg/syscfg.h>

static inline void syscfg_create_usage (void)
{
    printf("Usage: syscfg_create -f file\n");
}

static inline void syscfg_usage (void)
{
    printf("Usage: syscfg [show | set [ns] name value | get [ns] name | unset [ns] name | commit]\n");
}

int main (int argc, char **argv)
{
    int rc = 0;
    char *program;
    char **cmd;

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    if (strcmp(program, "syscfg_create") == 0) {
        if ((argc < 3) || (strcmp(argv[1], "-f") != 0)) {
            syscfg_create_usage();
            return 1;
        }

        return syscfg_create(argv[2], 0);
    }

    if (strcmp(program, "syscfg_destroy") == 0) {
        // check to see if we are going to force the destroy, if not, prompt the user
        if ((argc < 2) || ((argc >= 2) && (strcmp(argv[1], "-f") != 0))) {
            printf("WARNING!!! Are your sure you want to destroy system configuration?\n This will cause the system to be unstable. Press CTRL-C to abort or ENTER to proceed.\n");
            /*CID 65876: Unchecked return value */
            if (getchar() != EOF)
                printf("System configuration is going to destroy\n");
        }

        syscfg_destroy();

        return 0;
    }

    if (argc < 2) {
        syscfg_usage();
        return 1;
    }

    argc -= 1;
    cmd = argv + 1;

    if (strcmp(cmd[0], "get") == 0)
    {
        char val[512];

        if (argc == 2) {
            syscfg_get(NULL, cmd[1], val, sizeof(val));
        }
        else if (argc == 3) {
            syscfg_get(cmd[1], cmd[2], val, sizeof(val));
        }
        else {
            syscfg_usage();
            return 1;
        }

        puts(val);

        return 0;
    }
    else if (strcmp(cmd[0], "set") == 0)
    {
        if (argc == 3) {
            rc = syscfg_set(NULL, cmd[1], cmd[2]);
        }
        else if (argc == 4) {
            rc = syscfg_set(cmd[1], cmd[2], cmd[3]);
        }
        else {
            syscfg_usage();
            return 1;
        }

        if (rc != 0) {
            printf("Error. code=%d\n", rc);
        }

        return rc;
    }
    else if (strcmp(cmd[0], "unset") == 0)
    {
        if (argc == 2) {
            rc = syscfg_unset(NULL, cmd[1]);
        }
        else if (argc == 3) {
            rc = syscfg_unset(cmd[1], cmd[2]);
        }
        else {
            syscfg_usage();
            return 1;
        }

        if (rc != 0) {
//          printf("Error. code=%d\n", rc);
        }

        return rc;
    }
    else if (strcmp(cmd[0], "commit") == 0)
    {
        rc = syscfg_commit();

        if (rc != 0) {
            fprintf(stderr, "Error: internal error handling tmp file (%d)\n", rc);
        }

        return rc;
    }
    else if (strcmp(cmd[0], "destroy") == 0)
    {
        printf("WARNING!!! Are you sure you want to do this?\nPress CTRL-C to abort or ENTER to proceed\n");

        syscfg_destroy();

        return 0;
    }
    else if (strcmp(cmd[0], "show") == 0)
    {
        size_t sz;
        long int used_sz = 0, max_sz = 0;
        char *buf = NULL;

        buf = malloc(SYSCFG_SZ);
	if (NULL == buf) {
            printf("Error:Memory allocation failed\n");
            return -1;
        }

        if (syscfg_getall2(buf, SYSCFG_SZ, &sz) == 0) {
            fwrite(buf, 1, sz, stdout);
        }
        else {
            printf("No entries\n");
        }

        syscfg_getsz(&used_sz, &max_sz);
        printf("Used: %ld of %ld\n", used_sz, max_sz);

	free(buf);
        return 0;
    }

    syscfg_usage();

    return 0;
}

