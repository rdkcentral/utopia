#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "stackmode.h"
#include "stackmode_log.h"
#include "syscfg/syscfg.h"
#include "platform_hal.h"

#if defined(_ONESTACK_PRODUCT_REQ_)
#define BUFLEN_32 32
#define BUFLEN_256 256
#define MAX_RETRY 3
#define RETRY_DELAY_SEC 1
#define PARTNER_ID_FILE "/nvram/.partner_ID"
#define SETSTACKMODE_FILE "/nvram/setstackmode"
#define STACKMODE_BUSINESS "business-commercial-mode"
#define STACKMODE_RESIDENTIAL "residential-mode"

/**
 * @brief Trim trailing newline from string
 * @param str String to trim
 */
static inline void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0';
    }
}

/**
 * @brief Get partner ID with fallback mechanism
 * @param pValue Buffer to store the partner ID
 * @param size Size of the buffer
 * @return 0 on success, -1 on failure
 */
int get_setstackmode(char *pValue, int size)
{
    FILE *fp = NULL;
    char buffer[BUFLEN_256] = {0};
    int retry;

    if (!pValue || size <= 0)
    {
        STACKMODE_ERROR("%s: Invalid parameters (pValue=%p, size=%d)\n", __FUNCTION__, pValue, size);
        return -1;
    }

    STACKMODE_DEBUG("%s: Starting partner ID retrieval\n", __FUNCTION__);

    // 1. Try reading from file first
    if (access(PARTNER_ID_FILE, R_OK) == 0)
    {
        STACKMODE_DEBUG("%s: Attempting to read from file: %s\n", __FUNCTION__, PARTNER_ID_FILE);
        fp = fopen(PARTNER_ID_FILE, "r");
        if (fp)
        {
            if (fgets(buffer, sizeof(buffer), fp))
            {
                trim_newline(buffer);
                
                if (buffer[0] != '\0')
                {
                    strncpy(pValue, buffer, size - 1);
                    pValue[size - 1] = '\0';
                    fclose(fp);
                    STACKMODE_INFO("%s: Partner ID retrieved from file: %s\n", __FUNCTION__, pValue);
                    return 0;
                }
            }
            fclose(fp);
        }
        else
        {
            STACKMODE_WARN("%s: Failed to open file: %s\n", __FUNCTION__, PARTNER_ID_FILE);
        }
    }
    else
    {
        STACKMODE_DEBUG("%s: File not accessible: %s, trying HAL API\n", __FUNCTION__, PARTNER_ID_FILE);
    }

    // 2. Try HAL API with retries
    for (retry = 0; retry < MAX_RETRY; retry++)
    {
        STACKMODE_DEBUG("%s: Attempting HAL API call (attempt %d/%d)\n", __FUNCTION__, retry + 1, MAX_RETRY);
        if (platform_hal_getFactoryPartnerId(pValue) == 0 && pValue[0] != '\0')
        {
            STACKMODE_INFO("%s: Partner ID retrieved from HAL API: %s (attempt %d)\n", __FUNCTION__, pValue, retry + 1);
            return 0;
        }
        if (retry < MAX_RETRY - 1)
        {
            sleep(RETRY_DELAY_SEC);
        }
    }
    STACKMODE_WARN("%s: HAL API failed after %d retries, trying syscfg\n", __FUNCTION__, MAX_RETRY);

    // 3. Fallback to syscfg
    STACKMODE_DEBUG("%s: Attempting syscfg_get for PartnerID\n", __FUNCTION__);
    if (syscfg_get(NULL, "PartnerID", pValue, size) == 0 && pValue[0] != '\0')
    {
        STACKMODE_INFO("%s: Partner ID retrieved from syscfg: %s\n", __FUNCTION__, pValue);
        return 0;
    }

    STACKMODE_ERROR("%s: Failed to retrieve partner ID from all sources (File/HAL/Syscfg)\n", __FUNCTION__);
    return -1;
}

int main(int argc, char *argv[])
{
    char partnerId[BUFLEN_256] = {0};
    bool isBci = false;
    FILE *fp = NULL;
    int ret;

    // Initialize RDK logger
    if (!stackmode_log_init())
    {
        fprintf(stderr, "WARN: stackmode_log_init() failed, continuing without RDK logging\n");
    }

    STACKMODE_INFO("StackMode SetStackMode Utility started\n");

    if (get_setstackmode(partnerId, sizeof(partnerId)) == 0)
    {
        isBci = (strcmp(partnerId, "comcast-business") == 0);
        
        STACKMODE_INFO("Partner ID: %s | Is BCI: %s\n", partnerId, isBci ? "Yes" : "No");
        
        if (isBci)
        {
            // Create marker file for business-commercial mode
            fp = fopen(SETSTACKMODE_FILE, "w");
            if (fp)
            {
                fclose(fp);
                STACKMODE_INFO("Created marker file: %s\n", SETSTACKMODE_FILE);
            }
            else
            {
                STACKMODE_WARN("Failed to create marker file: %s\n", SETSTACKMODE_FILE);
            }
            
            // Set stackmode to business-commercial-mode
            ret = syscfg_set(NULL, "stackmode", STACKMODE_BUSINESS);
            if (ret == 0)
            {
                syscfg_commit();
                STACKMODE_INFO("Set stackmode to: %s\n", STACKMODE_BUSINESS);
            }
            else
            {
                STACKMODE_ERROR("Failed to set stackmode to: %s\n", STACKMODE_BUSINESS);
            }
        }
        else
        {
            // Set stackmode to residential-mode
            ret = syscfg_set(NULL, "stackmode", STACKMODE_RESIDENTIAL);
            if (ret == 0)
            {
                syscfg_commit();
                STACKMODE_INFO("Set stackmode to: %s\n", STACKMODE_RESIDENTIAL);
            }
            else
            {
                STACKMODE_ERROR("Failed to set stackmode to: %s\n", STACKMODE_RESIDENTIAL);
            }
        }
        
        stackmode_log_deinit();
        return 0;
    }

    STACKMODE_ERROR("Failed to retrieve Partner ID\n");
    
    stackmode_log_deinit();
    return 1;
}

#else

int main(int argc, char *argv[])
{
    fprintf(stderr, "ERROR: StackMode utility is not enabled (_ONESTACK_PRODUCT_REQ_ not defined)\n");
    return 1;
}

#endif
