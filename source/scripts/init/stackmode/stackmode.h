#ifndef _COMMON_STACKMODE_H_
#define _COMMON_STACKMODE_H_

#include <stdbool.h>

#ifdef _STACKMODE_PRODUCT_REQ_

/**
 * @brief Get partner ID and set stack mode with fallback mechanism
 * 
 * This function attempts to retrieve the partner ID using the following priority:
 * 1. Read from /nvram/.partner_ID file
 * 2. HAL API (platform_hal_getFactoryPartnerId) with 3 retries
 * 3. Read from syscfg (PartnerID)
 * 
 * Based on the partner ID, sets the stack mode:
 * - "comcast-business" -> business-commercial-mode (creates /nvram/setstackmode marker)
 * - Other -> residential-mode
 * 
 * @param pValue Buffer to store the partner ID
 * @param size Size of the buffer
 * @return 0 on success, -1 on failure
 */
int get_setstackmode(char *pValue, int size);

#endif

#endif /* _COMMON_STACKMODE_H_ */
