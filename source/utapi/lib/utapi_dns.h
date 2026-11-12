/*********************************************************************************
 If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 Deutsche Telekom AG.
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
********************************************************************************/

#ifndef _UTAPI_DNS_H_
#define _UTAPI_DNS_H_

#include "utapi.h"

int Utopia_GetNumberOfDnsForwards(UtopiaContext *ctx);
int Utopia_SetDnsRelayEnabled(UtopiaContext *ctx, boolean_t enabled);
int Utopia_GetDnsRelayEnabled(UtopiaContext *ctx, boolean_t *enabled);
#endif
