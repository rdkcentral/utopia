/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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

#ifndef FOPEN_MOCK_H
#define FOPEN_MOCK_H

#include <cstdio>
#include <gmock/gmock.h>

class FopenMock {
public:
    MOCK_METHOD(FILE*, fopen_mock, (const char* filename, const char* mode), ());
};

extern FopenMock* g_fopenMock;

extern "C" FILE* fopen_mock(const char* filename, const char* mode);

#endif // FOPEN_MOCK_H