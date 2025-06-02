/*
* Copyright 2025 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License cat
*
* https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#pragma once

#include "system_calls.h"
#include <gmock/gmock.h>
#include <sys/utsname.h>

class MockSystemCalls : public ISystemCalls {
public:
	MOCK_METHOD(int, uname, (utsname* buf), (const, override));
	MOCK_METHOD(std::FILE*, fopen, (const char* name, const char* mode), (const, override));
	MOCK_METHOD(void, fclose, (std::FILE* file), (const, override));
	MOCK_METHOD(std::size_t, fread, (char* buffer, std::size_t count, std::FILE* stream), (const, override));
};
