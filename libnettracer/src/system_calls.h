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

#include <cstdio>

struct utsname;

class ISystemCalls {
public:
	virtual int uname(utsname* buf) const = 0;
	virtual std::FILE* fopen(const char* name, const char* mode) const = 0;
	virtual void fclose(std::FILE* file) const = 0;
	virtual std::size_t fread(char* buffer, std::size_t count, std::FILE* stream) const = 0;
};

class SystemCalls : public ISystemCalls {
public:
	int uname(utsname* buf) const override;
	FILE* fopen(const char* name, const char* mode) const override;
	void fclose(std::FILE* file) const override;
	std::size_t fread(char* buffer, std::size_t count, std::FILE* stream) const override;

	static const SystemCalls& getInstance() {
		const static SystemCalls sysCalls;
		return sysCalls;
	}

	SystemCalls(const SystemCalls&) = delete;
	SystemCalls& operator=(const SystemCalls&) = delete;

private:
	SystemCalls() = default;
};

