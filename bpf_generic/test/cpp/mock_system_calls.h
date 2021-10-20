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
