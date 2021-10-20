#include "system_calls.h"
#include <sys/utsname.h>

int SystemCalls::uname(utsname* buf) const {
	return ::uname(buf);
}

std::FILE* SystemCalls::fopen(const char* name, const char* mode) const {
	return std::fopen(name, mode);
}

void SystemCalls::fclose(std::FILE* file) const {
	std::fclose(file);
}

std::size_t SystemCalls::fread(char* buffer, std::size_t count, std::FILE* stream) const {
	return std::fread(buffer, sizeof(char), count, stream);
}
