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

