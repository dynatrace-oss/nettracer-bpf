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
#include "system_utils.h"

#include <cerrno>
#include <cstdio>
#include <linux/version.h>
#include <regex>
#include <stdexcept>
#include <string_view>
#include <sys/utsname.h>
#include <string.h>


namespace {

utsname getUtsname(const ISystemCalls& sysCalls) {
	utsname result;
	if (sysCalls.uname(&result) != 0) {
		throw std::runtime_error{"cannot read system information using uname: " + std::string{strerror(errno)}};
	}
	return result;
}

std::optional<int> parseVersionFromString(std::string_view str) {
	// search for a version in the string that is of the same format as LINUX_VERSION_CODE
	// to handle versions like 4.18.0-305.3.1.el8.x86_64 (from CentOS), we also check the characters before and after the sequence:
	// they must not be a ., or it could be a string we don't want to catch
	std::regex versionRegex{R"((?:[^.]|^)(\d+)\.(\d+)\.(\d+)(?:[^.]|$))"};
	std::match_results<std::string_view::const_iterator> match, nextMatch;
	if (!std::regex_search(str.cbegin(), str.cend(), match, versionRegex)) {
		return std::nullopt;
	}
	// we use only the last match to deal with false positives on, for example, Ubuntu: Ubuntu 5.4.0-80.90~18.04.1-generic 5.4.124
	// implementation-wise, we could also do it by a negative lookahead but better not complicate the expression
	while (std::regex_search(str.cbegin() + (str.size() - match.suffix().str().size()), str.cend(), nextMatch, versionRegex)) {
		match = nextMatch;
	}
	int major{atoi(match.str(1).c_str())};
	int minor{atoi(match.str(2).c_str())};
	int patch{atoi(match.str(3).c_str())};
	return {KERNEL_VERSION(major, minor, patch)};
}

class FileScopeGuard {
public:
	explicit FileScopeGuard(std::FILE* file, const ISystemCalls& sysCalls)
		: file(file), sysCalls(sysCalls) {}
	~FileScopeGuard() {
		if (file) {
			sysCalls.fclose(file);
		}
	}
	std::FILE* operator*() {
		return file;
	}

private:
	std::FILE* file;
	const ISystemCalls& sysCalls;
};

std::optional<int> getKernelVersionOnUbuntu(const ISystemCalls& sysCalls) {
	// Ubuntu incorrectly reports patch version in `uname -r` (see https://www.spinics.net/lists/kernel/msg2392057.html)
	// that's why we try to obtain the version from Ubuntu-exclusive /proc/version_signature which contains the correct one
	FileScopeGuard file{sysCalls.fopen("/proc/version_signature", "r"), sysCalls};
	if (!*file) {
		return std::nullopt;
	}
	const size_t maxLength{128};
	std::string signature(maxLength, '\0');
	sysCalls.fread(signature.data(), maxLength, *file);
	return parseVersionFromString(signature);
}

std::optional<int> getKernelVersionOnDebian(const utsname& info) {
	// Debian stores the version corresponding to LINUX_VERSION_CODE in utsname.version
	return parseVersionFromString(info.version);
}

std::optional<int> getKernelVersionFromUname(const utsname& info) {
	// we rely on utsname.release for other distributions
	return parseVersionFromString(info.release);
}

} // namespace


std::optional<int> getKernelVersion(const ISystemCalls& sysCalls) {
	auto info{getUtsname(sysCalls)};

	std::string version{info.version};
	if (version.find("Ubuntu") != std::string::npos) {
		return getKernelVersionOnUbuntu(sysCalls);
	}
	else if (version.find("Debian") != std::string::npos) {
		return getKernelVersionOnDebian(info);
	}
	else {
		return getKernelVersionFromUname(info);
	}
}

bool isKernelSupported(int kernelVersion, int minimalVersion) {
	return kernelVersion >= minimalVersion;
}

std::string kernelVersionToString(int kernelVersion) {
	int major{kernelVersion >> 16};
	int minor{(kernelVersion >> 8) - (major << 8)};
	int patch{kernelVersion - (major << 16) - (minor << 8)};
	return std::to_string(major) + '.' + std::to_string(minor) + '.' + std::to_string(patch);
}

std::optional<unsigned> getNumPossibleCpus(const ISystemCalls& sysCalls) {
	// /sys/devices/system/cpu/possible contains a comma-separated list of
	// inclusive ranges describing CPU ids that the kernel may bring online,
	// e.g. "0-3", "0,2-5,7", or a bare "0". This is the same source libbpf
	// uses to size per-CPU map buffers (libbpf_num_possible_cpus()).
	FileScopeGuard file{sysCalls.fopen("/sys/devices/system/cpu/possible", "r"), sysCalls};
	if (!*file) {
		return std::nullopt;
	}
	const size_t maxLength{128};
	std::string content(maxLength, '\0');
	const size_t bytesRead{sysCalls.fread(content.data(), maxLength, *file)};
	if (bytesRead == 0) {
		return std::nullopt;
	}
	content.resize(bytesRead);

	unsigned total{0};
	bool sawAny{false};
	std::regex rangeRegex{R"((\d+)(?:-(\d+))?)"};
	auto begin{std::sregex_iterator{content.cbegin(), content.cend(), rangeRegex}};
	auto end{std::sregex_iterator{}};
	for (auto it{begin}; it != end; ++it) {
		const auto& match{*it};
		unsigned first{static_cast<unsigned>(std::stoul(match.str(1)))};
		unsigned last{match[2].matched ? static_cast<unsigned>(std::stoul(match.str(2))) : first};
		if (last < first) {
			return std::nullopt;
		}
		total += (last - first + 1);
		sawAny = true;
	}
	if (!sawAny) {
		return std::nullopt;
	}
	return total;
}

