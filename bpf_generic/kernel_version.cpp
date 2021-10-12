#include "kernel_version.h"

#include <cerrno>
#include <fstream>
#include <linux/version.h>
#include <regex>
#include <stdexcept>
#include <sys/utsname.h>

namespace bpf {

std::optional<int> getKernelVersion() {
	auto info{detail::getUtsname()};

	std::string version{info.version};
	if (version.find("Ubuntu") != std::string::npos) {
		return detail::getKernelVersionOnUbuntu();
	}
	else if (version.find("Debian") != std::string::npos) {
		return detail::getKernelVersionOnDebian(info);
	}
	else {
		return detail::getKernelVersionFromUname(info);
	}
}

namespace detail {

std::optional<int> getKernelVersionOnUbuntu() {
	// Ubuntu incorrectly reports patch version in `uname -r` (see https://www.spinics.net/lists/kernel/msg2392057.html)
	// that's why we try to obtain the version from Ubuntu-exclusive /proc/version_signature which contains the correct one
	std::ifstream ifs{"/proc/version_signature"};
	if (!ifs.is_open()) {
		return std::nullopt;
	}
	const size_t maxLength{128};
	std::string signature(maxLength, '\0');
	ifs.read(signature.data(), maxLength);
	return detail::parseVersionFromString(signature);
}

std::optional<int> getKernelVersionOnDebian(const utsname& info) {
	// Debian stores the version corresponding to LINUX_VERSION_CODE in utsname.version
	return detail::parseVersionFromString(info.version);
}

std::optional<int> getKernelVersionFromUname(const utsname& info) {
	// we rely on utsname.release for other distributions
	return detail::parseVersionFromString(info.release);
}

utsname getUtsname() {
	utsname result;
	if (uname(&result) != 0) {
		throw std::runtime_error{"cannot read system information using uname: " + std::string{strerror(errno)}};
	}
	return result;
}

std::optional<int> parseVersionFromString(std::string_view str) {
	// search for a version in the string that is of the same format as LINUX_VERSION_CODE
	// to handle versions like 4.18.0-305.3.1.el8.x86_64 (from CentOS), we also check the characters before and after the sequence - they must not be a ., or it could be a string we don't want to catch
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

} // namespace detail

} // namespace bpf
