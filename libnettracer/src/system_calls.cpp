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

#include "bpf_generic/src/bpf_interface.h"
#include "bpf_generic/src/log.h"
#include "system_calls.h"
#include "system_utils.h"
#include <linux/version.h>
#include <sys/utsname.h>

constexpr inline static auto KERNEL_VERSION_FOR_CLASSIC KERNEL_VERSION(4, 15, 0);
constexpr inline static auto KERNEL_VERSION_FOR_BTF KERNEL_VERSION(5, 4, 0);

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

bool SystemCalls::isKernelSupportedForClassic(int kernelVersion) const {
	return isKernelSupported(kernelVersion, KERNEL_VERSION_FOR_CLASSIC);
}

bool SystemCalls::isKernelSupportedForBTF(int kernelVersion) const {
	return isKernelSupported(kernelVersion, KERNEL_VERSION_FOR_BTF);
}

std::unique_ptr<bpf::Ibpf> createBPFinterface(int kernelVersion, std::string_view option, const ISystemCalls& isystem) {
	// @todo: BTF temporarily disabled -> enable
	// if (option == "auto") {
	// 	if (isystem.isKernelSupportedForBTF(kernelVersion)) {
	// 		return bpf::createBTFBPF();
	// 	}
	// 	if (!isystem.isKernelSupportedForClassic(kernelVersion)) {
	// 		LOG_ERROR("Kernel version {} is not supported", kernelVersionToString(kernelVersion));
	// 		// don't return, see what happens
	// 	}
	// 	return bpf::createOffsetGuessedBPF();
	// } else if (option == "BTF") {
	// 	return bpf::createBTFBPF();
	// } else if (option == "offsetguessing") {
	// 	return bpf::createOffsetGuessedBPF();
	// }

	// return {};
	if (!isystem.isKernelSupportedForClassic(kernelVersion)) {
		LOG_ERROR("Kernel version {} is not supported", kernelVersionToString(kernelVersion));
		// don't return, see what happens
	}
	return bpf::createOffsetGuessedBPF();
}
