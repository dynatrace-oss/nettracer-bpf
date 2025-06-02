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
#include "bpf_wrapper.h"
#include <algorithm>
#include <cstring>
#include <unistd.h>

namespace bpf {
	
// __NR_bpf may not be defined - if that's the case, define it here
#ifndef __NR_bpf
	#if defined(__x86_64__)
		#define __NR_bpf 321
	#elif defined(__aarch64__)
		#define __NR_bpf 280
	#else
		#error Could not define __NR_bpf. Architecture not supported.
	#endif
#endif

int sysCallBPF(bpf_cmd cmd, bpf_attr* attr, unsigned size) {
	return syscall(__NR_bpf, cmd, attr, size);
}

static char logBuffer[logBufferSize];

const char* getLogBuffer() {
	return logBuffer;
}

int loadProgram(uint32_t type, const bpf_insn* insns, uint32_t insnsCnt, const char* license, uint32_t logLevel, uint32_t kernVersion, BPFSysCall bpfCall) {
	bpf_attr attr{};
	attr.prog_type = type;
	attr.insn_cnt = insnsCnt;
	attr.insns = reinterpret_cast<uint64_t>(insns);
	attr.license = reinterpret_cast<uint64_t>(license);
	attr.kern_version = kernVersion;
	attr.log_level = logLevel;

	if (logLevel) {
		attr.log_buf = reinterpret_cast<uint64_t>(logBuffer);
		attr.log_size = logBufferSize;
	} else {
		attr.log_buf = 0;
		attr.log_size = 0;
	}

	return bpfCall(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int BPFMapsWrapper::createNode(
		bpf_map_type mapType,
		const std::string& name,
		uint32_t keySize,
		uint32_t valueSize,
		uint32_t maxEntries,
		uint32_t mapFlags,
		uint32_t node) {
	bpf_attr attr{};
	attr.map_type = mapType;
	attr.key_size = keySize;
	attr.value_size = valueSize;
	attr.max_entries = maxEntries;
	attr.map_flags = mapFlags;
	if (!name.empty()) {
		memcpy(attr.map_name, name.c_str(), std::min(name.size(), static_cast<size_t>(BPF_OBJ_NAME_LEN - 1)));
	}
	if (node >= 0) {
		attr.numa_node = node;
		attr.map_flags |= BPF_F_NUMA_NODE;
	}

	return sysCallBPF(BPF_MAP_CREATE, &attr, sizeof(attr));
}

bool BPFMapsWrapper::createElement(int fd, const void* key, const void* value) {
	bpf_attr attr{};
	attr.map_fd = fd;
	attr.key = reinterpret_cast<uint64_t>(key);
	attr.value = reinterpret_cast<uint64_t>(value);
	attr.flags = BPF_NOEXIST;

	return !sysCallBPF(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

bool BPFMapsWrapper::lookupElement(int fd, const void* key, void* value) const {
	bpf_attr attr{};
	attr.map_fd = fd;
	attr.key = reinterpret_cast<uint64_t>(key);
	attr.value = reinterpret_cast<uint64_t>(value);

	return !sysCallBPF(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

bool BPFMapsWrapper::updateElement(int fd, const void* key, const void* value, bool createIfDoesntExist) {
	bpf_attr attr{};
	attr.map_fd = fd;
	attr.key = reinterpret_cast<uint64_t>(key);
	attr.value = reinterpret_cast<uint64_t>(value);
	attr.flags = createIfDoesntExist ? BPF_ANY : BPF_EXIST;

	return !sysCallBPF(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

bool BPFMapsWrapper::removeElement(int fd, const void* key) {
	bpf_attr attr{};
	attr.map_fd = fd;
	attr.key = reinterpret_cast<uint64_t>(key);

	return !sysCallBPF(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

bool BPFMapsWrapper::getNextKey(int fd, const void* previousKey, void* key) const {
	bpf_attr attr{};
	attr.map_fd = fd;
	// that may be misleading and lead to incorrect iteration, see https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/
	attr.key = reinterpret_cast<uint64_t>(previousKey);
	attr.next_key = reinterpret_cast<uint64_t>(key);

	return !sysCallBPF(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

} // namespace bpf
