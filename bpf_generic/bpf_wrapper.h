#pragma once

#include <cstddef>
#include <limits>
#include <linux/bpf.h>
#include <string>

namespace bpf {

int sysCallBPF(bpf_cmd cmd, bpf_attr* attr, unsigned size);
using BPFSysCall = decltype(sysCallBPF);

// size set to maximum possible size in BPF verifier in kernel version <= 5.1
// (https://elixir.bootlin.com/linux/v5.1/source/kernel/bpf/verifier.c#L7882)
inline const size_t logBufferSize = std::numeric_limits<uint32_t>::max() >> 8;
// Log buffer used when loading BPF programs
const char* getLogBuffer();

// Load a BPF program and return a file descriptor to it
// Sets errno in case of errors
int loadProgram(uint32_t type, const bpf_insn* insns, uint32_t insnsCnt, const char* license, uint32_t logLevel, uint32_t kernVersion, BPFSysCall bpfCall);

class BPFMapsWrapper {
public:
	// Create a map node and return an fd to it
	virtual int createNode(
		bpf_map_type mapType,
		const std::string& name,
		uint32_t keySize,
		uint32_t valueSize,
		uint32_t maxEntries,
		uint32_t mapFlags,
		uint32_t node);

	virtual bool createElement(int fd, const void* key, const void* value);
	virtual bool lookupElement(int fd, const void* key, void* value) const;
	virtual bool updateElement(int fd, const void* key, const void* value, bool createIfDoesntExist = true);
	virtual bool removeElement(int fd, const void* key);

	virtual bool getNextKey(int fd, const void* previousKey, void* currentKey) const;
};

} // namespace bpf
