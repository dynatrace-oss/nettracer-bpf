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
#include "maps_loading.h"
#include "errors.h"
#include "log.h"
#include <bit>
#include <algorithm>
#include <cstring>
#include <fmt/core.h>
#include <stdexcept>
#include <string>

using namespace llvm;
using namespace llvm::object;

namespace bpf {
namespace {

constexpr int MAX_MAPS = 32;

std::string to_string(bpf_map_type type) {
	switch (type) {
	case BPF_MAP_TYPE_HASH:
		return "HASH";
	case BPF_MAP_TYPE_ARRAY:
		return "ARRAY";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return "PERF_EVENT_ARRAY";
	default:
		return "Unsupported type";
	}
}
}

SectionLoader::SectionLoader(const std::string& path){

	auto BufferOrErr = MemoryBuffer::getFile(path.c_str());
	if (!BufferOrErr) {
		throw std::runtime_error(fmt::format("Error reading file: {} ({})", strerror(errno), errno));
	}

	memBufffer.swap(*BufferOrErr);
	Expected<std::unique_ptr<Binary>> BinOrErr = createBinary(memBufffer->getMemBufferRef());
	if (!BinOrErr) {
		throw std::runtime_error("Error parsing ELF");
	}

	binary.swap(*BinOrErr);
	ELFobj = dyn_cast<ELFObjectFileBase>(binary.get());
	if (!ELFobj) {
		throw std::runtime_error("Error ELFObj");
	}
}

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper, const llvm::object::SectionRef* rodataSec) {
	bool all_ok = true;
	for (auto& map : maps) {
		int numa_node = map.def.map_flags & BPF_F_NUMA_NODE ? map.def.numa_node : -1;

		int fd = mapsWrapper.createNode(map.def.type, map.name, map.def.key_size, map.def.value_size, map.def.max_entries, map.def.map_flags, numa_node);
		if (fd < 0) {
			std::string msg{fmt::format("Failed to create map {}: {:d} ({})", map.name, errno, strerror(errno))};
			if (errno == EPERM) {
				throw InsufficientCapabilitiesError{msg};
			} else {
				LOG_ERROR(msg);
				all_ok = false;
				continue;
			}
		}
		map.fd = fd;

		// init (memcpy) rodata
		if (map.name == ".rodata" && rodataSec) {
			int zero = 0;
			all_ok = mapsWrapper.updateElement(fd, &zero, rodataSec->getContents()->data());
		}

		LOG_DEBUG("{:50} capacity={:d}, flags={:d}, kv size={:d}+{:d}",
			fmt::format("Map for FD={:d}: {} ({})", map.fd, map.name, to_string(map.def.type)),
			map.def.max_entries,
			map.def.map_flags,
			map.def.key_size,
			map.def.value_size);
	}
	return all_ok;
}

bool SectionLoader::loadSections() {
	// iterating over ELF sections is done by means of SectionRef::moveNext(), i.e. updating the SectionRef obj
	// -> must create another SectionRef instance for each section being enumerated
	for (auto& section : ELFobj->sections()) {
		if (!section.getName()) {
			continue;
		}
		std::string_view sectionName(*section.getName());
		auto sectionContent = section.getContents();
		if (!sectionContent) {
			continue;
		}

		if (sectionName.starts_with("kprobe") || sectionName.starts_with("kretprobe")) {
			sections.kprobes.emplace(sectionName, llvm::object::SectionRef(section.getRawDataRefImpl(), section.getObject()));
		} else if (sectionName.starts_with(".rel")) {
			auto relSectionName = sectionName.substr(4);
			if (!sections.rel.emplace(relSectionName, llvm::object::SectionRef(section.getRawDataRefImpl(), section.getObject())).second) {
				return false;
			}
			for (auto& rel : section.relocations()) {
				auto relSymbol = rel.getSymbol();
				if (!relSymbol->getSection()) {
					return false;
				}
				auto relSection = *relSymbol->getSection();
				if (!relSection->getName()) {
					return false;
				}
				auto relSectionName = relSection->getName();
				if (!relSectionName) {
					return false;
				}
				if (relSectionName->str() == "maps") {
					auto relSymbolAddr = relSymbol->getAddress();
					if (!relSymbolAddr) {
						return false;
					}
					auto relSymbolName = relSymbol->getName();
					if (!relSymbolName) {
						return false;
					}
					mapsRelSymOffsToName.try_emplace(*relSymbolAddr, std::string_view(*relSymbolName));
				}
			}
		} else if (sectionName == "maps") {
			if (sections.maps) {
				return false;
			}
			auto mapsBody = section.getContents();
			if (!mapsBody) {
				return false;
			}
			if (mapsBody->size() == 0) {
				return false;
			}
			sections.maps = std::make_unique<llvm::object::SectionRef>(section.getRawDataRefImpl(), section.getObject());
		} else if (sectionName == "license") {
			if (sections.license) {
				return false;
			}
			sections.license = std::make_unique<llvm::object::SectionRef>(section.getRawDataRefImpl(), section.getObject());
		} else if (sectionName == ".rodata") {
			if (sections.rodata) {
				return false;
			}
			auto rodataBody = section.getContents();
			if (!rodataBody) {
				return false;
			}
			if (rodataBody->size() == 0) {
				return false;
			}
			sections.rodata = std::make_unique<llvm::object::SectionRef>(section.getRawDataRefImpl(), section.getObject());
		}
	}
	return !sections.kprobes.empty() && sections.maps && !mapsRelSymOffsToName.empty() && sections.license;
}

bool SectionLoader::relocateData(maps_config& maps) {
	constexpr uint64_t R_BPF_64_64 = 1;
#if USE_RODATA
	auto rodataMap = std::find_if(maps.begin(), maps.end(), [](auto& map) { return map.name == ".rodata"; });
#endif // USE_RODATA

	for (auto& [kprobeName, kprobeRel] : sections.rel) {
		auto itkprobe = sections.kprobes.find(kprobeName);
		if (itkprobe == sections.kprobes.end()) {
			continue;
		}
		auto& kprobe = itkprobe->second;
		auto kprobeBody = *kprobe.getContents();

		// must copy the bpf prog body: llvm elf structs are mmap'd directly from .o file, and patching relocs would overwrite the file
		auto [itBody, ok] = bpfPrograms.emplace(kprobeName, std::vector<char>(kprobeBody.begin(), kprobeBody.end()));
		auto* bytecode = std::bit_cast<bpf_insn*>(itBody->second.data());

		// read and patch kprobe relocations
		for (auto& rel : kprobeRel.relocations()) {
			auto relOffs = rel.getOffset();
			if (relOffs >= itBody->second.size()) {
				LOG_ERROR("prog:{}[{}]: invalid relo offset {}", kprobeName, itBody->second.size(), relOffs);
				return false;
			}

			auto offs = relOffs / sizeof(bpf_insn);
			if (rel.getType() != R_BPF_64_64) {
				LOG_ERROR("prog:{}+{}: unknown relo type:{}", kprobeName, offs, rel.getType());
				return false;
			}
			if (auto opcode = bytecode[offs].code; opcode != (BPF_LD | BPF_IMM | BPF_DW)) {
				LOG_ERROR("prog:{}+{}: unknown opcode:{} ", kprobeName, offs, opcode);
				return false;
			}

			auto relSymbol = rel.getSymbol();
			auto relSymbolAddr = relSymbol->getAddress();
			if (!relSymbolAddr) {
				LOG_ERROR("prog:{}+{}: unknown relocation addr", kprobeName, offs);
				return false;
			}

			// (src_reg, imm) mapping ref. https://www.kernel.org/doc/html/latest/bpf/standardization/instruction-set.html#bit-immediate-instructions
			if (sections.maps->containsSymbol(*relSymbol)) {
				auto map = std::find_if(maps.begin(), maps.end(), [&relSymbolAddr](auto& map) { return map.elf_offset == *relSymbolAddr; });
				if (map == maps.end()) {
					LOG_ERROR("prog:{}+{}: unknown relocation to maps section", kprobeName, offs);
					return false;
				}
				bytecode[offs].src_reg = BPF_PSEUDO_MAP_FD;
				bytecode[offs].imm = map->fd;
#if USE_RODATA
			} else if (sections.rodata && sections.rodata->containsSymbol(*relSymbol) && rodataMap != maps.end()) {
				bytecode[offs + 1].imm = bytecode[offs].imm + *relSymbolAddr;
				bytecode[offs].src_reg = BPF_PSEUDO_MAP_VALUE;
				bytecode[offs].imm = rodataMap->fd;
#endif // USE_RODATA
			} else {
				LOG_ERROR("prog:{}+{}: invalid relocation to section:{}", kprobeName, offs, relSymbol->getName()->str());
				return false;
			}
		}
	}
	return true;
}

maps_config SectionLoader::getMapsConfig() {
	auto mapsBody = sections.maps->getContents();
	const std::size_t map_sz_elf = mapsBody->size() / mapsRelSymOffsToName.size();
	std::size_t map_sz_copy = sizeof(map_def);
	LOG_DEBUG("map_sz_elf {} {}" , map_sz_elf, map_sz_copy);
	if (map_sz_elf < map_sz_copy) {
		// For backward compatibility - use smaller struct's size
		map_sz_copy = map_sz_elf;
	}

	maps_config maps;
	for (const auto& [offset, name] : mapsRelSymOffsToName) {
		map_data map;
		map.name = name;
		if (map.name.empty()) {
			LOG_ERROR("Empty name, skipping map {}", name);
			continue;
		}
		// Calculate the offset where symbol is stored in maps section data area;
		const map_def* def = std::bit_cast<const map_def*>(mapsBody->data() + offset);
		map.elf_offset = offset;
		memset(&map.def, 0, sizeof(map.def));
		memcpy(&map.def, def, map_sz_copy);
		maps.push_back(std::move(map));
	}

#if USE_RODATA
	// create a map for .rodata
	if (sections.rodata) {
		auto rodataBody = sections.rodata->getContents();
		map_data map;
		map.name = ".rodata";
		map.elf_offset = 0;
		map.def = {
			.type = BPF_MAP_TYPE_ARRAY,
			.key_size = sizeof(int),
			.value_size = static_cast<uint32_t>(rodataBody->size()),
			.max_entries = 1,
			.map_flags = BPF_F_RDONLY_PROG | BPF_F_MMAPABLE,
			.inner_map_idx = 0,
			.numa_node = 0
		};
		map.fd = -1;
		maps.push_back(std::move(map));
	}
#endif // USE_RODATA

	return maps;
}
 
} // namespace bpf
