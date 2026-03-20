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

bool readAndApplyRelocations(const llvm::object::SectionRef& sec, bpf_insn* insn, maps_config& maps) {
	for (auto it = sec.relocation_begin(); it != sec.relocation_end(); ++it){
		unsigned insn_idx = it->getOffset() / sizeof(bpf_insn);
		if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
			LOG_ERROR("Invalid relo for insn[{}], code {}", insn_idx, insn[insn_idx].code);
			return false;
		}

		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
		size_t origOffset = *it->getSymbol()->getAddress();

		auto el = std::find_if(maps.begin(), maps.end(), [&](auto& mit) { return mit.elf_offset == origOffset; });
		if (el != maps.end()) {
			insn[insn_idx].imm = el->fd;
		} else {
			LOG_ERROR("Invalid relo for insn[{:d}] - no matching map", insn_idx);
			return false;
		}
	}

	return true;
}
}

MapsSectionLoader::MapsSectionLoader(const std::string& path){

    auto BufferOrErr = WriteThroughMemoryBuffer::getFile(path.c_str());
    if (!BufferOrErr) {
        throw std::runtime_error("Error reading file");
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

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper) {
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

		LOG_DEBUG("{:50} capacity={:d}, flags={:d}, kv size={:d}+{:d}",
			fmt::format("Map for FD={:d}: {} ({})", map.fd, map.name, to_string(map.def.type)),
			map.def.max_entries,
			map.def.map_flags,
			map.def.key_size,
			map.def.value_size);
	}
	return all_ok;
}

maps_config MapsSectionLoader::load() {
	auto sym{getSymTableEntriesForMaps()};

	if (sym.empty()) {
		LOG_ERROR("No maps found in sections");
		return {};
	}
	symbolsMap = sym;

	const std::size_t map_sz_elf = content.size() / sym.size();
	std::size_t map_sz_copy = sizeof(map_def);
	LOG_DEBUG("map_sz_elf {} {}" , map_sz_elf, map_sz_copy);
	if (map_sz_elf < map_sz_copy) {
		// For backward compatibility - use smaller struct's size
		map_sz_copy = map_sz_elf;
	}

	return copyElfMapsDataToMapsConfig(sym, map_sz_copy);
}
 
MapsSymbols MapsSectionLoader::getSymTableEntriesForMaps() {
	MapsSymbols symbols;

    for (const SectionRef &sec : ELFobj->sections()){
		for (auto it = sec.relocation_begin(); it != sec.relocation_end(); ++it){
			auto ssec =  it->getSymbol()->getSection();
			if( (*(*ssec)->getName()).str() == "maps" ){
				symbols.try_emplace(*it->getSymbol()->getAddress(), it->getSymbol()->getName()->str());
				content =  *(*ssec)->getContents();
			}
		}

		if(sec.getName()->starts_with("kprobe") || sec.getName()->starts_with("kretprobe")){
			bpfPrograms[sec.getName()->str()] = *sec.getContents();
		}
    }
	return symbols;
}

maps_config MapsSectionLoader::copyElfMapsDataToMapsConfig(const MapsSymbols& symbols, std::size_t map_sz_copy) const {
	maps_config maps;
	maps.reserve(symbols.size());
	for (const auto& [offset, name] : symbols) {
		map_data map;
		map.name = name;
		if (map.name.empty()) {
			LOG_ERROR("Empty name, skipping map {}", name);
			continue;
		}
		// Calculate the offset where symbol is stored in maps section data area;
		const map_def* def = reinterpret_cast<const map_def*>(content.data() + offset);
		map.elf_offset = offset;
		LOG_DEBUG("name {} offset {} def {:p}  ", map.name, offset, reinterpret_cast<const void*>( def));
		memset(&map.def, 0, sizeof(map.def));
		memcpy(&map.def, def, map_sz_copy);
		maps.push_back(std::move(map));
	}
	return maps;
}

bool MapsSectionLoader::processReloSections(maps_config& maps) {
	bool all_ok = true;
    for (const SectionRef &sec : ELFobj->sections()) {
		if(!sec.getName()) {
			continue;
		}
		if( !sec.getName()->starts_with(".rel")) {
			continue;
		}
		auto secName = sec.getName()->substr(4);
		if( secName.equals(".eh_frame")) {
			continue;
		}

		auto it = bpfPrograms.find(secName.str());
		if( it == bpfPrograms.end()){
			LOG_DEBUG("No program for section name {}", secName.str());
			continue;
		}

		bpf_insn* insns = (bpf_insn*) it->second.data();
		if (!readAndApplyRelocations(sec, insns, maps)) {
			LOG_ERROR("Relocations for section {:d} failed", sec.getIndex());
			all_ok = false;
		}
	}
	return all_ok;
}
} // namespace bpf
