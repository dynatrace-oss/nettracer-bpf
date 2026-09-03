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


namespace bpf {
namespace {

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

SectionLoader::SectionLoader(const std::string& path) : elfFile(path) {
}

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper, const elfSection* rodataSec) {
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
			all_ok = mapsWrapper.updateElement(fd, &zero, rodataSec->data);
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

static bool getSection(Elf* elf, GElf_Ehdr* ehdr, elfSection& section) {
	Elf_Scn* scn = elf_getscn(elf, section.indx);

	if (!scn) {
		LOG_ERROR("elf_getscn failed for section {:d}", section.indx);
		return false;
	}

	if (!gelf_getshdr(scn, &section.shdr)) {
		throw std::runtime_error(fmt::format("gelf_getshdr failed for section {:d}", section.indx));
	}

	char* shname = elf_strptr(elf, ehdr->e_shstrndx, section.shdr.sh_name);
	if (!shname) {
		LOG_ERROR("elf_strptr failed for section {:d}", section.indx);
		return false;
	}
	section.shname = std::string(shname);
	if (!section.shdr.sh_size) {
		return false;
	}

	section.data = elf_getdata(scn, nullptr);
	if (!section.data) {
		LOG_ERROR("No data descriptors found for section {:d}", section.indx);
		return false;
	}
	if (elf_getdata(scn, section.data)) {
		LOG_ERROR("More than one data descriptor found for section {:d}", section.indx);
		return false;
	}

	return true;
}

bool SectionLoader::loadSections() {
	Elf_Scn* scn = nullptr;
	while ((scn = elf_nextscn(elfFile.elf, scn)) != nullptr) {
		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB) {
			symdata = elf_getdata(scn, nullptr);
			symstrndx = shdr.sh_link;
			break;
		}
	}
	if (!symdata) {
		LOG_ERROR("No symtab found");
		return false;
	}

	size_t shstrndx;
	elf_getshdrstrndx(elfFile.elf, &shstrndx);
	for (unsigned i = 1; i < elfFile.ehdr.e_shnum; ++i) {
		elfSection sec{.indx = i};
		if (!getSection(elfFile.elf, &elfFile.ehdr, sec))
			continue;

		LOG_TRACE("section {:2d}: {}", i, sec.shname);

		if (sec.shname == "license") {
			sec.processed = true;
			sections.license = std::string((const char*)sec.data->d_buf, sec.data->d_size);
			LOG_DEBUG("license {}", sections.license);
		} else if (sec.shname == "version") {
			// Actually disregard the kernel version from ELF section
		} else if (sec.shname == "maps") {
			sec.processed = true;
			sections.maps = sec;
		} else if (sec.shname.starts_with("kprobe") || sec.shname.starts_with("kretprobe")) {
			sec.processed = true;
			sections.kprobes.emplace(sec.shname, sec);
		} else if (sec.shdr.sh_type == SHT_REL) {
			auto relSectionName = sec.shname.substr(4);
			LOG_TRACE("REL section {} {:d}: type: {} {}", sec.shname, sec.indx, sec.shdr.sh_type, 0);
			if (relSectionName.empty()) {
				continue;
			}
			sec.processed = true;
			sections.rel.emplace(relSectionName, sec);

			size_t count = sec.shdr.sh_size / sec.shdr.sh_entsize;
			for (size_t i = 0; i < count; i++) {
				GElf_Rel rel;
				gelf_getrel(sec.data, i, &rel);

				//getSymbol()
				uint32_t sym_idx = GELF_R_SYM(rel.r_info);
				GElf_Sym sym;
				if (!gelf_getsym(symdata, sym_idx, &sym)) {
					continue;
				}

				//getSection()
				if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE) {
					continue;
				}

				Elf_Scn* rel_scn = elf_getscn(elfFile.elf, sym.st_shndx);
				if (!rel_scn){
					continue;
				}

				GElf_Shdr rel_shdr;
				if (!gelf_getshdr(rel_scn, &rel_shdr)){
					continue;
				}

				//getName()
				const char* section_name = elf_strptr(elfFile.elf, shstrndx, rel_shdr.sh_name);
				if (!section_name){
					continue;
				}

				if (strcmp(section_name, "maps") == 0) {
					//getAddress()
					uint64_t sym_addr = sym.st_value;

					//getName()
					const char* sym_name = elf_strptr(elfFile.elf, symstrndx, sym.st_name);
					if (!sym_name){
						continue;
					}

					mapsRelSymOffsToName.try_emplace(sym_addr, std::string(sym_name));
				}
			}
		} else if (sec.shname == ".rodata") {
			auto rodataBody = sec.data;
			if (!rodataBody) {
				continue;
			}
			sections.rodata = sec;
			sections.rodata.processed = true;
		}
	}

	LOG_DEBUG(
			"kprobes {} maps {} mapsRelSymOffsToName {} lic {} ",
			sections.kprobes.size(),
			sections.maps.processed,
			mapsRelSymOffsToName.size(),
			sections.license);
	return !sections.kprobes.empty() && sections.maps.processed && !mapsRelSymOffsToName.empty() && !sections.license.empty();
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
		auto kprobeBody = static_cast<char*>(kprobe.data->d_buf);

		auto [itBody, ok] = bpfPrograms.emplace(kprobeName, std::vector<char>(kprobeBody, kprobeBody + kprobe.data->d_size));
		auto* bytecode = std::bit_cast<bpf_insn*>(itBody->second.data());

		// read and patch kprobe relocations
		size_t rel_count = kprobeRel.shdr.sh_size / kprobeRel.shdr.sh_entsize;
		for (size_t ri = 0; ri < rel_count; ri++) {
			GElf_Rel rel;
			gelf_getrel(kprobeRel.data, ri, &rel);

			auto relOffs = rel.r_offset;
			if (GELF_R_TYPE(rel.r_info) != R_BPF_64_64) {
				LOG_ERROR("prog:{}+{}: unknown relo type:{}", kprobeName, relOffs / sizeof(bpf_insn), GELF_R_TYPE(rel.r_info));
				return false;
			}

			GElf_Sym sym;
			if (!gelf_getsym(symdata, GELF_R_SYM(rel.r_info), &sym)) {
				LOG_ERROR("prog:{}+{}: unknown relocation addr", kprobeName, relOffs / sizeof(bpf_insn));
				return false;
			}
			uint64_t relSymbolAddr = sym.st_value;

			auto offs = relOffs / sizeof(bpf_insn);
			if (relOffs >= itBody->second.size()) {
				LOG_ERROR("prog:{}[{}]: invalid relo offset {}", kprobeName, itBody->second.size(), relOffs);
				return false;
			}
			if (auto opcode = bytecode[offs].code; opcode != (BPF_LD | BPF_IMM | BPF_DW)) {
				LOG_ERROR("prog:{}+{}: unknown opcode:{} ", kprobeName, offs, opcode);
				return false;
			}

			// containsSymbol
			if (sym.st_shndx == sections.maps.indx) {
				auto map = std::find_if(maps.begin(), maps.end(), [&relSymbolAddr](auto& map) { return map.elf_offset == relSymbolAddr; });
				if (map == maps.end()) {
					LOG_ERROR("prog:{}+{}: unknown relocation to maps section", kprobeName, offs);
					return false;
				}
				bytecode[offs].src_reg = BPF_PSEUDO_MAP_FD;
				bytecode[offs].imm = map->fd;
#if USE_RODATA
			} else if (sym.st_shndx == sections.rodata.indx && rodataMap != maps.end()) {
				bytecode[offs + 1].imm = bytecode[offs].imm + relSymbolAddr;
				bytecode[offs].src_reg = BPF_PSEUDO_MAP_VALUE;
				bytecode[offs].imm = rodataMap->fd;
#endif
			} else {
				const char* sym_name = elf_strptr(elfFile.elf, symstrndx, sym.st_name);
				LOG_ERROR("prog:{}+{}: invalid relocation to section:{}", kprobeName, offs, sym_name ? sym_name : "?");
				return false;
			}
		}
	}
	return true;
}

maps_config SectionLoader::getMapsConfig() {
	auto mapsBody = sections.maps.data;
	const std::size_t map_sz_elf = mapsBody->d_size / mapsRelSymOffsToName.size();
	std::size_t map_sz_copy = sizeof(map_def);
	LOG_DEBUG("map_sz_elf {} {}", map_sz_elf, map_sz_copy);
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
		const map_def* def = std::bit_cast<const map_def*>(static_cast<char*>(mapsBody->d_buf) + offset);
		map.elf_offset = offset;
		memset(&map.def, 0, sizeof(map.def));
		memcpy(&map.def, def, map_sz_copy);
		maps.push_back(std::move(map));
	}

#if USE_RODATA
	// create a map for .rodata
	if (sections.rodata.processed) {
		auto rodataBody = sections.rodata.data;
		map_data map;
		map.name = ".rodata";
		map.elf_offset = 0;
		map.def = {
			.type = BPF_MAP_TYPE_ARRAY,
			.key_size = sizeof(int),
			.value_size = static_cast<uint32_t>(rodataBody->d_size),
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

int calc_page_count(int max_entries){
	constexpr int max_value_size = 64; //maximal event size: aligned  sizeof(tcp_ipv6_event_t)
	static int page_size = getpagesize();
	int data_size = max_value_size * max_entries;
	int num_pages = (data_size + page_size - 1) / page_size;

	//roundup to power of 2
	int pow2_pages = 1;
	while (pow2_pages < num_pages)
		pow2_pages <<= 1;

	return pow2_pages;
}

} // namespace bpf
