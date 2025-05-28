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
#pragma once

#include "bpf_wrapper.h"

#include <gelf.h>
#include <libelf.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <vector>

namespace bpf {

struct elf_section;

struct map_def {
	bpf_map_type type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
	uint32_t inner_map_idx;
	uint32_t numa_node;
};

struct map_data {
	std::string name;
	size_t elf_offset;
	map_def def;
	int fd;
	// perf event part
	std::vector<int> pfd;
	int page_count;
	std::vector<perf_event_mmap_page*> header;
};

using maps_config = std::vector<map_data>;

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper);

class MapsSectionLoader {
public:
	explicit MapsSectionLoader(elf_section& section, Elf* elf, Elf_Data* symbols, int strtabidx) : section(section), elf(elf), symbols(symbols), strtabidx(strtabidx) {}

	maps_config load();

private:
	std::vector<GElf_Sym> getSymTableEntriesForMaps();
	void validateMapZeroes(const unsigned char* def, std::size_t map_sz_copy, std::size_t map_sz_elf) const;
	maps_config copyElfMapsDataToMapsConfig(const std::vector<GElf_Sym>& sym, unsigned char* elfMapsData, std::size_t map_sz_copy, std::size_t map_sz_elf, bool shouldValidateZeroes);

	elf_section& section;
	Elf* elf;
	Elf_Data* symbols;
	int strtabidx;
};

} // namespace bpf
