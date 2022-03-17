#include "maps_loading.h"

#include "elf_utils.h"
#include "errors.h"
#include "log.h"

#include <algorithm>
#include <cstring>
#include <fmt/core.h>
#include <stdexcept>
#include <string>

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
	// Get symbol table entries for maps
	std::vector<GElf_Sym> sym{getSymTableEntriesForMaps()};

	if (sym.empty()) {
		LOG_ERROR("No maps found in section");
		return {};
	}
	LOG_DEBUG("Number of Elf maps: {:d}", sym.size());

	std::sort(sym.begin(), sym.end(), [](const GElf_Sym& a, const GElf_Sym& b){ return a.st_value < b.st_value; });

	// Size of bpf_load_map_def is known in advance, but we don't know the size of the struct stored in ELF file (which may be different)
	// To deal with that, we assume all structs in ELF file are of the same size and divide data buffer size by number of symbols
	Elf_Data* data_maps = section.data;
	const std::size_t map_sz_elf = data_maps->d_size / sym.size();
	std::size_t map_sz_copy = sizeof(map_def);
	bool shouldValidateZeroes = false;
	if (map_sz_elf < map_sz_copy) {
		// For backward compatibility - use smaller struct's size
		map_sz_copy = map_sz_elf;
	} else if (map_sz_elf > map_sz_copy) {
		// For forward compatibility - allow loading larger structs with unknown features but make sure that the unknown features are not used (they are set to 0)
		shouldValidateZeroes = true;
	}

	return copyElfMapsDataToMapsConfig(sym, static_cast<unsigned char*>(data_maps->d_buf), map_sz_copy, map_sz_elf, shouldValidateZeroes);
}

std::vector<GElf_Sym> MapsSectionLoader::getSymTableEntriesForMaps() {
	std::vector<GElf_Sym> sym;
	sym.reserve(MAX_MAPS + 1);
	for (std::size_t i = 0; i < symbols->d_size / sizeof(GElf_Sym); ++i) {
		GElf_Sym nextEntry;
		if (!gelf_getsym(symbols, i, &nextEntry)) {
			LOG_DEBUG("gelf_getsym failed for symbol: {:d}", i);
			continue;
		}
		if (nextEntry.st_shndx != section.indx) {
			// Symbol does not belong to the section we're trying to load
			continue;
		}
		sym.push_back(nextEntry);
	}
	return sym;
}

void MapsSectionLoader::validateMapZeroes(const unsigned char* def, std::size_t map_sz_copy, std::size_t map_sz_elf) const {
	const unsigned char* addr = def + map_sz_copy;
	const unsigned char* end = def + map_sz_elf;
	const unsigned char* nonzeroAddr = std::find_if(addr, end, [](auto c){ return c != 0; });
	if (nonzeroAddr != end) {
		throw std::runtime_error{fmt::format("Validation failed - unknown Elf feature set at offset {}", std::distance(addr, nonzeroAddr))};
	}
}

maps_config MapsSectionLoader::copyElfMapsDataToMapsConfig(const std::vector<GElf_Sym>& sym, unsigned char* elfMapsData, std::size_t map_sz_copy, std::size_t map_sz_elf, bool shouldValidateZeroes) {
	maps_config maps;
	maps.reserve(sym.size());
	for (const auto& symEntry : sym) {
		map_data map;
		map.name = std::string{elf_strptr(elf, strtabidx, symEntry.st_name)};
		if (map.name.empty()) {
			LOG_ERROR("Empty name, skipping map {}: {}({:d})", symEntry.st_name, strerror(errno), errno);
			continue;
		}

		// Calculate the offset where symbol is stored in maps section data area
		const std::size_t offset = symEntry.st_value;
		const map_def* def = reinterpret_cast<map_def*>(elfMapsData + offset);
		map.elf_offset = offset;
		memset(&map.def, 0, sizeof(map.def));
		memcpy(&map.def, def, map_sz_copy);

		// Validate that there are no unknown features set
		if (shouldValidateZeroes) {
			validateMapZeroes(reinterpret_cast<const unsigned char*>(def), map_sz_copy, map_sz_elf);
		}
		maps.push_back(std::move(map));
	}
	return maps;
}

} // namespace bpf
