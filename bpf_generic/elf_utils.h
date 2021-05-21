#pragma once

#include <gelf.h>
#include <libelf.h>
#include <string>
#include <vector>

struct bpf_insn;

namespace bpf {

struct map_data;
using maps_config = std::vector<map_data>;

struct elf_section {
	std::string shname;
	GElf_Shdr shdr;
	Elf_Data* data;
	unsigned indx;
	bool processed;
};

std::string to_string(const elf_section& section);

bool getSection(Elf* elf, GElf_Ehdr* ehdr, elf_section& section);

bool readAndApplyRelocations(Elf_Data* data, Elf_Data* symbols, GElf_Shdr* shdr, bpf_insn* insn, maps_config& maps);

} // namespace bpf
