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
