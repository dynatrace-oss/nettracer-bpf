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
#include "classic_loader.h"
#include "maps_def.h"
#include <memory>
#include <unordered_map>
#include <fcntl.h>

namespace bpf {

struct elfSection {
	std::string shname;
	GElf_Shdr shdr{};
	Elf_Data* data{nullptr};
	unsigned indx{};
	bool processed{false};
};

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper, const elfSection* rodataSec);

using MapsSymbols = std::unordered_map<uintptr_t, std::string>;

struct ElfFile {
	int fd{};
	Elf* elf{nullptr};
	GElf_Ehdr ehdr;

	explicit ElfFile(const std::string& path) {
		if (elf_version(EV_CURRENT) == EV_NONE)
			throw std::runtime_error{"Cannot read elf version"};

		fd = ::open(path.c_str(), O_RDONLY);
		if (fd < 0)
			throw std::runtime_error{"cannot open file: " + path};

		elf = elf_begin(fd, ELF_C_READ, nullptr);
		if (!elf)
			throw std::runtime_error{"Cannot read elf " + path};

		if (gelf_getehdr(elf, &ehdr) != &ehdr)
			throw std::runtime_error{"Cannot read elf header"};
	}
	ElfFile(const ElfFile&) = delete;
    ElfFile& operator=(const ElfFile&) = delete;

	~ElfFile() {
		elf_end(elf);
		close(fd);
	}
};

class SectionLoader {
public:
	explicit SectionLoader(const std::string& path);
	bool loadSections();
	bool relocateData(maps_config& maps);

	const elfSection* getRodataSection() const {
		return (sections.rodata.processed)? &sections.rodata : nullptr;
	}

	maps_config getMapsConfig();
	BpfPrograms& getBpfPrograms(){ return bpfPrograms;}
	const char* getLicense(){ return sections.license.c_str();}
private:
	struct {
		std::unordered_map<std::string, elfSection> kprobes;
		std::unordered_map<std::string, elfSection> rel;
		elfSection maps;
		std::string license;
		elfSection rodata;
	} sections;
	MapsSymbols mapsRelSymOffsToName;
	ElfFile elfFile;
	BpfPrograms bpfPrograms;
	Elf_Data* symdata{nullptr};
	size_t symstrndx{};
};

} // namespace bpf
