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


#include <llvm/Object/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>

#include "bpf_loading.h"
#include "maps_def.h"
#include <memory>
#include <unordered_map>

namespace bpf {

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper, const llvm::object::SectionRef* rodataSec);

using MapsSymbols = std::unordered_map<uintptr_t, std::string_view>;

class SectionLoader {
public:
	explicit SectionLoader(const std::string& path);
	bool loadSections();
	bool relocateData(maps_config& maps);

	const llvm::object::SectionRef* getRodataSection() const { return sections.rodata.get(); }
	maps_config getMapsConfig();
	BpfPrograms& getBpfPrograms(){ return bpfPrograms;}
	const char* getLicense(){ return sections.license->getContents()->data();}
private:
	struct {
		std::unordered_map<std::string_view, llvm::object::SectionRef> kprobes{};
		std::unordered_map<std::string_view, llvm::object::SectionRef> rel{};
		std::unique_ptr<llvm::object::SectionRef> maps{};
		std::unique_ptr<llvm::object::SectionRef> license{};
		std::unique_ptr<llvm::object::SectionRef> rodata{};
	} sections{};
	MapsSymbols mapsRelSymOffsToName;

	std::unique_ptr<llvm::WriteThroughMemoryBuffer> memBufffer;
	std::unique_ptr<llvm::object::Binary> binary;
	llvm::object::ELFObjectFileBase *ELFobj;
	BpfPrograms bpfPrograms;
};

} // namespace bpf
