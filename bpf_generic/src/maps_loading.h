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
#include <unordered_map>

namespace bpf {

bool loadMaps(maps_config& maps, BPFMapsWrapper& mapsWrapper);

using BpfPrograms = std::unordered_map<std::string, llvm::StringRef>;
using MapsSymbols = std::unordered_map<size_t, std::string>;

class MapsSectionLoader {
public:
	explicit MapsSectionLoader(const std::string& path);
	maps_config load();
	bool processReloSections(maps_config& maps);
	BpfPrograms& getBpfPrograms(){ return bpfPrograms;}
private:
	MapsSymbols getSymTableEntriesForMaps();
	maps_config copyElfMapsDataToMapsConfig(const MapsSymbols& sym, std::size_t map_sz_copy) const;

	llvm::StringRef content;
	std::unique_ptr<llvm::WriteThroughMemoryBuffer> memBufffer;
	std::unique_ptr<llvm::object::Binary> binary;
	llvm::object::ELFObjectFileBase *ELFobj;
	MapsSymbols symbolsMap;
	BpfPrograms bpfPrograms;
};

} // namespace bpf
