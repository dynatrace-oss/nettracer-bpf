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

#include "system_calls.h"
#include <linux/bpf.h>
#include <cstdint>
#include <string>
#include <vector>

namespace bpf {

struct elf_section;
struct map_data;
using maps_config = std::vector<map_data>;

struct kprobe {
	std::string fname;
	bpf_insn* insn;
	size_t size;
	int fd;
	int efd;
};

class bpf_subsystem {
	maps_config maps;
	std::vector<kprobe> probes;
	bool debug_print = true;
	const ISystemCalls& sysCalls;

	bool load_and_attach(kprobe& prgrm, const char* license, int kernVersion);
	void load_programs_from_sections(std::vector<elf_section>& allSections, const char* license, int kernVersion);
	int install_kprobe_fs(const std::string& prefix, const std::string& name, bool is_kprobe, int fd);
	int uninstall_kprobe_fs(const std::string& cmd);
	void close_all_probes();
	void close_all_maps();
	void set_maps_max_entries(uint32_t map_max_entries);

public:
	explicit bpf_subsystem(const ISystemCalls& sysCalls = SystemCalls::getInstance());
	bool load_bpf_file(const std::string& path, uint32_t map_max_entries);
	int get_map_fd(const std::string& name);
	map_data get_perf_map(const std::string& name);
	void clear_all_probes();
	~bpf_subsystem();
};

} // namespace bpf
