/*
* Copyright 2026 Dynatrace LLC
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

#include "bpf_interface.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <unordered_map>
#include "nettracer-bpf.core.skel.h"


namespace bpf {

struct map_data;

class BTFLoader : public Ibpf {
	//maps_config maps;
	//std::vector<kprobe> probes;
	//bool debug_print = false;
	bool coreEnsured{false};
	bpf_object_open_opts openOpts{0};

	nettracer_bpf_core* skel{nullptr};
	void attachAllProbes();
public:
	BTFLoader() = default;
	virtual bool load_bpf(const std::string& path, uint32_t map_max_entries)  override;
	virtual int get_map_fd(const std::string& name) override;
	map_data get_perf_map(const std::string& name) override;
	void clear_all_probes() override;
	~BTFLoader() override;
};
} // namespace bpf
