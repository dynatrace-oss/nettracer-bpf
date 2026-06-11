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
#include <cstdint>
#include <memory>
#include <string>


namespace bpf {
	
struct map_data;

class Ibpf {
public:
	virtual bool load_bpf(const std::string& path, uint32_t map_max_entries, uint32_t kernVersion) = 0;
	virtual int get_map_fd(const std::string& name) = 0;
	virtual void clear_all_probes() = 0;
	virtual map_data get_perf_map(const std::string& name) = 0;
	virtual ~Ibpf() = default;
};

std::unique_ptr<Ibpf> createOffsetGuessedBPF();
std::unique_ptr<Ibpf> createBTFBPF();
} // namespace bpf
