/*
 * Copyright 2025 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_program/nettracer-bpf.h"
#include "configuration.h"

namespace netstat {

constexpr int ADDRESS_FIELD_WIDTH = 56;
constexpr int NUM_FIELD_WIDTH = 10;

class IStatsCollector {
public:
	virtual ~IStatsCollector() = default;
	virtual void set_kbhit() = 0;
	virtual void set_max_map_size(uint32_t size) = 0;
	virtual void on_config_change() = 0;
	virtual void init() = 0;
	virtual bool map_loop(const bpf::bpf_fds& fdsIPv4, const bpf::bpf_fds& fdsIPv6) = 0;
	virtual void eventIpv4(const tcp_ipv4_event_t& evt) = 0;
	virtual void eventIpv6(const tcp_ipv6_event_t& evt) = 0;
};

} // namespace netstat