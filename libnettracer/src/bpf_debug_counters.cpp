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
#include "bpf_debug_counters.h"

#include <fmt/format.h>

#include <cstring>
#include <iterator>
#include <vector>

namespace nettracer {

static_assert(sizeof(BpfDebugCounters) == kBpfDebugCountersFieldCount * sizeof(std::uint64_t),
	"BpfDebugCounters layout has drifted from kBpfDebugCountersFieldCount; update both together");

const std::array<BpfDebugCounterField, kBpfDebugCountersFieldCount>& bpfDebugCounterFields() {
	static const std::array<BpfDebugCounterField, kBpfDebugCountersFieldCount> fields = {{
		{"update_ipv4_on_connect_failures",      &BpfDebugCounters::update_ipv4_on_connect_failures},
		{"update_ipv6_on_connect_failures",      &BpfDebugCounters::update_ipv6_on_connect_failures},
		{"read_ipv4_on_connect_failures",        &BpfDebugCounters::read_ipv4_on_connect_failures},
		{"read_ipv6_on_connect_failures",        &BpfDebugCounters::read_ipv6_on_connect_failures},
		{"read_ipv4_on_close_failures",          &BpfDebugCounters::read_ipv4_on_close_failures},
		{"read_ipv6_on_close_failures",          &BpfDebugCounters::read_ipv6_on_close_failures},
		{"read_ipv4_on_accept_failures",         &BpfDebugCounters::read_ipv4_on_accept_failures},
		{"read_ipv6_on_accept_failures",         &BpfDebugCounters::read_ipv6_on_accept_failures},
		{"update_ipv4_on_accept_failures",       &BpfDebugCounters::update_ipv4_on_accept_failures},
		{"update_ipv6_on_accept_failures",       &BpfDebugCounters::update_ipv6_on_accept_failures},
		{"lookup_ipv4_on_close_failures",        &BpfDebugCounters::lookup_ipv4_on_close_failures},
		{"lookup_ipv6_on_close_failures",        &BpfDebugCounters::lookup_ipv6_on_close_failures},
		{"status_lookup_failures",               &BpfDebugCounters::status_lookup_failures},
		{"stats_updating_failures",              &BpfDebugCounters::stats_updating_failures},
		{"tcp_stats_updating_failures",          &BpfDebugCounters::tcp_stats_updating_failures},
		{"perf_output_ipv4_on_connect_failures", &BpfDebugCounters::perf_output_ipv4_on_connect_failures},
		{"perf_output_ipv6_on_connect_failures", &BpfDebugCounters::perf_output_ipv6_on_connect_failures},
		{"perf_output_ipv4_on_accept_failures",  &BpfDebugCounters::perf_output_ipv4_on_accept_failures},
		{"perf_output_ipv6_on_accept_failures",  &BpfDebugCounters::perf_output_ipv6_on_accept_failures},
		{"perf_output_ipv4_on_close_failures",   &BpfDebugCounters::perf_output_ipv4_on_close_failures},
		{"perf_output_ipv6_on_close_failures",   &BpfDebugCounters::perf_output_ipv6_on_close_failures},
		{"connectsock_ipv4_update_failures",     &BpfDebugCounters::connectsock_ipv4_update_failures},
		{"connectsock_ipv6_update_failures",     &BpfDebugCounters::connectsock_ipv6_update_failures},
		{"map_sends_update_failures",            &BpfDebugCounters::map_sends_update_failures},
	}};
	return fields;
}

BpfDebugCounters subtractBpfDebugCounters(const BpfDebugCounters& current, const BpfDebugCounters& previous) {
	BpfDebugCounters result{};
	for (const auto& field : bpfDebugCounterFields()) {
		result.*(field.pointer) = current.*(field.pointer) - previous.*(field.pointer);
	}
	return result;
}

BpfDebugCounters aggregatePerCpuBuffer(const BpfDebugCounters* perCpuBuffer, unsigned numCpus) {
	BpfDebugCounters result{};
	const auto& fields = bpfDebugCounterFields();
	for (unsigned cpu = 0; cpu < numCpus; ++cpu) {
		const auto& perCpu = perCpuBuffer[cpu];
		for (const auto& field : fields) {
			result.*(field.pointer) += perCpu.*(field.pointer);
		}
	}
	return result;
}

std::string formatNonZeroFields(const BpfDebugCounters& counters) {
	fmt::memory_buffer out;
	bool first = true;
	for (const auto& field : bpfDebugCounterFields()) {
		const std::uint64_t value = counters.*(field.pointer);
		if (value == 0) {
			continue;
		}
		fmt::format_to(std::back_inserter(out), "{}{}={}", first ? "" : " ", field.name, value);
		first = false;
	}
	if (first) {
		return "";
	}
	return fmt::to_string(out);
}

BpfDebugCountersReader::BpfDebugCountersReader(int mapFd, unsigned numPossibleCpus, const bpf::BPFMapsWrapper& mapsWrapper)
	: mapFd(mapFd), numPossibleCpus(numPossibleCpus), mapsWrapper(mapsWrapper) {}

std::optional<BpfDebugCounters> BpfDebugCountersReader::readAndAggregate() const {
	// For a PERCPU_ARRAY the kernel expects the user buffer to be
	// num_possible_cpus * round_up(value_size, 8) bytes long. The static_assert
	// at the top of this file guarantees sizeof(BpfDebugCounters) is 8-aligned.
	std::vector<BpfDebugCounters> perCpuBuffer(numPossibleCpus);
	std::uint32_t key{0};
	if (!mapsWrapper.lookupElement(mapFd, &key, perCpuBuffer.data())) {
		return std::nullopt;
	}
	return aggregatePerCpuBuffer(perCpuBuffer.data(), numPossibleCpus);
}

} // namespace nettracer
