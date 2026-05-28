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

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nettracer {

// User-space mirror of the BPF-side `struct bpf_debug_counters_t`.
// The layout is identical, so we expose it via a type alias and avoid
// duplicating the field list. The struct lives in bpf_program/nettracer-bpf.h.
using BpfDebugCounters = bpf_debug_counters_t;

// Number of uint64_t counters in BpfDebugCounters.
constexpr std::size_t kBpfDebugCountersFieldCount = sizeof(bpf_debug_counters_t) / sizeof(uint64_t);;

// (name, pointer-to-member) pair used to iterate over all counter fields
// generically for aggregation, subtraction and formatting.
struct BpfDebugCounterField {
	std::string_view name;
	std::uint64_t BpfDebugCounters::* pointer;
};

// Returns the static field table covering every counter in BpfDebugCounters.
const std::array<BpfDebugCounterField, kBpfDebugCountersFieldCount>& bpfDebugCounterFields();

// Returns current minus previous, field by field.
BpfDebugCounters subtractBpfDebugCounters(const BpfDebugCounters& current, const BpfDebugCounters& previous);

// Aggregates a per-CPU buffer (numCpus entries of BpfDebugCounters) into a
// single BpfDebugCounters by summing every field across CPUs.
BpfDebugCounters aggregatePerCpuBuffer(const BpfDebugCounters* perCpuBuffer, unsigned numCpus);

// Formats only the fields that are non-zero as "name=value" pairs separated by
// spaces. Returns "(all zero)" when every field is zero.
std::string formatNonZeroFields(const BpfDebugCounters& counters);

class BpfDebugCountersReader {
public:
	BpfDebugCountersReader(int mapFd, unsigned numPossibleCpus, const bpf::BPFMapsWrapper& mapsWrapper);

	// Reads the BPF PERCPU_ARRAY map at key 0 and aggregates across all CPUs.
	// Returns std::nullopt if the map lookup failed.
	std::optional<BpfDebugCounters> readAndAggregate() const;

private:
	int mapFd;
	unsigned numPossibleCpus;
	const bpf::BPFMapsWrapper& mapsWrapper;
};

} // namespace nettracer
