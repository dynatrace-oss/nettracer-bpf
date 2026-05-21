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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;

namespace {

class StubMapsWrapper : public bpf::BPFMapsWrapper {
public:
	std::vector<bpf_debug_counters_t> perCpuValues;
	bool lookupShouldFail{false};
	mutable int lookupCallCount{0};
	mutable int lastFd{-1};
	mutable std::uint32_t lastKey{~0u};

	bool lookupElement(int fd, const void* key, void* value) const override {
		++lookupCallCount;
		lastFd = fd;
		lastKey = *static_cast<const std::uint32_t*>(key);
		if (lookupShouldFail) {
			return false;
		}
		std::memcpy(value, perCpuValues.data(), perCpuValues.size() * sizeof(bpf_debug_counters_t));
		return true;
	}
};

bpf_debug_counters_t makeAllZero() {
	bpf_debug_counters_t c{};
	return c;
}

} // namespace

TEST(BpfDebugCountersAggregation, sums_a_single_field_across_cpus) {
	bpf_debug_counters_t cpu0{};
	cpu0.status_lookup_failures = 3;
	bpf_debug_counters_t cpu1{};
	cpu1.status_lookup_failures = 7;
	bpf_debug_counters_t cpu2{};
	cpu2.status_lookup_failures = 0;
	bpf_debug_counters_t cpu3{};
	cpu3.status_lookup_failures = 5;
	std::vector<bpf_debug_counters_t> buffer{cpu0, cpu1, cpu2, cpu3};

	auto result = nettracer::aggregatePerCpuBuffer(buffer.data(), buffer.size());

	EXPECT_EQ(result.status_lookup_failures, 15u);
	EXPECT_EQ(result.update_ipv4_on_connect_failures, 0u);
	EXPECT_EQ(result.map_sends_update_failures, 0u);
}

TEST(BpfDebugCountersAggregation, sums_multiple_fields_independently) {
	bpf_debug_counters_t cpu0{};
	cpu0.update_ipv4_on_connect_failures = 1;
	cpu0.read_ipv6_on_accept_failures = 4;
	cpu0.map_sends_update_failures = 100;
	bpf_debug_counters_t cpu1{};
	cpu1.update_ipv4_on_connect_failures = 2;
	cpu1.read_ipv6_on_accept_failures = 0;
	cpu1.map_sends_update_failures = 50;
	std::vector<bpf_debug_counters_t> buffer{cpu0, cpu1};

	auto result = nettracer::aggregatePerCpuBuffer(buffer.data(), buffer.size());

	EXPECT_EQ(result.update_ipv4_on_connect_failures, 3u);
	EXPECT_EQ(result.read_ipv6_on_accept_failures, 4u);
	EXPECT_EQ(result.map_sends_update_failures, 150u);
}

TEST(BpfDebugCountersAggregation, all_zero_buffer_yields_all_zero_result) {
	std::vector<bpf_debug_counters_t> buffer(4, makeAllZero());
	auto result = nettracer::aggregatePerCpuBuffer(buffer.data(), buffer.size());
	EXPECT_EQ(result.status_lookup_failures, 0u);
	EXPECT_EQ(result.update_ipv4_on_connect_failures, 0u);
	EXPECT_EQ(result.map_sends_update_failures, 0u);
}

TEST(BpfDebugCountersSubtract, computes_per_field_delta) {
	nettracer::BpfDebugCounters current{};
	current.status_lookup_failures = 10;
	current.update_ipv4_on_connect_failures = 5;
	current.map_sends_update_failures = 100;

	nettracer::BpfDebugCounters previous{};
	previous.status_lookup_failures = 7;
	previous.update_ipv4_on_connect_failures = 5;
	previous.map_sends_update_failures = 80;

	auto delta = nettracer::subtractBpfDebugCounters(current, previous);

	EXPECT_EQ(delta.status_lookup_failures, 3u);
	EXPECT_EQ(delta.update_ipv4_on_connect_failures, 0u);
	EXPECT_EQ(delta.map_sends_update_failures, 20u);
}

TEST(BpfDebugCountersFormat, all_zero_returns_marker) {
	nettracer::BpfDebugCounters counters{};
	EXPECT_EQ(nettracer::formatNonZeroFields(counters), "(all zero)");
}

TEST(BpfDebugCountersFormat, only_non_zero_fields_are_listed) {
	nettracer::BpfDebugCounters counters{};
	counters.update_ipv4_on_connect_failures = 1;
	counters.status_lookup_failures = 42;
	counters.map_sends_update_failures = 7;

	const auto formatted = nettracer::formatNonZeroFields(counters);

	EXPECT_THAT(formatted, ::testing::HasSubstr("update_ipv4_on_connect_failures=1"));
	EXPECT_THAT(formatted, ::testing::HasSubstr("status_lookup_failures=42"));
	EXPECT_THAT(formatted, ::testing::HasSubstr("map_sends_update_failures=7"));
	EXPECT_THAT(formatted, ::testing::Not(::testing::HasSubstr("update_ipv6_on_connect_failures")));
	EXPECT_THAT(formatted, ::testing::Not(::testing::HasSubstr("read_ipv4_on_close_failures")));
}

TEST(BpfDebugCountersFormat, fields_separated_by_single_space) {
	nettracer::BpfDebugCounters counters{};
	counters.update_ipv4_on_connect_failures = 1;
	counters.status_lookup_failures = 2;
	const auto formatted = nettracer::formatNonZeroFields(counters);
	EXPECT_EQ(formatted.find("  "), std::string::npos);
	EXPECT_NE(formatted.find(' '), std::string::npos);
}

TEST(BpfDebugCountersReader, returns_aggregated_counters_on_successful_lookup) {
	StubMapsWrapper wrapper;
	bpf_debug_counters_t cpu0{};
	cpu0.status_lookup_failures = 4;
	cpu0.update_ipv4_on_connect_failures = 1;
	bpf_debug_counters_t cpu1{};
	cpu1.status_lookup_failures = 6;
	cpu1.update_ipv4_on_connect_failures = 2;
	wrapper.perCpuValues = {cpu0, cpu1};

	nettracer::BpfDebugCountersReader reader{/*mapFd=*/42, /*numPossibleCpus=*/2, wrapper};
	auto result = reader.readAndAggregate();

	ASSERT_TRUE(result.has_value());
	EXPECT_EQ(result->status_lookup_failures, 10u);
	EXPECT_EQ(result->update_ipv4_on_connect_failures, 3u);
	EXPECT_EQ(wrapper.lastFd, 42);
	EXPECT_EQ(wrapper.lastKey, 0u);
	EXPECT_EQ(wrapper.lookupCallCount, 1);
}

TEST(BpfDebugCountersReader, returns_nullopt_when_lookup_fails) {
	StubMapsWrapper wrapper;
	wrapper.lookupShouldFail = true;
	wrapper.perCpuValues.resize(2);

	nettracer::BpfDebugCountersReader reader{/*mapFd=*/7, /*numPossibleCpus=*/2, wrapper};
	auto result = reader.readAndAggregate();

	EXPECT_FALSE(result.has_value());
}
