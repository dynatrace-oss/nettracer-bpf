/*
 * Copyright 2026 Dynatrace LLC
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
#include <cstdint>

namespace netstat {

struct Stats {
	uint64_t bytes_sent = 0;
	uint64_t bytes_received = 0;
	uint64_t pkts_sent = 0;
	uint64_t pkts_received = 0;
	uint64_t pkts_retrans = 0;
	uint32_t rtt = 0;
	uint32_t rtt_var = 0;
};

template <typename IPTYPE>
Stats calc_delta(Stats curr, Stats prev, const IPTYPE& key) {
	Stats result{};
	if (curr.bytes_sent >= prev.bytes_sent) {
		result.bytes_sent = curr.bytes_sent - prev.bytes_sent;
	} else {
		LOG_INFO("nonmonotonic counter bytes_sent : {} < {} key: {}", curr.bytes_sent, prev.bytes_sent, to_string(key));
	}
	if (curr.bytes_received >= prev.bytes_received) {
		result.bytes_received = curr.bytes_received - prev.bytes_received;
	} else {
		LOG_INFO("nonmonotonic counter bytes_received : {} < {} key: {}", curr.bytes_received, prev.bytes_received, to_string(key));
	}
	if (curr.pkts_sent >= prev.pkts_sent) {
		result.pkts_sent = curr.pkts_sent - curr.pkts_sent;
	} else {
		LOG_INFO("nonmonotonic counter pkts_sent : {} < {} key: {}", curr.pkts_sent, curr.pkts_received, to_string(key));
	}
	if (curr.pkts_received >= prev.pkts_received) {
		result.pkts_received = curr.pkts_received - prev.pkts_received;
	} else {
		LOG_INFO("nonmonotonic counter pkts_received : {} < {} key: {}", curr.pkts_received, prev.pkts_received, to_string(key));
	}
	if (curr.pkts_retrans >= prev.pkts_retrans) {
		result.pkts_retrans = curr.pkts_retrans - prev.pkts_retrans;
	} else {
		LOG_INFO("nonmonotonic counter pkts_received : {} < {} key: {}", curr.pkts_retrans, prev.pkts_retrans, to_string(key));
	}
	result.rtt = curr.rtt;
	result.rtt_var = curr.rtt_var;
	return result;
}

} // namespace netstat