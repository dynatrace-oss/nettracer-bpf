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
#include <functional>
#include "netstat.h"

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

struct ServerStats : public Stats {
	uint32_t session_counter = 0;
	uint32_t connection_attempts = 0;
	uint32_t connection_resets = 0;
	uint32_t connection_timeout = 0;

	void addStats(const Stats& conn) {
		bytes_sent += conn.bytes_sent;
		bytes_received += conn.bytes_received;
		pkts_sent += conn.pkts_sent;
		pkts_received += conn.pkts_received;
		pkts_retrans += conn.pkts_retrans;
		rtt = std::max(rtt, conn.rtt);
		rtt_var = std::max(rtt_var, conn.rtt_var);
	}
};

struct server_ipv4_tuple_t {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint32_t pid;
	bool operator==(const server_ipv4_tuple_t&) const = default;
};

struct server_ipv6_tuple_t {
	uint64_t saddr_h;
	uint64_t saddr_l;
	uint64_t daddr_h;
	uint64_t daddr_l;
	uint16_t sport;
	uint32_t pid;
	bool operator==(const server_ipv6_tuple_t&) const = default;
};

using ServersIPv4 = std::unordered_map<server_ipv4_tuple_t, ServerStats>;
using ServersIPv6 = std::unordered_map<server_ipv6_tuple_t, ServerStats>;
}

template <>
struct std::hash<netstat::server_ipv4_tuple_t> {
	std::size_t operator()(const netstat::server_ipv4_tuple_t& t) const noexcept {
		std::size_t h = 0;
		hash_combine(h, std::hash<uint32_t>{}(t.saddr));
		hash_combine(h, std::hash<uint32_t>{}(t.daddr));
		hash_combine(h, std::hash<uint16_t>{}(t.sport));
		hash_combine(h, std::hash<uint32_t>{}(t.pid));
		return h;
	}
};

template <>
struct std::hash<netstat::server_ipv6_tuple_t> {
	std::size_t operator()(const netstat::server_ipv6_tuple_t& t) const noexcept {
		std::size_t h = 0;
		hash_combine(h, std::hash<uint64_t>{}(t.saddr_h));
		hash_combine(h, std::hash<uint64_t>{}(t.saddr_l));
		hash_combine(h, std::hash<uint64_t>{}(t.daddr_h));
		hash_combine(h, std::hash<uint64_t>{}(t.daddr_l));
		hash_combine(h, std::hash<uint16_t>{}(t.sport));
		hash_combine(h, std::hash<uint32_t>{}(t.pid));
		return h;
	}
};

