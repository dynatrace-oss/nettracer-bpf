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

#include "bpf_program/nettracer-bpf.h"
#include "proc_tcp.h"
#include <boost/container_hash/hash.hpp>
#include <array>
#include <string>
#include <tuple>
#include <utility>


inline bool operator==(const ipv4_tuple_t& lhs, const ipv4_tuple_t& rhs) {
	return std::tie(lhs.saddr, lhs.daddr, lhs.sport, lhs.dport, lhs.netns) ==
		std::tie(rhs.saddr, rhs.daddr, rhs.sport, rhs.dport, rhs.netns);
}
inline bool operator!=(const ipv4_tuple_t& lhs, const ipv4_tuple_t& rhs) {
	return !(lhs == rhs);
}

inline bool operator==(const ipv6_tuple_t& lhs, const ipv6_tuple_t& rhs) {
	return std::tie(lhs.saddr_h, lhs.daddr_h, lhs.saddr_l, lhs.daddr_l, lhs.sport, lhs.dport, lhs.netns) ==
		std::tie(rhs.saddr_h, rhs.daddr_h, rhs.saddr_l, rhs.daddr_l, rhs.sport, rhs.dport, rhs.netns);
}
inline bool operator!=(const ipv6_tuple_t& lhs, const ipv6_tuple_t& rhs) {
	return !(lhs == rhs);
}

template <>
struct std::hash<ipv4_tuple_t> {
	std::size_t operator()(const ipv4_tuple_t& t) const noexcept {
		std::size_t h = 0;
		boost::hash_combine(h, t.saddr);
		boost::hash_combine(h, t.daddr);
		boost::hash_combine(h, t.sport);
		boost::hash_combine(h, t.dport);
		return h;
	}
};

template <>
struct std::hash<ipv6_tuple_t> {
	std::size_t operator()(const ipv6_tuple_t& t) const noexcept {
		std::size_t h = 0;
		boost::hash_combine(h, t.saddr_h);
		boost::hash_combine(h, t.saddr_l);
		boost::hash_combine(h, t.daddr_h);
		boost::hash_combine(h, t.daddr_l);
		boost::hash_combine(h, t.sport);
		boost::hash_combine(h, t.dport);
		return h;
	}
};

// format ipv6 address - h and l are 64 bit and in network byte order
std::string ipv6_to_string(uint64_t h, uint64_t l);
std::string ipv4_to_string(uint32_t addr);

std::string to_string(const ipv4_tuple_t& tup, ConnectionDirection direction);
std::string to_string(const ipv6_tuple_t& tup, ConnectionDirection direction);
std::ostream& operator<<(std::ostream& os, const ipv4_tuple_t& tup);
std::ostream& operator<<(std::ostream& os, const ipv6_tuple_t& tup);

uint64_t swap_uint32_t(uint64_t addrpart);
std::string short_num(uint64_t num);

inline std::string to_string(const ipv4_tuple_t& tuple) {
	return to_string(tuple, ConnectionDirection::Unknown);
}

inline std::string to_string(const ipv6_tuple_t& tuple) {
	return to_string(tuple, ConnectionDirection::Unknown);
}

std::string to_string(const tcp_ipv4_event_t& tuple);
std::string to_string(const tcp_ipv6_event_t& tuple);

ipv4_tuple_t eventToTuple(const tcp_ipv4_event_t& evt);
ipv6_tuple_t eventToTuple(const tcp_ipv6_event_t& evt);

bool shouldFilter(const ipv4_tuple_t key);
bool shouldFilter(const ipv6_tuple_t key);
bool isIpv4MappedIpv6(uint64_t addr_l, uint64_t addr_h);
ipv4_tuple_t convertMappedIpv6Tuple(const ipv6_tuple_t ipv6);

namespace netstat {
struct State;
}
std::ostream& operator<<(std::ostream& os, const netstat::State& s);
