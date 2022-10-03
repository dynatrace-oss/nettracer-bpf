#pragma once

#include "bpf_program/nettracer-bpf.h"
#include "proc_tcp.h"

#include <array>
#include <string>
#include <tuple>
#include <utility>

constexpr std::array<const char*, 5> name_of_evt = {"connect", "accept", "close", ""};

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

namespace std {

template <>
struct hash<ipv4_tuple_t> {
	std::size_t operator()(const ipv4_tuple_t& t) const noexcept {
		std::size_t h1 = std::hash<decltype(t.saddr)>{}(t.saddr);
		std::size_t h2 = std::hash<decltype(t.daddr)>{}(t.daddr);
		std::size_t h3 = std::hash<decltype(t.sport)>{}(t.sport);
		std::size_t h4 = std::hash<decltype(t.dport)>{}(t.dport);
		return h1 ^ (h2 << 1) ^ (h3 << 1) ^ h4; // or use boost::hash_combine
	}
};

/* TODO pjuszczyk
The following function is not used currently because events are not printed to OS Agent yet.

template <>
struct hash<tcp_ipv4_event_t> {
	std::size_t operator()(const tcp_ipv4_event_t& t) const noexcept {
		std::size_t h1 = std::hash<decltype(t.saddr)>{}(t.saddr);
		std::size_t h2 = std::hash<decltype(t.daddr)>{}(t.daddr);
		std::size_t h3 = std::hash<decltype(t.sport)>{}(t.sport);
		std::size_t h4 = std::hash<decltype(t.dport)>{}(t.dport);
		return h1 ^ (h2 << 1) ^ (h3 << 1) ^ h4; // or use boost::hash_combine
	}
};
*/

template <>
struct hash<ipv6_tuple_t> {
	std::size_t operator()(const ipv6_tuple_t& t) const noexcept {
		std::size_t h1 = std::hash<decltype(t.saddr_h)>{}(t.saddr_h);
		std::size_t h2 = std::hash<decltype(t.saddr_l)>{}(t.saddr_l);
		std::size_t h3 = std::hash<decltype(t.daddr_h)>{}(t.daddr_h);
		std::size_t h4 = std::hash<decltype(t.daddr_l)>{}(t.daddr_l);
		std::size_t h5 = std::hash<decltype(t.sport)>{}(t.sport);
		std::size_t h6 = std::hash<decltype(t.dport)>{}(t.dport);
		return h1 ^ (h2 << 1) ^ (h3 << 1) ^ (h4 << 1) ^ h5 ^ (h5 << 1) ^ h6; // or use boost::hash_combine
	}
};

} // namespace std

enum class LineId { Connection = 1, Event, Metrics };
enum class EventType { Accept = 1, Connect, Close };

/* TODO pjuszczyk
The following function is not used currently because events are not printed to OS Agent yet.

std::ostream& operator<<(std::ostream& os, const tcp_ipv4_event_t& evt);
*/

// format ipv6 address - h and l are 64 bit and in network byte order
std::string ipv6_to_string(uint64_t h, uint64_t l);
std::string ipv4_to_string(uint32_t addr);

std::string to_string(const std::pair<ipv4_tuple_t, ConnectionDirection>& tupleWithDirection);
std::string to_string(const std::pair<ipv6_tuple_t, ConnectionDirection>& tupleWithDirection);

inline std::string to_string(const ipv4_tuple_t& tuple) {
	return to_string(std::make_pair(tuple, ConnectionDirection::Unknown));
}
inline std::string to_string(const ipv6_tuple_t& tuple) {
	return to_string(std::make_pair(tuple, ConnectionDirection::Unknown));
}

std::string to_string(const tcp_ipv4_event_t& tuple);
std::string to_string(const tcp_ipv6_event_t& tuple);

ipv4_tuple_t eventToTuple(const tcp_ipv4_event_t& evt);
ipv6_tuple_t eventToTuple(const tcp_ipv6_event_t& evt);
