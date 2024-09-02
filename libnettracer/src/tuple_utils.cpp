#include "tuple_utils.h"
#include "proc_tcp.h"
#include <arpa/inet.h>
#include <fmt/core.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>

namespace {

constexpr std::array<const char*, 3> directionSigns = {"--", "<-", "->"};

}

std::string ipv6_to_string(uint64_t h, uint64_t l) {
	uint64_t addr[] = {h, l};
	char buff[48];
	return std::string(inet_ntop(AF_INET6, &addr, buff, sizeof(buff)));
}

std::string ipv4_to_string(uint32_t ip) {
	char buff[16];
	return std::string(inet_ntop(AF_INET, &ip, buff, sizeof(buff)));
}

std::string to_string(const std::pair<ipv4_tuple_t, ConnectionDirection>& tupleWithDirection) {
	auto tuple{tupleWithDirection.first};
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d}",
			ipv4_to_string(tuple.saddr),
			tuple.sport,
			directionSigns[static_cast<size_t>(tupleWithDirection.second)],
			ipv4_to_string(tuple.daddr),
			tuple.dport,
			tuple.netns);
}

std::string to_string(const std::pair<ipv6_tuple_t, ConnectionDirection>& tupleWithDirection) {
	auto tuple{tupleWithDirection.first};
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d}",
			ipv6_to_string(tuple.saddr_h, tuple.saddr_l),
			tuple.sport,
			directionSigns[static_cast<size_t>(tupleWithDirection.second)],
			ipv6_to_string(tuple.daddr_h, tuple.daddr_l),
			tuple.dport,
			tuple.netns);
}

std::string to_string(const tcp_ipv4_event_t& tuple) {
	ConnectionDirection direction{ConnectionDirection::Unknown};
	if (tuple.type == TCP_EVENT_TYPE_ACCEPT) {
		direction = ConnectionDirection::Incoming;
	} else if (tuple.type == TCP_EVENT_TYPE_CONNECT) {
		direction = ConnectionDirection::Outgoing;
	}

	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d} PID:{:d}",
			ipv4_to_string(tuple.saddr),
			tuple.sport,
			directionSigns[static_cast<size_t>(direction)],
			ipv4_to_string(tuple.daddr),
			tuple.dport,
			tuple.netns,
			tuple.pid);
}

std::string to_string(const tcp_ipv6_event_t& tuple) {
	ConnectionDirection direction{ConnectionDirection::Unknown};
	if (tuple.type == TCP_EVENT_TYPE_ACCEPT) {
		direction = ConnectionDirection::Incoming;
	} else if (tuple.type == TCP_EVENT_TYPE_CONNECT) {
		direction = ConnectionDirection::Outgoing;
	}
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d} PID:{:d}",
			ipv6_to_string(tuple.saddr_h, tuple.saddr_l),
			tuple.sport,
			directionSigns[static_cast<size_t>(direction)],
			ipv6_to_string(tuple.daddr_h, tuple.daddr_l),
			tuple.dport,
			tuple.netns,
			tuple.pid);
}

ipv4_tuple_t eventToTuple(const tcp_ipv4_event_t& evt) {
	ipv4_tuple_t tup;
	tup.saddr = evt.saddr;
	tup.daddr = evt.daddr;
	tup.sport = evt.sport;
	tup.dport = evt.dport;
	tup.netns = evt.netns;
	return tup;
}

ipv6_tuple_t eventToTuple(const tcp_ipv6_event_t& evt) {
	ipv6_tuple_t tup;
	tup.saddr_h = evt.saddr_h;
	tup.saddr_l = evt.saddr_l;
	tup.daddr_h = evt.daddr_h;
	tup.daddr_l = evt.daddr_l;
	tup.sport = evt.sport;
	tup.dport = evt.dport;
	tup.netns = evt.netns;
	return tup;
}

uint64_t swap_uint32_t(uint64_t addrpart) {
	uint64_t hpart = static_cast<uint32_t>(addrpart >> 32);
	uint64_t lpart = static_cast<uint32_t>(addrpart);
	return uint64_t{(hpart) | (lpart << 32)};
}

static bool shouldFilter(const uint32_t key) {
#ifdef __TARGET_ARCH_x86
	constexpr uint32_t loopback = 0x0000007f;
	return ((key & loopback) == loopback);
#else
	constexpr uint32_t loopback = 0x7f000000;
	return ((htonl(key) & loopback) == loopback);
#endif
}

bool shouldFilter(const ipv4_tuple_t key) {
	return shouldFilter(key.saddr);
}

bool isIpv4MappedIpv6(uint64_t addr_l, uint64_t addr_h) {
	if (addr_h != 0) {
		return false;
	}
#ifdef __TARGET_ARCH_x86
	uint64_t mask = 0x00000000ffff0000;
	return (addr_l & mask) == mask;
#else
	uint64_t mask = 0xffff;
	return (htonl(addr_l) & mask) == mask;
#endif
}

bool shouldFilter(const ipv6_tuple_t key) {
	if (isIpv4MappedIpv6(key.saddr_l, key.saddr_h)) {
		uint32_t ipv4 = static_cast<uint32_t>(key.saddr_l);
		return shouldFilter(ipv4);
	}

	constexpr uint64_t loopback = 0xffffffff00000000;
	return key.saddr_h == 0 && ((key.saddr_l & loopback) == key.saddr_l);
}

static uint32_t ipv4FromMapped(uint64_t adddrl) {
	const uint64_t mask = 0xffffffff00000000;
	return static_cast<uint32_t>((adddrl & mask) >> 32);
}

ipv4_tuple_t convertMappedIpv6Tuple(const ipv6_tuple_t ipv6) {
	ipv4_tuple_t ipv4{ipv4FromMapped(ipv6.saddr_l), ipv4FromMapped(ipv6.daddr_l), ipv6.sport, ipv6.dport, ipv6.netns};
	return ipv4;
}

std::ostream& operator<<(std::ostream& os, const ipv4_tuple_t& tup) {
	constexpr unsigned PROTO_BIT_IPV4{0};
	os << ' ' << PROTO_BIT_IPV4 << ' ' << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << tup.saddr << ' '
	   << std::setw(4) << tup.sport << ' ' << PROTO_BIT_IPV4 << ' ' << std::setw(8) << tup.daddr << ' ' << std::setw(4) << tup.dport
	   << std::dec << ' ' << std::setfill(' ');
	return os;
}

std::ostream& operator<<(std::ostream& os, const ipv6_tuple_t& tup) {
	constexpr unsigned PROTO_BIT_IPV6{1};
	if (!isIpv4MappedIpv6(tup.saddr_l, tup.saddr_h)) {
		os << ' ' << PROTO_BIT_IPV6 << ' ' << std::uppercase << std::hex << std::setfill('0') << std::setw(16) << tup.saddr_h
		   << std::setw(16) << tup.saddr_l << ' ' << std::setw(4) << tup.sport << ' ' << PROTO_BIT_IPV6 << ' ' << std::setw(16)
		   << tup.daddr_h << std::setw(16) << tup.daddr_l << ' ' << std::setw(4) << tup.dport << std::setfill(' ') << std::dec << ' ';
	} else {
		ipv4_tuple_t ipv4Tup = convertMappedIpv6Tuple(tup);
		os << ipv4Tup;
	}
	return os;
}

