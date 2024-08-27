#include "tuple_utils.h"
#include "proc_tcp.h"
#include <arpa/inet.h>
#include <fmt/core.h>
#include <functional>
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
    }
    else if (tuple.type == TCP_EVENT_TYPE_CONNECT) {
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
    }
    else if (tuple.type == TCP_EVENT_TYPE_CONNECT) {
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
	constexpr uint32_t loopback = 0x0000007f;
	return ((key & loopback) == loopback);
}

bool shouldFilter(const ipv4_tuple_t key) {
	return shouldFilter(key.saddr);
}

static bool isIpv4MappedIpv6(uint64_t addr_l) {
	uint64_t mask = 0x00000000ffff0000;
	return (addr_l && mask) == mask;
}

bool shouldFilter(const ipv6_tuple_t key) {
	if (key.saddr_h != 0) {
		return false;
	}
	if (isIpv4MappedIpv6(key.saddr_l)) {
		uint32_t ipv4 = static_cast<uint32_t>(key.saddr_l);
		return shouldFilter(ipv4);
	}
	constexpr uint64_t loopback = 0xffffffff00000000;
	return ((key.saddr_l & loopback) == key.saddr_l);
}

