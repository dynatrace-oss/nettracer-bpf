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
