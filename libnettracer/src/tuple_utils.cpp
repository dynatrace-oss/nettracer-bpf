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
    char buf[INET6_ADDRSTRLEN];
    in6_addr addr;
    auto low32 = [](uint64_t n)->uint32_t {
        return uint32_t(n & 0x00000000FFFFFFFF);
    };
    auto high32 = [](uint64_t n)->uint32_t {
        return uint32_t((n & 0xFFFFFFFF00000000) >> 32);
    };
    addr.__in6_u.__u6_addr32[0] = low32(h);
    addr.__in6_u.__u6_addr32[1] = high32(h);
    addr.__in6_u.__u6_addr32[2] = low32(l);
    addr.__in6_u.__u6_addr32[3] = high32(l);
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string to_string(const std::pair<ipv4_tuple_t, ConnectionDirection>& tupleWithDirection) {
    auto tuple{tupleWithDirection.first};
    char saBuf[16];
	char daBuf[16];
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d}",
			inet_ntop(AF_INET, &tuple.saddr, saBuf, sizeof(saBuf)),
			tuple.sport,
            directionSigns[static_cast<size_t>(tupleWithDirection.second)],
			inet_ntop(AF_INET, &tuple.daddr, daBuf, sizeof(daBuf)),
			tuple.dport,
			tuple.netns);
}

std::string to_string(const std::pair<ipv6_tuple_t, ConnectionDirection>& tupleWithDirection) {
    auto tuple{tupleWithDirection.first};
    uint64_t saArray[] = {tuple.saddr_h, tuple.saddr_l};
    uint64_t daArray[] = {tuple.daddr_h, tuple.daddr_l};

	char saBuf[46];
	char daBuf[46];
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d}",
			inet_ntop(AF_INET6, &saArray, saBuf, sizeof(saBuf)),
			tuple.sport,
            directionSigns[static_cast<size_t>(tupleWithDirection.second)],
			inet_ntop(AF_INET6, &daArray, daBuf, sizeof(daBuf)),
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

    char saBuf[16];
	char daBuf[16];
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d} PID:{:d}",
			inet_ntop(AF_INET, &tuple.saddr, saBuf, sizeof(saBuf)),
			tuple.sport,
            directionSigns[static_cast<size_t>(direction)],
			inet_ntop(AF_INET, &tuple.daddr, daBuf, sizeof(daBuf)),
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
    uint64_t saArray[] = {tuple.saddr_h, tuple.saddr_l};
    uint64_t daArray[] = {tuple.daddr_h, tuple.daddr_l};

    char saBuf[46];
	char daBuf[46];
	return fmt::format(
			"{}:{:d} {} {}:{:d} NS:{:d} PID:{:d}",
			inet_ntop(AF_INET6, &saArray, saBuf, sizeof(saBuf)),
			tuple.sport,
            directionSigns[static_cast<size_t>(direction)],
			inet_ntop(AF_INET6, &daArray, daBuf, sizeof(daBuf)),
			tuple.dport,
			tuple.netns,
			tuple.pid);
}

/* TODO pjuszczyk
The following function is not used currently because events are not printed to OS Agent yet.

std::ostream& operator<<(std::ostream& os, const tcp_ipv4_event_t& evt) {
	auto id = std::hash<tcp_ipv4_event_t>{}(evt);
	char sbuf[16];
	char dbuf[16];
	inet_ntop(AF_INET, &evt.saddr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET, &evt.daddr, dbuf, sizeof(dbuf));
	if (static_cast<EventType>(evt.type) == EventType::Accept || static_cast<EventType>(evt.type) == EventType::Connect) {
		os << static_cast<unsigned>(LineId::Connection) << " " << sbuf << " " << evt.sport << " " << dbuf << " " << evt.dport << " "
		   << evt.netns << " " << evt.pid << " " << id << "\n";
	}
	os << static_cast<unsigned>(LineId::Event) << " " << evt.type << " " << evt.timestamp << " " << id << std::endl;
	return os;
}
*/

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
