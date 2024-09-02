#pragma once

#include "bpf_program/nettracer-bpf.h"

#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

enum class ConnectionDirection : unsigned char { Unknown, Incoming, Outgoing };

struct ConnectionDetails {
    uint64_t pid;
    ConnectionDirection direction;
};

[[deprecated]]
std::optional<std::pair<ipv4_tuple_t, ConnectionDetails>> parseProcIPv4ConnectionLine(const std::string& line);
[[deprecated]]
std::optional<std::pair<ipv6_tuple_t, ConnectionDetails>> parseProcIPv6ConnectionLine(const std::string& line);

template<typename ConnectionType>
using MapTuple2Details = std::unordered_map<ConnectionType, ConnectionDetails>;

template<typename ConnectionType>
MapTuple2Details<ConnectionType> getCurrentConnections();

template <typename IPTYPE>
struct Connection {
	IPTYPE ep;
	int64_t pid;
	ConnectionDirection direction;
};

using iNode = unsigned long;
template<typename IPTYPE>
using tcpTable = std::unordered_map<iNode,Connection<IPTYPE>>;

tcpTable<ipv4_tuple_t> readTcpTable(const char* root, bool filter);
tcpTable<ipv6_tuple_t> readTcpTable6(const char* root, bool filter);

namespace test {
std::pair<iNode, Connection<ipv6_tuple_t>> parseLine6(const std::string& line, uint32_t ns);
std::pair<iNode, Connection<ipv4_tuple_t>> parseLine4(const std::string& line, uint32_t ns);
} // namespace test
