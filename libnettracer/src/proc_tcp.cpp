#include "proc_tcp.h"

#include "bpf_generic/src/log.h"
#include "tuple_utils.h"

#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace {

// fragment based on enum found in <include/net/tcp_states.h>
constexpr uint16_t TCP_ESTABLISHED = 1;
constexpr uint16_t TCP_LISTEN = 10;

}

namespace fs = std::filesystem;

std::optional<std::pair<ipv4_tuple_t, ConnectionDetails>> parseProcIPv4ConnectionLine(const std::string& line) {
    using std::hex;

    // for now, forget about PID and netns
    uint32_t localAddress, remoteAddress;
    uint16_t localPort, remotePort;
    uint16_t state;
    int skipInt;

    std::istringstream iss{line};
    iss >> skipInt;
    iss.ignore(std::numeric_limits<std::streamsize>::max(), ' ');
    iss >> hex >> localAddress;
    iss.ignore(1);
    iss >> hex >> localPort;
    iss.ignore(1);
    iss >> hex >> remoteAddress;
    iss.ignore(1);
    iss >> hex >> remotePort >> state;

    if (state == TCP_ESTABLISHED) {
        ipv4_tuple_t conn{
            localAddress,
            remoteAddress,
            localPort,
            remotePort,
            0
        };
        ConnectionDetails details{
            0,
            ConnectionDirection::Outgoing
        };
        return {std::make_pair(conn, details)};
    }
    else if (state == TCP_LISTEN) {
        ipv4_tuple_t conn{
            remoteAddress,
            localAddress,
            remotePort,
            localPort,
            0
        };
        ConnectionDetails details{
            0,
            ConnectionDirection::Incoming
        };
        return {std::make_pair(conn, details)};
    }
    else { // connection is probably closing
        return std::nullopt;

    }
}

std::optional<std::pair<ipv6_tuple_t, ConnectionDetails>> parseProcIPv6ConnectionLine(const std::string& line) {
    using std::hex;

    // for now, forget about PID and netns
    uint64_t localAddress[2], remoteAddress[2];
    uint16_t localPort, remotePort;
    uint16_t state;
    char localAddressTemp[32+1];
    char remoteAddressTemp[32+1];
    int skipInt;

    std::istringstream iss{line};
    iss >> skipInt;
    iss.ignore(std::numeric_limits<std::streamsize>::max(), ' ');
    iss.get(localAddressTemp, 32+1, ':');
    iss.ignore(1);
    iss >> hex >> localPort;
    iss.ignore(1);
    iss.get(remoteAddressTemp, 32+1, ':');
    iss.ignore(1);
    iss >> hex >> remotePort >> state;

    std::string localAddressStr{localAddressTemp, 32+1};
    std::string remoteAddressStr{remoteAddressTemp, 32+1};
    localAddressStr.insert(16, 1, ' ');
    remoteAddressStr.insert(16, 1, ' ');

    iss.str(localAddressStr);
    iss >> hex >> localAddress[0] >> localAddress[1];
    iss.str(remoteAddressStr);
    iss >> hex >> remoteAddress[0] >> remoteAddress[1];

    if (state == TCP_ESTABLISHED) {
        ipv6_tuple_t conn{
            localAddress[0],
            localAddress[1],
            remoteAddress[0],
            remoteAddress[1],
            localPort,
            remotePort,
            0
        };
        ConnectionDetails details{
            0,
            ConnectionDirection::Outgoing
        };
        return {std::make_pair(conn, details)};
    }
    else if (state == TCP_LISTEN) {
        ipv6_tuple_t conn{
            remoteAddress[0],
            remoteAddress[1],
            localAddress[0],
            localAddress[1],
            remotePort,
            localPort,
            0
        };
        ConnectionDetails details{
            0,
            ConnectionDirection::Incoming
        };
        return {std::make_pair(conn, details)};
    }
    else { // connection is probably closing
        return std::nullopt;
    }
}

namespace {

template<typename ConnectionType>
std::string getProcConnectionTablesFileName() {
    return "";
}
template<>
std::string getProcConnectionTablesFileName<ipv4_tuple_t>() {
    return "/proc/net/tcp";
}
template<>
std::string getProcConnectionTablesFileName<ipv6_tuple_t>() {
    return "/proc/net/tcp6";
}

template<typename ConnectionType>
std::optional<std::pair<ConnectionType, ConnectionDetails>> parseProcConnectionLine(const std::string& line) {
    return std::nullopt;
}
template<>
std::optional<std::pair<ipv4_tuple_t, ConnectionDetails>> parseProcConnectionLine(const std::string& line) {
    return parseProcIPv4ConnectionLine(line);
}
template<>
std::optional<std::pair<ipv6_tuple_t, ConnectionDetails>> parseProcConnectionLine(const std::string& line) {
    return parseProcIPv6ConnectionLine(line);
}

}

template<typename ConnectionType>
std::unordered_map<ConnectionType, ConnectionDetails> getCurrentConnections() {
    auto fileName{getProcConnectionTablesFileName<ConnectionType>()};
    if (!std::filesystem::is_regular_file(fileName)) {
        throw std::runtime_error{"Couldn't read /proc connection tables. File name: " + fileName};
    }

    std::unordered_map<ConnectionType, ConnectionDetails> conns;

    std::ifstream input{fileName};
    std::string line;
    std::getline(input, line); // skip header
    unsigned omittedConnsCnt = 0;
    LOG_DEBUG("Reading connections from {}...", fileName);
    while (std::getline(input, line)) {
        auto conn{parseProcConnectionLine<ConnectionType>(line)};
        if (conn) {
            conns.insert({conn->first, conn->second});
            LOG_DEBUG(to_string(std::make_pair(conn->first, conn->second.direction)));
        }
        else {
            ++omittedConnsCnt;
        }
    }
    LOG_DEBUG("Read {:d} connections from {} (omitted {} connections)", conns.size(), fileName, omittedConnsCnt);

    return conns;
}

template std::unordered_map<ipv4_tuple_t, ConnectionDetails> getCurrentConnections();
template std::unordered_map<ipv6_tuple_t, ConnectionDetails> getCurrentConnections();

namespace {

template <typename IPTYPE>
std::pair<iNode, Connection<IPTYPE>> parseLine(const std::string& line, uint32_t ns);

template <>
std::pair<iNode, Connection<ipv4_tuple_t>> parseLine(const std::string& line, uint32_t ns) {
	using std::hex;
	iNode in;
	uint32_t localAddress, remoteAddress;
	uint16_t localPort, remotePort;
	uint16_t state;
	int skipInt;

	std::istringstream iss{line};
	iss.exceptions(std::ios::failbit);
	iss >> skipInt;
	iss.ignore(std::numeric_limits<std::streamsize>::max(), ' ');
	iss >> hex >> localAddress;
	iss.ignore(1);
	iss >> hex >> localPort;
	iss.ignore(1);
	iss >> hex >> remoteAddress;
	iss.ignore(1);
	iss >> hex >> remotePort >> state;
	Connection<ipv4_tuple_t> conn;
	conn.ep = ipv4_tuple_t{localAddress, remoteAddress, localPort, remotePort, ns};

	iss >> hex >> skipInt;
	iss.ignore(1);
	iss >> hex >> skipInt;

	iss >> hex >> skipInt;
	iss.ignore(1);
	iss >> hex >> skipInt;
	iss >> hex >> skipInt >> std::dec >> skipInt >> std::dec >> skipInt >> std::dec >> in;
	return {in, conn};
}

template <>
std::pair<iNode, Connection<ipv6_tuple_t>> parseLine(const std::string& line, uint32_t ns) {
	using std::hex;
	iNode in;
	uint64_t localAddress[2], remoteAddress[2];
	uint16_t localPort, remotePort;
	uint16_t state;
	int skipInt;
	char localIp1[17], localIp2[17];
	char remoteIp1[17], remoteIp2[17];

	std::istringstream iss{line};
	iss.exceptions(std::ios::failbit);
	iss >> skipInt;
	// iss.ignore(std::numeric_limits<std::streamsize>::max(), ' ');
	iss.ignore(2);
	iss.get(localIp1, 17);
	iss.get(localIp2, 17);
	iss.ignore(1);
	iss >> hex >> localPort;
	iss.ignore(1);
	iss.get(remoteIp1, 17);
	iss.get(remoteIp2, 17);
	iss.ignore(1);
	iss >> hex >> remotePort >> state;

	localIp1[16] = 0;
	localIp2[16] = 0;
	remoteIp2[16] = 0;
	remoteIp2[16] = 0;
	localAddress[0] = std::strtoull(localIp1, nullptr, 16);
	localAddress[1] = std::strtoull(localIp2, nullptr, 16);
	remoteAddress[0] = std::strtoull(remoteIp1, nullptr, 16);
	remoteAddress[1] = std::strtoull(remoteIp2, nullptr, 16);

	Connection<ipv6_tuple_t> conn;
	conn.ep = ipv6_tuple_t{localAddress[0], localAddress[1], remoteAddress[0], remoteAddress[1], localPort, remotePort, ns};

	iss >> hex >> skipInt;
	iss.ignore(1);
	iss >> hex >> skipInt;
	iss >> hex >> skipInt;
	iss.ignore(1);
	iss >> hex >> skipInt;

	iss >> hex >> skipInt >> std::dec >> skipInt >> std::dec >> skipInt >> std::dec >> in;
	return {in, conn};
}

template <typename IPTYPE>
bool readTcpFile(tcpTable<IPTYPE> & table, const fs::path& fileName, uint32_t ns) {
	if (!fs::is_regular_file(fileName)) {
		LOG_INFO("Couldn't read /proc connection table: " + fileName.string());
		return false;
	}

	std::ifstream input{fileName.string()};
	std::string line;
	std::getline(input, line); // skip header
	while (std::getline(input, line)) {
		auto conn = parseLine<IPTYPE>(line, ns);
		if (conn.second.ep.dport && conn.first) {
			table.insert(conn);
		}
	}

	return true;
}

uint32_t readNetNS(const fs::path& p) {
	std::string s;
	try {
		if (!fs::exists(p) || !fs::is_symlink(p)) {
			return 0;
		}

		s = fs::read_symlink(p).string();
	} catch (fs::filesystem_error& e) {
		LOG_DEBUG("Couldn't read namespace file: " + p.string());
		return 0;
	}
	auto pos = s.find("net");
	if (pos == std::string::npos) {
		return 0;
	}

	pos = s.find_first_of("123456789");
	if (pos == std::string::npos) {
		return 0;
	}

	uint32_t ns = std::stoul(s.substr(pos));
	return ns;
}

template <typename IPTYPE>
tcpTable<IPTYPE> readTcpTableImpl(const fs::path& root, const fs::path& file) {
	tcpTable<IPTYPE> table;
	std::vector<uint32_t> visited;
	uint32_t currnet_ns = 0;
	currnet_ns = readNetNS(root / "self" / "ns" / "net");
	if (currnet_ns) {
		if (readTcpFile<IPTYPE>(table, root / "net" / file, currnet_ns)) {
			visited.push_back(currnet_ns);
		}
	}

	unsigned netNSReadFails = 0;
	unsigned allNetNSReads = 0;

	for (auto& p : fs::directory_iterator(root)) {
		std::string pid = p.path().filename();

		if (!std::all_of(pid.begin(), pid.end(), ::isdigit)) {
			continue;
		}

		uint32_t npid = std::stoul(pid);

		currnet_ns = readNetNS(p.path() / "ns" / "net");
		++allNetNSReads;
		if (!currnet_ns) {
			++netNSReadFails;
			continue;
		}
		if (!std::any_of(visited.begin(), visited.end(), [currnet_ns](auto& i) { return i == currnet_ns; })) {
			if (!readTcpFile<IPTYPE>(table, p.path() / "net" / file, currnet_ns))
				continue;

			LOG_DEBUG("tcptable for nondeafult ns: {} read", currnet_ns);
			visited.push_back(currnet_ns);
		}
		auto fdDir = p.path() / "fd";

		for (auto& p : fs::directory_iterator(fdDir)) {
			std::string s;
			try {
				if (!fs::exists(p) || !fs::is_symlink(p))
					continue;

				s = fs::read_symlink(p).string();
			} catch (fs::filesystem_error& e) {
				continue;
			}

			auto pos = s.find("socket");
			if (pos == std::string::npos)
				continue;

			pos = s.find_first_of("123456789");

			if (pos == std::string::npos)
				continue;

			iNode in;
			try {
				in = std::stoul(s.substr(pos));
			} catch (std::exception& e) {
				continue;
			}
			auto is = table.find(in);
			if (is == table.end())
				continue;

			is->second.pid = npid;
		}
	}

	constexpr float readFailsWarningThreshold = 0.5;
	if (netNSReadFails > readFailsWarningThreshold * allNetNSReads) {
		LOG_WARN("Out of {:d}, {:d} net namespace files couldn't be read. Maybe CAP_SYS_PTRACE capability is missing?", allNetNSReads, netNSReadFails);
	}

	return table;
}
}

tcpTable<ipv4_tuple_t> readTcpTable(const char* root) {
	return readTcpTableImpl<ipv4_tuple_t>(root, "tcp");
}

tcpTable<ipv6_tuple_t> readTcpTable6(const char* root) {
	return readTcpTableImpl<ipv6_tuple_t>(root, "tcp6");
}

namespace test {
std::pair<iNode, Connection<ipv6_tuple_t>> parseLine6(const std::string& line, uint32_t ns) {
	return parseLine<ipv6_tuple_t>(line, ns);
}
std::pair<iNode, Connection<ipv4_tuple_t>> parseLine4(const std::string& line, uint32_t ns) {
	return parseLine<ipv4_tuple_t>(line, ns);
}
} // namespace test
