#pragma once

#include "connections_printing.h"
#include "mock_bpf_maps.h"
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

class BPFMapsProcessingTest : public testing::Test {
protected:
	virtual ~BPFMapsProcessingTest() = default;

	void setUpIPv4Maps() {
		ipv4PIDsMap = &mockMapsWrapper.createMap<ipv4_tuple_t, pid_comm_t>(ipv4FDs.pid_fd);
		ipv4StatsMap = &mockMapsWrapper.createMap<ipv4_tuple_t, stats_t>(ipv4FDs.stats_fd);
		ipv4TCPStatsMap = &mockMapsWrapper.createMap<ipv4_tuple_t, tcp_stats_t>(ipv4FDs.tcp_stats_fd);

		ipv4ConnsState = std::make_unique<ConnectionsState<ipv4_tuple_t>>(MapTuple2Details<ipv4_tuple_t>{});
	}

	void setUpIPv6Maps() {
		ipv6PIDsMap = &mockMapsWrapper.createMap<ipv6_tuple_t, pid_comm_t>(ipv6FDs.pid_fd);
		ipv6StatsMap = &mockMapsWrapper.createMap<ipv6_tuple_t, stats_t>(ipv6FDs.stats_fd);
		ipv6TCPStatsMap = &mockMapsWrapper.createMap<ipv6_tuple_t, tcp_stats_t>(ipv6FDs.tcp_stats_fd);

		ipv6ConnsState = std::make_unique<ConnectionsState<ipv6_tuple_t>>(MapTuple2Details<ipv6_tuple_t>{});
	}

	virtual void SetUp() override {
		setUpIPv4Maps();
		setUpIPv6Maps();
	}

	virtual void TearDown() override {
		mockMapsWrapper.clearMaps();
	}

	static std::vector<ipv4_tuple_t> getIPv4Tuples() {
		return std::vector<ipv4_tuple_t>{
			ipv4_tuple_t{addrA, addrB, portA, portB, netns},
			ipv4_tuple_t{addrB, addrA, portB, portA, netns},
			ipv4_tuple_t{addrB, addrB, portB, portA, netns},
			ipv4_tuple_t{addrB, addrB, portA, portB, netns}
		};
	}

	static std::vector<ipv6_tuple_t> getIPv6Tuples() {
		return std::vector<ipv6_tuple_t>{
			ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns},
			ipv6_tuple_t{addrBh, addrBl, addrAh, addrAl, portB, portA, netns},
			ipv6_tuple_t{addrBh, addrBl, addrBh, addrBl, portB, portA, netns},
			ipv6_tuple_t{addrBh, addrBl, addrBh, addrBl, portA, portB, netns}
		};
	}

	template<typename Tuple>
	static void insertConnsIntoConnsState(const std::vector<std::pair<Tuple, pid_comm_t>>& conns, ConnectionsState<Tuple>& connsState) {
		bool outgoing{true};
		for (const auto& tupleAndPIDComm : conns) {
			connsState.connsDetails.insert(std::make_pair(tupleAndPIDComm.first, ConnectionDetails{tupleAndPIDComm.second.pid, outgoing ? ConnectionDirection::Outgoing : ConnectionDirection::Incoming}));
			outgoing = !outgoing;
		}
	}

	template<typename Tuple>
	static void addConns(std::unordered_map<Tuple, pid_comm_t>& pidsMap, ConnectionsState<Tuple>& connsState, const std::vector<Tuple>& tuples) {
		std::vector<std::pair<Tuple, pid_comm_t>> conns{
			std::make_pair(tuples[0], pid_comm_t{pidMax, CONN_ACTIVE}),
			std::make_pair(tuples[1], pid_comm_t{0, CONN_ACTIVE}),
			std::make_pair(tuples[2], pid_comm_t{pidMax, CONN_ACTIVE}),
			std::make_pair(tuples[3], pid_comm_t{pidMax, CONN_ACTIVE})
		};

		for (const auto& tupleAndPIDComm : conns) {
			pidsMap.insert(tupleAndPIDComm);
		}

		insertConnsIntoConnsState(conns, connsState);
	}

	void addIPv4Conns() {
		addConns(*ipv4PIDsMap, *ipv4ConnsState, getIPv4Tuples());
	}

	void addIPv6Conns() {
		addConns(*ipv6PIDsMap, *ipv6ConnsState, getIPv6Tuples());
	}

	template<typename Tuple>
	static void addStats(std::unordered_map<Tuple, stats_t>& statsMap, const std::vector<Tuple>& tuples) {
		statsMap.insert(std::make_pair(tuples[0], stats_t{0, 0}));
		statsMap.insert(std::make_pair(tuples[1], stats_t{0, 0}));

		statsMap.insert(std::make_pair(tuples[2], stats_t{0, bytesMax}));
		statsMap.insert(std::make_pair(tuples[3], stats_t{bytesMax, 0}));
	}

	void addIPv4Stats() {
		addStats(*ipv4StatsMap, getIPv4Tuples());
	}

	void addIPv6Stats() {
		addStats(*ipv6StatsMap, getIPv6Tuples());
	}

	template<typename Tuple>
	static void addTCPStats(std::unordered_map<Tuple, tcp_stats_t>& tcpStatsMap, const std::vector<Tuple>& tuples) {
		tcpStatsMap.insert(std::make_pair(tuples[0], tcp_stats_t{0, 0, 0, 0, 0}));
		tcpStatsMap.insert(std::make_pair(tuples[1], tcp_stats_t{0, 0, 0, 0, 0}));

		tcpStatsMap.insert(std::make_pair(tuples[2], tcp_stats_t{retransMax, segsMax, segsMax, rttMax, rttVarMax}));
		tcpStatsMap.insert(std::make_pair(tuples[3], tcp_stats_t{retransMax, segsMax, segsMax, rttMax, rttVarMax}));
	}

	void addIPv4TCPStats() {
		addTCPStats(*ipv4TCPStatsMap, getIPv4Tuples());
	}

	void addIPv6TCPStats() {
		addTCPStats(*ipv6TCPStatsMap, getIPv6Tuples());
	}

	static inline const bpf_fds ipv4FDs{1, 2, 3}, ipv6FDs{4, 5, 6};

	MockBPFMapsWrapper mockMapsWrapper;

	std::unordered_map<ipv4_tuple_t, pid_comm_t>* ipv4PIDsMap;
	std::unordered_map<ipv4_tuple_t, stats_t>* ipv4StatsMap;
	std::unordered_map<ipv4_tuple_t, tcp_stats_t>* ipv4TCPStatsMap;

	std::unordered_map<ipv6_tuple_t, pid_comm_t>* ipv6PIDsMap;
	std::unordered_map<ipv6_tuple_t, stats_t>* ipv6StatsMap;
	std::unordered_map<ipv6_tuple_t, tcp_stats_t>* ipv6TCPStatsMap;

	std::unique_ptr<ConnectionsState<ipv4_tuple_t>> ipv4ConnsState;
	std::unique_ptr<ConnectionsState<ipv6_tuple_t>> ipv6ConnsState;

	static inline const uint32_t addrA{0x0100007F}, addrB{0x04030201};
	static inline const uint64_t addrAh{0x3412341234123412}, addrAl{0x7856785678567856}, addrBh{0xffffffffffffffff}, addrBl{0x0};
	static inline const uint16_t portA{50000}, portB{80};
	static inline const uint32_t netns{1000};
	static inline const uint64_t pidMax{std::numeric_limits<uint64_t>::max()};
	static inline const uint64_t bytesMax{std::numeric_limits<uint64_t>::max()};
	static inline const uint64_t retransMax{std::numeric_limits<uint64_t>::max()};
	static inline const uint32_t segsMax{std::numeric_limits<uint32_t>::max()};
	static inline const uint32_t rttMax{std::numeric_limits<uint32_t>::max()};
	static inline const uint32_t rttVarMax{std::numeric_limits<uint32_t>::max()};
};
