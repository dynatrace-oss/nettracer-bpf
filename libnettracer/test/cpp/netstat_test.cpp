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
#include <gtest/gtest.h>
#include "configuration.h"
#include "netstat.h"
#include "bpf_maps_processing_testing.h"
#include <fmt/core.h>
#include <algorithm>
#include <memory>
#include <sstream>

using namespace netstat;
using namespace std::string_literals;
using testing::Return;

class TestNetStat : public NetStat {
public:
	explicit TestNetStat(config::ExitCtrl& e, bool inc, bpf::BPFMapsWrapper* mapsWrapper, std::ostream* os)
		: NetStat(e, inc, false, false) {
		this->mapsWrapper = mapsWrapper;
		this->os = os;
	}

	MOCK_METHOD(system_clock::time_point, getCurrentTimeFromSystemClock, (), (const, override));
	MOCK_METHOD(steady_clock::time_point, getCurrentTimeFromSteadyClock, (), (const, override));

	// make those methods public to make them easier to test (testing the main netstat loop is troublesome...)
	using NetStat::update;
	using NetStat::print;
	using NetStat::clean;
	using NetStat::clean_bpf;
	using NetStat::connections;
	using NetStat::listenPorts;
	using NetStat::resolveOldConnections;

};

class NetStatTest : public BPFMapsProcessingTest {
protected:
	void SetUp() override {
		BPFMapsProcessingTest::SetUp();

		exitCtrl = std::make_unique<config::ExitCtrl>();
		os = std::make_unique<std::ostringstream>();
	}

	void TearDown() override {
		BPFMapsProcessingTest::TearDown();

		netstat.reset();
	}

	void setUpNetStat(bool incremental = false) {
		netstat = std::make_unique<TestNetStat>(*exitCtrl, incremental, &mockMapsWrapper, os.get());
	}
	
	template<typename Tuple>
	static void markConnsAsClosed(std::unordered_map<Tuple, netstat::Connection>& conns) {
		for (auto& tupleAndConn : conns) {
			tupleAndConn.second.state.Closed = 1;
		}
	}

	void markIPv4ConnsAsClosed() {
		markConnsAsClosed(netstat->connections<ipv4_tuple_t>());
	}

	void markIPv6ConnsAsClosed() {
		markConnsAsClosed(netstat->connections<ipv6_tuple_t>());
	}

	template<typename Tuple>
	void checkIfNetstatContainsConnection(const Tuple& conn) {
		SCOPED_TRACE("Searched conn: "s + to_string(conn));
		EXPECT_NE(netstat->connections<Tuple>().find(conn), netstat->connections<Tuple>().cend());
	}
	template<typename Tuple>
	void checkIfNetstatStatsAreCorrect(const Tuple& conn, const std::unordered_map<Tuple, stats_t>& bpfMap) {
		SCOPED_TRACE("Stats for conn: "s + to_string(conn));
		const auto& netstatStats{netstat->connections<Tuple>().at(conn)};
		const auto& bpfMapStats{bpfMap.at(conn)};
		EXPECT_EQ(netstatStats.bytes_sent, bpfMapStats.sent_bytes);
		EXPECT_EQ(netstatStats.bytes_received, bpfMapStats.received_bytes);
	}
	
	template<typename Tuple>
	void checkIfNetstatTCPStatsAreCorrect(const Tuple& conn, const std::unordered_map<Tuple, tcp_stats_t>& bpfMap) {
		SCOPED_TRACE("TCP stats for conn: "s + to_string(conn));
		const auto& netstatTCPStats{netstat->connections<Tuple>().at(conn)};
		const auto& bpfMapTCPStats{bpfMap.at(conn)};
		EXPECT_EQ(netstatTCPStats.pkts_sent, bpfMapTCPStats.segs_out);
		EXPECT_EQ(netstatTCPStats.pkts_received, bpfMapTCPStats.segs_in);
		EXPECT_EQ(netstatTCPStats.pkts_retrans, bpfMapTCPStats.retransmissions);
		EXPECT_EQ(netstatTCPStats.rtt, bpfMapTCPStats.rtt);
		EXPECT_EQ(netstatTCPStats.rtt_var, bpfMapTCPStats.rtt_var);
	}

	std::unique_ptr<config::ExitCtrl> exitCtrl;
	std::unique_ptr<std::ostringstream> os;
	std::unique_ptr<TestNetStat> netstat;
};

TEST_F(NetStatTest, testUpdateEmptyIPv4) {
	setUpNetStat();
	netstat->update<ipv4_tuple_t>(ipv4FDs);
	EXPECT_TRUE(netstat->connections<ipv4_tuple_t>().empty());
}

TEST_F(NetStatTest, testUpdateEmptyIPv6) {
	setUpNetStat();
	netstat->update<ipv6_tuple_t>(ipv6FDs);
	EXPECT_TRUE(netstat->connections<ipv6_tuple_t>().empty());
}

TEST_F(NetStatTest, updateConnsfromStats) {
	setUpNetStat();
	addIPv4Stats();
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(2);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	const auto& netstatConns{netstat->connections<ipv4_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Established; });
}

TEST_F(NetStatTest, updateConnsfromStatsPv6) {
	setUpNetStat();
	addIPv6Stats();
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(2);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	const auto& netstatConns{netstat->connections<ipv6_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Established; });
}


TEST_F(NetStatTest, testCleanNotClosedPv4) {
	setUpNetStat();
	addIPv4Stats();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(3);
	netstat->update<ipv4_tuple_t>(ipv4FDs);
	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);
	EXPECT_FALSE(ipv4StatsMap->empty());
}

TEST_F(NetStatTest, testCleanNotClosedIPv6) {
	setUpNetStat();
	addIPv6Stats();
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);
	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);
	EXPECT_FALSE(ipv6StatsMap->empty());
}

TEST_F(NetStatTest, testCleanClosedIPv4) {
	setUpNetStat();
	addIPv4Stats();
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(4);
	netstat->update<ipv4_tuple_t>(ipv4FDs);
	markIPv4ConnsAsClosed();
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), 4u);
	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);
	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
	EXPECT_FALSE(netstat->connections<ipv4_tuple_t>().empty());
	netstat->clean<ipv4_tuple_t>();
	EXPECT_TRUE(netstat->connections<ipv4_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanClosedIPv6) {
	setUpNetStat();
	addIPv6Stats();
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(4);
	netstat->update<ipv6_tuple_t>(ipv6FDs);
	markIPv6ConnsAsClosed();
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), 4u);
	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);
	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
	EXPECT_FALSE(netstat->connections<ipv6_tuple_t>().empty());
	netstat->clean<ipv6_tuple_t>();
	EXPECT_TRUE(netstat->connections<ipv6_tuple_t>().empty());
}

TEST_F(NetStatTest, resolveDirectionForServer) {
	setUpNetStat();
	auto& lports = netstat->listenPorts<ipv4_tuple_t>();
	auto& aggrs = netstat->connections<ipv4_tuple_t>();

	ipv4_tuple_t sock{};
	sock.sport = 22;
	sock.netns = 11;
	lports.insert({sock, 1});
	sock.dport = 2222;
    sock.saddr = 0x11;
	sock.daddr  = 0x66;
	aggrs.insert({sock, netstat::Connection{}});
	auto sockData = aggrs.begin();
	EXPECT_EQ(sockData->second.state.Direction, 0);
	EXPECT_EQ(sockData->second.state.Established, 0);
	netstat->resolveOldConnections<ipv4_tuple_t>();
	EXPECT_EQ(sockData->second.state.Direction, 1);
	EXPECT_EQ(sockData->second.state.Established, 1);
}

TEST_F(NetStatTest, resolveDirectionForClient) {
	setUpNetStat();
	auto& lports = netstat->listenPorts<ipv4_tuple_t>();
	auto& aggrs = netstat->connections<ipv4_tuple_t>();

	ipv4_tuple_t sock{};
	sock.sport = 22;
	sock.netns = 11;
	lports.insert({sock, 1});
	sock.dport = 22;
	sock.sport = 2112;
	sock.saddr = 0x11;
	sock.daddr = 0x66;
	aggrs.insert({sock, netstat::Connection{}});
	auto sockData = aggrs.begin();
	EXPECT_EQ(sockData->second.state.Direction, 0);
	EXPECT_EQ(sockData->second.state.Established, 0);
	netstat->resolveOldConnections<ipv4_tuple_t>();
	EXPECT_EQ(sockData->second.state.Direction, 0);
	EXPECT_EQ(sockData->second.state.Established, 1);
}
