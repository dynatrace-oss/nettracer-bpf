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
#include "bpf_maps_processing_testing.h"
#include "connectivity_stats.h"
#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>

using namespace netstat;
using namespace std::string_literals;
using testing::Return;

class TestConnectivityStats : public ConnectivityStats {
public:
	explicit TestConnectivityStats(config::ExitCtrl& e, bool inc, bpf::BPFMapsWrapper* mapsWrapper, std::ostream* os)
			: ConnectivityStats(e, inc, false, false) {
		this->mapsWrapper = mapsWrapper;
		this->os = os;
	}

	MOCK_METHOD(system_clock::time_point, getCurrentTimeFromSystemClock, (), (const, override));
	MOCK_METHOD(steady_clock::time_point, getCurrentTimeFromSteadyClock, (), (const, override));

	using ConnectivityStats::aggregate;
	using ConnectivityStats::clean_bpf;
	using ConnectivityStats::clean_closed;
	using ConnectivityStats::clean_inactive;
	using ConnectivityStats::connections;
    using ConnectivityStats::print_to_pipe;
	using ConnectivityStats::servers;
	using ConnectivityStats::update;
};

class ConnectivityStatsTest : public BPFMapsProcessingTest {
protected:
	void SetUp() override {
		exitCtrl = std::make_unique<config::ExitCtrl>();
		netstat = std::make_unique<TestConnectivityStats>(*exitCtrl, true, &mockMapsWrapper, &os);
		sock.sport = 22;
		sock.netns = 0xf00001;
		sock.dport = 4343;
		sock.saddr = 0x1111;
		sock.daddr = 0x6611;
	}

	void TearDown() override {
		netstat.reset();
	}

	std::unique_ptr<config::ExitCtrl> exitCtrl;
	std::ostringstream os;
	std::unique_ptr<TestConnectivityStats> netstat;
	ipv4_tuple_t sock{};
};

TEST_F(ConnectivityStatsTest, printClients) {
	EXPECT_CALL(*netstat, getCurrentTimeFromSystemClock).Times(1);
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	aggr.emplace(sock, netstat::Connection{10, 12, State{1}});
	netstat->aggregate();
	netstat->print_to_pipe();
	auto str = os.str();
	size_t newlines = std::count(str.begin(), str.end(), '\n');
	EXPECT_EQ(newlines, 1u);
	std::istringstream iss(str);

	size_t count = 0;
	std::string word;
	while (iss >> word)
		++count;

	EXPECT_EQ(count, 19u); // 19 field should be printed
}

TEST_F(ConnectivityStatsTest, printServer) {
	EXPECT_CALL(*netstat, getCurrentTimeFromSystemClock).Times(1);
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	netstat::Connection conn{ 101, 122, State{ .Established = 1, .Direction = 1}};
	aggr.emplace(sock, conn);
	netstat->aggregate();
	netstat->print_to_pipe();
	auto str = os.str();
	size_t newlines = std::count(str.begin(), str.end(), '\n');
	EXPECT_EQ(newlines, 1u);
	std::istringstream iss(str);

	size_t count = 0;
	std::string word;
	while (iss >> word)
		++count;

	EXPECT_EQ(count, 20u); // 20 field should be printed
}

TEST_F(ConnectivityStatsTest, printClientsandServers) {
	EXPECT_CALL(*netstat, getCurrentTimeFromSystemClock).Times(2);
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	aggr.emplace(sock, netstat::Connection{10, 12, State{.Established = 1}});
	sock.dport = 33;
	aggr.emplace(sock, netstat::Connection{10, 12, State{.Established = 1, .Direction = 1}});
	netstat->aggregate();
	netstat->print_to_pipe();
	auto str = os.str();
	size_t newlines = std::count(str.begin(), str.end(), '\n');
	EXPECT_EQ(newlines, 2u);
}

TEST_F(ConnectivityStatsTest, aggregate2Servers) {
	EXPECT_CALL(*netstat, getCurrentTimeFromSystemClock).Times(1);
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	netstat::Connection conn{101, 122, State{.Established = 1, .Direction = 1 }};
	conn.curr.bytes_sent = 100;
	aggr.emplace(sock, conn);
	sock.dport = 55555;
	aggr.emplace(sock, conn);
	netstat->aggregate();
	EXPECT_EQ(aggr.size(), 2u);
	EXPECT_EQ(netstat->servers<ipv4_tuple_t>().size(), 1u);
	EXPECT_EQ(netstat->servers<ipv4_tuple_t>().begin()->second.bytes_sent, 200u);
	netstat->print_to_pipe();
	auto str = os.str();
	size_t newlines = std::count(str.begin(), str.end(), '\n');
	EXPECT_EQ(newlines, 1u);
}

TEST_F(ConnectivityStatsTest, closedAreRemoved) {
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	netstat::Connection conn{ 101, 122, State{ .Established = 1, .Direction = 1, .Closed = 1}};
	conn.curr.bytes_sent = 100;

	aggr.emplace(sock, conn);
	EXPECT_EQ(aggr.size(), 1u);
	netstat->aggregate();
	ASSERT_EQ(netstat->servers<ipv4_tuple_t>().size(), 1u);
	EXPECT_EQ(netstat->servers<ipv4_tuple_t>().begin()->second.bytes_sent, 100u);
}

TEST_F(ConnectivityStatsTest, connectivityEvent) {
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock).Times(1);
	tcp_ipv4_event_t evt{1, 1, TCP_EVENT_TYPE_SYN_ATTEMPT , 100, sock.saddr, sock.daddr, sock.sport, sock.dport, sock.netns, 100};
	std::unordered_map<ipv4_tuple_t, netstat::Connection>& aggr = netstat->connections<ipv4_tuple_t>();
	netstat::Connection conn{100, 122, State{.Established = 1, .Direction = 1, .Closed = 1}};
	conn.curr.bytes_sent = 100;
    aggr.emplace(sock, conn);
	netstat->eventIpv4(evt);
	netstat->aggregate();
	ASSERT_EQ(netstat->servers<ipv4_tuple_t>().size(), 1u);
	EXPECT_EQ(netstat->servers<ipv4_tuple_t>().begin()->second.connection_attempts, 1u);
	EXPECT_EQ(netstat->servers<ipv4_tuple_t>().begin()->second.bytes_sent, 100u);
}
