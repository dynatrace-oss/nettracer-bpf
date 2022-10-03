#include <gtest/gtest.h>
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
	explicit TestNetStat(ExitCtrl& e, bool inc, bpf::BPFMapsWrapper* mapsWrapper, std::ostream* os)
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
};

class NetStatTest : public BPFMapsProcessingTest {
protected:
	void SetUp() override {
		BPFMapsProcessingTest::SetUp();

		exitCtrl = std::make_unique<ExitCtrl>();
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

	std::unique_ptr<ExitCtrl> exitCtrl;
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

TEST_F(NetStatTest, testUpdateConnsNotYetCollectedIPv4) {
	setUpNetStat();
	addIPv4Conns();

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	const auto& netstatConns{netstat->connections<ipv4_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Established; });
}

TEST_F(NetStatTest, testUpdateConnsNotYetCollectedIPv6) {
	setUpNetStat();
	addIPv6Conns();

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	const auto& netstatConns{netstat->connections<ipv6_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Established; });
}

TEST_F(NetStatTest, testUpdateConnsUpdatedPIDIPv4) {
	setUpNetStat();
	addIPv4Conns();

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	auto tuples{getIPv4Tuples()};
	const auto& tupleWithPID0{tuples[1]};
	ASSERT_EQ(ipv4PIDsMap->at(tupleWithPID0).pid, 0);
	ipv4PIDsMap->at(tupleWithPID0).pid = 0x1234500000000; // bit shift by 32

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto& netstatConns{netstat->connections<ipv4_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	EXPECT_TRUE(std::none_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.pid == 0; }));
}

TEST_F(NetStatTest, testUpdateConnsUpdatedPIDIPv6) {
	setUpNetStat();
	addIPv6Conns();

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	auto tuples{getIPv6Tuples()};
	const auto& tupleWithPID0{tuples[1]};
	ASSERT_EQ(ipv6PIDsMap->at(tupleWithPID0).pid, 0);
	ipv6PIDsMap->at(tupleWithPID0).pid = 0x1234500000000; // bit shift by 32

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto& netstatConns{netstat->connections<ipv6_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	EXPECT_TRUE(std::none_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.pid == 0; }));
}

TEST_F(NetStatTest, testUpdateConnsUpdatedNotPIDIPv4) {
	setUpNetStat();
	addIPv4Conns();

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	markIPv4ConnsAsClosed();

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	
	const auto tuples{getIPv4Tuples()};
	const auto& netstatConns{netstat->connections<ipv4_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	EXPECT_TRUE(std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Closed; }));
}

TEST_F(NetStatTest, testUpdateConnsUpdatedNotPIDIPv6) {
	setUpNetStat();
	addIPv6Conns();

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	markIPv6ConnsAsClosed();

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	
	const auto tuples{getIPv6Tuples()};
	const auto& netstatConns{netstat->connections<ipv6_tuple_t>()};
	EXPECT_EQ(netstatConns.size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
	EXPECT_TRUE(std::all_of(netstatConns.cbegin(), netstatConns.cend(), [](const auto& pair){ return pair.second.state.Closed; }));
}

TEST_F(NetStatTest, testUpdateConnsRemovedButStillKeptInNetstatIPv4) {
	setUpNetStat();
	addIPv4Conns();

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	ipv4PIDsMap->clear();

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	
	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
}

TEST_F(NetStatTest, testUpdateConnsRemovedButStillKeptInNetstatIPv6) {
	setUpNetStat();
	addIPv6Conns();

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	ipv6PIDsMap->clear();

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	
	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatContainsConnection(tuple);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsNotYetCollectedIPv4) {
	setUpNetStat();
	addIPv4Stats();

	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, *ipv4StatsMap);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsNotYetCollectedIPv6) {
	setUpNetStat();
	addIPv6Stats();

	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, *ipv6StatsMap);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsUpdatedIPv4) {
	setUpNetStat();
	addIPv4Stats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	ipv4StatsMap->at(tuples[0]).sent_bytes = 77777;
	ipv4StatsMap->at(tuples[1]).received_bytes = 77777;
	ipv4StatsMap->at(tuples[2]).sent_bytes = 77777;
	ipv4StatsMap->at(tuples[2]).received_bytes = 77777;
	const size_t changedStats{3};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(changedStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, *ipv4StatsMap);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsUpdatedIPv6) {
	setUpNetStat();
	addIPv6Stats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	ipv6StatsMap->at(tuples[0]).sent_bytes = 77777;
	ipv6StatsMap->at(tuples[1]).received_bytes = 77777;
	ipv6StatsMap->at(tuples[2]).sent_bytes = 77777;
	ipv6StatsMap->at(tuples[2]).received_bytes = 77777;
	const size_t changedStats{3};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(changedStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, *ipv6StatsMap);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsRemovedButStillKeptInNetstatIPv4) {
	setUpNetStat();
	addIPv4Stats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	std::unordered_map<ipv4_tuple_t, stats_t> oldCopy;
	std::swap(*ipv4StatsMap, oldCopy);

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	
	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, oldCopy);
	}
}

TEST_F(NetStatTest, testUpdateGenericStatsRemovedButStillKeptInNetstatIPv6) {
	setUpNetStat();
	addIPv6Stats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	std::unordered_map<ipv6_tuple_t, stats_t> oldCopy;
	std::swap(*ipv6StatsMap, oldCopy);

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	
	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatStatsAreCorrect(tuple, oldCopy);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsNotYetCollectedIPv4) {
	setUpNetStat();
	addIPv4TCPStats();

	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, *ipv4TCPStatsMap);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsNotYetCollectedIPv6) {
	setUpNetStat();
	addIPv6TCPStats();

	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, *ipv6TCPStatsMap);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsUpdatedIPv4) {
	setUpNetStat();
	addIPv4TCPStats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	ipv4TCPStatsMap->at(tuples[0]).segs_in = 77777;
	ipv4TCPStatsMap->at(tuples[1]).retransmissions = 77777;
	ipv4TCPStatsMap->at(tuples[2]).rtt_var = 77777;
	const size_t changedStats{3};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(changedStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, *ipv4TCPStatsMap);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsUpdatedIPv6) {
	setUpNetStat();
	addIPv6TCPStats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	ipv6TCPStatsMap->at(tuples[0]).segs_in = 77777;
	ipv6TCPStatsMap->at(tuples[1]).retransmissions = 77777;
	ipv6TCPStatsMap->at(tuples[2]).rtt_var = 77777;
	const size_t changedStats{3};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(changedStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, *ipv6TCPStatsMap);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsRemovedButStillKeptInNetstatIPv4) {
	setUpNetStat();
	addIPv4TCPStats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	std::unordered_map<ipv4_tuple_t, tcp_stats_t> oldCopy;
	std::swap(*ipv4TCPStatsMap, oldCopy);

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	
	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, oldCopy);
	}
}

TEST_F(NetStatTest, testUpdateTCPStatsRemovedButStillKeptInNetstatIPv6) {
	setUpNetStat();
	addIPv6TCPStats();
	
	const size_t nonzeroStats{2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	std::unordered_map<ipv6_tuple_t, tcp_stats_t> oldCopy;
	std::swap(*ipv6TCPStatsMap, oldCopy);

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	
	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
	for (const auto& tuple : tuples) {
		checkIfNetstatTCPStatsAreCorrect(tuple, oldCopy);
	}
}

TEST_F(NetStatTest, testCleanBPFEmptyIPv4) {
	setUpNetStat();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanBPFEmptyIPv6) {
	setUpNetStat();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanBPFUpToDateIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);

	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(ipv4PIDsMap->size(), tuples.size());
	EXPECT_EQ(ipv4StatsMap->size(), tuples.size());
	EXPECT_EQ(ipv4TCPStatsMap->size(), tuples.size());
}

TEST_F(NetStatTest, testCleanBPFUpToDateIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);

	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(ipv6PIDsMap->size(), tuples.size());
	EXPECT_EQ(ipv6StatsMap->size(), tuples.size());
	EXPECT_EQ(ipv6TCPStatsMap->size(), tuples.size());
}

TEST_F(NetStatTest, testCleanBPFStaleIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.WillOnce(Return(steady_clock::time_point{std::chrono::hours(999)}));

	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanBPFStaleIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.WillOnce(Return(steady_clock::time_point{std::chrono::hours(999)}));

	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanBPFClosedIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	markIPv4ConnsAsClosed();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv4_tuple_t>(ipv4FDs);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanBPFClosedIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	markIPv6ConnsAsClosed();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean_bpf<ipv6_tuple_t>(ipv6FDs);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(NetStatTest, testCleanEmptyIPv4) {
	setUpNetStat();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv4_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv4_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanEmptyIPv6) {
	setUpNetStat();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv6_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv6_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanUpToDateIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv4_tuple_t>();

	const auto tuples{getIPv4Tuples()};
	EXPECT_EQ(netstat->connections<ipv4_tuple_t>().size(), tuples.size());
}

TEST_F(NetStatTest, testCleanUpToDateIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv6_tuple_t>();

	const auto tuples{getIPv6Tuples()};
	EXPECT_EQ(netstat->connections<ipv6_tuple_t>().size(), tuples.size());
}

TEST_F(NetStatTest, testCleanStaleIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.WillOnce(Return(steady_clock::time_point{std::chrono::hours(999)}));

	netstat->clean<ipv4_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv4_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanStaleIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.WillOnce(Return(steady_clock::time_point{std::chrono::hours(999)}));

	netstat->clean<ipv6_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv6_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanClosedIPv4) {
	setUpNetStat();
	addIPv4Conns();
	addIPv4Stats();
	addIPv4TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv4_tuple_t>(ipv4FDs);
	markIPv4ConnsAsClosed();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv4_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv4_tuple_t>().empty());
}

TEST_F(NetStatTest, testCleanClosedIPv6) {
	setUpNetStat();
	addIPv6Conns();
	addIPv6Stats();
	addIPv6TCPStats();

	const size_t nonzeroStats{2+2};
	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock)
		.Times(nonzeroStats);

	netstat->update<ipv6_tuple_t>(ipv6FDs);
	markIPv6ConnsAsClosed();

	EXPECT_CALL(*netstat, getCurrentTimeFromSteadyClock);

	netstat->clean<ipv6_tuple_t>();

	EXPECT_TRUE(netstat->connections<ipv6_tuple_t>().empty());
}
