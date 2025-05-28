/*
* Copyright 2025 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License cat
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
#include "connections_printing.h"
#include "bpf_maps_processing_testing.h"
#include "log_redirection.h"
#include <fmt/core.h>
#include <algorithm>
#include <string>
#include <vector>

class ConnectionsPrintingTest : public BPFMapsProcessingTest {
protected:
	virtual void TearDown() override {
		BPFMapsProcessingTest::TearDown();

		logsRedirector.reset();
	}

	static void testIfLogsContainOneInstanceOfSubstring(const std::vector<std::string>& logs, const std::string& substr) {
		auto found{std::count_if(logs.cbegin(), logs.cend(), [&](const std::string& log){ return log.find(substr) != std::string::npos; })};
		EXPECT_EQ(found, 1) << "Provided logs should contain exactly one instance of substring: " << substr;
	}
	
	template<typename Tuple>
	static void markConnsAsClosed(std::unordered_map<Tuple, pid_comm_t>& pidsMap, ConnectionsState<Tuple>& connsState) {
		for (auto& tupleAndPIDComm : pidsMap) {
			tupleAndPIDComm.second.state = CONN_CLOSED;
		}

		for (const auto& tupleAndDetails : connsState.connsDetails) {
			connsState.connsClosed.push_back(tupleAndDetails.first);
		}
	}

	void markIPv4ConnsAsClosed() {
		markConnsAsClosed(*ipv4PIDsMap, *ipv4ConnsState);
	}

	void markIPv6ConnsAsClosed() {
		markConnsAsClosed(*ipv6PIDsMap, *ipv6ConnsState);
	}

	LogsRedirector<> logsRedirector;
};

TEST_F(ConnectionsPrintingTest, testLogNothingIPv4) {
	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogNothingOnlyActiveIPv4Conns) {
	addIPv4Conns();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogNothingOnlyClosedIPv4Conns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogIPv4GenericStatsUnknownConns) {
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -- 1.2.3.4:80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 -- 127.0.0.1:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -- 1.2.3.4:50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 -- 1.2.3.4:80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv4GenericStatsActiveConns) {
	addIPv4Conns();
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -> 1.2.3.4:80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 <- 127.0.0.1:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -> 1.2.3.4:50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 <- 1.2.3.4:80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv4GenericStatsClosedConns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -> 1.2.3.4:80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 <- 127.0.0.1:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -> 1.2.3.4:50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 <- 1.2.3.4:80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv4TCPStatsUnknownConns) {
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -- 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 -- 127.0.0.1:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -- 1.2.3.4:50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 -- 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv4TCPStatsActiveConns) {
	addIPv4Conns();
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -> 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 <- 127.0.0.1:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -> 1.2.3.4:50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 <- 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv4TCPStatsClosedConns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "127.0.0.1:50000 -> 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "1.2.3.4:80 <- 127.0.0.1:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:80 -> 1.2.3.4:50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("1.2.3.4:50000 <- 1.2.3.4:80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testLogNothingIPv6) {
	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogNothingOnlyActiveIPv6Conns) {
	addIPv6Conns();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogNothingOnlyClosedIPv6Conns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getLastLog(), std::out_of_range);
}

TEST_F(ConnectionsPrintingTest, testLogIPv6GenericStatsUnknownConns) {
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -- ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 -- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -- ffff:ffff:ffff:ffff:::50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 -- ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv6GenericStatsActiveConns) {
	addIPv6Conns();
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -> ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 <- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -> ffff:ffff:ffff:ffff:::50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 <- ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv6GenericStatsClosedConns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -> ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 <- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - stats: Bytes sent=0 Bytes received=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -> ffff:ffff:ffff:ffff:::50000 NS:1000 - stats: Bytes sent=0 Bytes received={:d}", bytesMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 <- ffff:ffff:ffff:ffff:::80 NS:1000 - stats: Bytes sent={:d} Bytes received=0", bytesMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv6TCPStatsUnknownConns) {
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -- ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 -- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -- ffff:ffff:ffff:ffff:::50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 -- ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv6TCPStatsActiveConns) {
	addIPv6Conns();
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -> ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 <- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -> ffff:ffff:ffff:ffff:::50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 <- ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testLogIPv6TCPStatsClosedConns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_THROW(logsRedirector.getNLastLogs(4+1), std::out_of_range);
	auto logs{logsRedirector.getNLastLogs(4)};
	testIfLogsContainOneInstanceOfSubstring(logs, "1234:1234:1234:1234:5678:5678:5678:5678:50000 -> ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, "ffff:ffff:ffff:ffff:::80 <- 1234:1234:1234:1234:5678:5678:5678:5678:50000 NS:1000 - TCP stats: Retransmissions=0 Segs_in=0 Segs_out=0 RTT=0 RTT_var=0");
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::80 -> ffff:ffff:ffff:ffff:::50000 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
	testIfLogsContainOneInstanceOfSubstring(logs, fmt::format("ffff:ffff:ffff:ffff:::50000 <- ffff:ffff:ffff:ffff:::80 NS:1000 - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}", retransMax, segsMax, segsMax, rttMax, rttVarMax));
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsNothingIPv4) {
	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsOnlyActiveIPv4Conns) {
	addIPv4Conns();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsOnlyClosedIPv4Conns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4GenericStatsUnknownConns) {
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_FALSE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4GenericStatsActiveConns) {
	addIPv4Conns();
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv4PIDsMap->empty());
	EXPECT_FALSE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4GenericStatsClosedConns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();
	addIPv4Stats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4TCPStatsUnknownConns) {
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_FALSE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4TCPStatsActiveConns) {
	addIPv4Conns();
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_FALSE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv4TCPStatsClosedConns) {
	addIPv4Conns();
	markIPv4ConnsAsClosed();
	addIPv4TCPStats();

	updateConnectionsFromMaps(*ipv4ConnsState, ipv4FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv4PIDsMap->empty());
	EXPECT_TRUE(ipv4StatsMap->empty());
	EXPECT_TRUE(ipv4TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsNothingIPv6) {
	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsOnlyActiveIPv6Conns) {
	addIPv6Conns();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsOnlyClosedIPv6Conns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6GenericStatsUnknownConns) {
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_FALSE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6GenericStatsActiveConns) {
	addIPv6Conns();
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv6PIDsMap->empty());
	EXPECT_FALSE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6GenericStatsClosedConns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();
	addIPv6Stats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6TCPStatsUnknownConns) {
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_FALSE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6TCPStatsActiveConns) {
	addIPv6Conns();
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_FALSE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_FALSE(ipv6TCPStatsMap->empty());
}

TEST_F(ConnectionsPrintingTest, testCleanUpMapsIPv6TCPStatsClosedConns) {
	addIPv6Conns();
	markIPv6ConnsAsClosed();
	addIPv6TCPStats();

	updateConnectionsFromMaps(*ipv6ConnsState, ipv6FDs, mockMapsWrapper);

	EXPECT_TRUE(ipv6PIDsMap->empty());
	EXPECT_TRUE(ipv6StatsMap->empty());
	EXPECT_TRUE(ipv6TCPStatsMap->empty());
}
