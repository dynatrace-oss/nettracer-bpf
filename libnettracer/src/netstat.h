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
#pragma once

#include "bpf_program/nettracer-bpf.h"
#include "connections_printing.h"
#include <chrono>
#include <ostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

namespace netstat {

struct State {
	unsigned char Established : 1;
	unsigned char Direction : 1;
	unsigned char Closed : 1;
};

using namespace std::chrono;

struct Connection {
	uint32_t pid = 0;
	uint32_t ns;
	State state;
	steady_clock::time_point update_time;
	system_clock::time_point start;
	system_clock::time_point end;
	uint64_t bytes_sent;
	uint64_t bytes_sent_prev = 0;
	uint64_t bytes_received;
	uint64_t bytes_received_prev = 0;
	uint64_t pkts_sent;
	uint64_t pkts_sent_prev = 0;
	uint64_t pkts_received;
	uint64_t pkts_received_prev = 0;
	uint64_t pkts_retrans;
	uint64_t pkts_retrans_prev = 0;
	uint32_t rtt;
	uint32_t rtt_var;
};

using ConnectionsIPv4 = std::unordered_map<ipv4_tuple_t, Connection>;
using ConnectionsIPv6 = std::unordered_map<ipv6_tuple_t, Connection>;

class NetStat {
protected:
	ConnectionsIPv4 aggr_;
	ConnectionsIPv6 aggr6_;
	std::mutex mx;
	bool kbhit;
	bool config_changed{false};
	const int max_map_size = 1024;
	ExitCtrl& exitCtrl;
	bool incremental;
	bool add_header_mode_ = false;
	bpf::BPFMapsWrapper* mapsWrapper;
	std::ostream* os;
	int field_width;
	bool interactive;
	bool filter_loopback;

	template <typename IPTYPE>
	inline auto& connections(); // no default instantiation

	template<typename IPTYPE>
	void initConnection(const tcpTable<IPTYPE>&);
	void initConnections();

	std::pair<unsigned, unsigned> countTcpSessions();
	template<typename IPTYPE>
	void update(const bpf_fds& fds);

	template<typename IPTYPE, typename T, typename F>
	void process_bpf_map(int fd, F func);

	void printHeader();
	template<typename IPTYPE>
	void print();
	template<typename IPTYPE>
	void print_human_readable();
	void flush();
	template <typename IPTYPE>
	void clean();

	template<typename IPTYPE>
	void clean_bpf(const bpf_fds& fds);

	virtual system_clock::time_point getCurrentTimeFromSystemClock() const;
	virtual steady_clock::time_point getCurrentTimeFromSteadyClock() const;

public:
	explicit NetStat(ExitCtrl& e, bool deltaMode, bool headerMode, bool nonInteractive, bool filterLoopback = true);
	virtual ~NetStat();
	void set_kbhit();
	void on_config_change();
	void init();

	bool map_loop(const bpf_fds& fdsIPv4, const bpf_fds& fdsIPv6);

	template<typename IPTYPE, typename EventIPTYPE>
	void event(const EventIPTYPE& evt);
};

template<>
inline auto& NetStat::connections<ipv4_tuple_t>() {
	return aggr_;
}
template<>
inline auto& NetStat::connections<ipv6_tuple_t>() {
	return aggr6_;
}

} // namespace netstat
