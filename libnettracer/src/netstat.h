/*
 * Copyright 2025 Dynatrace LLC
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
#pragma once

#include "Istats_collector.h"
#include "configuration.h"
#include "stats.h"
#include "tuple_utils.h"
#include <chrono>
#include <mutex>
#include <ostream>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace netstat {

using namespace std::chrono;

struct Connection {
	uint32_t pid = 0;
	uint32_t ns;
	State state;
	steady_clock::time_point update_time;
	system_clock::time_point start;
	system_clock::time_point end;
	Stats curr;
	Stats prev;
};

using ConnectionsIPv4 = std::unordered_map<ipv4_tuple_t, Connection>;
using ConnectionsIPv6 = std::unordered_map<ipv6_tuple_t, Connection>;
using IPv4ListenSock2Pid = std::unordered_multimap<ipv4_tuple_t, uint32_t>;
using IPv6ListenSock2Pid = std::unordered_multimap<ipv6_tuple_t, uint32_t>;

class NetStat : public IStatsCollector {
	mutable std::mutex mx_aggr;
	bpf::bpf_fds fdsIPv4;
	bpf::bpf_fds fdsIPv6;

protected:
	ConnectionsIPv4 aggr_;
	ConnectionsIPv6 aggr6_;
	IPv4ListenSock2Pid listen_;
	IPv6ListenSock2Pid listen6_;
	bool kbhit;
	bool config_changed{false};
	int max_map_size{1024};
	config::ExitCtrl& exitCtrl;
	bool incremental;
	bool add_header_mode_ = false;
	bpf::BPFMapsWrapper* mapsWrapper;
	std::ostream* os;
	int field_width;
	bool interactive;
	bool filter_loopback;

	template <typename IPTYPE>
	inline auto& connections() const;
	template <typename IPTYPE>
	inline auto& connections();
	template <typename IPTYPE>
	inline auto& listenPorts();
	template <typename IPTYPE>
	std::unordered_map<IPTYPE, Connection> filterServerAggrs();

	template <typename IPTYPE>
	void readListenPorts(const tcpTable<IPTYPE>&);
	void readListenPorts();

	std::tuple<unsigned, unsigned, unsigned> countTcpSessions();
	template <typename IPTYPE>
	void update(const bpf::bpf_fds& fds);

	template <typename IPTYPE, typename T, typename F>
	void process_bpf_map(int fd, F func);

	virtual void print_to_pipe();
	template <typename IPTYPE>
	void print(bool clientsOnly) const ;
	virtual void print_human_readable();
	void print_human_readable_clients();
	void flush();
	template <typename IPTYPE>
	void clean();
	template <typename IPTYPE>
	void clean_bpf(const bpf::bpf_fds& fds);

	virtual system_clock::time_point getCurrentTimeFromSystemClock() const;
	virtual steady_clock::time_point getCurrentTimeFromSteadyClock() const;

	template <typename IPTYPE>
	void resolveOldConnections();
	template <typename IPTYPE>
	void set_prev_metrics();
	virtual void aggregate();
	template <typename IPTYPE, typename EventIPTYPE>
	bool event(const EventIPTYPE& evt);

public:
	explicit NetStat(config::ExitCtrl& e, bool deltaMode, bool headerMode, bool nonInteractive, bool filterLoopback = true);
	virtual ~NetStat();
	void set_kbhit() override;
	void set_max_map_size(uint32_t size) override;
	void on_config_change() override;
	void init(bpf::Ibpf& ebpf) override;
	bool map_loop() override;
	void eventIpv4(const tcp_ipv4_event_t& evt) override;
	void eventIpv6(const tcp_ipv6_event_t& evt) override;
};

template <>
inline auto& NetStat::connections<ipv4_tuple_t>() const {
	return aggr_;
}
template <>
inline auto& NetStat::connections<ipv6_tuple_t>() const {
	return aggr6_;
}
template <>
inline auto& NetStat::connections<ipv4_tuple_t>() {
	return aggr_;
}
template <>
inline auto& NetStat::connections<ipv6_tuple_t>() {
	return aggr6_;
}
template <>
inline auto& NetStat::listenPorts<ipv4_tuple_t>() {
	return listen_;
}
template <>
inline auto& NetStat::listenPorts<ipv6_tuple_t>() {
	return listen6_;
}

template <class IPTYPE>
constexpr uint64_t addAvgHeaderSize(uint64_t pkts, bool count) {
	return 0;
}
template <>
constexpr uint64_t addAvgHeaderSize<ipv4_tuple_t>(uint64_t pkts, bool count) {
	return count ? 66 * pkts : 0;
}

template <>
constexpr uint64_t addAvgHeaderSize<ipv6_tuple_t>(uint64_t pkts, bool count) {
	return count ? 77 * pkts : 0;
}
} // namespace netstat
