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
#include "netstat.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
#include "proc_tcp.h"
#include "system_utils.h"
#include <iomanip>
#include <iostream>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace netstat {

constexpr auto INACTIVE_TIMEOUT = minutes(1);
constexpr unsigned INTERVAL_DIVIDER = 10;

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

static int getWindowWidth() {
	winsize sz{};
	if (ioctl(0, TIOCGWINSZ, &sz) < 0) {
		LOG_DEBUG("cannot get window size");
	}
	return sz.ws_col;
}

template <typename IPTYPE, typename T, typename F>
void NetStat::process_bpf_map(int fd, F func) {
	IPTYPE previousKey{};
	IPTYPE currentKey{};
	for (int k = 0; k < max_map_size && mapsWrapper->getNextKey(fd, &previousKey, &currentKey); ++k) {
		T val{};
		if (mapsWrapper->lookupElement(fd, &currentKey, &val)) {
			if (currentKey.sport > 0) {
				std::unique_lock<std::mutex> l(mx_aggr);
				auto& el = connections<IPTYPE>()[currentKey];
				if (func(el, val)) {
					el.update_time = getCurrentTimeFromSteadyClock();
				}
			} else {
				LOG_DEBUG("src port = 0 for {}", to_string(currentKey));
				mapsWrapper->removeElement(fd, static_cast<const void*>(&currentKey));
			}
		}
		previousKey = currentKey;
	}
}

template<typename IPTYPE>
void NetStat::update(const bpf::bpf_fds& fds) {
	process_bpf_map<IPTYPE, pid_comm_t>(fds.pid_fd, [&](auto& el, const auto& val) {
		uint32_t pid = static_cast<uint32_t>(val.pid >> 32);
		if(el.pid == 0){
			el.pid = pid;
		}
		return false;
	});

	process_bpf_map<IPTYPE, stats_t>(fds.stats_fd, [&](auto& el, const auto& val) {
		bool changed = (el.curr.bytes_sent != val.sent_bytes) || (el.curr.bytes_received != val.received_bytes);
		el.curr.bytes_sent = val.sent_bytes;
		el.curr.bytes_received = val.received_bytes;
		return changed;
	});

	process_bpf_map<IPTYPE, tcp_stats_t>(fds.tcp_stats_fd, [&](auto& el, const auto& val) {
		bool changed = (el.curr.pkts_retrans != val.retransmissions) || (el.curr.pkts_sent != val.segs_out) || (el.curr.pkts_received != val.segs_in) ||
					   (el.curr.rtt != val.rtt) || (el.curr.rtt_var != val.rtt_var);

		if ((el.curr.pkts_sent > 0 && val.segs_out < el.curr.pkts_sent) ||
			(el.prev.pkts_sent > 0 && (val.segs_out - el.prev.pkts_sent) > (el.curr.bytes_sent - el.prev.bytes_sent + 4))) {
			LOG_DEBUG(
					"Suspected segs_out:{} segs_out_prev:{} bytes_out:{} bytes_out_prev:{}",
					val.segs_out,
					el.prev.pkts_sent,
					el.curr.bytes_sent,
					el.prev.bytes_sent);
		}

		if ((el.curr.pkts_received > 0 && val.segs_in < el.curr.pkts_received) ||
			(el.prev.pkts_received > 0 && (val.segs_in - el.prev.pkts_received) > (el.curr.bytes_received - el.prev.bytes_received + 4))) {
			LOG_DEBUG(
					"Suspected segs_in:{} segs_in_prev:{} bytes_in:{} bytes_in_prev:{}",
					val.segs_in,
					el.prev.pkts_received,
					el.curr.bytes_received,
					el.prev.bytes_received);
		}

		el.curr.pkts_sent = val.segs_out;
		el.curr.pkts_received = val.segs_in;
		el.curr.pkts_retrans = val.retransmissions;
		el.curr.rtt = val.rtt;
		el.curr.rtt_var = val.rtt_var;
		return changed;
	});
}

struct TimeGuard {
	unsigned long counter{};
	unsigned ticks_per_wait_time;

	TimeGuard(unsigned time){
		counter = ticks_per_wait_time = time * INTERVAL_DIVIDER;
	}

	bool time_elapsed() {
		if (counter >= ticks_per_wait_time) {
			counter = 0;
			return true;
		} else {
			return false;
		}
	}

	void bump() {
		counter++;
	}

	void reset() {
		counter = 0;
	}
};

std::tuple<unsigned, unsigned, unsigned> NetStat::countTcpSessions() {
	const auto& container4 = connections<ipv4_tuple_t>();
	unsigned incoming =
			std::count_if(std::begin(container4), std::end(container4), [](const auto& it) { return it.second.state.Direction == 1; });
	unsigned established =
			std::count_if(std::begin(container4), std::end(container4), [](const auto& it) { return it.second.state.Established == 1; });

	const auto& container6 = connections<ipv6_tuple_t>();
	incoming += std::count_if(std::begin(container6), std::end(container6), [](const auto& it) { return it.second.state.Direction == 1; });
	established +=
			std::count_if(std::begin(container6), std::end(container6), [](const auto& it) { return it.second.state.Established == 1; });
	return {incoming, container4.size() + container6.size() - incoming, established};
}

bool NetStat::map_loop(const bpf::bpf_fds& fdsIPv4, const bpf::bpf_fds& fdsIPv6) {
	using namespace std::literals::chrono_literals;

	TimeGuard outputCtr(exitCtrl.wait_time), logCtr(seconds(5min).count());

	while (exitCtrl.running && !config_changed) {
		update<ipv4_tuple_t>(fdsIPv4);
		update<ipv6_tuple_t>(fdsIPv6);

		clean_bpf<ipv4_tuple_t>(fdsIPv4);
		clean_bpf<ipv6_tuple_t>(fdsIPv6);

		if (kbhit || outputCtr.time_elapsed()) {
			resolveOldConnections<ipv4_tuple_t>();
			resolveOldConnections<ipv6_tuple_t>();
			aggregateServers();
			const auto [passive, active, established] = countTcpSessions();
			const auto tcpSessionsStr =
					fmt::format("Number of passive tcp sessions: {}, active: {}, established: {}", passive, active, established);
			if (interactive) {
				print_human_readable();
				std::cout << tcpSessionsStr;
			} else {
				print_to_pipe();
				if (logCtr.time_elapsed()) {
					LOG_INFO(tcpSessionsStr);
				}
			}
			outputCtr.reset();
			flush();
			clean<ipv4_tuple_t>();
			clean<ipv6_tuple_t>();
			readListenPorts();
		}

		outputCtr.bump();
		logCtr.bump();
		std::unique_lock<std::mutex> lk(exitCtrl.m);
		kbhit = false;
		exitCtrl.cv.wait_for(lk, milliseconds(1000 / INTERVAL_DIVIDER), [this] { return !exitCtrl.running || kbhit || config_changed; });
	}
	return exitCtrl.running;
}

template<typename IPTYPE>
void NetStat::clean_bpf(const bpf::bpf_fds& fds) {
	auto now = getCurrentTimeFromSteadyClock();
	std::unique_lock<std::mutex> l(mx_aggr);
	auto& aggr{connections<IPTYPE>()};
	for (auto it = aggr.begin(); it != aggr.end(); ++it) {
		if (it->second.state.Closed || now - it->second.update_time >= INACTIVE_TIMEOUT) {
			mapsWrapper->removeElement(fds.pid_fd, static_cast<const void*>(&it->first));
			mapsWrapper->removeElement(fds.stats_fd, static_cast<const void*>(&it->first));
			mapsWrapper->removeElement(fds.tcp_stats_fd, static_cast<const void*>(&it->first));
		}
	}
}

template<typename IPTYPE>
void NetStat::clean() {
	auto now = getCurrentTimeFromSteadyClock();
	std::unique_lock<std::mutex> l(mx_aggr);
	auto& aggr{connections<IPTYPE>()};
	for (auto it = aggr.begin(); it != aggr.end();) {
		if (it->second.state.Closed || now - it->second.update_time >= INACTIVE_TIMEOUT) {
			it = aggr.erase(it);
		} else {
			++it;
		}
	}
}

template<typename IPTYPE, typename EventIPTYPE>
void NetStat::event(const EventIPTYPE& evt) {
	auto key{eventToTuple(evt)};
	auto time = bpfTimeToSystemTime(evt.timestamp);

	if (key.sport == 0) {
		LOG_DEBUG("Event src port = 0 for {} ", to_string(evt));
		return;
	}

	std::unique_lock<std::mutex> l(mx_aggr);
	auto& el = connections<IPTYPE>()[key];

	if (el.state.Closed == 1) {
		LOG_INFO("Event on closed connection {}", to_string(evt));
	}
	el.pid = evt.pid;
	el.update_time = getCurrentTimeFromSteadyClock();
	if (evt.type == TCP_EVENT_TYPE_CONNECT) {
		el.start = time;
		el.state.Established = 1;
		el.state.Direction = 0;
		return;
	}

	if (evt.type == TCP_EVENT_TYPE_ACCEPT) {
		el.state.Direction = 1;
		el.state.Established = 1;
		el.start = time;
	} else if (evt.type == TCP_EVENT_TYPE_CLOSE) {
		el.state.Closed = 1;
		el.end = time;
	}
}

void NetStat::eventIpv4(const tcp_ipv4_event_t& evt) {
	return event<ipv4_tuple_t>(evt);
}
void NetStat::eventIpv6(const tcp_ipv6_event_t& evt) {
	return event<ipv6_tuple_t>(evt);
}

#define PRINT_BIT(field) ((s.field) ? "1" : "0")

static std::ostream& operator<<(std::ostream& os, const netstat::State& s) {
	os << " " << PRINT_BIT(Established) << PRINT_BIT(Direction) << PRINT_BIT(Closed) << " ";
	return os;
}

void NetStat::flush() {
	*os << " " << std::endl;
	logging::getLogger()->flush();
}

template <typename IPTYPE>
void NetStat::set_prev_metrics() {
	std::unique_lock<std::mutex> l(mx_aggr);
	auto& aggr = connections<IPTYPE>();

	for (auto& [tup, stats] : aggr) {
		stats.prev.bytes_received = stats.curr.bytes_received;
		stats.prev.bytes_sent = stats.curr.bytes_sent;
		stats.prev.pkts_retrans = stats.curr.pkts_retrans;
		stats.prev.pkts_sent = stats.curr.pkts_sent;
		stats.prev.pkts_received = stats.curr.pkts_received;
		stats.prev.rtt = stats.curr.rtt;
		stats.prev.rtt_var = stats.curr.rtt_var;
	}
}

template<typename IPTYPE>
void NetStat::print() const {
	std::unique_lock<std::mutex> lock(mx_aggr);
	const std::unordered_map<IPTYPE, Connection> aggr = connections<IPTYPE>();
	lock.unlock();
	std::stringstream buf;

	for (auto it = aggr.begin(); it != aggr.end(); ++it) {

		buf.str("");
		auto wall_now = getCurrentTimeFromSystemClock();
		Stats delta = (incremental) ? calc_delta(it->second.curr, it->second.prev, it->first) : it->second.curr;

		buf << std::right
			<< std::setw(12) << duration_cast<seconds>(wall_now.time_since_epoch()).count()
			<< it->first
			<< std::setw(12) << it->second.pid
			<< std::setw(12) << it->first.netns << it->second.state
			<< std::setw(22) << delta.bytes_sent + addAvgHeaderSize<IPTYPE>( delta.pkts_sent, add_header_mode_)
			<< std::setw(22) << delta.bytes_received + addAvgHeaderSize<IPTYPE>( delta.pkts_received, add_header_mode_ )
		  	<< std::setw(22) << delta.pkts_sent
			<< std::setw(22) << delta.pkts_received
			<< std::setw(22) << delta.pkts_retrans
			<< std::setw(12) << delta.rtt
			<< std::setw(12) << delta.rtt_var;

		if (it->second.state.Established) {
			auto end = (it->second.end != system_clock::time_point{}) ? it->second.end : getCurrentTimeFromSystemClock();
			auto duration = duration_cast<seconds>(end - it->second.start);
			buf << std::setw(16) << duration_cast<seconds>(it->second.start.time_since_epoch()).count() << std::setw(9)
					  << duration.count();
		} else {
			LOG_WARN("Unknown server for {}", to_string(it->first));
		}

		*os << buf.str() << std::endl;
		LOG_TRACE(buf.str());
	}
}

void NetStat::print_to_pipe() {
	print<ipv4_tuple_t>();
	print<ipv6_tuple_t>();
	set_prev_metrics<ipv4_tuple_t>();
	set_prev_metrics<ipv6_tuple_t>();
}

static void printHeader(int field_width, std::ostream& os) {
	os << std::left << std::setw(2 * field_width) << "local address <-> remote address" << std::setw(field_width) << "pid"
	   << std::setw(field_width) << "bytes sent" << std::setw(field_width) << "bytes received " << std::setw(field_width) << "rtt" << "\n";
}

template <typename IPTYPE>
void print_human_readable(const std::unordered_map<IPTYPE, Connection>& aggr, int direction, int field_width, std::ostream& os) {
	ConnectionDirection dirconn = (direction == 1) ? ConnectionDirection::Incoming : ConnectionDirection::Outgoing;

	for (auto& [tup, stats] : aggr) {
		if (stats.state.Direction != direction) {
			continue;
		}

		os << std::setw(ADDRESS_FIELD_WIDTH) << to_string(tup, dirconn);
		os << std::setw(field_width) << stats.pid << std::setw(field_width) << short_num(stats.curr.bytes_sent) << std::setw(field_width)
		   << short_num(stats.curr.bytes_received) << std::setw(field_width) << stats.curr.rtt << std::setw(field_width) << stats.curr.rtt_var
		   << "\n";
	}
}

void NetStat::print_human_readable_clients() {
	std::unique_lock<std::mutex> l(mx_aggr);
	print_human_readable<ipv4_tuple_t>(aggr_, 0, field_width, *os);
	print_human_readable<ipv6_tuple_t>(aggr6_, 0, field_width, *os);
}

void NetStat::print_human_readable() {
	printHeader(field_width, *os);
	print_human_readable_clients();

	std::unique_lock<std::mutex> l(mx_aggr);
	print_human_readable<ipv4_tuple_t>(aggr_, 1, field_width, *os);
	print_human_readable<ipv6_tuple_t>(aggr6_, 1, field_width, *os);
}

template <typename IPTYPE>
void NetStat::readListenPorts(const tcpTable<IPTYPE>& tblisten) {
	auto& lports = listenPorts<IPTYPE>();
	lports.clear();
	for (auto& [inode, tuple] : tblisten) {
		lports.insert({tuple.ep, tuple.pid});
	}
}

void NetStat::readListenPorts() {
	readListenPorts<ipv4_tuple_t>(readTcpTable("/proc", filter_loopback));
	readListenPorts<ipv6_tuple_t>(readTcpTable6("/proc", filter_loopback));
}

template <typename IPTYPE>
void NetStat::resolveOldConnections() {
	auto& listenports{listenPorts<IPTYPE>()};
	auto& aggr{connections<IPTYPE>()};

	for (auto& [sock, data] : aggr) {

		if (data.state.Established == 1) {
			continue;
		}
		IPTYPE listenSock{};
		listenSock.sport = sock.sport;
		listenSock.netns = sock.netns;

		auto it = listenports.find(listenSock);
		if (it != listenports.end()) {
			data.state.Direction = 1;
			data.state.Established = 1;
			continue;
		}
		if constexpr (std::is_same_v<IPTYPE, ipv4_tuple_t>) {
			listenSock.saddr = sock.saddr;
		} else {
			listenSock.saddr_l = sock.saddr_l;
			listenSock.saddr_h = sock.saddr_h;
		}

		it = listenports.find(listenSock);
		if (it != listenports.end()) {
			data.state.Direction = 1;
		}
		data.state.Established = 1;
	}
}

void NetStat::init() {
	// wrapper just wraps syscalls so using it is thread-safe
	static bpf::BPFMapsWrapper wrapper;
	mapsWrapper = &wrapper;

	readListenPorts();
}

system_clock::time_point NetStat::getCurrentTimeFromSystemClock() const {
	return system_clock::now();
}

steady_clock::time_point NetStat::getCurrentTimeFromSteadyClock() const {
	return steady_clock::now();
}

NetStat::NetStat(config::ExitCtrl& e, bool deltaMode, bool headerMode, bool nonInteractive, bool filterLoopback)
		: exitCtrl(e), incremental(deltaMode), add_header_mode_(headerMode), os(&std::cout), filter_loopback(filterLoopback) {
	interactive = ((isatty(STDIN_FILENO) == 1) && !nonInteractive);
	if (interactive) {
		int window_width = getWindowWidth();
		field_width = window_width / 10;
		if (field_width < NUM_FIELD_WIDTH) {
			field_width = NUM_FIELD_WIDTH;
		}
	}
}

NetStat::~NetStat() {
}

void netstat::NetStat::set_max_map_size(uint32_t size) {
    max_map_size = size;
}

void NetStat::set_kbhit() {
	std::unique_lock<std::mutex> ul(exitCtrl.m);
	kbhit = true;
	ul.unlock();
	exitCtrl.cv.notify_all();
}

void NetStat::on_config_change() {
	std::unique_lock<std::mutex> ul(exitCtrl.m);
	config_changed = true;
	ul.unlock();
	exitCtrl.cv.notify_all();
}

void NetStat::aggregateServers() {
}

template <typename IPTYPE>
std::unordered_map<IPTYPE, Connection> NetStat::filterServerAggrs() {
	std::unordered_map<IPTYPE, Connection> result;
	std::unique_lock<std::mutex> ul(mx_aggr);
	auto aggr = connections<IPTYPE>();
	for (auto& [tup, stats] : aggr) {
		if (stats.state.Direction != 1) {
			continue;
		}
		result.insert({tup, stats});
	}

	return result;
}

template void NetStat::update<ipv4_tuple_t>(const bpf::bpf_fds&);
template void NetStat::update<ipv6_tuple_t>(const bpf::bpf_fds&);
template void NetStat::resolveOldConnections<ipv4_tuple_t>();
template void NetStat::resolveOldConnections<ipv6_tuple_t>();
template std::unordered_map<ipv4_tuple_t, Connection> NetStat::filterServerAggrs<ipv4_tuple_t>();
template std::unordered_map<ipv6_tuple_t, Connection> NetStat::filterServerAggrs<ipv6_tuple_t>();
} // namespace netstat
