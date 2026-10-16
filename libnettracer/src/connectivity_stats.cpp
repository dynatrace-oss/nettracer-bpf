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

#include "connectivity_stats.h"
#include "bpf_generic/src/bpf_interface.h"
#include "system_utils.h"

namespace netstat {

template <typename IPTYPE>
void print_human_readable(const std::unordered_map<ServerTuple_t<IPTYPE>, ServerStats>& aggr, int field_width, std::ostream& os) {

	for (auto& [tup, stats] : aggr) {
		os << std::setw(ADDRESS_FIELD_WIDTH) << to_string(tup.get_tuple(), ConnectionDirection::Incoming);
		os << std::setw(field_width) << tup.pid << std::setw(field_width) << short_num(stats.bytes_sent) << std::setw(field_width)
		   << short_num(stats.bytes_received) << std::setw(field_width) << stats.rtt << std::setw(field_width) << stats.connection_attempts
		   << std::setw(field_width) << stats.connection_timeouts << std::setw(field_width) << stats.connection_resets << "\n";
	}
}

static void printHeader(int field_width, std::ostream& os) {
	os << std::left << std::setw(ADDRESS_FIELD_WIDTH) << "local address <-> remote address" << std::setw(field_width) << "pid"
	   << std::setw(field_width) << "bytes sent" << std::setw(field_width) << "bytes received " << std::setw(field_width) << "rtt"
	   << std::setw(field_width) << "conn_attempts" << std::setw(field_width) << "conn_timeouts"
	   << std::setw(field_width) << "conn_resets" << "\n";
}

void ConnectivityStats::print_human_readable() {
	printHeader(field_width, *os);
	print_human_readable_clients();
	ServersIPv4 s4;
	ServersIPv6 s6;
	{
		std::unique_lock l(mx_servers);
		s4.swap(servers_);
		s6.swap(servers6_);
	}
	print_human_readable<ipv4_tuple_t>(s4, field_width, *os);
	print_human_readable<ipv6_tuple_t>(s6, field_width, *os);
	set_prev_metrics<ipv4_tuple_t>();
	set_prev_metrics<ipv6_tuple_t>();
}

void ConnectivityStats::print_to_pipe() {
	NetStat::print<ipv4_tuple_t>(true);
	NetStat::print<ipv6_tuple_t>(true);
	ServersIPv4 s4;
	ServersIPv6 s6;
	{
		std::unique_lock l(mx_servers);
		s4.swap(servers_);
		s6.swap(servers6_);
	}
	print<ipv4_tuple_t>(s4);
	print<ipv6_tuple_t>(s6);
	set_prev_metrics<ipv4_tuple_t>();
	set_prev_metrics<ipv6_tuple_t>();
}

template <typename IPTYPE>
void ConnectivityStats::aggregate() {
	auto aggr = filterServerAggrs<IPTYPE>();
	std::unique_lock lock(mx_servers);
	for (auto& [tup, stats] : aggr) {
		auto skey = createServerKey(tup, stats.pid);
		auto& statsExt = servers<IPTYPE>()[skey];
		statsExt.addStats(calc_delta(stats.curr, stats.prev, tup));
	}
}

void ConnectivityStats::aggregate() {
	aggregate<ipv4_tuple_t>();
	aggregate<ipv6_tuple_t>();
}

template <typename IPTYPE>
std::unordered_map<uint32_t, uint32_t>& ConnectivityStats::getTcpConf(int& fd) {
	if constexpr (std::is_same_v<IPTYPE, ipv4_tuple_t>) {
		fd = tcp_params_fd;
		return syn_backlog_conf;
	}

	fd = tcp6_params_fd;
	return syn_backlog_conf6;
}

template <typename IPTYPE, typename EventIPTYPE>
void ConnectivityStats::event(const EventIPTYPE& evt) {
	if(NetStat::event<IPTYPE>(evt)){
		return;
	}
	auto key = createServerKey(eventToTuple(evt), evt.pid);
	std::unique_lock lock(mx_servers);
	auto& serv = servers<IPTYPE>()[key];
	serv.update_time = getCurrentTimeFromSteadyClock();

	if (evt.type == TCP_EVENT_TYPE_SYN_ATTEMPT) {
		serv.connection_attempts++;
		tcp_params_t val{};
        int fd;
		auto& conf = getTcpConf<IPTYPE>(fd);
		auto it = conf.find(evt.netns);
		if (it == conf.end()) {
			if (mapsWrapper->lookupElement(fd, &evt.netns, &val)) {
				conf[evt.netns] = val.syn_queue_size;
				LOG_INFO("Namespace {} max_syn_queuelen: {}", evt.netns, val.syn_queue_size);
			}
		} else {
			val.syn_queue_size = it->second;
		}

		if (val.syn_queue_size > 0 && evt.synqueuelen >= val.syn_queue_size) {
			serv.connection_timeouts++;
		}
	} else if (evt.type == TCP_EVENT_TYPE_RST) {
		serv.connection_resets++;
	} else if (evt.type == TCP_EVENT_TYPE_DROP) {
		serv.connection_timeouts++; //we accounts drops as timeouts
	}
}

void ConnectivityStats::eventIpv4(const tcp_ipv4_event_t& evt) {
	return event<ipv4_tuple_t>(evt);
}

void ConnectivityStats::eventIpv6(const tcp_ipv6_event_t& evt) {
	return event<ipv6_tuple_t>(evt);
}

void ConnectivityStats::init(bpf::Ibpf& ebpf) {
	NetStat::init(ebpf);

	tcp_params_fd = ebpf.get_map_fd("tcp_params");
	if (tcp_params_fd < 0) {
		throw std::invalid_argument("invalid tcp_params_fd");
	}

	tcp6_params_fd = ebpf.get_map_fd("tcp6_params");
	if (tcp6_params_fd < 0) {
		throw std::invalid_argument("invalid tcp6_params_fd");
	}
}

template <typename IPTYPE>
void ConnectivityStats::print(const std::unordered_map<ServerTuple_t<IPTYPE>, ServerStats>& aggr)  const {
	std::stringstream buf;
	State  kind{};
	kind.Aggregated = 1;

	for (const auto& [sock, stat] : aggr) {

		buf.str("");
		auto wall_now = getCurrentTimeFromSystemClock();
		const ServerStats& delta = stat;

		buf << std::right << std::setw(12) << duration_cast<seconds>(wall_now.time_since_epoch()).count() << sock.get_tuple()
			<< std::setw(12) << sock.pid << std::setw(12) << sock.netns << kind << std::setw(22)
			<< delta.bytes_sent + addAvgHeaderSize<IPTYPE>(delta.pkts_sent, add_header_mode_) << std::setw(22)
			<< delta.bytes_received + addAvgHeaderSize<IPTYPE>(delta.pkts_received, add_header_mode_) << std::setw(22) << delta.pkts_sent
			<< std::setw(22) << delta.pkts_received << std::setw(22) << delta.pkts_retrans << std::setw(12) << delta.rtt << std::setw(12)
			<< delta.connection_attempts << std::setw(12) << delta.connection_timeouts << std::setw(12) << delta.connection_resets;

		*os << buf.str() << std::endl;
		LOG_TRACE(buf.str());
	}
}

} // namespace netstat
