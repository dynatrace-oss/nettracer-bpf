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
	std::unique_lock l(mx_servers);
	print_human_readable<ipv4_tuple_t>(servers_, field_width, *os);
	print_human_readable<ipv6_tuple_t>(servers6_, field_width, *os);
    servers_.clear();
	servers6_.clear();
}

void ConnectivityStats::print_to_pipe() {

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
	lock.unlock();
	set_prev_metrics<IPTYPE>();
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
	NetStat::event<IPTYPE>(evt);
	auto key = createServerKey(eventToTuple(evt), evt.pid);
	std::unique_lock l(mx_servers);
	auto& serv = servers<IPTYPE>()[key];
	serv.update_time = getCurrentTimeFromSteadyClock();

	if (evt.type == TCP_EVENT_TYPE_SYN_ATTEMPT) {
		serv.connection_attempts++;;
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

} // namespace netstat
