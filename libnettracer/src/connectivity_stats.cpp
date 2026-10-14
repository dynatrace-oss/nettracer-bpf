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
	std::unique_lock<std::mutex> l(mx_servers);
	print_human_readable<ipv4_tuple_t>(servers_, field_width, *os);
	print_human_readable<ipv6_tuple_t>(servers6_, field_width, *os);
    servers_.clear();
	servers6_.clear();
}

void ConnectivityStats::print_to_pipe() {

}

template <typename IPTYPE>
void ConnectivityStats::aggregateServers() {
	auto aggr = filterServerAggrs<IPTYPE>();
	std::unique_lock<std::mutex> lock(mx_servers);
	for (auto& [tup, stats] : aggr) {
		auto skey = createServerKey(tup, stats.pid);
		auto& statsExt = servers<IPTYPE>()[skey];
		statsExt.addStats(calc_delta(stats.curr, stats.prev, tup));
	}
	lock.unlock();
	set_prev_metrics<IPTYPE>();
}

void ConnectivityStats::aggregateServers() {
	aggregateServers<ipv4_tuple_t>();
	aggregateServers<ipv6_tuple_t>();
}

template <typename IPTYPE, typename EventIPTYPE>
void ConnectivityStats::event(const EventIPTYPE& evt) {
	NetStat::event<IPTYPE>(evt);
	auto key = createServerKey(eventToTuple(evt), evt.pid);
	std::unique_lock<std::mutex> l(mx_servers);
	auto& serv = servers<IPTYPE>()[key];
	serv.update_time = getCurrentTimeFromSteadyClock();

	if (evt.type == TCP_EVENT_TYPE_SYN_ATTEMPT) {
		serv.connection_attempts++;
	} else if (evt.type == TCP_EVENT_TYPE_RST) {
		serv.connection_resets++;
	} else if (evt.type == TCP_EVENT_TYPE_DROP) {
		serv.connection_timeouts++;
	}
}

void ConnectivityStats::eventIpv4(const tcp_ipv4_event_t& evt) {
	return event<ipv4_tuple_t>(evt);
}
void ConnectivityStats::eventIpv6(const tcp_ipv6_event_t& evt) {
	return event<ipv6_tuple_t>(evt);
}
} // namespace netstat
