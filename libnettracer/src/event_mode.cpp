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
#include "event_mode.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
#include "tuple_utils.h"
#include <chrono>
#include <fmt/core.h>

using namespace std::chrono_literals;

namespace {

template<typename Tuple, typename T, typename F>
void processBPFMap(int fd, bpf::BPFMapsWrapper& mapsWrapper, F func) {
	Tuple previousKey{};
	Tuple currentKey{};
	while (mapsWrapper.getNextKey(fd, &previousKey, &currentKey)) {
		T val{};
		if (mapsWrapper.lookupElement(fd, &currentKey, &val)) {
			func(currentKey, val);
		}
		previousKey = currentKey;
	}
}

} // namespace

template<typename Tuple>
void ignoreConnectionsFromMaps(const bpf::bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper) {
	const int detailsFd{fds.pid_fd};
	const int statsFd{fds.stats_fd};
	const int tcpStatsFd{fds.tcp_stats_fd};

	processBPFMap<Tuple, pid_comm_t>(
			detailsFd, mapsWrapper, [&mapsWrapper, detailsFd](const Tuple& key, [[maybe_unused]] const pid_comm_t& val) {
				mapsWrapper.removeElement(detailsFd, &key);
			});

	processBPFMap<Tuple, stats_t>(statsFd, mapsWrapper, [&mapsWrapper, statsFd](const Tuple& key, [[maybe_unused]] const stats_t& val) {
		mapsWrapper.removeElement(statsFd, &key);
	});

	processBPFMap<Tuple, tcp_stats_t>(
			tcpStatsFd, mapsWrapper, [&mapsWrapper, tcpStatsFd](const Tuple& key, [[maybe_unused]] const tcp_stats_t& val) {
				mapsWrapper.removeElement(tcpStatsFd, &key);
			});
}

template<typename Event>
void processEvent(const Event& evt) {
	auto recv = std::chrono::steady_clock::now();
	uint64_t recv_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(recv.time_since_epoch()).count();
	int64_t latency_us = (static_cast<int64_t>(recv_ns) - static_cast<int64_t>(evt.timestamp)) / 1000;
	LOG_INFO("Event {} latency: {}us", to_string(evt), (latency_us >= 0) ? latency_us : 0);
}

template void ignoreConnectionsFromMaps<ipv4_tuple_t>(const bpf::bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper);
template void ignoreConnectionsFromMaps<ipv6_tuple_t>(const bpf::bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper);

template void processEvent(const tcp_ipv4_event_t& evt);
template void processEvent(const tcp_ipv6_event_t& evt);
