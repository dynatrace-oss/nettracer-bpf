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
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
#include "tuple_utils.h"
#include "proc_tcp.h"
#include <unordered_set>
#include <tuple>
#include <condition_variable>

struct bpf_fds {
    int pid_fd;
    int stats_fd;
    int tcp_stats_fd;
    bool isInvalid() {
        return (pid_fd < 0 || stats_fd < 0 || tcp_stats_fd < 0);
    }
};

template<typename T>
struct ConnectionsState {
	explicit ConnectionsState(const MapTuple2Details<T>& connections = getCurrentConnections<T>())
		: connsDetails(connections) {}

	MapTuple2Details<T> connsDetails;
	std::vector<T> connsClosed;
	std::mutex mutex;
};

struct ExitCtrl {
	bool running{true};
	std::mutex m;
	std::condition_variable cv;
	unsigned wait_time;
};

template<typename Tuple>
void updateConnectionsFromMaps(ConnectionsState<Tuple>& connsState, const bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper);
template<typename Tuple, typename Event>
void updateConnectionsAfterEvent(const Event& evt, ConnectionsState<Tuple>& connsState);
