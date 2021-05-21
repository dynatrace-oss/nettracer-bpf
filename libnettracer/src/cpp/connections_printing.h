#pragma once

#include "bpf_program/nettracer-bpf.h"
#include "bpf_generic/bpf_wrapper.h"
#include "bpf_generic/log.h"
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
