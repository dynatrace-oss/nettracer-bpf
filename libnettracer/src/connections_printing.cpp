#include "connections_printing.h"
#include "bpf_generic/src/bpf_loading.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
#include <fmt/core.h>

using namespace std::chrono_literals;

namespace {

template<typename Tuple>
bool areTuplesEqualDisregardingNamespace(const Tuple& a, const Tuple& b) {
	Tuple c{a};
	c.netns = b.netns;
	return c == b;
}

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
void updateConnectionsFromMaps(ConnectionsState<Tuple>& connsState, const bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper) {
	const int detailsFd{fds.pid_fd};
	const int statsFd{fds.stats_fd};
	const int tcpStatsFd{fds.tcp_stats_fd};

	MapTuple2Details<Tuple>& connsDetails{connsState.connsDetails};
	std::vector<Tuple>& closedConns{connsState.connsClosed};
	std::mutex& connsMutex{connsState.mutex};

	processBPFMap<Tuple, pid_comm_t>(detailsFd, mapsWrapper, [&](const Tuple& key, const pid_comm_t& val){
		// check for tuples collected during startup that can be improved
		for (const auto& e : connsDetails) {
			if (e.first.netns == 0 && areTuplesEqualDisregardingNamespace(e.first, key)) {
				connsDetails.insert({key, {val.pid, e.second.direction}});
				connsDetails.erase(e.first);
				break;
			}
		}

		if (val.state == CONN_CLOSED) {
			mapsWrapper.removeElement(detailsFd, &key);
		}
	});

	processBPFMap<Tuple, stats_t>(statsFd, mapsWrapper, [&](const Tuple& key, const stats_t& val){
		ConnectionDirection direction{ConnectionDirection::Unknown};
		std::lock_guard<std::mutex> connsLock{connsMutex};
		auto detailsFound{connsDetails.find(key)};
		if (detailsFound != connsDetails.end()) {
			direction = detailsFound->second.direction;
		}
		else {
			LOG_DEBUG("Stats for unknown connection: {}", to_string(key));
		}

		LOG_INFO("{} - stats: Bytes sent={:d} Bytes received={:d}",
			to_string({key, direction}), val.sent_bytes, val.received_bytes);
	});

	processBPFMap<Tuple, tcp_stats_t>(tcpStatsFd, mapsWrapper, [&](const Tuple& key, const tcp_stats_t& val){
		ConnectionDirection direction{ConnectionDirection::Unknown};
		std::lock_guard<std::mutex> connsLock{connsMutex};
		auto detailsFound{connsDetails.find(key)};
		if (detailsFound != connsDetails.end()) {
			direction = detailsFound->second.direction;
		}
		else {
			LOG_DEBUG("TCP stats for unknown connection: {}", to_string(key));
		}

		LOG_INFO("{} - TCP stats: Retransmissions={:d} Segs_in={:d} Segs_out={:d} RTT={:d} RTT_var={:d}",
			to_string({key, direction}), val.retransmissions, val.segs_in, val.segs_out, val.rtt, val.rtt_var);
	});

	std::unique_lock<std::mutex> connsLock{connsMutex};

	for (const auto& conn : closedConns) {
		LOG_DEBUG("Remove connection stats {}", to_string(conn));
		mapsWrapper.removeElement(statsFd, &conn);
		mapsWrapper.removeElement(tcpStatsFd, &conn);
		size_t removed{connsDetails.erase(conn)};
		if (removed != 1) {
			// it's most likely caused by 0.0.0.0 addresses read on startup being treated the same as specified addresses, see APM-286176
			LOG_DEBUG("Couldn't remove connection after close event - connection {} doesn't exist in the map", to_string({conn, ConnectionDirection::Unknown}));
		}
	}
	closedConns.clear();
}

template<typename Tuple, typename Event>
void updateConnectionsAfterEvent(const Event& evt, ConnectionsState<Tuple>& connsState) {
	std::string etype = name_of_evt[evt.type];
	LOG_INFO("event {} {}", etype, to_string(evt));
	
	Tuple conn{eventToTuple(evt)};
	std::lock_guard<std::mutex> lock{connsState.mutex};

	if (evt.type == TCP_EVENT_TYPE_CLOSE) {
		LOG_DEBUG("moved conn:{} on evt CLOSE", to_string(conn));
		connsState.connsClosed.push_back(conn);
	} else {
		ConnectionDetails details{
			evt.pid,
			ConnectionDirection::Outgoing
		};
		if (evt.type == TCP_EVENT_TYPE_ACCEPT) {
			details.direction = ConnectionDirection::Incoming;
		} else if (evt.type != TCP_EVENT_TYPE_CONNECT) {
			return; // neither accept or connect - not supported event
		}

		auto result{connsState.connsDetails.insert({conn, details})};
		if (!result.second) {
			LOG_WARN("Couldn't add new connection after event {} - connection already exists", to_string(evt));
		}
	}
}

template void updateConnectionsFromMaps(ConnectionsState<ipv4_tuple_t>& connsState, const bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper);
template void updateConnectionsFromMaps(ConnectionsState<ipv6_tuple_t>& connsState, const bpf_fds& fds, bpf::BPFMapsWrapper& mapsWrapper);

template void updateConnectionsAfterEvent(const tcp_ipv4_event_t& evt, ConnectionsState<ipv4_tuple_t>& connsState);
template void updateConnectionsAfterEvent(const tcp_ipv6_event_t& evt, ConnectionsState<ipv6_tuple_t>& connsState);
