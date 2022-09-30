#include "netstat.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
#include "proc_tcp.h"
#include <sys/ioctl.h>
#include <iomanip>
#include <iostream>
#include <poll.h>
#include <unistd.h>

namespace netstat {

constexpr auto INACTIVE_TIMEOUT = minutes(1);
constexpr unsigned INTERVAL_DIVIDER = 10;
constexpr int MIN_FIELD_WIDTH = 22;

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
				std::unique_lock<std::mutex> l(mx);
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
void NetStat::update(const bpf_fds& fds) {
	process_bpf_map<IPTYPE, pid_comm_t>(fds.pid_fd, [&](auto& el, const auto& val) {
		uint32_t pid = static_cast<uint32_t>(val.pid >> 32);
		if(el.pid == 0){
			el.pid = pid;
		}
		return false;
	});

	process_bpf_map<IPTYPE, stats_t>(fds.stats_fd, [&](auto& el, const auto& val) {
		bool changed = (el.bytes_sent != val.sent_bytes) || (el.bytes_received != val.received_bytes);
		el.bytes_sent = val.sent_bytes;
		el.bytes_received = val.received_bytes;
		return changed;
	});

	process_bpf_map<IPTYPE, tcp_stats_t>(fds.tcp_stats_fd, [&](auto& el, const auto& val) {
		bool changed = (el.pkts_retrans != val.retransmissions) || (el.pkts_sent != val.segs_out) || (el.pkts_received != val.segs_in) || (el.rtt != val.rtt) || (el.rtt_var != val.rtt_var);
		el.pkts_retrans = val.retransmissions;
		el.pkts_sent = val.segs_out;
		el.pkts_received = val.segs_in;
		el.rtt = val.rtt;
		el.rtt_var = val.rtt_var;
		return changed;
	});
}

void NetStat::map_loop(const bpf_fds& fdsIPv4, const bpf_fds& fdsIPv6) {
	unsigned counter = 0;
	unsigned factor = exitCtrl.wait_time * INTERVAL_DIVIDER;
	printHeader();
	while (exitCtrl.running) {
		update<ipv4_tuple_t>(fdsIPv4);
		update<ipv6_tuple_t>(fdsIPv6);
		clean_bpf<ipv4_tuple_t>(fdsIPv4);
		clean_bpf<ipv6_tuple_t>(fdsIPv6);

		if (kbhit || ((counter % factor) == 0)) {
			if (interactive) {
				print_human_readable<ipv4_tuple_t>();
				print_human_readable<ipv6_tuple_t>();
			} else {
				print<ipv4_tuple_t>();
				print<ipv6_tuple_t>();
			}
			flush();
			clean<ipv4_tuple_t>();
			clean<ipv6_tuple_t>();
			counter = 0;
		}

		++counter;
		std::unique_lock<std::mutex> lk(exitCtrl.m);
		kbhit = false;
		exitCtrl.cv.wait_for(lk, milliseconds(1000 / INTERVAL_DIVIDER), [this] { return !exitCtrl.running || kbhit; });
	}
}

template<typename IPTYPE>
void NetStat::clean_bpf(const bpf_fds& fds) {
	auto now = getCurrentTimeFromSteadyClock();
	std::unique_lock<std::mutex> l(mx);
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
	std::unique_lock<std::mutex> l(mx);
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
	auto time = getCurrentTimeFromSystemClock();

	std::unique_lock<std::mutex> l(mx);
	auto& el = connections<IPTYPE>()[key];
	if( key.sport == 0 ){
		LOG_DEBUG("Event src port = 0 for {} ", to_string(evt));
		return;
	}
	el.pid = evt.pid;
	el.update_time = getCurrentTimeFromSteadyClock();
	if (evt.type == TCP_EVENT_TYPE_CONNECT) {
		el.start = time;
		el.state.Established = 1;
	} else if (evt.type == TCP_EVENT_TYPE_ACCEPT) {
		el.state.Direction = 1;
		el.state.Established = 1;
		el.start = time;
	} else if (evt.type == TCP_EVENT_TYPE_CLOSE) {
		el.state.Closed = 1;
		el.end = time;
	}
}

template void NetStat::event<ipv4_tuple_t>(const tcp_ipv4_event_t& evt);
template void NetStat::event<ipv6_tuple_t>(const tcp_ipv6_event_t& evt);

#define PRINT_BIT(field) ((s.field) ? "1" : "0")

static std::ostream& operator<<(std::ostream& os, const netstat::State& s) {
	os << " " << PRINT_BIT(Established) << PRINT_BIT(Direction) << PRINT_BIT(Closed) << " ";
	return os;
}

const unsigned PROTO_BIT_IPV4{0};
const unsigned PROTO_BIT_IPV6{1};

static std::ostream& operator<<(std::ostream& os, const ipv4_tuple_t& tup) {
	os << ' ' << PROTO_BIT_IPV4 << ' ' << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << tup.saddr << ' '
	   << std::setw(4) << tup.sport << ' ' << PROTO_BIT_IPV4 << ' ' << std::setw(8) << tup.daddr << ' ' << std::setw(4) << tup.dport
	   << std::dec << ' ' << std::setfill(' ');
	return os;
}

static std::ostream& operator<<(std::ostream& os, const ipv6_tuple_t& tup) {
	os << ' ' << PROTO_BIT_IPV6 << ' ' << std::uppercase << std::hex << std::setfill('0') << std::setw(16) << tup.saddr_h << std::setw(16)
	   << tup.saddr_l << ' ' << std::setw(4) << tup.sport << ' ' << PROTO_BIT_IPV6 << ' ' << std::setw(16) << tup.daddr_h << std::setw(16)
	   << tup.daddr_l << ' ' << std::setw(4) << tup.dport << std::setfill(' ') << std::dec << ' ';
	return os;
}

static void printAddr(std::ostream& os, const ipv4_tuple_t& tup, int field_width) {
	os << std::setw(field_width) << fmt::format("{}:{}", ipv4_to_string(tup.saddr), tup.sport)
	   << std::setw(field_width) << fmt::format("{}:{}", ipv4_to_string(tup.daddr), tup.dport);
}

static void printAddr(std::ostream& os, const ipv6_tuple_t& tup, int field_width) {
	os << std::setw(field_width) << fmt::format("{}:{}", ipv6_to_string(tup.saddr_h, tup.saddr_l), tup.sport)
	   << std::setw(field_width) << fmt::format("{}:{}", ipv6_to_string(tup.daddr_h, tup.daddr_l), tup.dport);
}

static uint64_t subtract(uint64_t& a, uint64_t& b, int pos, bool incremental) {
	uint64_t result = 0;
	if (a >= b) {
		result = a - b;
		if (incremental) {
			b = a;
		}
	} else {
		LOG_DEBUG("nonmonotonic values {} < {} pos: {}", a, b, pos);
	}
	return result;
}

void NetStat::flush() {
	*os << " " << std::endl;
}

template<typename IPTYPE>
void NetStat::print() {
	std::unique_lock<std::mutex> l(mx);
	auto& aggr{connections<IPTYPE>()};
	for (auto it = aggr.begin(); it != aggr.end(); ++it) {
		auto wall_now = getCurrentTimeFromSystemClock();
		uint64_t pkts_sent = subtract(it->second.pkts_sent, it->second.pkts_sent_prev, 2, incremental);
		uint64_t pkts_received = subtract(it->second.pkts_received, it->second.pkts_received_prev, 3, incremental);

		*os << std::right
			  << std::setw(12) << duration_cast<seconds>(wall_now.time_since_epoch()).count()
			  << it->first
			  << std::setw(12) << it->second.pid
			  << std::setw(12) << it->first.netns << it->second.state
			  << std::setw(22) << subtract( it->second.bytes_sent, it->second.bytes_sent_prev, 0, incremental) + addAvgHeaderSize<IPTYPE>( pkts_sent, add_header_mode_)
			  << std::setw(22) << subtract( it->second.bytes_received, it->second.bytes_received_prev, 1, incremental) + addAvgHeaderSize<IPTYPE>( pkts_received, add_header_mode_ )
		  	  << std::setw(22) << pkts_sent
			  << std::setw(22) << pkts_received
			  << std::setw(22) << subtract( it->second.pkts_retrans, it->second.pkts_retrans_prev, 4, incremental)
			  << std::setw(12) << it->second.rtt
			  << std::setw(12) << it->second.rtt_var;

		if (it->second.state.Established) {
			auto end = (it->second.end != system_clock::time_point{}) ? it->second.end : getCurrentTimeFromSystemClock();
			auto duration = duration_cast<seconds>(end - it->second.start);
			*os << std::setw(16) << duration_cast<seconds>(it->second.start.time_since_epoch()).count() << std::setw(9)
					  << duration.count();
		}
		*os << "\n";
	}
}

void NetStat::printHeader() {
	if (!interactive)
		return;

	*os << std::left << std::setw(field_width) << "local address" << std::setw(field_width) << "remote address"
		<< std::setw(field_width) << "pid" << std::setw(field_width) << "bytes sent" << std::setw(field_width)
		<< "bytes received " << std::setw(field_width) << "rtt" << "\n";
}

template <typename IPTYPE>
void NetStat::print_human_readable() {
	std::unique_lock<std::mutex> l(mx);
	auto& aggr{connections<IPTYPE>()};
	for (const auto& it : aggr) {
		printAddr(*os, it.first, field_width);
		*os << std::setw(field_width) << it.second.pid <<  std::setw(field_width) << it.second.bytes_sent
			<< std::setw(field_width) << it.second.bytes_received << std::setw(field_width) << it.second.rtt << "\n";
	}
}

template<typename IPTYPE>
void NetStat::initConnection(const tcpTable<IPTYPE> &tbl){
	auto& aggr{connections<IPTYPE>()};
	for(auto &el: tbl){
		auto &conn = aggr[el.second.ep];
		conn.pid = el.second.pid;
		//conn.state.Direction = (el.second.direction == ConnectionDirection::Incoming) ? 1 : 0;
		conn.update_time = getCurrentTimeFromSteadyClock();
	}
}

void NetStat::initConnections() {
	tcpTable<ipv4_tuple_t> initTcp = readTcpTable("/proc");
	tcpTable<ipv6_tuple_t> initTcp6 = readTcpTable6("/proc");
	initConnection<ipv4_tuple_t>(initTcp);
	initConnection<ipv6_tuple_t>(initTcp6);
}

void NetStat::init() {
	initConnections();

	// wrapper just wraps syscalls so using it is thread-safe
	static bpf::BPFMapsWrapper wrapper;
	mapsWrapper = &wrapper;

	kbhit_t = std::thread(&NetStat::kbhit_check, this);
}

system_clock::time_point NetStat::getCurrentTimeFromSystemClock() const {
	return system_clock::now();
}

steady_clock::time_point NetStat::getCurrentTimeFromSteadyClock() const {
	return steady_clock::now();
}

NetStat::NetStat(ExitCtrl& e, bool deltaMode, bool headerMode, bool nonInteractive)
		: exitCtrl(e), incremental(deltaMode), add_header_mode_(headerMode), os(&std::cout) {
	interactive = ((isatty(STDIN_FILENO) == 1) && !nonInteractive);
	if (interactive) {
		int window_width = getWindowWidth();
		field_width = window_width / 6;
		if (field_width < MIN_FIELD_WIDTH) {
			field_width = MIN_FIELD_WIDTH;
		}
	}
}

NetStat::~NetStat() {
	if (kbhit_t.joinable()) {
		kbhit_t.join();
	}
}

// kbhit should enforce refersh data display
void NetStat::kbhit_check() {
	char tmp[128];
	std::vector<pollfd> pfd(1);
	while (exitCtrl.running) {
		pfd[0].fd = 0;
		pfd[0].events = POLLIN;

		int res = poll(pfd.data(), pfd.size(), 200);
		if (res < 0) {
			break;
		} else if (res == 0) {
			continue;
		}

		if (!std::cin.read(tmp, std::min(128, res))) {
			exit(1);
		}
		std::unique_lock<std::mutex> ul(exitCtrl.m);
		kbhit = true;
		ul.unlock();
		exitCtrl.cv.notify_all();
	}
}

} // namespace netstat
