#pragma once

#include "bpf_program/nettracer-bpf.h"
#include "connections_printing.h"
#include <chrono>
#include <ostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

namespace netstat {

struct State {
	unsigned char Established : 1;
	unsigned char Direction : 1;
	unsigned char Closed : 1;
};

using namespace std::chrono;

struct Connection {
	uint32_t pid = 0;
	uint32_t ns;
	State state;
	steady_clock::time_point update_time;
	system_clock::time_point start;
	system_clock::time_point end;
	uint64_t bytes_sent;
	uint64_t bytes_sent_prev = 0;
	uint64_t bytes_received;
	uint64_t bytes_received_prev = 0;
	uint64_t pkts_sent;
	uint64_t pkts_sent_prev = 0;
	uint64_t pkts_received;
	uint64_t pkts_received_prev = 0;
	uint64_t pkts_retrans;
	uint64_t pkts_retrans_prev = 0;
	uint32_t rtt;
	uint32_t rtt_var;
};

using ConnectionsIPv4 = std::unordered_map<ipv4_tuple_t, Connection>;
using ConnectionsIPv6 = std::unordered_map<ipv6_tuple_t, Connection>;

class NetStat {
protected:
	ConnectionsIPv4 aggr_;
	ConnectionsIPv6 aggr6_;
	std::mutex mx;
	bool kbhit;
	std::thread kbhit_t;
	const int max_map_size = 1024;
	ExitCtrl& exitCtrl;
	bool incremental;
	bool add_header_mode_ = false;
	bpf::BPFMapsWrapper* mapsWrapper;
	std::ostream* os;
	int field_width;
	bool interactive;

	template <typename IPTYPE>
	inline auto& connections(); // no default instantiation

	void kbhit_check();

	template<typename IPTYPE>
	void initConnection(const tcpTable<IPTYPE>&);
	void initConnections();

	template<typename IPTYPE>
	void update(const bpf_fds& fds);

	template<typename IPTYPE, typename T, typename F>
	void process_bpf_map(int fd, F func);

	void printHeader();
	template<typename IPTYPE>
	void print();
	template<typename IPTYPE>
	void print_human_readable();
	void flush();
	template <typename IPTYPE>
	void clean();

	template<typename IPTYPE>
	void clean_bpf(const bpf_fds& fds);

	virtual system_clock::time_point getCurrentTimeFromSystemClock() const;
	virtual steady_clock::time_point getCurrentTimeFromSteadyClock() const;

public:
	explicit NetStat(ExitCtrl& e, bool deltaMode, bool headerMode, bool nonInteractive);
	virtual ~NetStat();

	void init();

	void map_loop(const bpf_fds& fdsIPv4, const bpf_fds& fdsIPv6);

	template<typename IPTYPE, typename EventIPTYPE>
	void event(const EventIPTYPE& evt);
};

template<>
inline auto& NetStat::connections<ipv4_tuple_t>() {
	return aggr_;
}
template<>
inline auto& NetStat::connections<ipv6_tuple_t>() {
	return aggr6_;
}

} // namespace netstat
