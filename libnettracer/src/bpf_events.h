#pragma once

#include "bpf_generic/src/maps_loading.h"
#include "bpf_program/nettracer-bpf.h"
#include <functional>
#include <thread>
#include <variant>
#include <vector>

struct pollfd;

template <typename T>
struct evt_descr {
	bpf::map_data md;
	std::function<void(const T&)> action;
	using evt_type = T;
};

class bpf_events {
	std::thread reader;
	bool running = false;
	void read_loop();
	evt_descr<tcp_ipv4_event_t> ipv4_event_observer;
	evt_descr<tcp_ipv6_event_t> ipv6_event_observer;
	evt_descr<bpf_log_event_t> log_event_observer;
    std::vector<pollfd> create_pfds();
public:
    void add_observer(evt_descr<tcp_ipv4_event_t>&& o) {
		ipv4_event_observer = o;
	}
	void add_observer(evt_descr<tcp_ipv6_event_t>&& o) {
		ipv6_event_observer = o;
	}
	void add_observer(evt_descr<bpf_log_event_t>&& o) {
		log_event_observer = o;
	}
	void start();
	void stop();
	void loop();

private:
	using evt_variant = std::pair<int, std::variant<evt_descr<tcp_ipv4_event_t>, evt_descr<tcp_ipv6_event_t>, evt_descr<bpf_log_event_t>>>;
	evt_variant fd_to_evtype(int fd);
};

