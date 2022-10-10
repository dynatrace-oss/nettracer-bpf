#pragma once

#include "bpf_generic/src/maps_loading.h"
#include "bpf_program/nettracer-bpf.h"
#include <functional>
#include <thread>
#include <variant>
#include <vector>

struct pollfd;

template <typename T>
using f_ac = std::function<void(const T&)>;
using actions = std::variant<f_ac<tcp_ipv4_event_t>, f_ac<tcp_ipv6_event_t>, f_ac<bpf_log_event_t>>;

struct evt_descr {
	bpf::map_data md;
	actions action;
};

class bpf_events {
	std::thread reader;
	bool running = false;
	void read_loop();
	std::vector<evt_descr> observers;
	std::vector<pollfd> create_pfds();
	std::function<void()> kbhit_observer;

public:
	template <typename T>
	void add_observer(const bpf::map_data md, f_ac<T> ac) {
		evt_descr tmp;
		tmp.md = md;
		tmp.action = ac;
		observers.push_back(tmp);
	}

	void set_kbhit_observer(std::function<void()>&& f) {
		kbhit_observer = f;
	}
	void start();
	void stop();
	void loop();

private:
	using evt_source = std::pair<int, evt_descr>;
	evt_source fd_to_evtype(int fd);
};

