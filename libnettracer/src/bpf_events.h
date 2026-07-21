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

#include "bpf_generic/src/maps_def.h"
#include "bpf_program/nettracer-bpf.h"
#include <bpf/libbpf.h>
#include <functional>
#include <thread>
#include <variant>
#include <vector>

class config_watcher;

struct pollfd;

template <typename T>
using f_ac = std::function<void(const T&)>;
using actions = std::variant<f_ac<tcp_ipv4_event_t>, f_ac<tcp_ipv6_event_t>>;

struct evt_descr {
	bpf::map_data md;
	actions action;
	perf_buffer* perf_buf{nullptr};
	int perf_buf_fd{};
	int expected_size;

	evt_descr() = default;
	evt_descr(const evt_descr&) = delete;
	evt_descr& operator=(const evt_descr&) = delete;
	evt_descr(evt_descr&& other) noexcept
			: md(std::move(other.md)),
			  action(std::move(other.action)),
			  perf_buf(other.perf_buf),
			  perf_buf_fd(other.perf_buf_fd),
			  expected_size(other.expected_size) {
		other.perf_buf = nullptr;
	}

	evt_descr& operator=(evt_descr&&) = delete;
	~evt_descr();
};

class bpf_events {
	std::thread reader;
	bool running = false;
	int page_size;
	bool legacy_perf_events;
	void read_loop();
	std::vector<evt_descr> observers;
	std::vector<pollfd> create_pfds();
	std::function<void()> kbhit_observer;
	std::function<void()> config_change_observer;
	config_watcher& cw;

public:
	bpf_events(config_watcher& cw, bool legacy) : page_size(getpagesize()), legacy_perf_events(legacy), cw(cw) {
	}

	template <typename T>
	void add_observer(const bpf::map_data md, f_ac<T> ac) {
		evt_descr tmp;
		tmp.md = md;
		tmp.action = ac;
		tmp.expected_size = sizeof(T);
		observers.emplace_back(std::move(tmp));
	}

	void set_kbhit_observer(std::function<void()>&& f) {
		kbhit_observer = f;
	}

	void set_config_change_observer(std::function<void()>&& f) {
		config_change_observer = f;
	}

	void start();
	void stop();
	void loop();

private:
	using evt_source = std::pair<int, const evt_descr*>;
	evt_source fd_to_evtype(int fd);
	perf_buffer* fd_to_perfbuf(int fd);
	void process_bpf_event(int fd);
};

