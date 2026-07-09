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
#include "bpf_events.h"
#include "bpf_generic/src/perf_event.h"
#include "config_watcher.h"
#include <algorithm>
#include <exception>
#include <iostream>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>


static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz){
	evt_descr *desc = static_cast<evt_descr*>(ctx);
	if (data_sz < desc->expected_size) {
		LOG_DEBUG(
				"Event {} size too low ", desc->md.name);
		return;
	}

	if (std::holds_alternative<std::function<void(const tcp_ipv4_event_t&)>>(desc->action)) {
		auto& fn = std::get<std::function<void(const tcp_ipv4_event_t&)>>(desc->action);
		fn(*reinterpret_cast<const tcp_ipv4_event_t*>(data));
	} else {
		auto& fn = std::get<std::function<void(const tcp_ipv6_event_t&)>>(desc->action);
		fn(*reinterpret_cast<const tcp_ipv6_event_t*>(data));
	}
}


static void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
	evt_descr *desc = static_cast<evt_descr*>(ctx);
	LOG_WARN("lost events {}:{}", desc->md.name, lost_cnt);
}

evt_descr::~evt_descr() {
	if (rb) {
		perf_buffer__free(rb);
	}
}

void bpf_events::start() {
	if (!legacy_perf_events) {
		for (auto& it : observers) {
			perf_buffer* rb = perf_buffer__new(
					it.md.fd,
					1024,
					handle_event,
					handle_lost,
					&it, // ctx
					nullptr);
			if (!rb) {
				LOG_ERROR("cannot allocate perfbuf for {}", it.md.name);
			}
			it.rb = rb;
		}
	}
	running = true;
	std::thread t(&bpf_events::loop, this);
	reader.swap(t);
}

void bpf_events::stop() {
	if (running) {
		running = false;
		reader.join();
	}
}

std::vector<pollfd> bpf_events::create_pfds() {
	std::vector<pollfd> fds;
	fds.push_back(pollfd{STDIN_FILENO, POLLIN, 0});

	if (!legacy_perf_events) {
		for (auto& it : observers) {
			if (it.rb) {
				int poll_fd = perf_buffer__epoll_fd(it.rb);
				fds.push_back(pollfd{poll_fd, POLLIN, 0});
				it.rb_idx = poll_fd;
			}
		}
	} else {
		for (const auto& ito : observers) {
			std::transform(ito.md.pfd.begin(), ito.md.pfd.end(), std::back_inserter(fds), [](auto& it) { return pollfd{it, POLLIN, 0}; });
		}
	}

	if (cw) {
		fds.push_back(pollfd{cw.get_poll_fd(), POLLIN, 0});
	}
	return fds;
}

void bpf_events::loop() {
	using namespace std::chrono_literals;
	std::vector<pollfd> fds = create_pfds();
	while (running) {
		int res = poll(fds.data(), fds.size(), 100);
		if (res < 0) {
			LOG_ERROR("poll error {} event exit", res);
			running = false;
			break;
		} else if (res == 0) {
			continue;
		}

		for (auto& fd : fds) {
			if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				exit(1);
			}
			if (!(fd.revents & POLLIN)) {
				continue;
			}
			if (fd.fd == STDIN_FILENO) {
				char tmp[128];
				if (!std::cin.read(tmp, std::min(128, res))) {
					exit(1);
				}
				kbhit_observer();
			} else if (fd.fd == cw.get_poll_fd()) {
				cw.on_pollin();
				if (cw.is_config_changed()) {
					config_change_observer();
				}
			} else {
				process_bpf_event(fd.fd);
			}
			fd.events = POLLIN;
			fd.revents = 0;
		}
	}
}

perf_buffer* bpf_events::fd_to_perfbuf(int fd) {
	for (const auto& it : observers) {
		if (it.rb_idx == fd) {
			return it.rb;
		}
	}
	return nullptr;
}

bpf_events::evt_source bpf_events::fd_to_evtype(int fd) {
	for (const auto& it : observers) {
		auto ft = std::find(it.md.pfd.begin(), it.md.pfd.end(), fd);
		if (ft != it.md.pfd.end())
			return {std::distance(it.md.pfd.begin(), ft), &it};
	}
	throw std::range_error("no type conversion");
}

void bpf_events::process_bpf_event(int fd) {

	if (!legacy_perf_events) {
		perf_buffer* rb = fd_to_perfbuf(fd);
		if (rb) {
			perf_buffer__consume(rb);
		}
	} else {
		auto ac = fd_to_evtype(fd);
		const size_t cpu = ac.first;
		auto page_size = this->page_size;
		std::visit(
				[page_size, cpu, &ac](auto&& arg) {
					using atype = typename std::decay<decltype(arg)>::type::argument_type;
					auto events = bpf::deserializeEvent<typename std::decay<atype>::type>(ac.second->md, page_size, cpu);
					std::sort(events.begin(), events.end(), [](auto const& a, auto const& b) { return a.timestamp < b.timestamp; });
					std::for_each(events.begin(), events.end(), arg);
				},
				ac.second->action);
	}
}
