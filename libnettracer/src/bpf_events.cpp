#include "bpf_events.h"
#include "bpf_generic/src/perf_event.h"
#include "config_watcher.h"
#include <algorithm>
#include <exception>
#include <iostream>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>

void bpf_events::start() {
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
	for (const auto& ito : observers) {
		std::transform(ito.md.pfd.begin(), ito.md.pfd.end(), std::back_inserter(fds), [](auto& it) { return pollfd{it, POLLIN, 0}; });
	}
	if (cw) {
		fds.push_back(pollfd{cw.get_poll_fd(), POLLIN, 0});
	}
	return fds;
}

void bpf_events::loop() {
	using namespace std::chrono_literals;
	int page_size = getpagesize();
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

				auto ac = fd_to_evtype(fd.fd);
				const size_t cpu = ac.first;
				std::visit(
						[page_size, cpu, &ac](auto&& arg) {
							using atype = typename std::decay<decltype(arg)>::type::argument_type;
							auto events = bpf::deserializeEvent<typename std::decay<atype>::type>(ac.second.md, page_size, cpu);
							std::sort(events.begin(), events.end(), [](auto const& a, auto const& b) { return a.timestamp < b.timestamp; });
							std::for_each(events.begin(), events.end(), arg);
						},
						ac.second.action);
			}

			fd.events = POLLIN;
			fd.revents = 0;
		}
	}
}

bpf_events::evt_source bpf_events::fd_to_evtype(int fd) {
	for (const auto& it : observers) {
		auto ft = std::find(it.md.pfd.begin(), it.md.pfd.end(), fd);
		if (ft != it.md.pfd.end())
			return {std::distance(it.md.pfd.begin(), ft), it};
	}
	throw std::range_error("no type conversion");
}

