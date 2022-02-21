#include "bpf_events.h"
#include "bpf_generic/src/perf_event.h"
#include <algorithm>
#include <exception>
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

	std::transform(ipv4_event_observer.md.pfd.begin(), ipv4_event_observer.md.pfd.end(), std::back_inserter(fds), [](auto& it) {
		return pollfd{it, POLLIN, 0};
	});
	std::transform(ipv6_event_observer.md.pfd.begin(), ipv6_event_observer.md.pfd.end(), std::back_inserter(fds), [](auto& it) {
		return pollfd{it, POLLIN, 0};
	});
	std::transform(log_event_observer.md.pfd.begin(), log_event_observer.md.pfd.end(), std::back_inserter(fds), [](auto& it) {
		return pollfd{it, POLLIN, 0};
	});
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

			auto ac = fd_to_evtype(fd.fd);
			const size_t cpu = ac.first;
			std::visit(
					[page_size, cpu](auto&& arg) {
						using atype = typename std::decay<decltype(arg)>::type;
						auto events = bpf::deserializeEvent<typename atype::evt_type>(arg.md, page_size, cpu);
						std::sort(events.begin(), events.end(), [](auto const& a, auto const& b) { return a.timestamp < b.timestamp; });
						std::for_each(events.begin(), events.end(), arg.action);
					},
					ac.second);

			fd.events = POLLIN;
			fd.revents = 0;
		}
	}
}

bpf_events::evt_variant bpf_events::fd_to_evtype(
		int fd) {
	auto it = std::find(ipv4_event_observer.md.pfd.begin(), ipv4_event_observer.md.pfd.end(), fd);
	if (it != ipv4_event_observer.md.pfd.end())
		return {std::distance(ipv4_event_observer.md.pfd.begin(), it), ipv4_event_observer};

	auto it2 = std::find(ipv6_event_observer.md.pfd.begin(), ipv6_event_observer.md.pfd.end(), fd);
	if (it2 != ipv6_event_observer.md.pfd.end())
		return {std::distance( ipv6_event_observer.md.pfd.begin(), it2), ipv6_event_observer};

	auto it3 = std::find(log_event_observer.md.pfd.begin(), log_event_observer.md.pfd.end(), fd);
	if (it3 != log_event_observer.md.pfd.end())
		return {std::distance( log_event_observer.md.pfd.begin(), it3), log_event_observer};

	throw std::range_error("no type conversion");
}
