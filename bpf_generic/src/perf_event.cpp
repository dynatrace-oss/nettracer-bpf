#include "log.h"
#include <fmt/core.h>
#include <chrono>
#include <functional>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <variant>
#include <vector>

template <typename T>
using event = std::variant<perf_event_sample<T>*, perf_event_lost*, std::nullptr_t>;

// pattern https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go
template <typename T>
event<T> perf_event_read(int page_count, int page_size, read_state* state, perf_event_mmap_page* header) {
	uint64_t data_head = header->data_head;
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	uint8_t* base = ((uint8_t*)header) + page_size;
	perf_event_sample<T>* e;
	uint8_t *begin, *end;
	event<T> evt;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return nullptr;

	begin = base + data_tail % raw_size;
	e = (perf_event_sample<T>*)begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;
		memcpy(state->buf, begin, len);
		memcpy((char*)state->buf + len, base, e->header.size - len);
		e = (perf_event_sample<T>*)state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		evt = (perf_event_sample<T>*)state->buf;
		break;
	case PERF_RECORD_LOST:
		evt = (perf_event_lost*)state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return evt;
}

template <typename T, typename Func>
void event_reader::read_loop(Func f) {
	using namespace std::chrono_literals;
	int page_size = getpagesize();
	const int pc = get_nprocs();
	while (running) {
		std::vector<pollfd> pfd(perf_data.pfd.size());
		for (size_t i = 0; i < pfd.size(); i++) {
			pfd[i].fd = perf_data.pfd[i];
			pfd[i].events = POLLIN;
		}

		int res = poll(pfd.data(), pfd.size(), 500);
		if (res < 0) {
			LOG_ERROR("poll error {} event exit", res);
			running = false;
			break;
		} else if (res == 0) {
			continue;
		}

		read_state rstate{};
		static std::vector<T> events(pc);
		events.clear();
		for (int cpu = 0; cpu < pc; cpu++) {
			bool is_result = false;
			do {
				auto res = perf_event_read<T>(perf_data.page_count, page_size, &rstate, perf_data.header[cpu]);
				is_result = !std::holds_alternative<std::nullptr_t>(res);
				if (is_result) {
					try {
						perf_event_sample<T>* smple = std::get<0>(res);
						T* evt = (T*)&(smple->data);
						events.emplace_back(*evt);
					} catch (const std::bad_variant_access&) { // PERF_RECORD_LOST:
						LOG_DEBUG("event lost");
						break;
					}
				}

			} while (is_result);
		}

		std::sort(events.begin(), events.end(), [](T const& a, T const& b) { return a.timestamp < b.timestamp; });
		std::for_each(events.begin(), events.end(), f);
	}
}

template <typename T, typename Func>
void event_reader::start(bpf::map_data& m, Func f) {
	perf_data = m;
	running = true;
	std::thread t(&event_reader::read_loop<T, Func>, this, f);
	reader.swap(t);
}

void event_reader::stop() {
	if (running) {
		running = false;
		reader.join();
	}
}
