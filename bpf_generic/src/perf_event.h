#pragma once
#include "bpf_loading.h"
#include "log.h"
#include "maps_loading.h"
#include <fmt/core.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <stdint.h>
#include <thread>
#include <vector>

namespace bpf {

constexpr int maxbuf_len = 512;
struct read_buffer {
	const int buf_len = maxbuf_len;
	uint8_t buf[maxbuf_len];
};

struct perf_event_lost {
	perf_event_header header;
	uint64_t id;
	uint64_t lost;
};

template <typename T>
struct perf_event_sample {
	perf_event_header header;
	uint32_t size;
	uint8_t data[sizeof(T)];
};

enum class perf_read_result { sample, lost, error };
perf_read_result perf_event_read(int page_count, int page_size, read_buffer* buffer, perf_event_mmap_page* header);

template <typename T>
std::vector<T> deserializeEvent(const bpf::map_data& perf_data, const size_t page_size, const int cpu) {
	std::vector<T> events;
	bool is_result = true;
	read_buffer rbuff{};
	while (is_result) {
		auto res = perf_event_read(perf_data.page_count, page_size, &rbuff, perf_data.header[cpu]);
		if (res == perf_read_result::sample) {
			perf_event_sample<T>* sample = (perf_event_sample<T>*)rbuff.buf;
			T* evt = (T*)&(sample->data);
			events.emplace_back(*evt);
			is_result = true;
		} else if (res == perf_read_result::lost) {
			LOG_DEBUG("event lost");
			is_result = false;
		} else {
			is_result = false;
		}
	}
	return events;
}
} // namespace bpf
