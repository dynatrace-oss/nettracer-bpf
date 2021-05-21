#pragma once

#include "bpf_loading.h"
#include "maps_loading.h"
#include <linux/perf_event.h>
#include <poll.h>
#include <stdint.h>
#include <thread>
#include <vector>

struct read_state {
	void* buf;
	int buf_len;
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

class event_reader {
	std::thread reader;
	bpf::map_data perf_data;
	bool running = false;
	template<typename T, typename Func>
	void read_loop(Func f);

public:
	template<typename T, typename Func>
	void start(bpf::map_data& m, Func f);
	void stop();
};

#include "perf_event.cpp"
