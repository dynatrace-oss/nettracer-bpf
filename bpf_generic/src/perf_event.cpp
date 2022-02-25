#include "perf_event.h"
#include <arpa/inet.h>
#include <chrono>
#include <functional>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <variant>
#include <vector>

namespace bpf{
// pattern https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go
perf_read_result perf_event_read(int page_count, int page_size, read_buffer* state, perf_event_mmap_page* header) {
	uint64_t data_head = header->data_head;
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	uint8_t* base = ((uint8_t*)header) + page_size;
	uint8_t *begin, *end;
	perf_read_result res = perf_read_result::error;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return res;

	begin = base + data_tail % raw_size;
	perf_event_header* pheader = (perf_event_header*)begin;
	end = base + (data_tail + pheader->size) % raw_size;
	if (state->buf_len < pheader->size) {
		LOG_INFO("event of unexpected size {}", pheader->size);
		return res;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;
		memcpy(state->buf, begin, len);
		memcpy((char*)state->buf + len, base, pheader->size - len);
	} else {
		memcpy(state->buf, begin, pheader->size);
	}
	switch (pheader->type) {
	case PERF_RECORD_SAMPLE:
		res = perf_read_result::sample;
		break;
	case PERF_RECORD_LOST:
		res = perf_read_result::lost;
		break;
	}

	__sync_synchronize();
	header->data_tail += pheader->size;

	return res;
}
}
