#pragma once

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

static inline int perf_event_open_map(int pid, int cpu, int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_SOFTWARE;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	attr.size = sizeof(struct perf_event_attr);
	attr.config = 10; // PERF_COUNT_SW_BPF_OUTPUT

	return syscall(__NR_perf_event_open, &attr, pid, cpu,
		       group_fd, flags);
}


static inline  int perf_event_open_tracepoint(int tracepoint_id, int pid, int cpu,
                           int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = tracepoint_id;

	return syscall(__NR_perf_event_open, &attr, pid, cpu,
                      group_fd, flags);
}

