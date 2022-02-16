#pragma once

#include "bpf_helpers.h"
#include "maps.h"
#include "nettracer-bpf.h"

#include <linux/ptrace.h>

__attribute__((always_inline))
enum bpf_log_level get_log_level() {
	uint32_t zero = 0;
	struct nettracer_config_t* config = bpf_map_lookup_elem(&nettracer_config, &zero);
	if (config == NULL) {
		return BPF_LOG_LEVEL_INFO; // default level
	}
	return config->log_level;
}

__attribute__((always_inline))
void log_bpf(struct pt_regs *ctx, enum bpf_log_level severity, const char* fmt, uint8_t args_num, const int64_t* args) {
	if (severity < get_log_level()) {
		return;
	}
	uint64_t ts = bpf_ktime_get_ns();
	uint32_t cpu = bpf_get_smp_processor_id();
	uint64_t pid = bpf_get_current_pid_tgid();

	struct bpf_log_event_t evt = {
		.timestamp = ts,
		.cpu = cpu,
		.pid = pid >> 32,
		.severity = severity
	};

	for (int i = 0; i < sizeof(evt.format); ++i) {
		evt.format[i] = fmt[i];
		if (fmt[i] == '\0') {
			break;
		}
	}

	evt.args_num = args_num;
	for (int i = 0; i < args_num && i < sizeof(evt.args) / sizeof(evt.args[0]); ++i) {
		evt.args[i] = args[i];
	}

	bpf_perf_event_output(ctx, &bpf_logs, cpu, &evt, sizeof(evt));
}

#define CHOOSE_MACRO(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, NAME, ...) NAME

// requires an additional initial value to handle effective 0-arg calls nicely
#define COUNT_ARGUMENTS(...) \
	CHOOSE_MACRO(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define LOG_BPF(ctx, severity, fmt, ...) \
	{ \
		int args_count = COUNT_ARGUMENTS(NULL, __VA_ARGS__); \
		if (args_count > 0) { \
			int64_t args[] = {__VA_ARGS__}; \
			log_bpf(ctx, severity, fmt, args_count, args); \
		} \
		else { \
			log_bpf(ctx, severity, fmt, 0, NULL); \
		} \
	}

// max 10 fmtlib-style args allowed

#define LOG_TRACE_BPF(ctx, fmt, ...)    LOG_BPF(ctx, BPF_LOG_LEVEL_TRACE, fmt, __VA_ARGS__)
#define LOG_DEBUG_BPF(ctx, fmt, ...)    LOG_BPF(ctx, BPF_LOG_LEVEL_DEBUG, fmt, __VA_ARGS__)
#define LOG_INFO_BPF(ctx, fmt, ...)     LOG_BPF(ctx, BPF_LOG_LEVEL_INFO, fmt, __VA_ARGS__)
#define LOG_WARN_BPF(ctx, fmt, ...)     LOG_BPF(ctx, BPF_LOG_LEVEL_WARN, fmt, __VA_ARGS__)
#define LOG_ERROR_BPF(ctx, fmt, ...)    LOG_BPF(ctx, BPF_LOG_LEVEL_ERROR, fmt, __VA_ARGS__)
#define LOG_CRITICAL_BPF(ctx, fmt, ...) LOG_BPF(ctx, BPF_LOG_LEVEL_CRITICAL, fmt, __VA_ARGS__)

// use DEBUG_BPF only for debugging purposes where using perf event-based logging is not possible
// the messages appear in /sys/kernel/debug/tracing/trace
// max 3 printf-style args allowed

#ifdef DEBUG
#define DEBUG_BPF(format, ...) \
	{ \
		char fmt[] = "[nettracer] " format "\n"; \
		bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); \
	}
#else
#define DEBUG_BPF(...)
#endif
