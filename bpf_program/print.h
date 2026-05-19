#pragma once

#ifdef LEGACY_BPF
#include "legacy/bpf_helpers.h"
#else
#include <bpf/bpf_helpers.h>
#endif

#if USE_RODATA
#define BPF_PRINTK_FMT_DECLSPEC static
#else
#define BPF_PRINTK_FMT_DECLSPEC
#endif

#define BPF_PRINTK_ARGS(fmt, ...) \
do { \
	BPF_PRINTK_FMT_DECLSPEC const char format[] = fmt; \
	bpf_trace_printk(format, sizeof(format), __VA_ARGS__); \
} while (false)

#define BPF_PRINTK_NOARGS(msg) \
do { \
	BPF_PRINTK_FMT_DECLSPEC const char message[] = msg; \
	bpf_trace_printk(message, sizeof(message)); \
} while (false)

#define BPF_PRINTK_SELECT(a0, a1, a2, a3, select, ...) select

// use only for debug purposes where using perf event-based logging is not possible
// output in /sys/kernel/debug/tracing/trace
// max 3 printf-style args allowed
#if BPF_DEBUG
#define BPF_PRINTK(fmt, ...) \
	BPF_PRINTK_SELECT(a0, ##__VA_ARGS__, BPF_PRINTK_ARGS, BPF_PRINTK_ARGS, BPF_PRINTK_ARGS, BPF_PRINTK_NOARGS)(fmt, ##__VA_ARGS__)
#else
#define BPF_PRINTK(fmt, ...)
#endif
