#pragma once

#include "bpf_helpers.h"
#include "nettracer-bpf.h"

#include <linux/bpf.h>

#define  MAP_MAX_ENTRIES 1024

// Map with only one element at 0-key, representing offset guessing status
struct bpf_map_def SEC("maps") nettracer_status = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct guess_status_t),
	.max_entries = 1
};

// Map with only one element at 0-key, representing configuration for BPF program
struct bpf_map_def SEC("maps") nettracer_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct nettracer_config_t),
	.max_entries = 1
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps") bpf_logs = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = 2024
};

/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps") connectsock_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint64_t),
	.value_size = sizeof(void *),
	.max_entries = MAP_MAX_ENTRIES
};

/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps") connectsock_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint64_t),
	.value_size = sizeof(void *),
	.max_entries = MAP_MAX_ENTRIES
};

/* This is a key/value store with the keys being an ipv4_tuple_t
 * and the values being a struct pid_comm_t.
 */
struct bpf_map_def SEC("maps") tuplepid_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv4_tuple_t),
	.value_size = sizeof(struct pid_comm_t),
	.max_entries = MAP_MAX_ENTRIES
};

/* This is a key/value store with the keys being an ipv6_tuple_t
 * and the values being a struct pid_comm_t.
 */
struct bpf_map_def SEC("maps") tuplepid_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv6_tuple_t),
	.value_size = sizeof(struct pid_comm_t),
	.max_entries = MAP_MAX_ENTRIES
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps") tcp_event_ipv4 = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = MAP_MAX_ENTRIES
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps") tcp_event_ipv6 = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint32_t),
	.max_entries = MAP_MAX_ENTRIES
};

// Key/value stores with generic and TCP stats for IPv4 and IPv6

struct bpf_map_def SEC("maps") stats_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv4_tuple_t),
	.value_size = sizeof(struct stats_t),
	.max_entries = MAP_MAX_ENTRIES
};
struct bpf_map_def SEC("maps") stats_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv6_tuple_t),
	.value_size = sizeof(struct stats_t),
	.max_entries = MAP_MAX_ENTRIES
};

struct bpf_map_def SEC("maps") tcp_stats_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv4_tuple_t),
	.value_size = sizeof(struct tcp_stats_t),
	.max_entries = MAP_MAX_ENTRIES
};
struct bpf_map_def SEC("maps") tcp_stats_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv6_tuple_t),
	.value_size = sizeof(struct tcp_stats_t),
	.max_entries = MAP_MAX_ENTRIES
};
