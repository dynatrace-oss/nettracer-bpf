/*
 * Copyright 2026 Dynatrace LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#pragma once

#include "vmlinux.h"
#include "nettracer-bpf.h"
#include <bpf/bpf_helpers.h>

#define  MAP_MAX_ENTRIES 1024

// Map with only one element at 0-key, representing offset guessing status
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct guess_status_t);
	__uint(max_entries, 1);
} nettracer_status SEC(".maps");

// Map with only one element at 0-key, representing configuration for BPF program
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct nettracer_config_t);
	__uint(max_entries, 1);
} nettracer_config SEC(".maps");

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2024);
} bpf_logs SEC(".maps");

/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64); //(void *)
	__uint(max_entries, MAP_MAX_ENTRIES);
} connectsock_ipv4 SEC(".maps");

/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64); // sizeof(void *),
	__uint(max_entries, MAP_MAX_ENTRIES);
} connectsock_ipv6 SEC(".maps");

/* This is a key/value store with the keys being an ipv4_tuple_t
 * and the values being a struct pid_comm_t.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_tuple_t);
	__type(value, struct pid_comm_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tuplepid_ipv4 SEC(".maps");

/* This is a key/value store with the keys being an ipv6_tuple_t
 * and the values being a struct pid_comm_t.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv6_tuple_t);
	__type(value, struct pid_comm_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tuplepid_ipv6 SEC(".maps");

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value,  __u32);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tcp_event_ipv4 SEC(".maps");

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tcp_event_ipv6 SEC(".maps");

// Key/value stores with generic and TCP stats for IPv4 and IPv6

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_tuple_t);
	__type(value, struct stats_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} stats_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv6_tuple_t);
	__type(value, struct stats_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} stats_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_tuple_t);
	__type(value, struct tcp_stats_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tcp_stats_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv6_tuple_t);
	__type(value, struct tcp_stats_t);
	__uint(max_entries, MAP_MAX_ENTRIES);
} tcp_stats_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64); //void*
	__uint(max_entries, MAP_MAX_ENTRIES);
} map_sends SEC(".maps");

