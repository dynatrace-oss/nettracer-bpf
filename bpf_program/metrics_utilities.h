#pragma once

#include "bpf_helpers.h"
#include "maps.h"
#include "tuples_utilities.h"
#include <linux/bpf.h>
#include <net/sock.h>

__attribute__((always_inline))
static void update_stats(void *tuple, enum protocol proto, uint64_t sent, uint64_t received) {
	void *map = (proto == IPV4) ? &stats_ipv4 : &stats_ipv6;

	struct stats_t empty = { 0 };
	bpf_map_update_elem(map, tuple, &empty, BPF_NOEXIST);
	struct stats_t* stats = bpf_map_lookup_elem(map, tuple);

	if (stats == NULL) {
		return;
	}

	if (sent > 0) {
		__sync_add_and_fetch(&stats->sent_bytes, sent);
	}
	if (received > 0) {
		__sync_add_and_fetch(&stats->received_bytes, received);
	}
}

__attribute__((always_inline))
static void update_tcp_stats(void *tuple, enum protocol proto, struct guess_status_t *status, struct sock *sk) {
	void *map = (proto == IPV4) ? &tcp_stats_ipv4 : &tcp_stats_ipv6;
	struct tcp_stats_t empty = { 0 };
	bpf_map_update_elem(map, tuple, &empty, BPF_NOEXIST);
	struct tcp_stats_t* stats = bpf_map_lookup_elem(map, tuple);

	if (stats == NULL) {
		return;
	}

	bpf_probe_read(&stats->segs_in, sizeof(stats->segs_in), ((char *)sk) + status->offset_segs_in);
	bpf_probe_read(&stats->segs_out, sizeof(stats->segs_out), ((char *)sk) + status->offset_segs_out);
	if (status->offset_rtt != 0) { // if RTT was properly guessed
		uint32_t rtt, rtt_var;
		bpf_probe_read(&rtt, sizeof(stats->rtt), ((char *)sk) + status->offset_rtt);
		bpf_probe_read(&rtt_var, sizeof(stats->rtt_var), ((char *)sk) + status->offset_rtt_var);
		stats->rtt = rtt >> 3;
		stats->rtt_var = rtt_var >> 2;
	}

}

__attribute__((always_inline))
static void maybe_fix_missing_connection_tuple(enum protocol proto, void* tuple) {
	void *map = (proto == IPV4) ? &tuplepid_ipv4 : &tuplepid_ipv6;
	uint64_t pid = bpf_get_current_pid_tgid();

	if ((pid >> 32) <= 10) { // probe activated with insufficient context
		return;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
	bpf_map_update_elem(map, tuple, &p, BPF_NOEXIST);
}

__attribute__((always_inline))
static bool filter_loopback(const int32_t ip) {
#ifdef __TARGET_ARCH_x86
	const uint32_t loopback = 0x0000007f;
	return (ip & loopback) == loopback;
#else
	const uint32_t loopback = 0x7f000000;
	return (htonl(ip) & loopback) == loopback;
#endif
}

__attribute__((always_inline))
static bool filter_ipv4(struct ipv4_tuple_t* ipv4) {
	return filter_loopback(ipv4->saddr);
}

__attribute__((always_inline))
static bool isipv4ipv6(uint64_t addr_l, uint64_t addr_h) {
	if (addr_h != 0) {
		return false;
	}

#ifdef __TARGET_ARCH_x86
	uint64_t mask = 0x00000000ffff0000;
	uint64_t res = addr_l & mask;
#else
	uint64_t mask = 0xffff;
	uint64_t res = htonl(addr_l) & mask;
#endif
	return res  == mask;
}

__attribute__((always_inline))
static bool filter_ipv6(const struct ipv6_tuple_t* key) {
	if (isipv4ipv6(key->saddr_l, key->daddr_h)) {
		uint32_t ipv4 = (uint32_t)(key->saddr_l >> 32);
		return filter_loopback(ipv4);
	}
	const uint64_t loopback = 0xffffffff00000000;
	return ((key->saddr_l & loopback) == key->saddr_l);
}
