#pragma once

#include "bpf_helpers.h"
#include "maps.h"
#include "tuples_utilities.h"
#include <linux/bpf.h>
#include <net/sock.h>

__attribute__((always_inline))
static void update_stats(void *tuple, enum protocol proto, uint64_t sent, uint64_t received) {
	void *map = NULL;
	if (proto == IPV4) {
		map = &stats_ipv4;
	}
	else if (proto == IPV6) {
		map = &stats_ipv6;
	}
	else {
		return;
	}

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
	void *map = NULL;
	if (proto == IPV4) {
		map = &tcp_stats_ipv4;
	}
	else if (proto == IPV6) {
		map = &tcp_stats_ipv6;
	}
	else {
		return;
	}

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
	void *map = NULL;
	if (proto == IPV4) {
		map = &tuplepid_ipv4;
	}
	else if (proto == IPV6) {
		map = &tuplepid_ipv6;
	}
	else {
		return;
	}

	uint64_t pid = bpf_get_current_pid_tgid();
	if ((pid >> 32) <= 10) { // probe activated with insufficient context
		return;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
	bpf_map_update_elem(map, tuple, &p, BPF_NOEXIST);
}
