/*
 * Copyright 2025 Dynatrace LLC
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
#include "bpf_helpers.h"
#include "log.h"
#include "maps.h"
#include "metrics_utilities.h"
#include "tuples_utilities.h"

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <net/inet_sock.h>
#include <net/sock.h>

__attribute__((always_inline))
static int send_metric(struct sock* sk, int32_t bytes_sent) {

	if (bytes_sent < 0) {
		return 0;
	}

	struct guess_status_t* status;
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	if (check_family(sk, AF_INET)) {
		struct ipv4_tuple_t ipv4_tuple = {};
		if (!read_ipv4_tuple(&ipv4_tuple, status, sk)) {
			return 0;
		}

		if(filter_ipv4(&ipv4_tuple)){
			return 0;
		}

		maybe_fix_missing_connection_tuple(IPV4, &ipv4_tuple);
		update_stats(&ipv4_tuple, IPV4, bytes_sent, 0);
		update_tcp_stats(&ipv4_tuple, IPV4, status, sk);
	} else if (check_family(sk, AF_INET6)) {
		struct ipv6_tuple_t ipv6_tuple = {};
		if (!read_ipv6_tuple(&ipv6_tuple, status, sk)) {
			return 0;
		}

		if(filter_ipv6(&ipv6_tuple)){
			return 0;
		}

		maybe_fix_missing_connection_tuple(IPV6, &ipv6_tuple);
		update_stats(&ipv6_tuple, IPV6, bytes_sent, 0);
		update_tcp_stats(&ipv6_tuple, IPV6, status, sk);
	}
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs* ctx) {
	struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&map_sends, &pid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
	uint64_t pid = bpf_get_current_pid_tgid();
	struct sock **skpp;

	skpp = bpf_map_lookup_elem(&map_sends, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	bpf_map_delete_elem(&map_sends, &pid);
	int32_t bytes_sent = PT_REGS_RC(ctx);
	return send_metric(*skpp, bytes_sent);
}

SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs *ctx) {
	struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
	int32_t bytes_sent = (int32_t)PT_REGS_PARM4(ctx);

	return send_metric(sk, bytes_sent);
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs* ctx) {
	struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
	int32_t bytes_received = (int32_t)PT_REGS_PARM2(ctx);

	if (bytes_received < 0) {
		return 0;
	}

	struct guess_status_t *status;
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	if (check_family(sk, AF_INET)) {
		struct ipv4_tuple_t ipv4_tuple = {};
		if (!read_ipv4_tuple(&ipv4_tuple, status, sk)) {
			return 0;
		}

		if(filter_ipv4(&ipv4_tuple)){
			return 0;
		}

		maybe_fix_missing_connection_tuple(IPV4, &ipv4_tuple);
		update_stats(&ipv4_tuple, IPV4, 0, bytes_received);
		update_tcp_stats(&ipv4_tuple, IPV4, status, sk);
	}
	else if (check_family(sk, AF_INET6)) {
		struct ipv6_tuple_t ipv6_tuple = {};
		if (!read_ipv6_tuple(&ipv6_tuple, status, sk)) {
			return 0;
		}
		if(filter_ipv6(&ipv6_tuple)){
			return 0;
		}

		maybe_fix_missing_connection_tuple(IPV6, &ipv6_tuple);
		update_stats(&ipv6_tuple, IPV6, 0, bytes_received);
		update_tcp_stats(&ipv6_tuple, IPV6, status, sk);
	}
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs* ctx) {
	struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

	struct guess_status_t *status;
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	if (check_family(sk, AF_INET)) {
		struct ipv4_tuple_t ipv4_tuple = {};
		if (!read_ipv4_tuple(&ipv4_tuple, status, sk)) {
			return 0;
		}

		if(filter_ipv4(&ipv4_tuple)){
			return 0;
		}

		struct tcp_stats_t empty = { 0 };
		maybe_fix_missing_connection_tuple(IPV4, &ipv4_tuple);
		bpf_map_update_elem(&tcp_stats_ipv4, &ipv4_tuple, &empty, BPF_NOEXIST);
		struct tcp_stats_t* stats = bpf_map_lookup_elem(&tcp_stats_ipv4, &ipv4_tuple);

		if (stats == NULL) {
			return 0;
		}

		__sync_add_and_fetch(&stats->retransmissions, 1);
	}
	else if (check_family(sk, AF_INET6)) {
		struct ipv6_tuple_t ipv6_tuple = {};
		if (!read_ipv6_tuple(&ipv6_tuple, status, sk)) {
			return 0;
		}

		if(filter_ipv6(&ipv6_tuple)){
			return 0;
		}

		struct tcp_stats_t empty = { 0 };
		struct tcp_stats_t *stats = NULL;

		maybe_fix_missing_connection_tuple(IPV6, &ipv6_tuple);
		bpf_map_update_elem(&tcp_stats_ipv6, &ipv6_tuple, &empty, BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&tcp_stats_ipv6, &ipv6_tuple);
		if (stats == NULL) {
			return 0;
		}

		__sync_add_and_fetch(&stats->retransmissions, 1);
	}
	return 0;
}
