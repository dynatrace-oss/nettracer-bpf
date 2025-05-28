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
#include "offset_guessing.h"
#include "tuples_utilities.h"

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <net/inet_sock.h>
#include <net/sock.h>

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	uint64_t pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t zero = 0;
	struct sock **skpp;
	struct guess_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	struct ipv4_tuple_t t = { };
	if (!read_ipv4_tuple(&t, status, skp)) {
		return 0;
	}

	if(filter_ipv4(&t)){
		return 0;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
	uint32_t cpu = bpf_get_smp_processor_id();
	if (bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY) < 0) {
		LOG_DEBUG_BPF(ctx, "Connect missed, reached max conns?: {:d}:{:d} {:d}:{:d} {:d}", t.saddr, t.sport, t.daddr, t.dport, pid >> 32);
	}

	struct tcp_ipv4_event_t evt = convert_ipv4_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CONNECT, pid >> 32);
	bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt));
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	uint64_t pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t zero = 0;
	struct sock **skpp;
	struct guess_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv6, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv6, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL || status->state == GUESS_STATE_UNINITIALIZED) {
		return 0;
	}

	if (!are_offsets_ready_v6(status, skp, pid)) {
		return 0;
	}

	struct ipv6_tuple_t t = { };
	if (!read_ipv6_tuple(&t, status, skp)) {
		return 0;
	}


	if(filter_ipv6(&t)){
		return 0;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE };
	uint32_t cpu = bpf_get_smp_processor_id();

	if (bpf_map_update_elem(&tuplepid_ipv6, &t, &p, BPF_ANY) < 0) {
		LOG_DEBUG_BPF(ctx, "Connect v6 missed, reached max conns?: {:d}{:d}:{:d} {:d}{:d}:{:d} {:d}", t.saddr_h, t.saddr_l, t.sport, t.daddr_h, t.daddr_l, t.dport, pid >> 32);
	}

	struct tcp_ipv6_event_t evt = convert_ipv6_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CONNECT, pid >> 32);
	bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt));
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct guess_status_t *status;
	uint32_t zero = 0;
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t cpu = bpf_get_smp_processor_id();

	if (newsk == NULL)
		return 0;

	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	if (check_family(newsk, AF_INET)) {
		struct ipv4_tuple_t t = { };
		if (!read_ipv4_tuple(&t, status, newsk)){
			return 0;
		}

		if(filter_ipv4(&t)){
			return 0;
		}

		struct tcp_ipv4_event_t evt = convert_ipv4_tuple_to_event(t, cpu, TCP_EVENT_TYPE_ACCEPT, pid >> 32);

		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt.saddr != 0 && evt.daddr != 0 && evt.sport != 0 && evt.dport != 0) {
			struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
			if (bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY) < 0) {
				LOG_DEBUG_BPF(ctx, "Accept missed, reached max conns?: {:d}:{:d} {:d}:{:d} {:d}", t.saddr, t.sport, t.daddr, t.dport, pid >> 32);
			}
			bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt));
		}
	} else if (check_family(newsk, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, newsk)) {
			return 0;
		}

		if (filter_ipv6(&t)) {
			return 0;
		}

		struct tcp_ipv6_event_t evt = convert_ipv6_tuple_to_event(t, cpu, TCP_EVENT_TYPE_ACCEPT, pid >> 32);

		// do not send event if IP address is :: or port is 0
		if ((evt.saddr_h || evt.saddr_l) && (evt.daddr_h || evt.daddr_l) && evt.sport != 0 && evt.dport != 0) {
			struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
			if (bpf_map_update_elem(&tuplepid_ipv6, &t, &p, BPF_ANY) < 0) {
				LOG_DEBUG_BPF(
						ctx,
						"Accept v6 missed, reached max conns?: {:d}{:d}:{:d} {:d}{:d}:{:d} {:d}",
						t.saddr_h,
						t.saddr_l,
						t.sport,
						t.daddr_h,
						t.daddr_l,
						t.dport,
						pid >> 32);
			}
			bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt));
		}
	}
	return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
	struct sock *sk;
	struct guess_status_t *status;
	uint32_t zero = 0;
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t cpu = bpf_get_smp_processor_id();
	sk = (struct sock *) PT_REGS_PARM1(ctx);

	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	if (check_family(sk, AF_INET)) {
		struct ipv4_tuple_t t = {};
		if (!read_ipv4_tuple(&t, status, sk)){
			return 0;
		}


		if(filter_ipv4(&t)){
			return 0;
		}

		struct pid_comm_t* pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv4, &t);
		if (pp == NULL) {
			LOG_DEBUG_BPF(ctx, "Missing tuplepid entry: {:d}:{:d} {:d}:{:d}", t.saddr, t.sport, t.daddr, t.dport);
		} else {
			pp->state = CONN_CLOSED;
		}

		struct tcp_ipv4_event_t evt = convert_ipv4_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CLOSE, pid >> 32);
		bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt));
	} else if (check_family(sk, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}
		if (filter_ipv6(&t)) {
			return 0;
		}

		struct pid_comm_t* pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv6, &t);
		if (pp == NULL) {
			LOG_DEBUG_BPF(
					ctx,
					"Missing tuplepid entry: {:d}{:d}:{:d} {:d}{:d}:{:d}",
					t.saddr_h,
					t.saddr_l,
					t.sport,
					t.daddr_h,
					t.daddr_l,
					t.dport);
		} else {
			pp->state = CONN_CLOSED;
		}

		struct tcp_ipv6_event_t evt = convert_ipv6_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CLOSE, pid >> 32);
		bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt));
	}
	return 0;
}
