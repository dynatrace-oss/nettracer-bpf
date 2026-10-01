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
#include "metrics_utilities.h"
#include "tuples_utilities.h"
#include "print.h"

#ifdef LEGACY_BPF
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include "legacy/bpf_helpers.h"
#include "legacy/maps.h"
#else
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#define AF_INET 2
#define AF_INET6 10
#endif

#ifdef LEGACY_BPF
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect( struct pt_regs *ctx) {
	struct sock *sk;
	uint64_t pid = bpf_get_current_pid_tgid();
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	if (bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY) < 0) {
		INC_DEBUG_COUNTER(connectsock_ipv4_update_failures);
	}
	return 0;
}

#else
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len){
	uint64_t pid = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY) < 0) {
		INC_DEBUG_COUNTER(connectsock_ipv4_update_failures);
	}
	return 0;
}

SEC("kprobe/tcp_v4_conn_request")
int handle_syn(struct pt_regs* ctx) {
	struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
	struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_SYN_ATTEMPT, .timestamp = bpf_ktime_get_ns()};
	// local port
	evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	evt.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

	struct net* net_ptr = NULL;
	uint32_t netns = 0;
	bpf_core_read(&net_ptr, sizeof(net_ptr), &sk->__sk_common.skc_net.net);
	if (net_ptr) {
		bpf_core_read(&netns, sizeof(netns), &net_ptr->ns.inum);
	}

	u32 syn_qlen = BPF_CORE_READ(sk, sk_ack_backlog);
	u32 max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
	uint32_t cpu = bpf_get_smp_processor_id();

	evt.cpu = cpu;
	evt.synqueuelen = syn_qlen;
	evt.netns = netns;
	if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_attempt_failures);
	}

	struct tcp_params_t val = {.syn_queue_size = max_backlog};
	bpf_map_update_elem(&tcp_params, &netns, &val, BPF_NOEXIST);

	return 0;
}

SEC("kprobe/tcp_v6_conn_request")
int handle_syn6(struct pt_regs* ctx) {
	struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
	struct tcp_ipv6_event_t evt = {.type = TCP_EVENT_TYPE_SYN_ATTEMPT, .timestamp = bpf_ktime_get_ns()};
	// local port
	evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

	struct net* net_ptr = NULL;
	uint32_t netns = 0;
	bpf_core_read(&net_ptr, sizeof(net_ptr), &sk->__sk_common.skc_net.net);
	if (net_ptr) {
		bpf_core_read(&netns, sizeof(netns), &net_ptr->ns.inum);
	}
	u32 syn_qlen = BPF_CORE_READ(sk, sk_ack_backlog);
	u32 max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
	uint32_t cpu = bpf_get_smp_processor_id();

	evt.cpu = cpu;
	evt.synqueuelen = syn_qlen;
	evt.netns = netns;
	if (bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
	}

	struct tcp_params_t val = {.syn_queue_size = max_backlog};
	bpf_map_update_elem(&tcp6_params, &netns, &val, BPF_NOEXIST);

	return 0;
}

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(handle_reset, struct sock* sk, struct sk_buff* skb) {
	//precondition: sk is not created yet - connection refused
	if(sk != NULL){
		return 0;
	}
	struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_RST, .timestamp = bpf_ktime_get_ns()};
	// local port
	u16 network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct iphdr iph;
	bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);
	if (iph.ihl < 5)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + iph.ihl * 4);
	evt.saddr = iph.saddr;
	evt.sport = tcph.source;
	evt.daddr = iph.daddr;  //destination is a server
	evt.dport = tcph.dest;

	struct net_device* dev = BPF_CORE_READ(skb, dev);
	if (dev) {
		struct net* net_ptr = BPF_CORE_READ(dev, nd_net.net);
		if (net_ptr) {
			bpf_core_read(&evt.netns, sizeof(evt.netns), &net_ptr->ns.inum);
		}
	}

	uint32_t cpu = bpf_get_smp_processor_id();

	evt.cpu = cpu;
	if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_attempt_failures);
	}

	return 0;
}

SEC("kprobe/tcp_v6_send_reset")
int BPF_KPROBE(handle_reset6, struct sock* sk, struct sk_buff* skb) {
	if (sk != NULL)
		return 0;

	struct tcp_ipv6_event_t evt = {.type = TCP_EVENT_TYPE_RST, .timestamp = bpf_ktime_get_ns()};

	u16 network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct ipv6hdr ip6h;
	bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + network_header);

	// IPv6 is const size
	if (ip6h.nexthdr != IPPROTO_TCP)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + sizeof(struct ipv6hdr));
	__builtin_memcpy(&evt.saddr_h, &ip6h.saddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt.saddr_l, &ip6h.saddr.in6_u.u6_addr8[8], sizeof(__u64));
	__builtin_memcpy(&evt.daddr_h, &ip6h.daddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt.daddr_l, &ip6h.daddr.in6_u.u6_addr8[8], sizeof(__u64));
	evt.sport = tcph.source;
	evt.dport = tcph.dest;

	struct net_device* dev = BPF_CORE_READ(skb, dev);
	if (dev) {
		struct net* net_ptr = BPF_CORE_READ(dev, nd_net.net);
		if (net_ptr)
			bpf_core_read(&evt.netns, sizeof(evt.netns), &net_ptr->ns.inum);
	}

	evt.cpu = bpf_get_smp_processor_id();
	if (bpf_perf_event_output(ctx, &tcp_event_ipv6, evt.cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
	}

	return 0;
}

SEC("kprobe/inet_csk_reqsk_queue_drop")
int BPF_KPROBE(handle_accept_queue_drop, struct sock* sk, struct request_sock* req) {

	uint64_t pid = bpf_get_current_pid_tgid();
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	struct net* net_ptr = NULL;
	uint32_t netns = 0;
	bpf_core_read(&net_ptr, sizeof(net_ptr), &sk->__sk_common.skc_net.net);
	if (net_ptr) {
		bpf_core_read(&netns, sizeof(netns), &net_ptr->ns.inum);
	}

	if (family == AF_INET) {
		struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_DROP, .timestamp = bpf_ktime_get_ns()};
		evt.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		evt.daddr = BPF_CORE_READ(req, __req_common.skc_daddr);
		evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		evt.dport = BPF_CORE_READ(req, __req_common.skc_dport);
		evt.netns = netns;
		evt.pid  = pid >> 32;
		evt.cpu = bpf_get_smp_processor_id();
		if (bpf_perf_event_output(ctx, &tcp_event_ipv4, evt.cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_attempt_failures);
		}
	} else if (family == AF_INET6) {
		struct tcp_ipv6_event_t evt = {.type = TCP_EVENT_TYPE_DROP, .timestamp = bpf_ktime_get_ns()};
		evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		evt.dport = BPF_CORE_READ(req, __req_common.skc_dport);
		struct inet_sock* inet = (struct inet_sock*)sk;
		struct ipv6_pinfo* np;
		struct in6_addr saddr, daddr;
		bpf_core_read(&np, sizeof(np), &inet->pinet6);
		bpf_core_read(&saddr, sizeof(saddr), &np->saddr);
		evt.saddr_h = *(__u64*)&saddr.in6_u.u6_addr8[0];
		evt.saddr_l = *(__u64*)&saddr.in6_u.u6_addr8[8];
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr);
		evt.daddr_h = *(__u64*)&daddr.in6_u.u6_addr8[0];
		evt.daddr_l = *(__u64*)&daddr.in6_u.u6_addr8[8];
		evt.netns = netns;
		evt.pid = pid >> 32;

		evt.cpu = bpf_get_smp_processor_id();
		if (bpf_perf_event_output(ctx, &tcp_event_ipv6, evt.cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
		}
	}
	return 0;
}
#endif

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs* ctx) {
	int ret = PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	struct sock** skpp;
	struct guess_status_t* status = NULL;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0; // missed entry
	}

	struct sock* skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

#ifdef LEGACY_BPF
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		INC_DEBUG_COUNTER(status_lookup_failures);
		return 0;
	}
#endif

	struct ipv4_tuple_t t = {};
	if (!read_ipv4_tuple(&t, status, skp)) {
		INC_DEBUG_COUNTER(read_ipv4_on_connect_failures);
		return 0;
	}

	if (filter_ipv4(&t)) {
		return 0;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE};
	uint32_t cpu = bpf_get_smp_processor_id();
	if (bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY) < 0) {
		INC_DEBUG_COUNTER(update_ipv4_on_connect_failures);
	}

	struct tcp_ipv4_event_t evt = convert_ipv4_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CONNECT, pid >> 32);
	if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_failures);
	}
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	uint64_t pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	if (bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY) < 0) {
		INC_DEBUG_COUNTER(connectsock_ipv6_update_failures);
	}
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	struct guess_status_t *status = NULL;

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

#ifdef LEGACY_BPF
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL || status->state == GUESS_STATE_UNINITIALIZED) {
		INC_DEBUG_COUNTER(status_lookup_failures);
		return 0;
	}
	if (!are_offsets_ready_v6(status, skp, pid)) {
		return 0;
	}
#endif
	struct ipv6_tuple_t t = { };
	if (!read_ipv6_tuple(&t, status, skp)) {
		INC_DEBUG_COUNTER(read_ipv6_on_connect_failures);
		return 0;
	}


	if(filter_ipv6(&t)){
		return 0;
	}

	struct pid_comm_t p = {.pid = pid, .state = CONN_ACTIVE };
	uint32_t cpu = bpf_get_smp_processor_id();

	if (bpf_map_update_elem(&tuplepid_ipv6, &t, &p, BPF_ANY) < 0) {
		INC_DEBUG_COUNTER(update_ipv6_on_connect_failures);
	}

	struct tcp_ipv6_event_t evt = convert_ipv6_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CONNECT, pid >> 32);
	if (bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_failures);
	}
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct guess_status_t *status = NULL;
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t cpu = bpf_get_smp_processor_id();

	if (newsk == NULL) {
		return 0;
	}

#ifdef LEGACY_BPF
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		INC_DEBUG_COUNTER(status_lookup_failures);
		return 0;
	}
#endif

	if (check_family(newsk, AF_INET)) {
		struct ipv4_tuple_t t = { };
		if (!read_ipv4_tuple(&t, status, newsk)){
			INC_DEBUG_COUNTER(read_ipv4_on_accept_failures);
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
				INC_DEBUG_COUNTER(update_ipv4_on_accept_failures);
			}
			if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
				INC_DEBUG_COUNTER(perf_output_ipv4_on_accept_failures);
			}
		}
	} else if (check_family(newsk, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, newsk)) {
			INC_DEBUG_COUNTER(read_ipv6_on_accept_failures);
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
				INC_DEBUG_COUNTER(update_ipv6_on_accept_failures);
			}
			if (bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt)) < 0) {
				INC_DEBUG_COUNTER(perf_output_ipv6_on_accept_failures);
			}
		}
	}
	return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
	struct sock *sk;
	struct guess_status_t *status = NULL;
	uint64_t pid = bpf_get_current_pid_tgid();
	uint32_t cpu = bpf_get_smp_processor_id();
	sk = (struct sock *) PT_REGS_PARM1(ctx);

#ifdef LEGACY_BPF
	uint32_t zero = 0;
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		INC_DEBUG_COUNTER(status_lookup_failures);
		return 0;
	}
#endif

	if (check_family(sk, AF_INET)) {
		struct ipv4_tuple_t t = {};
		if (!read_ipv4_tuple(&t, status, sk)){
			INC_DEBUG_COUNTER(read_ipv4_on_close_failures);
			return 0;
		}


		if(filter_ipv4(&t)){
			return 0;
		}

		struct pid_comm_t* pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv4, &t);
		if (pp == NULL) {
			INC_DEBUG_COUNTER(lookup_ipv4_on_close_failures);
		} else {
			struct pid_comm_t updated = *pp;
			updated.state = CONN_CLOSED;
			bpf_map_update_elem(&tuplepid_ipv4, &t, &updated, BPF_EXIST);
		}

		struct tcp_ipv4_event_t evt = convert_ipv4_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CLOSE, pid >> 32);
		if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv4_on_close_failures);
		}
	} else if (check_family(sk, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, sk)) {
			INC_DEBUG_COUNTER(read_ipv6_on_close_failures);
			return 0;
		}
		if (filter_ipv6(&t)) {
			return 0;
		}

		struct pid_comm_t* pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv6, &t);
		if (pp == NULL) {
			INC_DEBUG_COUNTER(lookup_ipv6_on_close_failures);
		} else {
			struct pid_comm_t updated = *pp;
			updated.state = CONN_CLOSED;
			bpf_map_update_elem(&tuplepid_ipv6, &t, &updated, BPF_EXIST);
		}

		struct tcp_ipv6_event_t evt = convert_ipv6_tuple_to_event(t, cpu, TCP_EVENT_TYPE_CLOSE, pid >> 32);
		if (bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv6_on_close_failures);
		}
	}
	return 0;
}
