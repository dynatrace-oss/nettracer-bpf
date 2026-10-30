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
#include "maps.h"
#include "metrics_utilities.h"
#include "print.h"
#include "tuples_utilities.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define IPV4_MIN_IHL 5 //minimal ipv4 heade length

__attribute__((always_inline)) static int read_packet_header_rev(struct sk_buff* skb, struct tcp_ipv4_event_t* evt) {
	uint16_t network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct iphdr iph;
	bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);
	if (iph.ihl < IPV4_MIN_IHL)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + iph.ihl * 4);
	evt->daddr = iph.saddr;
	evt->dport = bpf_ntohs(tcph.source);
	evt->saddr = iph.daddr;
	evt->sport = bpf_ntohs(tcph.dest);
	return 1;
}

__attribute__((always_inline)) static int read_packet_header(struct sk_buff* skb, struct tcp_ipv4_event_t* evt) {
	uint16_t network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct iphdr iph;
	bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);
	if (iph.ihl < IPV4_MIN_IHL)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + iph.ihl * 4);
	evt->daddr = iph.daddr;
	evt->dport = bpf_ntohs(tcph.dest);
	evt->saddr = iph.saddr;
	evt->sport = bpf_ntohs(tcph.source);
	return 1;
}

__attribute__((always_inline)) static int read_packet_header6_rev(struct sk_buff* skb, struct tcp_ipv6_event_t* evt) {
	uint16_t network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct ipv6hdr ip6h;
	bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + network_header);

	// IPv6 is const size
	if (ip6h.nexthdr != IPPROTO_TCP)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + sizeof(struct ipv6hdr));
	__builtin_memcpy(&evt->daddr_h, &ip6h.saddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt->daddr_l, &ip6h.saddr.in6_u.u6_addr8[8], sizeof(__u64));
	__builtin_memcpy(&evt->saddr_h, &ip6h.daddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt->saddr_l, &ip6h.daddr.in6_u.u6_addr8[8], sizeof(__u64));
	evt->dport = bpf_ntohs(tcph.source);
	evt->sport = bpf_ntohs(tcph.dest);
	return 1;
}

__attribute__((always_inline)) static int read_packet_header6(struct sk_buff* skb, struct tcp_ipv6_event_t* evt) {
	uint16_t network_header = BPF_CORE_READ(skb, network_header);
	unsigned char* head = BPF_CORE_READ(skb, head);

	struct ipv6hdr ip6h;
	bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + network_header);

	// IPv6 is const size
	if (ip6h.nexthdr != IPPROTO_TCP)
		return 0;

	struct tcphdr tcph;
	bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + sizeof(struct ipv6hdr));
	__builtin_memcpy(&evt->saddr_h, &ip6h.saddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt->saddr_l, &ip6h.saddr.in6_u.u6_addr8[8], sizeof(__u64));
	__builtin_memcpy(&evt->daddr_h, &ip6h.daddr.in6_u.u6_addr8[0], sizeof(__u64));
	__builtin_memcpy(&evt->daddr_l, &ip6h.daddr.in6_u.u6_addr8[8], sizeof(__u64));
	evt->dport = bpf_ntohs(tcph.dest);
	evt->sport = bpf_ntohs(tcph.source);
	return 1;
}

SEC("kprobe/tcp_v4_conn_request")
int BPF_KPROBE(handle_syn, struct sock* sk, struct sk_buff* skb) {
	struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_SYN_ATTEMPT, .timestamp = bpf_ktime_get_ns()};
	if (!read_packet_header_rev(skb, &evt)) {
		return 0;
	}
	if (filter_loopback(evt.saddr)) {
		return 0;
	}

	uint32_t netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	uint32_t syn_qlen = BPF_CORE_READ(sk, sk_ack_backlog);
	uint32_t max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
	uint32_t cpu = bpf_get_smp_processor_id();

	evt.cpu = cpu;
	evt.synqueuelen = syn_qlen;
	evt.netns = netns;

	struct tcp_params_key_t key = {.netns = netns, .sport = evt.sport};
	struct tcp_params_t val = {.syn_queue_size = max_backlog};
	bpf_map_update_elem(&tcp_params, &key, &val, BPF_NOEXIST);

	if (bpf_perf_event_output(ctx, &tcp_event_ipv4, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_attempt_failures);
	}

	return 0;
}

SEC("kprobe/tcp_v6_conn_request")
int BPF_KPROBE(handle_syn6, struct sock* sk, struct sk_buff* skb) {
	struct tcp_ipv6_event_t evt = {.type = TCP_EVENT_TYPE_SYN_ATTEMPT, .timestamp = bpf_ktime_get_ns()};
	if (!read_packet_header6_rev(skb, &evt)) {
		return 0;
	}
	if (filter_loopback6(evt.saddr_l, evt.saddr_h)) {
		return 0;
	}

	uint32_t netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	uint32_t syn_qlen = BPF_CORE_READ(sk, sk_ack_backlog);
	uint32_t max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
	uint32_t cpu = bpf_get_smp_processor_id();

	evt.cpu = cpu;
	evt.synqueuelen = syn_qlen;
	evt.netns = netns;

	struct tcp_params_key_t key = {.netns = netns, .sport = evt.sport};
	struct tcp_params_t val = {.syn_queue_size = max_backlog};
	bpf_map_update_elem(&tcp6_params, &key, &val, BPF_NOEXIST);

	if (bpf_perf_event_output(ctx, &tcp_event_ipv6, cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
	}

	return 0;
}

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(handle_reset, struct sock* sk, struct sk_buff* skb) {
	// precondition: sk is not created yet - connection refused
	if (sk != NULL) {
		return 0;
	}
	struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_RST, .timestamp = bpf_ktime_get_ns()};
	if (!read_packet_header(skb, &evt)) {
		return 0;
	}
	if (filter_loopback(evt.saddr)) {
		return 0;
	}

	evt.netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);
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
	if (!read_packet_header6(skb, &evt)) {
		return 0;
	}
	if (filter_loopback6(evt.saddr_l, evt.saddr_h)) {
		return 0;
	}

	evt.netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);
	evt.cpu = bpf_get_smp_processor_id();
	if (bpf_perf_event_output(ctx, &tcp_event_ipv6, evt.cpu, &evt, sizeof(evt)) < 0) {
		INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
	}

	return 0;
}

SEC("kprobe/inet_csk_reqsk_queue_drop")
int BPF_KPROBE(handle_accept_queue_drop, struct sock* sk, struct request_sock* req) {

	uint64_t pid = bpf_get_current_pid_tgid();
	uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
	uint32_t netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

	if (family == AF_INET) {
		struct tcp_ipv4_event_t evt = {.type = TCP_EVENT_TYPE_DROP, .timestamp = bpf_ktime_get_ns()};
		evt.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		evt.daddr = BPF_CORE_READ(req, __req_common.skc_daddr);
		evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		evt.dport = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport));
		evt.netns = netns;
		evt.pid = pid >> 32;
		evt.cpu = bpf_get_smp_processor_id();
		if (filter_loopback(evt.saddr)) {
			return 0;
		}
		if (bpf_perf_event_output(ctx, &tcp_event_ipv4, evt.cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv4_on_connect_attempt_failures);
		}
	} else if (family == AF_INET6) {
		struct tcp_ipv6_event_t evt = {.type = TCP_EVENT_TYPE_DROP, .timestamp = bpf_ktime_get_ns()};
		evt.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		evt.dport = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport));
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
		if (filter_loopback6(evt.saddr_l, evt.saddr_h)) {
			return 0;
		}
		if (bpf_perf_event_output(ctx, &tcp_event_ipv6, evt.cpu, &evt, sizeof(evt)) < 0) {
			INC_DEBUG_COUNTER(perf_output_ipv6_on_connect_attempt_failures);
		}
	}
	return 0;
}
