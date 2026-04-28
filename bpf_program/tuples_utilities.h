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
#pragma once

#include "nettracer-bpf.h"

#ifdef LEGACY_BPF
#include <net/net_namespace.h>
#include <net/sock.h>
#include "bpf_helpers.h"
#include "legacy/maps.h"
#else
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"
#include "maps.h"

#define ntohs bpf_ntohs
#endif

enum protocol {
	IPV4,
	IPV6
};

__attribute__((always_inline))
static bool check_family(struct sock *sk, uint16_t expected_family) {
	struct guess_status_t *status;
	uint32_t zero = 0;
	uint16_t family;
	family = 0;

#ifdef LEGACY_BPF
	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	bpf_probe_read(&family, sizeof(uint16_t), ((char *)sk) + status->offset_family);
	return family == expected_family;
#else
	bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
	return false;
#endif
}

__attribute__((always_inline))
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct guess_status_t *status, struct sock *sk)
{
	uint32_t saddr = 0, daddr = 0, net_ns_inum = 0;
	uint16_t sport = 0, dport = 0;
	possible_net_t *skc_net = NULL;

#ifdef LEGACY_BPF
	bpf_probe_read(&saddr, sizeof(saddr), ((char *)skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *)skp) + status->offset_daddr);
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);
	bpf_probe_read(&skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + status->offset_ino);
#else
	bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
	bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
	bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
	bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	struct net *net_ptr = NULL;
	// Read sk_net pointer
	bpf_core_read(&net_ptr, sizeof(net_ptr), &sk->__sk_common.skc_net.net);
	if (net_ptr) {
		// Read namespace inode number
		bpf_core_read(&net_ns_inum, sizeof(net_ns_inum), &net_ptr->ns.inum);
	}
#endif
	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = ntohs(dport);
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 ||  dport == 0 || sport == 0 ) {
		return 0;
	}

	return 1;
}

__attribute__((always_inline))
static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct guess_status_t *status, struct sock *sk)
{
	uint64_t saddr_h = 0, saddr_l = 0, daddr_h = 0, daddr_l = 0;
	uint32_t net_ns_inum = 0;
	uint16_t sport = 0, dport = 0;
	possible_net_t *skc_net = NULL;

#ifdef LEGACY_BPF
	bpf_probe_read(&saddr_h, sizeof(saddr_h), ((char *)skp) + status->offset_daddr_ipv6 + 2 * sizeof(uint64_t));
	bpf_probe_read(&saddr_l, sizeof(saddr_l), ((char *)skp) + status->offset_daddr_ipv6 + 3 * sizeof(uint64_t));
	bpf_probe_read(&daddr_h, sizeof(daddr_h), ((char *)skp) + status->offset_daddr_ipv6);
	bpf_probe_read(&daddr_l, sizeof(daddr_l), ((char *)skp) + status->offset_daddr_ipv6 + sizeof(uint64_t));
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);
	bpf_probe_read(&skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + status->offset_ino);
#else
	struct inet_sock *inet = (struct inet_sock *)sk;
    struct ipv6_pinfo *np = inet->pinet6;
	bpf_core_read(&saddr_h, sizeof(saddr_h), &np->saddr);
	bpf_core_read(&saddr_l, sizeof(saddr_l), &np->saddr + sizeof(uint64_t));
	bpf_core_read(&daddr_h, sizeof(daddr_h), &sk->__sk_common.skc_v6_daddr);  //beware this field can be in different place 
	bpf_core_read(&daddr_l, sizeof(daddr_l), &sk->__sk_common.skc_v6_daddr + sizeof(uint64_t));  // beware this field can be in different place 
	bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
	bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	//struct dst_entry *dst = NULL;
     //       bpf_probe_read_kernel(&dst, sizeof(dst), &sk->sk_dst_cache);
     //       if (dst) {
     //           struct rt6_info *rt = (struct rt6_info *)dst;
     //           struct in6_addr daddr = {};
     //           bpf_probe_read_kernel(&daddr, sizeof(daddr), &rt->rt6i_dst.addr);
	struct net *net_ptr = NULL;
    // Read sk_net pointer
    bpf_core_read(&net_ptr, sizeof(net_ptr), &sk->__sk_common.skc_net.net);
    if (net_ptr) {
        // Read namespace inode number
        bpf_core_read(&net_ns_inum, sizeof(net_ns_inum), &net_ptr->ns.inum);
	}
#endif

	tuple->saddr_h = saddr_h;
	tuple->saddr_l = saddr_l;
	tuple->daddr_h = daddr_h;
	tuple->daddr_l = daddr_l;
	tuple->sport = sport;
	tuple->dport = ntohs(dport);
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (!(saddr_h || saddr_l) || !(daddr_h || daddr_l) || dport == 0 || sport == 0 ) {
		return 0;
	}

	return 1;
}

__attribute__((always_inline))
static struct tcp_ipv4_event_t convert_ipv4_tuple_to_event(struct ipv4_tuple_t t, uint32_t cpu, enum tcp_event_type type, uint32_t pid) {
	struct tcp_ipv4_event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.cpu = cpu,
		.type = type,
		.pid = pid,
		.saddr = t.saddr,
		.daddr = t.daddr,
		.sport = t.sport,
		.dport = t.dport,
		.netns = t.netns
	};
	return evt;
}

__attribute__((always_inline))
static struct tcp_ipv6_event_t convert_ipv6_tuple_to_event(struct ipv6_tuple_t t, uint32_t cpu, enum tcp_event_type type, uint32_t pid) {
	struct tcp_ipv6_event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.cpu = cpu,
		.type = type,
		.pid = pid,
		.saddr_h = t.saddr_h,
		.saddr_l = t.saddr_l,
		.daddr_h = t.daddr_h,
		.daddr_l = t.daddr_l,
		.sport = t.sport,
		.dport = t.dport,
		.netns = t.netns
	};
	return evt;
}
