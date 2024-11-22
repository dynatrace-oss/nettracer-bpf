#pragma once

#include "bpf_helpers.h"
#include "maps.h"
#include "nettracer-bpf.h"

#include <net/net_namespace.h>
#include <net/sock.h>

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

	status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		return 0;
	}

	bpf_probe_read(&family, sizeof(uint16_t), ((char *)sk) + status->offset_family);

	return family == expected_family;
}

__attribute__((always_inline))
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct guess_status_t *status, struct sock *skp)
{
	uint32_t saddr = 0, daddr = 0, net_ns_inum = 0;
	uint16_t sport = 0, dport = 0;
	possible_net_t *skc_net = NULL;

	bpf_probe_read(&saddr, sizeof(saddr), ((char *)skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *)skp) + status->offset_daddr);
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + status->offset_ino);

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
static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct guess_status_t *status, struct sock *skp)
{
	uint64_t saddr_h = 0, saddr_l = 0, daddr_h = 0, daddr_l = 0;
	uint32_t net_ns_inum = 0;
	uint16_t sport = 0, dport = 0;
	possible_net_t *skc_net = NULL;

	bpf_probe_read(&saddr_h, sizeof(saddr_h), ((char *)skp) + status->offset_daddr_ipv6 + 2 * sizeof(uint64_t));
	bpf_probe_read(&saddr_l, sizeof(saddr_l), ((char *)skp) + status->offset_daddr_ipv6 + 3 * sizeof(uint64_t));
	bpf_probe_read(&daddr_h, sizeof(daddr_h), ((char *)skp) + status->offset_daddr_ipv6);
	bpf_probe_read(&daddr_l, sizeof(daddr_l), ((char *)skp) + status->offset_daddr_ipv6 + sizeof(uint64_t));
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *)skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + status->offset_ino);

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
