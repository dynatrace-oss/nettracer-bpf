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

#include "bpf_helpers.h"
#include "maps.h"
#include "nettracer-bpf.h"

#include <linux/bpf.h>
#include <net/net_namespace.h>

__attribute__((always_inline))
static int are_offsets_ready_v4(struct guess_status_t *status, struct sock *skp, uint64_t pid) {
	uint32_t zero = 0;

	switch (status->state) {
		case GUESS_STATE_UNINITIALIZED:
			return 0;
		case GUESS_STATE_CHECKING:
			break;
		case GUESS_STATE_CHECKED:
			return 0;
		case GUESS_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only accept the exact pid & tid. Extraneous connections from other
	// threads must be ignored here. Userland must take care to generate
	// connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	if (status->pid_tgid != pid)
		return 0;

	struct guess_status_t new_status = { };
	new_status.state = GUESS_STATE_CHECKED;
	new_status.pid_tgid = status->pid_tgid;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.offset_segs_in = status->offset_segs_in;
	new_status.offset_segs_out = status->offset_segs_out;
	new_status.offset_rtt = status->offset_rtt;
	new_status.offset_rtt_var = status->offset_rtt_var;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.segs_in = status->segs_in;
	new_status.segs_out = status->segs_out;
	new_status.rtt = status->rtt;
	new_status.rtt_var = status->rtt_var;

	for (int i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	uint32_t possible_saddr;
	uint32_t possible_daddr;
	uint16_t possible_sport;
	uint16_t possible_dport;
	possible_net_t *possible_skc_net;
	uint32_t possible_netns;
	uint16_t possible_family;
	uint32_t possible_segs_in;
	uint32_t possible_segs_out;
	uint32_t possible_rtt;
	uint32_t possible_rtt_var;
	long ret = 0;

	switch (status->what) {
		case GUESS_FIELD_SADDR:
			possible_saddr = 0;
			bpf_probe_read(&possible_saddr, sizeof(possible_saddr), ((char *)skp) + status->offset_saddr);
			new_status.saddr = possible_saddr;
			break;
		case GUESS_FIELD_DADDR:
			possible_daddr = 0;
			bpf_probe_read(&possible_daddr, sizeof(possible_daddr), ((char *)skp) + status->offset_daddr);
			new_status.daddr = possible_daddr;
			break;
		case GUESS_FIELD_FAMILY:
			possible_family = 0;
			bpf_probe_read(&possible_family, sizeof(possible_family), ((char *)skp) + status->offset_family);
			new_status.family = possible_family;
			break;
		case GUESS_FIELD_SPORT:
			possible_sport = 0;
			bpf_probe_read(&possible_sport, sizeof(possible_sport), ((char *)skp) + status->offset_sport);
			new_status.sport = possible_sport;
			break;
		case GUESS_FIELD_DPORT:
			possible_dport = 0;
			bpf_probe_read(&possible_dport, sizeof(possible_dport), ((char *)skp) + status->offset_dport);
			new_status.dport = possible_dport;
			break;
		case GUESS_FIELD_NETNS:
			possible_netns = 0;
			possible_skc_net = NULL;
			bpf_probe_read(&possible_skc_net, sizeof(possible_net_t *), ((char *)skp) + status->offset_netns);
			// if we get a kernel fault, it means possible_skc_net
			// is an invalid pointer, signal an error so we can go
			// to the next offset_netns
			ret = bpf_probe_read(&possible_netns, sizeof(possible_netns), ((char *)possible_skc_net) + status->offset_ino);
			if (ret == -EFAULT) {
				new_status.err = 1;
				break;
			}
			new_status.netns = possible_netns;
			break;
		case GUESS_FIELD_SEGS_IN:
			possible_segs_in = 0;
			bpf_probe_read(&possible_segs_in, sizeof(possible_segs_in), ((char *)skp) + status->offset_segs_in);
			new_status.segs_in = possible_segs_in;
			break;
		case GUESS_FIELD_SEGS_OUT:
			possible_segs_out = 0;
			bpf_probe_read(&possible_segs_out, sizeof(possible_segs_out), ((char *)skp) + status->offset_segs_out);
			new_status.segs_out = possible_segs_out;
			break;
		case GUESS_FIELD_RTT:
			possible_rtt = 0;
			possible_rtt_var = 0;
			bpf_probe_read(&possible_rtt, sizeof(possible_rtt), ((char *)skp) + status->offset_rtt);
			bpf_probe_read(&possible_rtt_var, sizeof(possible_rtt_var), ((char *)skp) + status->offset_rtt_var);
			new_status.rtt = possible_rtt >> 3; // bits shifted like here: see https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp.c#L3443
			new_status.rtt_var = possible_rtt_var >> 2;
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&nettracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int are_offsets_ready_v6(struct guess_status_t *status, struct sock *skp, uint64_t pid) {
	uint32_t zero = 0;

	switch (status->state) {
		case GUESS_STATE_UNINITIALIZED:
			return 0;
		case GUESS_STATE_CHECKING:
			break;
		case GUESS_STATE_CHECKED:
			return 0;
		case GUESS_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only accept the exact pid & tid. Extraneous connections from other
	// threads must be ignored here. Userland must take care to generate
	// connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	if (status->pid_tgid != pid)
		return 0;

	struct guess_status_t new_status = { };
	new_status.state = GUESS_STATE_CHECKED;
	new_status.pid_tgid = status->pid_tgid;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.offset_segs_in = status->offset_segs_in;
	new_status.offset_segs_out = status->offset_segs_out;
	new_status.offset_rtt = status->offset_rtt;
	new_status.offset_rtt_var = status->offset_rtt_var;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.segs_in = status->segs_in;
	new_status.segs_out = status->segs_out;
	new_status.rtt = status->rtt;
	new_status.rtt_var = status->rtt_var;

	for (int i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	uint32_t possible_daddr_ipv6[4] = { };
	switch (status->what) {
		case GUESS_FIELD_DADDR_IPV6:
			bpf_probe_read(&possible_daddr_ipv6, sizeof(possible_daddr_ipv6), ((char *)skp) + status->offset_daddr_ipv6);

			for (int i = 0; i < 4; i++) {
				new_status.daddr_ipv6[i] = possible_daddr_ipv6[i];
			}
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&nettracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}
