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
#include "nettracer-bpf.h"
#include "offset_guessing.h"

#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>

SEC("kprobe/tcp_getsockopt")
int kprobe__tcp_getsockopt(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int level = (int)PT_REGS_PARM2(ctx);
	int optname = (int)PT_REGS_PARM3(ctx);

	if (level != SOL_TCP || optname != TCP_INFO) {
		return 0; // our guessing attempts only use TCP_INFO
	}

	uint32_t zero = 0;
	struct guess_status_t *status = bpf_map_lookup_elem(&nettracer_status, &zero);
	if (status == NULL) {
		DEBUG_BPF("tcp_getsockopt: guessing status is null");
		return 0;
	}

	uint64_t pid = bpf_get_current_pid_tgid();
	if (status->pid_tgid != pid) {
		DEBUG_BPF("tcp_getsockopt: non-matching pid (%d != %d)", status->pid_tgid, pid);
		return 0;
	}

	(void)are_offsets_ready_v4(status, sk, pid);
	return 0;
}
