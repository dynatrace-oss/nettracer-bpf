#pragma once

#include <linux/bpf.h>
#include <linux/types.h>

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int32_t (*bpf_map_update_elem)(void *map, void *key, void *value, uint64_t flags) =
	(void *) BPF_FUNC_map_update_elem;
static int32_t (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;

static int32_t (*bpf_probe_read)(void *dst, int32_t size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;

static uint64_t (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;

static int32_t (*bpf_trace_printk)(const char *fmt, int32_t fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;

static uint64_t (*bpf_get_smp_processor_id)(void) =
	(void *) BPF_FUNC_get_smp_processor_id;
static uint64_t (*bpf_get_current_pid_tgid)(void) =
	(void *) BPF_FUNC_get_current_pid_tgid;
static uint64_t (*bpf_get_current_uid_gid)(void) =
	(void *) BPF_FUNC_get_current_uid_gid;
static int32_t (*bpf_get_current_comm)(void *buf, int32_t buf_size) =
	(void *) BPF_FUNC_get_current_comm;

static int32_t (*bpf_perf_event_read)(void *map, int32_t index) =
	(void *) BPF_FUNC_perf_event_read;
static int32_t (*bpf_perf_event_output)(void *ctx, void *map, uint64_t flags, void *data, int32_t size) =
	(void *) BPF_FUNC_perf_event_output;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
uint64_t load_byte(void *skb, uint64_t off) asm("llvm.bpf.load.byte");
uint64_t load_half(void *skb, uint64_t off) asm("llvm.bpf.load.half");
uint64_t load_word(void *skb, uint64_t off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
#define BUF_SIZE_MAP_NS 256

struct bpf_map_def {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
	uint32_t pinning;
	char namespace[BUF_SIZE_MAP_NS];
};

#if defined(__x86_64__)

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#elif defined(__s390x__)

#define PT_REGS_PARM1(x) ((x)->gprs[2])
#define PT_REGS_PARM2(x) ((x)->gprs[3])
#define PT_REGS_PARM3(x) ((x)->gprs[4])
#define PT_REGS_PARM4(x) ((x)->gprs[5])
#define PT_REGS_PARM5(x) ((x)->gprs[6])
#define PT_REGS_RET(x) ((x)->gprs[14])
#define PT_REGS_FP(x) ((x)->gprs[11]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->gprs[2])
#define PT_REGS_SP(x) ((x)->gprs[15])
#define PT_REGS_IP(x) ((x)->ip)

#elif defined(__aarch64__)

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RET(x) ((x)->regs[30])
#define PT_REGS_FP(x) ((x)->regs[29]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[0])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->pc)

#elif defined(__powerpc__)

#define PT_REGS_PARM1(x) ((x)->gpr[3])
#define PT_REGS_PARM2(x) ((x)->gpr[4])
#define PT_REGS_PARM3(x) ((x)->gpr[5])
#define PT_REGS_PARM4(x) ((x)->gpr[6])
#define PT_REGS_PARM5(x) ((x)->gpr[7])
#define PT_REGS_RC(x) ((x)->gpr[3])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->nip)

#endif

#ifdef __powerpc__
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({ (ip) = (ctx)->link; })
#define BPF_KRETPROBE_READ_RET_IP		BPF_KPROBE_READ_RET_IP
#else
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({				\
		bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })
#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)	({				\
		bpf_probe_read(&(ip), sizeof(ip),				\
				(void *)(PT_REGS_FP(ctx) + sizeof(ip))); })
#endif
