#pragma once

#include <linux/types.h>
#ifdef __cplusplus
#include <cstdint>
#endif

enum tcp_event_type {
	TCP_EVENT_TYPE_CONNECT,
	TCP_EVENT_TYPE_ACCEPT,
	TCP_EVENT_TYPE_CLOSE
};

struct tcp_ipv4_event_t {
	uint64_t timestamp;
	uint32_t cpu;
	enum tcp_event_type type;
	uint32_t pid;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint32_t netns;
	uint8_t padding[4];
 };

struct tcp_ipv6_event_t {
	uint64_t timestamp;
	uint32_t cpu;
	enum tcp_event_type type;
	uint32_t pid;
	uint8_t padding[4];
	uint64_t saddr_h;
	uint64_t saddr_l;
	uint64_t daddr_h;
	uint64_t daddr_l;
	uint16_t sport;
	uint16_t dport;
	uint32_t netns;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint32_t netns;
};

struct ipv6_tuple_t {
	uint64_t saddr_h;
	uint64_t saddr_l;
	uint64_t daddr_h;
	uint64_t daddr_l;
	uint16_t sport;
	uint16_t dport;
	uint32_t netns;
};

struct stats_t {
	uint64_t sent_bytes;
	uint64_t received_bytes;
};

struct tcp_stats_t {
	uint64_t retransmissions;
	uint32_t segs_in;
	uint32_t segs_out;
	uint32_t rtt;
	uint32_t rtt_var;
};

enum conn_state {
	CONN_ACTIVE = 1,
	CONN_CLOSED
};

struct pid_comm_t {
	uint64_t pid;
	enum conn_state state;
	uint8_t padding[4];
};

enum guess_state {
	GUESS_STATE_UNINITIALIZED,
	GUESS_STATE_CHECKING,
	GUESS_STATE_CHECKED,
	GUESS_STATE_READY
};

enum guess_field {
	GUESS_FIELD_SADDR,
	GUESS_FIELD_DADDR,
	GUESS_FIELD_FAMILY,
	GUESS_FIELD_SPORT,
	GUESS_FIELD_DPORT,
	GUESS_FIELD_NETNS,
	GUESS_FIELD_DADDR_IPV6,
	GUESS_FIELD_SEGS_IN,
	GUESS_FIELD_SEGS_OUT,
	GUESS_FIELD_RTT
};

struct guess_status_t {
	enum guess_state state;
	enum guess_field what;

	uint64_t pid_tgid;
	uint16_t offset_saddr;
	uint16_t offset_daddr;
	uint16_t offset_sport;
	uint16_t offset_dport;
	uint16_t offset_netns;
	uint16_t offset_ino;
	uint16_t offset_family;
	uint16_t offset_daddr_ipv6;
	uint16_t offset_segs_in;
	uint16_t offset_segs_out;
	uint16_t offset_rtt;
	uint16_t offset_rtt_var;

	uint64_t err;

	uint32_t daddr_ipv6[4];
	uint32_t netns;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint16_t family;
	uint8_t padding[6];
	uint32_t segs_in;
	uint32_t segs_out;
	uint32_t rtt;
	uint32_t rtt_var;
};

enum bpf_log_level {
	BPF_LOG_LEVEL_TRACE,
	BPF_LOG_LEVEL_DEBUG,
	BPF_LOG_LEVEL_INFO,
	BPF_LOG_LEVEL_WARN,
	BPF_LOG_LEVEL_ERROR,
	BPF_LOG_LEVEL_CRITICAL,
	BPF_LOG_LEVEL_OFF
};

struct nettracer_config_t {
	enum bpf_log_level log_level;
};

struct bpf_log_event_t {
	uint64_t timestamp;
	uint32_t cpu;
	uint32_t pid;
	enum bpf_log_level severity;
	char format[80];
	uint8_t args_num;
	uint8_t padding[3];
	int64_t args[10];
};
