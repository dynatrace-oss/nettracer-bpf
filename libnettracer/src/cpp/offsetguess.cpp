#include "offsetguess.h"

extern "C" {
#include "bpf_program/nettracer-bpf.h"
}
#include "bpf_generic/bpf_loading.h"
#include "bpf_generic/bpf_wrapper.h"
#include "bpf_generic/log.h"
#include "localsock.h"
#include "localsock6.h"

#include <fmt/core.h>

#include <arpa/inet.h>
#include <chrono>
#include <linux/tcp.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <utility>

static ino_t own_net_ns() {
	struct stat statbuf;
	int ret = stat("/proc/self/ns/net", &statbuf);
	if (ret != 0) {
		LOG_ERROR("stat");
		exit(-1);
	}
	return statbuf.st_ino;
}

bool guess(int status_fd) {
	auto logger{logging::getLogger()};

	// Don't go over that limit when guessing offsets for fields in inet_sock
	const int thresholdInetSock = 1500;
	// Fields outside inet_sock are stored much farther
	const int thresholdTcpSock = 2500;

	uint32_t zero = 0;
	int max_retries = 100;

	logger->debug("guess enter fd:{:d}", status_fd);
	// nettracer_status map holds only one entry with key zero which is
	// created (and updated) in bpf program inside call are_offsets_ready_v(4|6)
	// which in turn are called in kretprobe tcp_v(4|6)_connect

	uint64_t pid_tgid = (uint64_t)getpid() << 32 | syscall(SYS_gettid);
	logger->debug("guess thread pid:{:d}", pid_tgid);

	// prepare server ipv4 and client ipv6 on this thread
	LocalSock localsock;
	if (!localsock.running()) {
		const unsigned maxRetries = 2;
		const auto interval = std::chrono::seconds(3);
		bool ok = false;
		for (unsigned i = 0; i < maxRetries; ++i) {
			logger->warn("LocalSock start failed, retrying in {:d}s...", interval.count());

			std::this_thread::sleep_for(interval);
			localsock.stop();
			if (localsock.start()) {
				ok = true;
				break;
			}
		}
		if (!ok) {
			logger->error("LocalSock could not start");
			return false;
		}
	}

	ClientSock6 client6;
	client6.readLocalInterface();
	client6.setRemoteServerAndPort();

	// create or update status entry in map - signal that we are starting guessing
	bpf::BPFMapsWrapper mapsWrapper;
	struct guess_status_t status = {};
	status.state = GUESS_STATE_CHECKING;
	status.pid_tgid = pid_tgid;
	if (!mapsWrapper.updateElement(status_fd, &zero, &status)) {
		logger->error("failed to set tracer status, errno: {:d}", errno);
		return false;
	}
	logger->debug("guess status, set state: {:d}", status.state);

	// prepare values used to verify that we are at right offset
	field_values expected;
	try {
		auto expectedOpt{detail::getExpectedValues(localsock, client6)};
		if (!expectedOpt) {
			return false;
		}
		expected = *expectedOpt;
	}
	catch (const std::runtime_error& ex) {
		logger->error(ex.what());
		return false;
	}

	// RTT guessing config
	const unsigned rttMaxAttempts{10}; // at max that many offsets may be verified
	const unsigned rttRequiredReps{3}; // value at an offset must match with the expected value at least that many times in a row
	unsigned rttCurrentAttempts{0};
	unsigned rttCurrentReps{0};

	// in loop below we need a swich to select connect trigger from IPv4 to IPv6 - we start with IPv4
	bool guessIpv6 = false;
	while (true) {
		logger->trace("guess status, poking {:s} with state:{:d} what:{:d}",
			(guessIpv6?"ipv6":"ipv4"),
			status.state, status.what
		);
		if (guessIpv6) {
			client6.pokeRemoteServerAndPort();
		} else {
			(void)localsock.getTCPInfo();
		}
		// check what we got from bpf in status record
		if (!mapsWrapper.lookupElement(status_fd, &zero, &status)) {
			logger->error("Couldn't look up tracer status");
		}
		logger->trace("guess got status - state:{:d} what:{:d}",
			status.state, status.what
		);
		if (status.state != GUESS_STATE_CHECKED) {
			if (max_retries == 0) {
				logger->error("max_retries exhausted");
				return false;
			} else {
				--max_retries;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
		}

		switch (status.what) {
		case GUESS_FIELD_SADDR:
			if (status.saddr == expected.saddr) {
				logger->debug("Source address offset: {:#010x}", status.offset_saddr);
				status.what = GUESS_FIELD_DADDR;
			} else {
				status.offset_saddr++;
				status.saddr = expected.saddr;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_DADDR:
			if (status.daddr == expected.daddr) {
				logger->debug("Destination address offset: {:#010x}", status.offset_daddr);
				status.what = GUESS_FIELD_FAMILY;
			} else {
				status.offset_daddr++;
				status.daddr = expected.daddr;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_FAMILY:
			if (status.family == expected.family) {
				logger->debug("Family offset: {:#010x}", status.offset_family);
				status.what = GUESS_FIELD_SPORT;
			} else {
				status.offset_family++;
				status.family = expected.family;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_SPORT:
			if (status.sport == expected.sport) {
				logger->debug("Source port offset: {:#010x}", status.offset_sport);
				status.what = GUESS_FIELD_DPORT;
			} else {
				status.offset_sport++;
				status.sport = expected.sport;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_DPORT:
			if (status.dport == expected.dport) {
				logger->debug("Destination port offset: {:#010x}", status.offset_dport);
				status.what = GUESS_FIELD_NETNS;
			} else {
				status.offset_dport++;
				status.dport = expected.dport;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_NETNS:
			if (status.netns == expected.netns) {
				logger->debug("Network namespace offset: {:#010x}", status.offset_netns);
				status.what = GUESS_FIELD_DADDR_IPV6;
				guessIpv6 = true;
			} else {
				status.offset_ino++;
				if (status.err != 0 || status.offset_ino >= thresholdInetSock) {
					status.offset_ino = 0;
					status.offset_netns++;
				}
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_DADDR_IPV6:
			{
				auto ipv6_equal = [](uint32_t a[4], uint32_t b[4])->bool {
					for (int i = 0; i < 4; ++i) {
						if(a[i] != b[i]) {
							return false;
						}
					}
					return true;
				};
				if (ipv6_equal(status.daddr_ipv6, expected.daddr6)) {
					logger->debug("IPv6 daddress offset: {:#010x}", status.offset_daddr_ipv6);
					status.what = GUESS_FIELD_SEGS_IN;
					guessIpv6 = false;
					// values specified below are placed somewhere below this value (actually, below inet_sock), so let's initialize their offsets
					status.offset_segs_in = status.offset_segs_out = status.offset_rtt = status.offset_rtt_var = status.offset_daddr_ipv6 + sizeof(status.daddr_ipv6);
				} else {
					memcpy(&(status.daddr_ipv6), &(expected.daddr6), sizeof(expected.daddr6));
					logger->trace("Check IPv6 daddress offset: {:#010x}", status.offset_daddr_ipv6);
					status.offset_daddr_ipv6++;
				}
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_SEGS_IN:
			if (status.segs_in == expected.segs_in) {
				logger->debug("Segs in offset: {:#010x}", status.offset_segs_in);
				status.what = GUESS_FIELD_SEGS_OUT;
			} else {
				status.offset_segs_in++;
				status.segs_in = expected.segs_in;
			}
			status.state = GUESS_STATE_CHECKING;
			break;
		case GUESS_FIELD_SEGS_OUT:
			if (status.segs_out == expected.segs_out) {
				logger->debug("Segs out offset: {:#010x}", status.offset_segs_out);
				status.what = GUESS_FIELD_RTT;
			} else {
				status.offset_segs_out++;
				status.segs_out = expected.segs_out;
				status.state = GUESS_STATE_CHECKING;
			}
			break;
		case GUESS_FIELD_RTT:
			if (status.rtt == expected.rtt && status.rtt_var == expected.rtt_var) {
				if (++rttCurrentReps == rttRequiredReps) {
					logger->debug("RTT offset: {:#010x}", status.offset_rtt);
					logger->debug("RTT var offset: {:#010x}", status.offset_rtt_var);
					status.state = GUESS_STATE_READY;
				} else {
					// reload expected RTT
					if (!localsock.stopClient() || !localsock.startClient()) {
						logger->error("Couldn't restart client for RTT guessing");
						return false;
					}
					try {
						auto expectedOpt{detail::getExpectedValues(localsock, client6)};
						if (!expectedOpt) {
							return false;
						}
						expected = *expectedOpt;
					}
					catch (const std::runtime_error& ex) {
						logger->error(ex.what());
						return false;
					}
					status.rtt = expected.rtt;
					status.rtt_var = expected.rtt_var;
					status.state = GUESS_STATE_CHECKING;
				}
			} else {
				if (rttCurrentReps > 0) {
					logger->debug("Skipping offset {:#010x}; RTT, RTT var values don't match anymore - found: {:d}, {:d}, expected: {:d}, {:d}",
					status.offset_rtt, status.rtt, status.rtt_var, expected.rtt, expected.rtt_var);
					if (++rttCurrentAttempts == rttMaxAttempts) {
						logger->warn("Reached max attempts (%d) in RTT guessing, skipping", rttMaxAttempts);
						status.offset_rtt = status.offset_rtt_var = 0;
						status.state = GUESS_STATE_READY;
						break;
					}
					rttCurrentReps = 0;
				}
				status.offset_rtt++;
				status.offset_rtt_var = status.offset_rtt + sizeof(status.rtt);
				status.rtt = expected.rtt;
				status.rtt_var = expected.rtt_var;
				status.state = GUESS_STATE_CHECKING;
			}
			break;
		default:
			logger->error("unexpected status.what:{:d}", status.what);
			return false;
		}

		if (!mapsWrapper.updateElement(status_fd, &zero, &status)) {
			logger->error("failed to set tracer status, errno: {:d}", errno);
			return false;
		}
		if (status.state == GUESS_STATE_READY) {
			break;
		}
		if (status.offset_saddr >= thresholdInetSock || status.offset_daddr >= thresholdInetSock || status.offset_sport >= thresholdInetSock ||
			status.offset_dport >= thresholdInetSock || status.offset_netns >= thresholdInetSock || status.offset_family >= thresholdInetSock ||
			status.offset_daddr_ipv6 >= thresholdInetSock || status.offset_segs_in >= thresholdTcpSock || status.offset_segs_out >= thresholdTcpSock ||
			status.offset_rtt >= thresholdTcpSock || status.offset_rtt_var >= thresholdTcpSock
		) {
			logger->error("overflow while guessing {:d}, bailing out", status.what);
			return false;
		}
	}
	return true;
}

namespace detail {

std::optional<field_values> getExpectedValues(LocalSock& localsock, const ClientSock6& clientsock6) {
	field_values expected;
	expected.saddr = 0x0100007F;                   // 127.0.0.1
	expected.daddr = 0x0200007F;                   // 127.0.0.2
	expected.dport = htons(LocalSock::serverPort);
	expected.sport = htons(localsock.getClientPort());
	expected.netns = own_net_ns();
	clientsock6.getDAddress(expected.daddr6);
	expected.family = AF_INET;
	expected.rtt = 0;
	expected.rtt_var = 0;

	const unsigned maxAttempts{10};
	const auto interval{std::chrono::milliseconds(100)};
	const unsigned requiredReps{2};
	unsigned currentReps{0};

	for (unsigned i = 0; i <= maxAttempts; ++i) {
		auto ti{localsock.getTCPInfo()};
		if (std::tie(expected.rtt, expected.rtt_var) == std::tie(ti.tcpi_rtt, ti.tcpi_rttvar)) {
			if (++currentReps == requiredReps) {
				expected.segs_in = ti.tcpi_segs_in;
				expected.segs_out = ti.tcpi_segs_out;
				return {expected};
			}
		}
		else {
			expected.rtt = ti.tcpi_rtt;
			expected.rtt_var = ti.tcpi_rttvar;
			currentReps = 1;
		}
		std::this_thread::sleep_for(interval);
	}
	LOG_WARN("Failed to stabilize expected values");
	return std::nullopt;
}

}
