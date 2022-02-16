#include "offsetguess.h"

#include "bpf_generic/src/bpf_loading.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/log.h"
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

namespace {

ino_t own_net_ns() {
	struct stat statbuf;
	int ret = stat("/proc/self/ns/net", &statbuf);
	if (ret) {
		throw std::runtime_error{"stat failed"};
	}
	return statbuf.st_ino;
}

// Offset thresholds
inline const int thresholdInetSock = 1500; // Don't go over that limit when guessing offsets for fields in inet_sock
inline const int thresholdTcpSock = 2500; // Fields outside inet_sock are stored much farther

}

namespace detail {

// ctor and dtor definitions moved after definition of LocalSock and ClientSock6 to allow fwd declaration
OffsetGuessing::OffsetGuessing() = default;
OffsetGuessing::~OffsetGuessing() = default;

bool OffsetGuessing::guess(int status_fd) {
	const unsigned maxAttempts = 3;
	for (unsigned i = 0; i < maxAttempts; ++i) {
		if (makeGuessingAttempt(status_fd)) {
			return true;
		}
		else {
			LOG_WARN("Guessing attempt #{:d} failed", i+1);
		}
	}
	return false;
}

#define GUESS_SIMPLE_FIELD(field, str, next) guessSimpleField(status.field, expected.field, status.offset_##field, status, str, next)

bool OffsetGuessing::makeGuessingAttempt(int status_fd) {
	logger = logging::getLogger();

	logger->debug("guess enter fd: {:d}", status_fd);
	// nettracer_status map holds only one entry with key zero which is
	// created (and updated) in bpf program inside call are_offsets_ready_v(4|6)
	// which in turn are called in kretprobe tcp_v(4|6)_connect

	uint64_t pid_tgid = (uint64_t)getpid() << 32 | syscall(SYS_gettid);
	logger->debug("guess thread pid: {:d}", pid_tgid);

	// prepare server ipv4 and client ipv6 on this thread
	localsock = startLocalSock();
	if (!localsock) {
		return false;
	}

	bool skipIPv6Guessing = false;
	client6 = prepareClient6();
	if (!client6) {
		logger->warn("Skipping offset guessing for IPv6 due to failed preparation of ClientSock6");
		logger->warn("NetTracer won't be able to monitor IPv6 traffic. To give it another try, please restart.");
		skipIPv6Guessing = true;
	}

	// create or update status entry in map - signal that we are starting guessing
	bpf::BPFMapsWrapper mapsWrapper;
	const uint32_t zero = 0;
	status = {};
	status.state = GUESS_STATE_CHECKING;
	status.pid_tgid = pid_tgid;
	if (!mapsWrapper.updateElement(status_fd, &zero, &status)) {
		logger->error("failed to set tracer status, errno: {:d}", errno);
		return false;
	}
	logger->debug("guess status, set state: {:d}", status.state);

	// prepare values used to verify that we are at right offset
	try {
		auto expectedOpt{getExpectedValues(skipIPv6Guessing)};
		if (!expectedOpt) {
			return false;
		}
		expected = *expectedOpt;
	}
	catch (const std::runtime_error& ex) {
		logger->error(ex.what());
		return false;
	}

	// limit how many failed attempts at communicating with the BPF side are accepted
	int maxRetries = 100;

	unsigned rttCurrentAttempts = 0;
	unsigned rttCurrentReps = 0;

	// in loop below we need a swich to select connect trigger from IPv4 to IPv6 - we start with IPv4
	bool guessIPv6 = false;
	while (true) {
		logger->trace("guess status, poking {:s} with state:{:d} what:{:d}",
			(guessIPv6?"ipv6":"ipv4"),
			status.state, status.what
		);
		if (guessIPv6) {
			client6->pokeRemoteServerAndPort();
		} else {
			(void)localsock->getTCPInfo();
		}
		// check what we got from bpf in status record
		if (!mapsWrapper.lookupElement(status_fd, &zero, &status)) {
			logger->error("Couldn't look up tracer status");
		}
		logger->trace("guess got status - state:{:d} what:{:d}",
			status.state, status.what
		);
		if (status.state != GUESS_STATE_CHECKED) {
			if (maxRetries == 0) {
				logger->error("max retries of communicating with kernel side exhausted");
				return false;
			} else {
				--maxRetries;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
		}

		switch (status.what) {
		case GUESS_FIELD_SADDR:
			GUESS_SIMPLE_FIELD(saddr, "Source address", GUESS_FIELD_DADDR);
			break;
		case GUESS_FIELD_DADDR:
			GUESS_SIMPLE_FIELD(daddr, "Destination address", GUESS_FIELD_FAMILY);
			break;
		case GUESS_FIELD_FAMILY:
			GUESS_SIMPLE_FIELD(family, "Family", GUESS_FIELD_SPORT);
			break;
		case GUESS_FIELD_SPORT:
			GUESS_SIMPLE_FIELD(sport, "Source port", GUESS_FIELD_DPORT);
			break;
		case GUESS_FIELD_DPORT:
			GUESS_SIMPLE_FIELD(dport, "Destination port", GUESS_FIELD_NETNS);
			break;
		case GUESS_FIELD_NETNS:
			guessNetns();
			if (status.what == GUESS_FIELD_DADDR_IPV6) {
				if (skipIPv6Guessing) {
					status.offset_daddr_ipv6 = 0;
					status.what = GUESS_FIELD_SEGS_IN;
				}
				else {
					guessIPv6 = true;
				}
			}
			break;
		case GUESS_FIELD_DADDR_IPV6:
			guessDAddrIPv6();
			if (status.what == GUESS_FIELD_SEGS_IN) {
				guessIPv6 = false;
			}
			break;
		case GUESS_FIELD_SEGS_IN:
			GUESS_SIMPLE_FIELD(segs_in, "Segs in", GUESS_FIELD_SEGS_OUT);
			break;
		case GUESS_FIELD_SEGS_OUT:
			GUESS_SIMPLE_FIELD(segs_out, "Segs out", GUESS_FIELD_RTT);
			break;
		case GUESS_FIELD_RTT:
			if (!guessRTT(rttCurrentAttempts, rttCurrentReps, skipIPv6Guessing)) {
				return false;
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
		if (overflowOccurred()) {
			logger->error("overflow while guessing {:d}, bailing out", status.what);
			if (status.what == GUESS_FIELD_RTT) {
				// allow failure for RTT
				status.offset_rtt = status.offset_rtt_var = 0;
				return true;
			}
			return false;
		}
	}
	return true;
}

template<typename T>
void OffsetGuessing::guessSimpleField(T& statusValue, const T& expectedValue, uint16_t& offset, guess_status_t& status, const std::string& fieldStr, const guess_field& next) {
	if (statusValue == expectedValue) {
		logger->debug("{} offset: {:#010x}", fieldStr, offset);
		status.what = next;
	}
	else {
		++offset;
		statusValue = expectedValue;
	}
	status.state = GUESS_STATE_CHECKING;
}

void OffsetGuessing::guessNetns() {
	if (status.netns == expected.netns) {
		logger->debug("Network namespace offset: {:#010x}", status.offset_netns);
		status.what = GUESS_FIELD_DADDR_IPV6;
	} else {
		++status.offset_ino;
		if (status.err != 0 || status.offset_ino >= thresholdInetSock) {
			status.offset_ino = 0;
			status.offset_netns++;
		}
	}
	status.state = GUESS_STATE_CHECKING;
}

void OffsetGuessing::guessDAddrIPv6() {
	auto ipv6_equal = [](uint32_t a[4], uint32_t b[4])->bool {
		for (int i = 0; i < 4; ++i) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	};
	if (ipv6_equal(status.daddr_ipv6, expected.daddr6)) {
		logger->debug("IPv6 daddress offset: {:#010x}", status.offset_daddr_ipv6);
		status.what = GUESS_FIELD_SEGS_IN;
		// values specified below are placed somewhere below this value (actually, below inet_sock), so let's initialize their offsets
		status.offset_segs_in = status.offset_segs_out = status.offset_rtt = status.offset_rtt_var = status.offset_daddr_ipv6 + sizeof(status.daddr_ipv6);
	} else {
		memcpy(&(status.daddr_ipv6), &(expected.daddr6), sizeof(expected.daddr6));
		logger->trace("Check IPv6 daddress offset: {:#010x}", status.offset_daddr_ipv6);
		status.offset_daddr_ipv6++;
	}
	status.state = GUESS_STATE_CHECKING;
}

bool OffsetGuessing::guessRTT(unsigned& currentAttempts, unsigned& currentReps, bool skipIPv6) {
	const unsigned maxAttempts = 10; // that many offsets may be verified
	const unsigned requiredReps = 3; // value at an offset must match with the expected value at least that many times in a row

	if (status.rtt == expected.rtt && status.rtt_var == expected.rtt_var) {
		if (++currentReps == requiredReps) {
			logger->debug("RTT offset: {:#010x}", status.offset_rtt);
			logger->debug("RTT var offset: {:#010x}", status.offset_rtt_var);
			status.state = GUESS_STATE_READY;
		} else {
			// reload expected RTT
			if (!localsock->stopClient() || !localsock->startClient()) {
				logger->error("Couldn't restart client for RTT guessing");
				return false;
			}
			try {
				auto expectedOpt{getExpectedValues(skipIPv6)};
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
		if (currentReps > 0) {
			logger->debug("Skipping offset {:#010x}; RTT, RTT var values don't match anymore - found: {:d}, {:d}, expected: {:d}, {:d}",
			status.offset_rtt, status.rtt, status.rtt_var, expected.rtt, expected.rtt_var);
			if (++currentAttempts == maxAttempts) {
				logger->warn("Reached max attempts={:d} in RTT guessing, skipping", maxAttempts);
				status.offset_rtt = status.offset_rtt_var = 0;
				status.state = GUESS_STATE_READY;
				return true;
			}
			currentReps = 0;
		}
		status.offset_rtt++;
		status.offset_rtt_var = status.offset_rtt + sizeof(status.rtt);
		status.rtt = expected.rtt;
		status.rtt_var = expected.rtt_var;
		status.state = GUESS_STATE_CHECKING;
	}
	return true;
}

bool OffsetGuessing::overflowOccurred() const {
	return status.offset_saddr >= thresholdInetSock || status.offset_daddr >= thresholdInetSock || status.offset_sport >= thresholdInetSock ||
		status.offset_dport >= thresholdInetSock || status.offset_netns >= thresholdInetSock || status.offset_family >= thresholdInetSock ||
		status.offset_daddr_ipv6 >= thresholdInetSock || status.offset_segs_in >= thresholdTcpSock || status.offset_segs_out >= thresholdTcpSock ||
		status.offset_rtt >= thresholdTcpSock || status.offset_rtt_var >= thresholdTcpSock;
}

std::optional<field_values> OffsetGuessing::getExpectedValues(bool skipIPv6) {
	field_values expected;
	expected.saddr = 0x0100007F;                   // 127.0.0.1
	expected.daddr = 0x0200007F;                   // 127.0.0.2
	expected.dport = htons(localsock->getServerPort());
	expected.sport = htons(localsock->getClientPort());
	expected.netns = own_net_ns();
	if (!skipIPv6 && !client6->getDAddress(expected.daddr6)) {
		LOG_WARN("Could not obtain IPv6 destination address for guessing");
	}
	expected.family = AF_INET;
	expected.rtt = 0;
	expected.rtt_var = 0;

	const unsigned maxAttempts{10};
	const auto interval{std::chrono::milliseconds(100)};
	const unsigned requiredReps{2};
	unsigned currentReps{0};

	for (unsigned i = 0; i <= maxAttempts; ++i) {
		auto ti{localsock->getTCPInfo()};
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

std::unique_ptr<LocalSock> startLocalSock() {
	auto localsock = std::make_unique<LocalSock>();
	if (!localsock->running()) {
		const unsigned maxRetries = 2;
		const auto interval = std::chrono::seconds(3);
		bool ok = false;
		for (unsigned i = 0; i < maxRetries; ++i) {
			LOG_WARN("LocalSock start failed, retrying in {:d}s...", interval.count());

			std::this_thread::sleep_for(interval);
			localsock->stop();
			localsock->randomizeServerPort();
			if (localsock->start()) {
				ok = true;
				break;
			}
		}
		if (!ok) {
			LOG_ERROR("LocalSock could not start");
			return {};
		}
	}
	return localsock;
}

std::unique_ptr<ClientSock6> prepareClient6() {
	auto client6 = std::make_unique<ClientSock6>();
	if (!client6->readLocalInterface() || !client6->setRemoteServerAndPort()) {
		// there's no point in retrying
		// reading local interface won't fix itself in the next attempt
		// and setting IP/port even to a busy one should work fine unless interface reading failed
		return {};
	}
	return client6;
}

}
