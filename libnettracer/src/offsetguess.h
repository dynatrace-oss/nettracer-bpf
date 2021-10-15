#pragma once

#include "bpf_program/nettracer-bpf.h"
#include "localsock.h"
#include "localsock6.h"
#include <spdlog/fwd.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <sys/types.h>

struct field_values {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	ino_t netns;
	uint16_t family;
	uint32_t daddr6[4];
	uint32_t segs_in;
	uint32_t segs_out;
	uint32_t rtt;
	uint32_t rtt_var;
};

class OffsetGuessing {
public:
	bool guess(int status_fd);

private:
	bool makeGuessingAttempt(int status_fd);
	std::optional<field_values> getExpectedValues();
	template<typename T>
	void guessSimpleField(T& statusValue, const T& expectedValue, uint16_t& offset, guess_status_t& status, const std::string& fieldStr, const guess_field& next);
	void guessNetns();
	void guessDAddrIPv6();
	bool guessRTT(unsigned& currentAttempts, unsigned& currentReps);
	bool overflowOccurred() const;

	std::shared_ptr<spdlog::logger> logger;
	std::unique_ptr<LocalSock> localsock;
	ClientSock6 client6;
	guess_status_t status;
	field_values expected;
};

namespace detail {

std::unique_ptr<LocalSock> startLocalSock();
ClientSock6 prepareClient6();

}
