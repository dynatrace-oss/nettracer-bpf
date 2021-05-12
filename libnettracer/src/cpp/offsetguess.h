#pragma once

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

class LocalSock;
class ClientSock6;

bool guess(int status_fd);

namespace detail {

std::unique_ptr<LocalSock> startLocalSock();

std::optional<field_values> getExpectedValues(LocalSock& localsock, const ClientSock6& clientsock6);

}
