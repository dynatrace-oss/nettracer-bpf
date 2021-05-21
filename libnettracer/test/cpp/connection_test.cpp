#include <gtest/gtest.h>
#include "proc_tcp.h"
#include "tuple_utils.h"

using namespace std::string_literals;

using IPv4ParseResult = std::optional<std::pair<ipv4_tuple_t, ConnectionDetails>>;
using IPv6ParseResult = std::optional<std::pair<ipv6_tuple_t, ConnectionDetails>>;

class IPv4ConnectionParsingTest : public testing::TestWithParam<std::pair<std::string, IPv4ParseResult>> {};
class IPv6ConnectionParsingTest : public testing::TestWithParam<std::pair<std::string, IPv6ParseResult>> {};

TEST_P(IPv4ConnectionParsingTest, testParseIPv4ConnFromProcNet) {
	const auto& [rawLine, expParsedLine] = GetParam();

	const auto parsedLine = parseProcIPv4ConnectionLine(rawLine);
	ASSERT_EQ(static_cast<bool>(expParsedLine), static_cast<bool>(parsedLine));

	if (expParsedLine) {
		const auto& [expTuple, expDetails] = *expParsedLine;
		const auto& [tuple, details] = *parsedLine;

		EXPECT_EQ(expTuple.saddr, tuple.saddr);
		EXPECT_EQ(expTuple.daddr, tuple.daddr);
		EXPECT_EQ(expTuple.sport, tuple.sport);
		EXPECT_EQ(expTuple.dport, tuple.dport);
		// netns not set

		EXPECT_EQ(expDetails.direction, details.direction);
		// pid not set
	}
}

INSTANTIATE_TEST_SUITE_P(IPv4ConnectionParsingTests, IPv4ConnectionParsingTest, testing::Values(
	// junk
	std::make_pair(""s, IPv4ParseResult{std::nullopt}),
	std::make_pair(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"s,
		IPv4ParseResult{std::nullopt}),
	// outgoing
	std::make_pair(
		"   0: 0100007F:7AB7 01020304:07E5 01 00000000:00000000 00:00000000 00000000   999        0 8480039 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv4_tuple_t{0x100007F, 0x1020304, 31415, 2021, 0}, ConnectionDetails{0, ConnectionDirection::Outgoing})}),
	std::make_pair(
		"14: 05060708:07E4 0100007F:7AB7 01 00000000:00000000 00:00000000 00000000  999    0 536185 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv4_tuple_t{0x5060708, 0x100007F, 2020, 31415, 0}, ConnectionDetails{0, ConnectionDirection::Outgoing})}),
	// incoming
	std::make_pair(
		"  3: 0100007F:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000  999      0 8587888 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv4_tuple_t{0x0, 0x100007F, 0, 50000, 0}, ConnectionDetails{0, ConnectionDirection::Incoming})}),
	// other states
	std::make_pair(
		" 15: 0100007F:C350 05060708:07E6 06 00000000:00000000 00:00000000 00000000  999      0 888 1 0000000000000000 100 0 0 10 0"s,
		IPv4ParseResult{std::nullopt})
));

TEST_P(IPv6ConnectionParsingTest, testParseIPv6ConnFromProcNet) {
	const auto& [rawLine, expParsedLine] = GetParam();

	const auto parsedLine = parseProcIPv6ConnectionLine(rawLine);
	ASSERT_EQ(static_cast<bool>(expParsedLine), static_cast<bool>(parsedLine));

	if (expParsedLine) {
		const auto& [expTuple, expDetails] = *expParsedLine;
		const auto& [tuple, details] = *parsedLine;

		EXPECT_EQ(expTuple.saddr_h, tuple.saddr_h);
		EXPECT_EQ(expTuple.saddr_l, tuple.saddr_l);
		EXPECT_EQ(expTuple.daddr_h, tuple.daddr_h);
		EXPECT_EQ(expTuple.daddr_l, tuple.daddr_l);
		EXPECT_EQ(expTuple.sport, tuple.sport);
		EXPECT_EQ(expTuple.dport, tuple.dport);
		// netns not set

		EXPECT_EQ(expDetails.direction, details.direction);
		// pid not set
	}
}

INSTANTIATE_TEST_SUITE_P(IPv6ConnectionParsingTests, IPv6ConnectionParsingTest, testing::Values(
	// junk
	std::make_pair(""s, IPv6ParseResult{std::nullopt}),
	std::make_pair(
		"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"s,
		IPv6ParseResult{std::nullopt}),
	// outgoing
	std::make_pair(
		" 18: 00000000000000000000000001000000:0278 00000000000000000000000001000000:C355 01 00000000:00000000 00:00000000 00000000  0    0 8670135 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv6_tuple_t{0x0, 0x1000000, 0x0, 0x1000000, 632, 50005, 0}, ConnectionDetails{0, ConnectionDirection::Outgoing})}),
	// incoming
	std::make_pair(
		"1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv6_tuple_t{0x0, 0x0, 0x0, 0x1000000, 0, 631, 0}, ConnectionDetails{0, ConnectionDirection::Incoming})}),
	std::make_pair(
		"   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 56336 1 0000000000000000 100 0 0 10 0"s,
		std::optional{std::make_pair(ipv6_tuple_t{0x0, 0x0, 0x0, 0x1000000, 0, 631, 0}, ConnectionDetails{0, ConnectionDirection::Incoming})}),
	// other states
	std::make_pair(
		"   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 56336 1 0000000000000000 100 0 0 10 0"s,
		IPv6ParseResult{std::nullopt})
));
