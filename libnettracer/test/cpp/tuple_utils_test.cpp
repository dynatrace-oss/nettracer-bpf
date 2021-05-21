#include <gtest/gtest.h>
#include "tuple_utils.h"
#include <arpa/inet.h>

using namespace std::string_literals;

TEST(TupleComparisonTests, testIPv4TuplesEquality) {
	const uint32_t addrA{2130706433}, addrB{16909060};
	const uint16_t portA{50000}, portB{80};
	const uint32_t netns{1000};

	EXPECT_EQ((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	// addr mismatch
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrB, addrA, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrB, addrA, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrA, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrA, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrB, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrB, addrB, portA, portB, netns}));

	// port mismatch
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portB, portA, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portB, portA, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portA, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portA, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portB, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portB, portB, netns}));

	// port as addr
	EXPECT_NE((ipv4_tuple_t{portA, portB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{portA, portB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{portB, portA, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{portB, portA, portA, portB, netns}));

	// one changed
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{1, addrB, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{1, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, 1, portA, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, 1, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, 1, portB, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, 1, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, 1, netns}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, 1, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));

	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), (ipv4_tuple_t{addrA, addrB, portA, portB, 1}));
	EXPECT_NE((ipv4_tuple_t{addrA, addrB, portA, portB, 1}), (ipv4_tuple_t{addrA, addrB, portA, portB, netns}));
}

TEST(TupleComparisonTests, testIPv6TuplesEquality) {
	const uint64_t addrAh{1111111111}, addrAl{2222222222}, addrBh{3333333333}, addrBl{4444444444};
	const uint16_t portA{50000}, portB{80};
	const uint32_t netns{1000};

	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	// addr mismatch
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrBh, addrBl, addrAh, addrAl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrBh, addrBl, addrAh, addrAl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrAh, addrAl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrAh, addrAl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrBh, addrBl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrBh, addrBl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAh, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAh, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAl, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAl, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBh, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBh, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBl, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBl, addrBl, portA, portB, netns}));

	// port mismatch
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portB, portA, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portB, portA, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portA, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portA, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portB, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portB, portB, netns}));

	// port as addr
	EXPECT_NE((ipv6_tuple_t{portA, portA, portB, portB, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{portA, portA, portB, portB, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{portB, portB, portA, portA, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{portB, portB, portA, portA, portA, portB, netns}));

	// one changed
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{1, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{1, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, 1, addrBh, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, 1, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, 1, addrBl, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, 1, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, 1, portA, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, 1, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, 1, portB, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, 1, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, 1, netns}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, 1, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));

	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, 1}));
	EXPECT_NE((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, 1}), (ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
}

class IPv4TupleToStringTest : public testing::TestWithParam<std::tuple<std::string, std::string, uint32_t, uint32_t, uint16_t, uint16_t, uint32_t>> {};
class IPv6TupleToStringTest : public testing::TestWithParam<std::tuple<std::string, std::string, uint64_t, uint64_t, uint64_t, uint64_t, uint16_t, uint16_t, uint32_t>> {};

TEST_P(IPv4TupleToStringTest, testIPv4TupleToString) {
	const auto& [outStrBegin, outStrEnd, addrA, addrB, portA, portB, netns] = GetParam();

	EXPECT_EQ(outStrBegin + " -- "s + outStrEnd, to_string(std::make_pair(ipv4_tuple_t{addrA, addrB, portA, portB, netns}, ConnectionDirection::Unknown)));
	EXPECT_EQ(outStrBegin + " -> "s + outStrEnd, to_string(std::make_pair(ipv4_tuple_t{addrA, addrB, portA, portB, netns}, ConnectionDirection::Outgoing)));
	EXPECT_EQ(outStrBegin + " <- "s + outStrEnd, to_string(std::make_pair(ipv4_tuple_t{addrA, addrB, portA, portB, netns}, ConnectionDirection::Incoming)));
}

INSTANTIATE_TEST_SUITE_P(IPv4TupleToStringTests, IPv4TupleToStringTest, testing::Values(
	std::make_tuple("127.0.0.1:50000"s, "0.0.0.0:80 NS:1000"s, 0x0100007F, 0x0, 50000, 80, 1000),
	std::make_tuple("100.100.100.100:44444"s, "255.255.255.255:40000 NS:55555"s, 0x64646464, 0xFFFFFFFF, 44444, 40000, 55555),
	std::make_tuple("1.1.1.1:12"s, "5.6.7.8:88 NS:0"s, 0x01010101, 0x08070605, 12, 88, 0)
));

TEST_P(IPv6TupleToStringTest, testIPv6TupleToString) {
	const auto& [outStrBegin, outStrEnd, addrAh, addrAl, addrBh, addrBl, portA, portB, netns] = GetParam();

	EXPECT_EQ(outStrBegin + " -- "s + outStrEnd, to_string(std::make_pair(ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}, ConnectionDirection::Unknown)));
	EXPECT_EQ(outStrBegin + " -> "s + outStrEnd, to_string(std::make_pair(ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}, ConnectionDirection::Outgoing)));
	EXPECT_EQ(outStrBegin + " <- "s + outStrEnd, to_string(std::make_pair(ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}, ConnectionDirection::Incoming)));
}

INSTANTIATE_TEST_SUITE_P(IPv6TupleToStringTests, IPv6TupleToStringTest, testing::Values(
	std::make_tuple(":::12"s, "1:::80 NS:1000"s, 0x0, 0x0, 0x100, 0x0, 12, 80, 1000),
	std::make_tuple("abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:44444"s, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:40000 NS:55555"s, 0xcdabcdabcdabcdab, 0xcdabcdabcdabcdab, 0xffffffffffffffff, 0xffffffffffffffff, 44444, 40000, 55555),
	std::make_tuple("f:f:f:f:f:f:f:f:50000"s, "1234:5678::9012:34567 NS:0"s, 0x0f000f000f000f00, 0x0f000f000f000f00, 0x0000000078563412, 0x1290000000000000, 50000, 34567, 0)
));

class IPv4EventToStringTest : public testing::TestWithParam<std::tuple<std::string, std::string, uint32_t, uint32_t, uint16_t, uint16_t, uint32_t, uint32_t>> {};
class IPv6EventToStringTest : public testing::TestWithParam<std::tuple<std::string, std::string, uint64_t, uint64_t, uint64_t, uint64_t, uint16_t, uint16_t, uint32_t, uint32_t>> {};

TEST_P(IPv4EventToStringTest, testIPv4EventToString) {
	const auto& [outStrBegin, outStrEnd, addrA, addrB, portA, portB, netns, pid] = GetParam();
	const uint64_t ts{12345};
	const uint32_t cpu{1};

	EXPECT_EQ(outStrBegin + " -- "s + outStrEnd, to_string(tcp_ipv4_event_t{ts, cpu, TCP_EVENT_TYPE_CLOSE, pid, addrA, addrB, portA, portB, netns}));
	EXPECT_EQ(outStrBegin + " -> "s + outStrEnd, to_string(tcp_ipv4_event_t{ts, cpu, TCP_EVENT_TYPE_CONNECT, pid, addrA, addrB, portA, portB, netns}));
	EXPECT_EQ(outStrBegin + " <- "s + outStrEnd, to_string(tcp_ipv4_event_t{ts, cpu, TCP_EVENT_TYPE_ACCEPT, pid, addrA, addrB, portA, portB, netns}));
}

INSTANTIATE_TEST_SUITE_P(IPv4EventToStringTests, IPv4EventToStringTest, testing::Values(
	std::make_tuple("127.0.0.1:50000"s, "0.0.0.0:80 NS:1000 PID:100"s, 0x0100007F, 0x0, 50000, 80, 1000, 100),
	std::make_tuple("100.100.100.100:44444"s, "255.255.255.255:40000 NS:55555 PID:99999"s, 0x64646464, 0xFFFFFFFF, 44444, 40000, 55555, 99999),
	std::make_tuple("1.1.1.1:12"s, "5.6.7.8:88 NS:0 PID:0"s, 0x01010101, 0x08070605, 12, 88, 0, 0)
));

TEST_P(IPv6EventToStringTest, testIPv6EventToString) {
	const auto& [outStrBegin, outStrEnd, addrAh, addrAl, addrBh, addrBl, portA, portB, netns, pid] = GetParam();
	const uint64_t ts{12345};
	const uint32_t cpu{1};

	EXPECT_EQ(outStrBegin + " -- "s + outStrEnd, to_string(tcp_ipv6_event_t{ts, cpu, TCP_EVENT_TYPE_CLOSE, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ(outStrBegin + " -> "s + outStrEnd, to_string(tcp_ipv6_event_t{ts, cpu, TCP_EVENT_TYPE_CONNECT, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ(outStrBegin + " <- "s + outStrEnd, to_string(tcp_ipv6_event_t{ts, cpu, TCP_EVENT_TYPE_ACCEPT, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
}

INSTANTIATE_TEST_SUITE_P(IPv6EventToStringTests, IPv6EventToStringTest, testing::Values(
	std::make_tuple(":::12"s, "1:::80 NS:1000 PID:100"s, 0x0, 0x0, 0x100, 0x0, 12, 80, 1000, 100),
	std::make_tuple("abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd:44444"s, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:40000 NS:55555 PID:99999"s, 0xcdabcdabcdabcdab, 0xcdabcdabcdabcdab, 0xffffffffffffffff, 0xffffffffffffffff, 44444, 40000, 55555, 99999),
	std::make_tuple("f:f:f:f:f:f:f:f:50000"s, "1234:5678::9012:34567 NS:0 PID:0"s, 0x0f000f000f000f00, 0x0f000f000f000f00, 0x0000000078563412, 0x1290000000000000, 50000, 34567, 0, 0)
));

TEST(TupleConversionTests, testIPv4EventToTuple) {
	const uint32_t addrA{2130706433}, addrB{16909060};
	const uint16_t portA{50000}, portB{80};
	const uint32_t netns{1000};
	const uint64_t timestamp{1234567890};
	const uint32_t cpu{2};
	const uint32_t pid{1234};

	EXPECT_EQ((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), eventToTuple(tcp_ipv4_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_ACCEPT, pid, addrA, addrB, portA, portB, netns}));
	EXPECT_EQ((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), eventToTuple(tcp_ipv4_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CLOSE, pid, addrA, addrB, portA, portB, netns}));
	EXPECT_EQ((ipv4_tuple_t{addrA, addrB, portA, portB, netns}), eventToTuple(tcp_ipv4_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CONNECT, pid, addrA, addrB, portA, portB, netns}));
}

TEST(TupleConversionTests, testIPv6EventToTuple) {
	const uint64_t addrAh{1111111111}, addrAl{2222222222}, addrBh{3333333333}, addrBl{4444444444};
	const uint16_t portA{50000}, portB{80};
	const uint32_t netns{1000};
	const uint64_t timestamp{1234567890};
	const uint32_t cpu{2};
	const uint32_t pid{1234};

	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_ACCEPT, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CLOSE, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CONNECT, pid, 0, 0, 0, 0, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
}
