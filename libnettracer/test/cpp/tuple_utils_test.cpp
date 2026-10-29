/*
* Copyright 2025 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License cat
*
* https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
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

	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_ACCEPT, pid, 1, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CLOSE, pid, 2, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
	EXPECT_EQ((ipv6_tuple_t{addrAh, addrAl, addrBh, addrBl, portA, portB, netns}), eventToTuple(tcp_ipv6_event_t{timestamp, cpu, tcp_event_type::TCP_EVENT_TYPE_CONNECT, pid, 3, addrAh, addrAl, addrBh, addrBl, portA, portB, netns}));
}

TEST(HumanReadableTests, printUint64) {
	uint64_t var = 123;
	std::string result = short_num(var);
	EXPECT_EQ(result, "123");
	var = 123456;
	result = short_num(var);
	EXPECT_EQ(result, "123.5K");
	var = 123456789;
	result = short_num(var);
	EXPECT_EQ(result, "123.5M");
	var = 123456789123;
	result = short_num(var);
	EXPECT_EQ(result, "123.5G");
	var = 123456789123123;
	result = short_num(var);
	EXPECT_EQ(result, "123456.8G");
}

