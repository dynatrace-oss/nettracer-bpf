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
#include "proc_tcp.h"
#include "tuple_utils.h"
#include <gtest/gtest.h>

using namespace std::string_literals;

TEST(ProcTcpTest, EmptyCasueEceptionv4) {
	EXPECT_THROW(test::parseLine4("", 0), std::exception);
}

TEST(ProcTcpTest, EmptyCasueEceptionv6) {
	EXPECT_THROW(test::parseLine6("", 0), std::exception);
}

TEST(ProcTcpTest, OkParsing4) {
	std::string input =
			"   0: 0100007F:7AB7 01020304:07E5 01 00000000:00000000 00:00000000 00000000   999        0 8480039 1 0000000000000000 100 0 0 10 0"s;

	const auto [inode, conn] = test::parseLine4(input, 0);
	EXPECT_EQ(conn.ep.saddr, 0x100007F);
	EXPECT_EQ(conn.ep.daddr, 0x1020304);
	EXPECT_EQ(conn.ep.sport, 31415);
	EXPECT_EQ(conn.ep.dport, 2021);
	EXPECT_EQ(inode, 8480039);
}

TEST(ProcTcpTest, OkParsing6) {
	std::string input =
			" 18: 00000000000000000000000001000000:0278 00000000000000000000000001000000:C355 01 00000000:00000000 00:00000000 00000000  0    0 8670135 1 0000000000000000 100 0 0 10 0"s;

	const auto [inode, conn] = test::parseLine6(input, 0);
	EXPECT_EQ(conn.ep.saddr_h, 0x0000000);
	EXPECT_EQ(conn.ep.saddr_l, 0x1000000);
	EXPECT_EQ(conn.ep.daddr_h, 0x0000000);
	EXPECT_EQ(conn.ep.daddr_l, 0x1000000);
	EXPECT_EQ(conn.ep.sport, 632);
	EXPECT_EQ(conn.ep.dport, 50005);
	EXPECT_EQ(inode, 8670135);
}
