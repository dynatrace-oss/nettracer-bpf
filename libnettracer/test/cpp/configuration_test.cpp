/*
 * Copyright 2026 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "configuration.h"
#include <gtest/gtest.h>

using namespace config;

TEST(ConfigurationTest, connectivityDisabledByDefault) {
	Configuration cfg;
	const char* argv[] = {"nettracer"};
	cfg.parseOptions(1, const_cast<char**>(argv));
	EXPECT_FALSE(cfg.connectivityEnabled());
}

TEST(ConfigurationTest, connectivityEnabledByFlag) {
	Configuration cfg;
	const char* argv[] = {"nettracer", "--connectivity"};
	cfg.parseOptions(2, const_cast<char**>(argv));
	EXPECT_TRUE(cfg.connectivityEnabled());
}

TEST(ConfigurationTest, disabledEventAndConnectivityCannotCoexist) {
	Configuration cfg;
	const char* argv[] = {"nettracer", "--connectivity", "--disable_events"};
	cfg.parseOptions(3, const_cast<char**>(argv));
	EXPECT_TRUE(cfg.connectivityEnabled());
	EXPECT_THROW(cfg.eventsEnabled(), po::invalid_option_value);
}
