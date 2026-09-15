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
#pragma once
#include "bpf_generic/src/log.h"
#include <boost/program_options.hpp>
#include <condition_variable>
#include <filesystem>
#include <mutex>

namespace config {

struct ExitCtrl {
	bool running{true};
	std::mutex m;
	std::condition_variable cv;
	unsigned wait_time;
};

namespace po = boost::program_options;
class Configuration {
	po::variables_map variablesMap;
	bool noStdoutLog;
	uint32_t mapsSize;
	bool connectivity{false};
	bool disableEvents{false};
	bool testrun{false};
	po::options_description getOptionsDescription();
	po::variables_map parseArgsFile(const std::filesystem::path& argsFilePath);
	bool setUpLogging() const;

public:
	std::filesystem::path parseOptions(int argc, char* argv[]);

	uint32_t getMapsSize();
	bool printVersion() const {
		return variablesMap.count("version") > 0;
	}
	bool logEventsOnly() const {
		return noStdoutLog;
	}
	unsigned mainLoopTimeInterval() const {
		return variablesMap["time_interval"].as<unsigned>();
	}
	unsigned countersInterval() const {
		return variablesMap["counters_interval"].as<unsigned>();
	}
	bool testRun() const {
		return testrun;
	}
	bool deltaMetricsEnabled() const {
		return variablesMap.count("incremental") > 0;
	}
	bool addHeadersToMetrics() const {
		return variablesMap.count("header") > 0;
	}
	bool noninteractiveEnabled() const {
		return variablesMap.count("noninteractive") > 0;
	}
	bool filterLoopback() const {
		return variablesMap.count("with_loopback") == 0;
	}
	bool eventsEnabled() const;
	bool connectivityEnabled() const {
		return connectivity;
	}
	std::string bpfProgram() const {
		return variablesMap["program"].as<std::string>();
	}
	std::string bpfType() const {
		return variablesMap["bpf"].as<std::string>();
	}
};
}
