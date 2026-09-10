/*
 * Copyright 2026 Dynatrace LLC
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
	po::variables_map vm;
	bool noStdoutLog;
	uint32_t mapsSize;
	po::options_description getOptionsDescription() const;
	po::variables_map parseArgsFile(const std::filesystem::path& argsFilePath);
	bool setUpLogging(const boost::program_options::variables_map& vm);

public:
	std::filesystem::path parseOptions(int argc, char* argv[]);

	uint32_t getMapsSize();
	bool printVersion() const {
		return vm.count("version") > 0;
	}
	bool logEventsOnly() const {
		return noStdoutLog;
	}
	unsigned mainLoopTimeInterval() const {
		return vm["time_interval"].as<unsigned>();
	}
	unsigned countersInterval() {
		return vm["counters_interval"].as<unsigned>();
	}
	bool testRun() const {
		return vm.count("test") > 0;
	}

	bool deltaMetricsEnabled() const {
		return vm.count("incremental") > 0;
	}
	bool addHeadersToMetrics() const {
		return vm.count("header") > 0;
	}
	bool noninteractiveEnabled() const {
		return vm.count("noninteractive") > 0;
	}
	bool loopbackEnabled() const {
		return vm.count("with_loopback") == 0;
	}
	bool eventsEnabled() const {
		return vm["events"].as<unsigned>() == 1;
	}
	std::string bpfProgram() const {
		return vm["program"].as<std::string>();
	}
	std::string bpfType() const {
		return vm["bpf"].as<std::string>();
	}
};
}