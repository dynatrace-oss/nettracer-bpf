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
#include <boost/program_options.hpp>
#include <filesystem>

namespace po = boost::program_options;

class Configuration {
	po::variables_map vm;
	po::options_description getOptionsDescription();
	po::variables_map parseArgsFile(const std::filesystem::path& argsFilePath);
    bool noStdoutLog;
    uint32_t mapsSize;
public:
	std::filesystem::path parseOptions(int argc, char* argv[]);
	bool setupLogger();
	uint32_t getMapsSize();
	bool printVersion() {
		return vm.count("version") > 0;
	}
	unsigned mainLoopTimeInterval() {
		return vm["time_interval"].as<unsigned>();
	}
	unsigned countersInterval() {
		return vm["counters_interval"].as<unsigned>();
	}
	bool testRun() {
		return vm.count("test") > 0;
	}

    bool deltaMetricsEnabled() {
		return vm.count("incremental") > 0;
	}
    bool addHeadersToMetrics() {
		return vm.count("header") > 0;
	}
    bool noninteractiveEnabled() {
		return vm.count("noninteractive") > 0;
	}
	bool loopbackEnabled() {
		return vm.count("with_loopback") == 0;
	}
    bool eventsEnabled() {
		return vm["events"].as<unsigned>() == 1;
	}
	std::string bpfProgram() {
		return vm["program"].as<std::string>();
	}
    std::string bpfType() {
		return vm["bpf"].as<std::string>();
	}
};