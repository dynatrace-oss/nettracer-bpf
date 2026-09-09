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
#include "configuration.h"
#include "unified_log.h"
#include <iostream>

po::options_description Configuration::getOptionsDescription() {
	po::options_description desc{"Options"};
	// clang-format off
	desc.add_options()
			("connectivity,c", "Enable connectivity")
			("debug,d", po::value<std::string>()->default_value("info"), "Enable debug logs")
			("events,e", po::value<unsigned>()->default_value(1), "Enable events")
			("no_stdout_log,n", "Disable logging to stdout, print metrics data in tabular format")
			("log,l", po::value<std::string>()->default_value(""), "Logger path")
			("time_interval,t", po::value<unsigned>()->default_value(30), "Time interval of printing metrics data")
			("counters_interval", po::value<unsigned>()->default_value(300), "Interval (seconds) for logging BPF debug counters; 0 disables")
			("incremental,i", "Enable incremental data")
			("noninteractive,r", "Hex output")
			("with_loopback,f", "With loopback")
			("bpf,b", po::value<std::string>()->default_value("auto"), "BTF or classic")
			("program,p", po::value<std::string>()->default_value("nettracer-bpf.o"), "BPF program path")
			("header,s", "Add average header size to traffic")
			("map_size,m", po::value<uint32_t>()->default_value(4096), "Number of entries in BPF maps")
			("args_file", po::value<std::filesystem::path>(), "Arguments file")
			("test", "Check if NetTracer can start properly, then exit")
			("version,v", "Print version")
			("help,h", "Print this help screen");
	return desc;
}

std::filesystem::path Configuration::parseOptions(int argc, char* argv[]) {
	po::options_description desc{getOptionsDescription()};
	// clang-format on
	//po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			std::cout << desc << '\n';
			exit(0);
		}

		if (vm.count("args_file")) {
			auto fname = vm["args_file"].as<std::filesystem::path>();
            vm = parseArgsFile(fname);
			return fname;
		}

		return {};
	} catch (const po::invalid_syntax& ex) {
		if (ex.kind() == po::invalid_syntax::unrecognized_line) {
			LOG_WARN("the options configuration file contains an invalid line");
		} else {
			LOG_WARN("{} running without args_file", ex.what());
		}
		LOG_WARN("{}", (std::stringstream{} << desc).str());
		exit(1);
	} catch (const po::error& ex) {
		std::cout << ex.what() << '\n';
		std::cout << desc << '\n';
		exit(1);
	} catch (const std::exception& ex) {
		std::cout << ex.what() << '\n';
		exit(1);
	}
}

po::variables_map Configuration::parseArgsFile(const std::filesystem::path& argsFilePath) {
	if (argsFilePath.empty()) {
		LOG_INFO("args_file provided but empty");
		return {};
	}
	if (::access(argsFilePath.c_str(), R_OK) != 0) {
		std::error_code errCode(errno, std::generic_category());
		throw std::filesystem::filesystem_error("File access permissions validation failed", argsFilePath, errCode);
	}
	po::variables_map vm;
	po::options_description desc{getOptionsDescription()};
	po::store(po::parse_config_file<char>(argsFilePath.c_str(), desc), vm);
	po::notify(vm);
	return vm;
}

bool Configuration::setupLogger(){
	noStdoutLog = setUpLogging(vm);
	return noStdoutLog;
}

uint32_t Configuration::getMapsSize() {
	mapsSize = vm["map_size"].as<uint32_t>();
	const int MAX_MAP_SIZE = 1024 * 1024;
	if (mapsSize > MAX_MAP_SIZE) {
		LOG_INFO("map_size too large: {}, using maximum value allowed: {}", mapsSize, MAX_MAP_SIZE);
		mapsSize = MAX_MAP_SIZE;
	}
	return mapsSize;
}