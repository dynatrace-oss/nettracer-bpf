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
#include "unified_log.h"
#include <filesystem>
#include <string>
#include <utility>

spdlog::level::level_enum loglevelFromConfig(const boost::program_options::variables_map& vm) {
	std::string level = vm["debug"].as<std::string>();
	if (level == "debug") {
		return spdlog::level::debug;
	} else if (level == "trace") {
		return spdlog::level::trace;
	} else {
		return spdlog::level::info;
	}
}

static void validate_log_path(const std::filesystem::path& path) {
	const auto target_path = path.empty() ? std::filesystem::path(".") : path;
	std::error_code ec;
	const auto status = std::filesystem::status(target_path, ec);
	if (ec) {
		throw std::filesystem::filesystem_error("Failed to stat parent log directory", target_path, ec);
	}

	if (!std::filesystem::is_directory(status)) {
		throw std::filesystem::filesystem_error(
				"Log directory does not exist or is not a directory", target_path, std::make_error_code(std::errc::not_a_directory));
	}

	if (access(target_path.c_str(), W_OK) != 0) {
		std::error_code access_ec(errno, std::generic_category());
		throw std::filesystem::filesystem_error("Log directory access permissions validation failed", target_path, access_ec);
	}
}

bool setUpLogging(const boost::program_options::variables_map& vm) {
	std::string logger_path = vm["log"].as<std::string>();
	bool noStdoutLog = vm.count("no_stdout_log");
	bool noFileLog =  logger_path.empty();

	if (!noFileLog) {
		validate_log_path(logger_path);
	}

	logging::setUpLogger(logger_path, !noStdoutLog);
	auto level = loglevelFromConfig(vm);
	logging::getLogger()->set_level(level);


	return noStdoutLog;
}

