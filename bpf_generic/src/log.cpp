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
#include "log.h"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace logging {

constexpr std::size_t max_size = 10 * 1024 * 1024;
constexpr std::size_t max_files = 3;

namespace fs = std::filesystem;

void setUpLogger(const fs::path logDir, bool logToStdout) {
	std::vector<spdlog::sink_ptr> sinks;

	if (logToStdout){
		sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}

	if (!logDir.empty()) {
		std::error_code ec;
		bool dirExists = fs::exists(logDir, ec);
		if (!dirExists || ec || !fs::is_directory(logDir)) {
			exit(5);
		} else {
			auto  logFile = logDir / fmt::format("oneagent_nettracer_{:d}.log", getpid());
			sinks.emplace_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logFile.string(), max_size, max_files));
		}
	}

	auto logger{ std::make_shared<spdlog::logger>(LOGGER_NAME, sinks.begin(), sinks.end()) };
	logger->set_level(spdlog::level::info);
	logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%t] %^%l%$ [%n] %v");

	spdlog::drop(LOGGER_NAME);
	spdlog::register_logger(logger);
	spdlog::set_default_logger(logger);
}

} // namespace logging
