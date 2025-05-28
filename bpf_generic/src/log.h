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
#pragma once

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include <spdlog/spdlog.h>
#include <filesystem>
#include <memory>
#include <string>

namespace logging {

inline const std::string LOGGER_NAME = "nettracer";

inline std::shared_ptr<spdlog::logger> getLogger() {
	return spdlog::get(LOGGER_NAME);
}

void setUpLogger(const std::filesystem::path logDir, bool logToStdout);

} // namespace logging

#define LOG_TRACE(...)		SPDLOG_TRACE(__VA_ARGS__)
#define LOG_DEBUG(...)		SPDLOG_DEBUG(__VA_ARGS__)
#define LOG_INFO(...)		SPDLOG_INFO(__VA_ARGS__)
#define LOG_WARN(...)		SPDLOG_WARN(__VA_ARGS__)
#define LOG_ERROR(...)		SPDLOG_ERROR(__VA_ARGS__)
#define LOG_CRITICAL(...) 	SPDLOG_CRITICAL(__VA_ARGS__)
