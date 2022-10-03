#pragma once

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include <spdlog/spdlog.h>
#include <memory>
#include <string>

namespace logging {

inline const std::string LOGGER_NAME = "nettracer";

inline std::shared_ptr<spdlog::logger> getLogger() {
	return spdlog::get(LOGGER_NAME);
}

void setUpLogger(const std::string& logDir, bool logToStdout);

} // namespace logging

#define LOG_TRACE(...)		SPDLOG_TRACE(__VA_ARGS__)
#define LOG_DEBUG(...)		SPDLOG_DEBUG(__VA_ARGS__)
#define LOG_INFO(...)		SPDLOG_INFO(__VA_ARGS__)
#define LOG_WARN(...)		SPDLOG_WARN(__VA_ARGS__)
#define LOG_ERROR(...)		SPDLOG_ERROR(__VA_ARGS__)
#define LOG_CRITICAL(...) 	SPDLOG_CRITICAL(__VA_ARGS__)
