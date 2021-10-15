#include "log.h"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include <unistd.h>
#include <vector>

namespace logging {

void setUpLogger(const std::string& logDir, bool standardout) {
	namespace fs = std::filesystem;

	std::vector<spdlog::sink_ptr> sinks;
	if(standardout){
		sinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}

	if (!logDir.empty()) {
		fs::path logPath;
		if (!fs::is_directory(logDir)) {
			spdlog::warn("{} doesn't exist or is not a directory.", logDir);
		}
		else {
			std::string logFile = fmt::format("{}/oneagent_nettracer_{:d}.log", logDir, getpid());
			sinks.emplace_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(logFile));
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
