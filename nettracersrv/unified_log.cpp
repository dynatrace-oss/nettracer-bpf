#include "unified_log.h"
#include <filesystem>
#include <string>
#include <utility>

bool setUpLogging(const boost::program_options::variables_map& vm) {
	std::string logger_path = vm["log"].as<std::string>();
	bool noStdoutLog = vm.count("no_stdout_log");
	bool noFileLog =  logger_path.empty();

	if (!noFileLog) {
		std::filesystem::create_directory(logger_path);
	}
	logging::setUpLogger(logger_path, !noStdoutLog);
	if (areDebugLogsEnabled(vm)) {
		logging::getLogger()->set_level(spdlog::level::debug);
	}

	return noStdoutLog;
}

spdlog::level::level_enum bpfLogLevelToSpdlogLevel(const bpf_log_level& level) {
	using namespace spdlog::level;
	switch (level) {
		case BPF_LOG_LEVEL_TRACE:
			return trace;
		case BPF_LOG_LEVEL_DEBUG:
			return debug;
		case BPF_LOG_LEVEL_INFO:
			return info;
		case BPF_LOG_LEVEL_WARN:
			return warn;
		case BPF_LOG_LEVEL_ERROR:
			return err;
		case BPF_LOG_LEVEL_CRITICAL:
			return critical;
		case BPF_LOG_LEVEL_OFF:
			return off;
	}
	return off;
}

void unifyBPFLog(const bpf_log_event_t& evt) {
	spdlog::level::level_enum level{bpfLogLevelToSpdlogLevel(evt.severity)};
	// some of the message content args may be empty but that's alright, they won't be used then
	std::string messageContent{fmt::format(evt.format, evt.args[0], evt.args[1], evt.args[2], evt.args[3], evt.args[4], evt.args[5], evt.args[6], evt.args[7], evt.args[8], evt.args[9])};
	std::string message{fmt::format("[BPF][{:d}][{:d}][{:d}] {}", evt.timestamp, evt.cpu, evt.pid, messageContent)};
	logging::getLogger()->log(level, message);
}
