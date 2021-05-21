#pragma once

// Used for redirecting logs so that they can be easily checked in unit tests

#include "bpf_generic/log.h"
#include <fmt/core.h>
#include <spdlog/sinks/ringbuffer_sink.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

template<size_t maxLogs = 100>
class LogsRedirector {
public:
	LogsRedirector() {
		reset();
	}

	~LogsRedirector() {
		spdlog::default_logger()->sinks().clear();
	}

	std::vector<std::string> getNLastLogs(size_t n) {
		if (n > maxLogs) {
			throw std::out_of_range{fmt::format("{:d} logs requested but only {:d} potentially available with the current settings", n, maxLogs)};
		}

		auto logs{logsBuffer->last_formatted(n)};
		if (n > logs.size()) {
			throw std::out_of_range{fmt::format("{:d} log(s) requested but only {:d} currently available", n, logs.size())};
		}
		return logs;
	}

	std::string getLastLog() {
		return getNLastLogs(1)[0];
	}

	void reset() {
		logsBuffer = std::make_shared<RingBuffer>(maxLogs);
		spdlog::default_logger()->sinks() = std::vector<spdlog::sink_ptr>{logsBuffer};
	}

private:
	using RingBuffer = spdlog::sinks::ringbuffer_sink_st;

	std::shared_ptr<RingBuffer> logsBuffer;
};
