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

// Used for redirecting logs so that they can be easily checked in unit tests

#include "bpf_generic/src/log.h"
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
