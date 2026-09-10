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
#include "bpf_generic/src/bpf_interface.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/errors.h"
#include "bpf_generic/src/log.h"

#include "bpf_debug_counters.h"
#include "bpf_events.h"
#include "configuration.h"
#include "config_watcher.h"
#include "event_mode.h"
#include "netstat.h"
#include "offsetguess.h"
#include "proc_tcp.h"
#include "system_utils.h"
#include "tuple_utils.h"

#include <fmt/core.h>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <filesystem>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <signal.h>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>



 config::ExitCtrl exitCtrl;

void atexit_handler(int a) {
	exitCtrl.running = false;
	close(0);
	close(1);
	exitCtrl.cv.notify_all();
}

void setUpExitBehavior() {
	struct sigaction action {};
	action.sa_handler = atexit_handler;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGPIPE, &action, nullptr);
}


bool increaseMemoryLimit() {
	// increase limit of lockable RAM to allow creation of userspace-mapped BPF maps
	rlimit r{RLIM_INFINITY, RLIM_INFINITY};
	int ret{setrlimit(RLIMIT_MEMLOCK, &r)};
	if (ret) {
		LOG_ERROR("setrlimit failed: {:d}", ret);
		return false;
	}
	return true;
}

unsigned resolveNumPossibleCpus() {
	if (auto detected = getNumPossibleCpus(SystemCalls::getInstance())) {
		return detected.value();
	}
	const unsigned hardwareConcurrency{std::thread::hardware_concurrency()};
	const unsigned fallback{hardwareConcurrency > 0 ? hardwareConcurrency : 1u};
	LOG_WARN("Could not read /sys/devices/system/cpu/possible, falling back to {}", fallback);
	return fallback;
}

void runDebugCountersLoop(int mapFd, unsigned numPossibleCpus, unsigned intervalSeconds, const bpf::BPFMapsWrapper& mapsWrapper) {
	nettracer::BpfDebugCountersReader reader{mapFd, numPossibleCpus, mapsWrapper};
	nettracer::BpfDebugCounters previousCounters{};
	const auto period = std::chrono::seconds(intervalSeconds);
	while (true) {
		std::unique_lock<std::mutex> lk{exitCtrl.m};
		if (exitCtrl.cv.wait_for(lk, period, [] { return !exitCtrl.running; })) {
			break;
		}
		lk.unlock();
		auto currentCounters = reader.readAndAggregate();
		if (!currentCounters) {
			LOG_WARN("[bpf_debug_counters] lookup failed, skipping interval");
			continue;
		}
		const auto cumulativeStr = nettracer::formatNonZeroFields(*currentCounters);
		const auto deltaStr = nettracer::formatNonZeroFields(nettracer::subtractBpfDebugCounters(*currentCounters, previousCounters));
		if (!deltaStr.empty()) {
			LOG_INFO("[bpf_debug_counters] delta:      {}", deltaStr);
		}
		previousCounters = *currentCounters;
	}
}

std::thread startDebugCountersThread(bpf::Ibpf* ebpf, const bpf::BPFMapsWrapper& mapsWrapper, unsigned intervalSeconds) {
	if (intervalSeconds == 0) {
		return {};
	}
	const int mapFd{ebpf->get_map_fd("bpf_debug_counters")};
	if (mapFd < 0) {
		LOG_WARN("bpf_debug_counters map not available, skipping debug counters logging");
		return {};
	}
	const unsigned numPossibleCpus{resolveNumPossibleCpus()};
	LOG_INFO("Starting BPF debug counters logger (interval={}s, cpus={})", intervalSeconds, numPossibleCpus);
	return std::thread{runDebugCountersLoop, mapFd, numPossibleCpus, intervalSeconds, std::cref(mapsWrapper)};
}

ReturnCodes startNetTracer(config_watcher& cw, config::Configuration& config) {
	const std::string nettracerVersionStr{
			fmt::format("{}.{}.{}", NETTRACER_VERSION_MAJOR, NETTRACER_VERSION_MINOR, NETTRACER_VERSION_PATCH)};
	if (config.printVersion()) {
		std::cout << "version: " << nettracerVersionStr << std::endl;
		return ReturnCodes::Success;
	}

	bool eventsOnly = config.logEventsOnly();
	LOG_INFO("Starting NetTracer v{}", nettracerVersionStr);
	if (!increaseMemoryLimit()) {
		return ReturnCodes::InsufficientCapabilities;
	}

	unsigned time_interval = config.mainLoopTimeInterval();
	LOG_INFO("time_interval: {}", time_interval);
	exitCtrl.wait_time = time_interval;

	auto kernelVersion{getKernelVersion(SystemCalls::getInstance())};
	if (!kernelVersion.has_value()) {
		LOG_ERROR("Could not obtain current kernel version");
		return ReturnCodes::GenericError;
	}
	LOG_DEBUG("Detected kernel {}", kernelVersionToString(*kernelVersion));

	auto ebpf = createBPFinterface(*kernelVersion, config.bpfType(), SystemCalls::getInstance());
	if (!ebpf) {
		LOG_ERROR("Unsuported option for bpf");
		return ReturnCodes::GenericError;
	}
	bpf::BPFMapsWrapper mapsWrapper;

	netstat::NetStat netst(
			exitCtrl, config.deltaMetricsEnabled(), config.addHeadersToMetrics(), config.noninteractiveEnabled(), config.loopbackEnabled());

	try {
		uint32_t nn_entries = config.getMapsSize();
		LOG_INFO("map_size: {}", nn_entries);
		netst.set_max_map_size(nn_entries);
		if (!ebpf->load_bpf(config.bpfProgram(), nn_entries, *kernelVersion, config.connectivityEnabled())) {
			return ReturnCodes::GenericError;
		}
	} catch (const InsufficientCapabilitiesError& e) {
		LOG_ERROR(e.what());
		return ReturnCodes::InsufficientCapabilities;
	} catch (const std::exception& e) {
		LOG_ERROR(e.what());
		return ReturnCodes::GenericError;
	}
	LOG_INFO("BPF program loaded");

	bpf::bpf_fds ipv4_fds{getIPv4Fds(*ebpf)};
	if (ipv4_fds.isInvalid()) {
		LOG_ERROR("invalid fds for ipv4 maps");
		return ReturnCodes::GenericError;
	}

	bpf::bpf_fds ipv6_fds{getIPv6Fds(*ebpf)};
	if (ipv6_fds.isInvalid()) {
		LOG_ERROR("invalid fds for ipv6 maps");
		return ReturnCodes::GenericError;
	}

	if (config.testRun()) {
		LOG_INFO("All checks passed, stopping NetTracer");
		return ReturnCodes::Success;
	}

	bool monitorIPv6 = true;
	if (ebpf->needs_offset_guessing()) {
		LOG_INFO("Offset guessing...");
		auto status_fd = ebpf->get_map_fd("nettracer_status");
		if (status_fd < 0) {
			LOG_ERROR("no fd for status map");
			return ReturnCodes::GenericError;
		}
		if (!doOffsetGuessing(status_fd)) {
			LOG_ERROR("Offset guessing failed");
			return ReturnCodes::GenericError;
		}
		monitorIPv6 = bpf::isIPv6MonitoringPossible(status_fd, mapsWrapper);
		LOG_INFO(fmt::format("Offset guessing finished: ipv6:{}", monitorIPv6));
	}

	netst.init();
	bpf_events bevents(cw, ebpf->needs_offset_guessing());
	bevents.set_kbhit_observer(std::bind(&netstat::NetStat::set_kbhit, &netst));

	std::function<void(const tcp_ipv4_event_t&)> ipv4_event_update;
	std::function<void(const tcp_ipv6_event_t&)> ipv6_event_update;
	std::function<void(std::promise<bool>&&)> map_reading;

	if (eventsOnly) {
		ipv4_event_update = [&](const tcp_ipv4_event_t& evt) { netst.event<ipv4_tuple_t>(evt); };
		if (monitorIPv6) {
			ipv6_event_update = [&](const tcp_ipv6_event_t& evt) { netst.event<ipv6_tuple_t>(evt); };
		}
		bevents.set_config_change_observer(std::bind(&netstat::NetStat::on_config_change, &netst));
		map_reading = [&](std::promise<bool>&& promise) {
			auto ret = netst.map_loop(ipv4_fds, ipv6_fds);
			promise.set_value(ret);
		};
	} else {
		LOG_INFO("Only TCP events are output");
		ipv4_event_update = [](const tcp_ipv4_event_t& evt) { processEvent(evt); };
		if (monitorIPv6) {
			ipv6_event_update = [](const tcp_ipv6_event_t& evt) { processEvent(evt); };
		}
		map_reading = [&](std::promise<bool>&& promise) {
			while (exitCtrl.running) {
				cw.on_pollin();
				if (cw.is_config_changed()) {
					break;
				}

				ignoreConnectionsFromMaps<ipv4_tuple_t>(ipv4_fds, mapsWrapper);
				if (monitorIPv6) {
					ignoreConnectionsFromMaps<ipv6_tuple_t>(ipv6_fds, mapsWrapper);
				}

				std::unique_lock<std::mutex> lk{exitCtrl.m};
				exitCtrl.cv.wait_for(lk, std::chrono::seconds(exitCtrl.wait_time), [] { return !exitCtrl.running; });
			}

			promise.set_value(exitCtrl.running);
		};
	}

	const bool eventsEnabled = config.eventsEnabled();
	auto ipv4_pmap = ebpf->get_perf_map("tcp_event_ipv4");
	if (eventsEnabled) {
		LOG_INFO("Starting TCP IPv4 events");
		bevents.add_observer<tcp_ipv4_event_t>(ipv4_pmap, ipv4_event_update);

		auto ipv6_pmap = ebpf->get_perf_map("tcp_event_ipv6");
		if (monitorIPv6) {
			LOG_INFO("Starting TCP IPv6 events");
			bevents.add_observer<tcp_ipv6_event_t>(ipv6_pmap, ipv6_event_update);
		}
	}
	const unsigned debugCountersInterval{config.countersInterval()};
	std::thread debugCountersThread{startDebugCountersThread(ebpf.get(), mapsWrapper, debugCountersInterval)};

	bevents.start();
	std::promise<bool> map_reader_promise;
	auto map_reader_future = map_reader_promise.get_future();
	auto map_reader = std::thread{map_reading, std::move(map_reader_promise)};

	if (map_reader.joinable()) {
		map_reader.join();
	}
	if (debugCountersThread.joinable()) {
		debugCountersThread.join();
	}
    bevents.stop();
	LOG_INFO("Events stopped");

	return map_reader_future.get() ? ReturnCodes::Reconfigure : ReturnCodes::Success;
}

int main(int argc, char* argv[]) {
	setUpExitBehavior();
	ReturnCodes rc;
	config_watcher cw{};
	config::Configuration config;
	do {
		auto argsFilePath{config.parseOptions(argc, argv)};
		if (!cw) {
			cw.init(argsFilePath);
		}
		cw.reset();
		rc = startNetTracer(cw, config);
		LOG_INFO("NetTracer stop reason {}", std::underlying_type_t<ReturnCodes>(rc));
	} while (rc == ReturnCodes::Reconfigure);
	return rc;
}
