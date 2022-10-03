#include "bpf_generic/src/bpf_loading.h"
#include "bpf_generic/src/bpf_wrapper.h"
#include "bpf_generic/src/errors.h"
#include "bpf_generic/src/log.h"

#include "bpf_events.h"
#include "connections_printing.h"
#include "netstat.h"
#include "offsetguess.h"
#include "proc_tcp.h"
#include "tuple_utils.h"
#include "unified_log.h"

#include <boost/program_options.hpp>
#include <fmt/core.h>

#include <chrono>
#include <condition_variable>
#include <ctime>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <signal.h>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <unordered_map>
#include <vector>

namespace po = boost::program_options;

static ExitCtrl exitCtrl;

void atexit_handler(int a) {
	exitCtrl.running = false;
	close(0);
	close(1);
	exitCtrl.cv.notify_all();
}

void setUpExitBehavior() {
	struct sigaction action{};
	action.sa_handler = atexit_handler;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGPIPE, &action, nullptr);
}

po::variables_map parseOptions(int argc, char* argv[]) {
	po::options_description desc{"Options"};
	// clang-format off
	desc.add_options()
			("clear_probes,c", "Clear all probes on start")
			("debug,d", "Enable debug logs")
			("no_stdout_log,n", "Disable logging to stdout, print metrics data in tabular format")
			("log,l", po::value<std::string>()->default_value(""), "Logger path")
			("time_interval,t", po::value<unsigned>()->default_value(30), "Time interval of printing metrics data")
			("incremental,i", "Enable incremental data")
			("noninteractive,r", "Hex output")
			("program,p", po::value<std::string>()->default_value("nettracer-bpf.o"), "BPF program path")
			("header,s", "Add average header size to traffic")
			("map_size,m", po::value<uint32_t>()->default_value(4096), "Number of entries in BPF maps")
			("test", "Check if NetTracer can start properly, then exit")
			("version,v", "Print version")
			("help,h", "Print this help screen");
	// clang-format on
	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			std::cout << desc << '\n';
			exit(0);
		}

		return vm;
	} catch (const po::error& ex) {
		std::cout << desc << '\n';
		exit(1);
	} catch (const std::exception& ex) {
		std::cout << ex.what() << '\n';
		exit(1);
	}
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

bool setUpBPFConfig(const po::variables_map& vm, bpf::bpf_subsystem& ebpf, bpf::BPFMapsWrapper& mapsWrapper) {
	int configFd{ebpf.get_map_fd("nettracer_config")};
	uint32_t zero{0};
	nettracer_config_t config{};
	(void)mapsWrapper.lookupElement(configFd, &zero, &config);

	config.log_level = areDebugLogsEnabled(vm) ? BPF_LOG_LEVEL_DEBUG : BPF_LOG_LEVEL_INFO;

	if (!mapsWrapper.updateElement(configFd, &zero, &config)) {
		LOG_ERROR("Could not set up BPF config");
		return false;
	}
	return true;
}

bpf_fds getIPv4Fds(bpf::bpf_subsystem& ebpf) {
	bpf_fds ipv4_fds{};
	ipv4_fds.pid_fd = ebpf.get_map_fd("tuplepid_ipv4");
	ipv4_fds.stats_fd = ebpf.get_map_fd("stats_ipv4");
	ipv4_fds.tcp_stats_fd = ebpf.get_map_fd("tcp_stats_ipv4");
	return ipv4_fds;
}

bpf_fds getIPv6Fds(bpf::bpf_subsystem& ebpf) {
	bpf_fds ipv6_fds{};
	ipv6_fds.pid_fd = ebpf.get_map_fd("tuplepid_ipv6");
	ipv6_fds.stats_fd = ebpf.get_map_fd("stats_ipv6");
	ipv6_fds.tcp_stats_fd = ebpf.get_map_fd("tcp_stats_ipv6");
	return ipv6_fds;
}

bool isIPv6MonitoringPossible(int status_fd, bpf::BPFMapsWrapper& mapsWrapper) {
	const uint32_t zero = 0;
	guess_status_t status;
	return mapsWrapper.lookupElement(status_fd, &zero, &status) && status.offset_daddr_ipv6 != 0;
}

enum ReturnCodes {
	Success,
	InsufficientCapabilities,
	GenericError
};

int main(int argc, char* argv[]) {
	setUpExitBehavior();

	auto vm{parseOptions(argc, argv)};

	const std::string nettracerVersionStr{fmt::format("{}.{}.{}", NETTRACER_VERSION_MAJOR, NETTRACER_VERSION_MINOR, NETTRACER_VERSION_PATCH)};
	if (vm.count("version")) {
		std::cout << "version: " << nettracerVersionStr << std::endl;
		return ReturnCodes::Success;
	}

	bool noStdoutLog{setUpLogging(vm)};
	LOG_INFO("Starting NetTracer v{}", nettracerVersionStr);

	if (!increaseMemoryLimit()) {
		return ReturnCodes::InsufficientCapabilities;
	}

	unsigned time_interval = vm["time_interval"].as<unsigned>();
	exitCtrl.wait_time = time_interval;

	bpf::bpf_subsystem ebpf;
	bpf::BPFMapsWrapper mapsWrapper;

	if (vm.count("clear_probes")) {
		ebpf.clear_all_probes();
	}

	try {
		uint32_t nn_entries = vm["map_size"].as<uint32_t>();
		if (!ebpf.load_bpf_file(vm["program"].as<std::string>(), nn_entries)) {
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

	if (!setUpBPFConfig(vm, ebpf, mapsWrapper)) {
		return ReturnCodes::InsufficientCapabilities;
	}

	int status_fd = ebpf.get_map_fd("nettracer_status");
	if (status_fd < 0) {
		LOG_ERROR("no fd for status map");
		return ReturnCodes::GenericError;
	}

	bpf_fds ipv4_fds{getIPv4Fds(ebpf)};
	if (ipv4_fds.isInvalid()){
		LOG_ERROR("invalid fds for ipv4 maps");
		return ReturnCodes::GenericError;
	}

	bpf_fds ipv6_fds{getIPv6Fds(ebpf)};
	if (ipv6_fds.isInvalid()) {
		LOG_ERROR("invalid fds for ipv6 maps");
		return ReturnCodes::GenericError;
	}

	if (vm.count("test")) {
	    LOG_INFO("All checks passed, stopping NetTracer");
	    return ReturnCodes::Success;
	}

	if (!doOffsetGuessing(status_fd)) {
		LOG_ERROR("Offset guessing failed");
		return ReturnCodes::GenericError;
	}

	bool monitorIPv6 = isIPv6MonitoringPossible(status_fd, mapsWrapper);

	netstat::NetStat netst(exitCtrl, vm.count("incremental"), vm.count("header"), vm.count("noninteractive"));
	netst.init();
    bpf_events bevents;
    
	std::function<void(const tcp_ipv4_event_t&)> ipv4_event_update;
	std::function<void(const tcp_ipv6_event_t&)> ipv6_event_update;
	std::function<void(const bpf_log_event_t&)> bpf_log_event_update;
	std::function<void()> map_reading;

	if (noStdoutLog) {
		ipv4_event_update = [&](const tcp_ipv4_event_t& evt) { netst.event<ipv4_tuple_t>(evt); };
		if (monitorIPv6) {
			ipv6_event_update = [&](const tcp_ipv6_event_t& evt) { netst.event<ipv6_tuple_t>(evt); };
		}
		map_reading = [&]() { netst.map_loop(ipv4_fds, ipv6_fds); };
	} else {
		static ConnectionsState<ipv4_tuple_t> ipv4Connections;
		static ConnectionsState<ipv6_tuple_t> ipv6Connections;
		bpf_log_event_update = [](const bpf_log_event_t& evt) { unifyBPFLog(evt); };
		ipv4_event_update = [&](const tcp_ipv4_event_t& evt) {
			updateConnectionsAfterEvent(evt, ipv4Connections);
		};
		if (monitorIPv6) {
		ipv6_event_update = [&](const tcp_ipv6_event_t& evt) {
			updateConnectionsAfterEvent(evt, ipv6Connections);
		};}
		map_reading = [&](){
			while (exitCtrl.running) {
				updateConnectionsFromMaps(ipv4Connections, ipv4_fds, mapsWrapper);
				if (monitorIPv6) {
					updateConnectionsFromMaps(ipv6Connections, ipv6_fds, mapsWrapper);
				}

				std::unique_lock<std::mutex> lk{exitCtrl.m};
				exitCtrl.cv.wait_for(lk, std::chrono::seconds(exitCtrl.wait_time), [] { return !exitCtrl.running; });
			}
		};
	}

	auto log_pmap = ebpf.get_perf_map("bpf_logs");
	if (!log_pmap.pfd.empty() && !noStdoutLog) {
		LOG_INFO("Starting BPF log events");
		bevents.add_observer({ log_pmap,bpf_log_event_update});
	}

    auto ipv4_pmap = ebpf.get_perf_map("tcp_event_ipv4");
	if (!ipv4_pmap.pfd.empty()) {
		LOG_INFO("Starting TCP IPv4 events");
		bevents.add_observer({ipv4_pmap, ipv4_event_update});
	}

	auto ipv6_pmap = ebpf.get_perf_map("tcp_event_ipv6");
	if (!ipv6_pmap.pfd.empty() && monitorIPv6) {
		LOG_INFO("Starting TCP IPv6 events");
		bevents.add_observer({ipv6_pmap, ipv6_event_update});
	}

    bevents.start();
	auto map_reader = std::thread{map_reading};

	if (map_reader.joinable()) {
		map_reader.join();
	};
    bevents.stop();
	LOG_INFO("Events stopped");

	return ReturnCodes::Success;
}
