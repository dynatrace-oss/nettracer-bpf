#include "bpf_generic/bpf_loading.h"
#include "bpf_generic/bpf_wrapper.h"
#include "bpf_generic/log.h"
#include "bpf_generic/perf_event.h"
#include "proc_tcp.h"
#include "connections_printing.h"
#include "netstat.h"
#include "offsetguess.h"
#include "tuple_utils.h"
#include "unified_log.h"

#include <boost/program_options.hpp>

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
	exitCtrl.cv.notify_all();
}

void setUpExitBehavior() {
	struct sigaction action{};
	action.sa_handler = atexit_handler;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
}

po::variables_map parseOptions(int argc, char* argv[]) {
	po::options_description desc{"Options"};
	desc.add_options()("help,h", "Help screen")("clear_probes,c", "Clear all probes")("debug,d", "Debug logs")(
			"no_stdout_log,n", "Log only to file")("time_interval,t", po::value<unsigned>()->default_value(30), "Time interval")(
			"log,l", po::value<std::string>()->default_value("./log"), "Logger path")("incremental,i", "Inceremental data")(
			"program,p", po::value<std::string>()->default_value("nettracer-bpf.o"), "BPF program path")("header,s", "Add header size")(
			"version,v", "")("map_size,m", po::value<uint32_t>()->default_value(2048), "Number of entries BPF maps");
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

int main(int argc, char* argv[]) {
	setUpExitBehavior();

	auto vm{parseOptions(argc, argv)};

	if (vm.count("version")) {
		std::cout<<"version: "<< NETTRACER_VERSION_MAJOR << "." << NETTRACER_VERSION_MINOR << "." << NETTRACER_VERSION_PATCH << std::endl;
		return 0;
	}

	bool stdoutlog{setUpLogging(vm)};

	if (!increaseMemoryLimit()) {
		return 1;
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
		ebpf.load_bpf_file(vm["program"].as<std::string>(), nn_entries);
	} catch (std::exception& e) {
		LOG_ERROR(e.what());
		return 1;
	}
	LOG_INFO("BPF program loaded");

	if (!setUpBPFConfig(vm, ebpf, mapsWrapper)) {
		return 1;
	}

	int status_fd = ebpf.get_map_fd("nettracer_status");
	if (status_fd < 0) {
		LOG_ERROR("no fd for status map");
		return 1;
	}

	bpf_fds ipv4_fds{getIPv4Fds(ebpf)};
	if (ipv4_fds.isInvalid()){
		LOG_ERROR("invalid fds for ipv4 maps");
		return 1;
	}

	bpf_fds ipv6_fds{getIPv6Fds(ebpf)};
	if (ipv6_fds.isInvalid()) {
		LOG_ERROR("invalid fds for ipv6 maps");
		return 1;
	}

	guess(status_fd);

	netstat::NetStat netst{exitCtrl, vm.count("incremental"), vm.count("header")};
	netst.init();
	ConnectionsState<ipv4_tuple_t> ipv4Connections;
	ConnectionsState<ipv6_tuple_t> ipv6Connections;

	std::function<void(const tcp_ipv4_event_t&)> ipv4_event_update;
	std::function<void(const tcp_ipv6_event_t&)> ipv6_event_update;
	std::function<void(const bpf_log_event_t&)> bpf_log_event_update;
	std::function<void()> map_reading;
	if (stdoutlog) {
		ipv4_event_update = [&](const tcp_ipv4_event_t& evt) { netst.event<ipv4_tuple_t>(evt); };
		ipv6_event_update = [&](const tcp_ipv6_event_t& evt) { netst.event<ipv6_tuple_t>(evt); };
		map_reading = [&]() { netst.map_loop(ipv4_fds, ipv6_fds); };
	} else {
		bpf_log_event_update = [](const bpf_log_event_t& evt) { unifyBPFLog(evt); };
		ipv4_event_update = [&](const tcp_ipv4_event_t& evt) {
			std::string etype = name_of_evt[evt.type];
			LOG_INFO("event {} {}", etype, to_string(evt));
			updateConnectionsAfterEvent(evt, ipv4Connections);
		};
		ipv6_event_update = [&](const tcp_ipv6_event_t& evt) {
			std::string etype = name_of_evt[evt.type];
			LOG_INFO("event {} {}", etype, to_string(evt));
			updateConnectionsAfterEvent(evt, ipv6Connections);
		};
		map_reading = [&](){
			while (exitCtrl.running) {
				updateConnectionsFromMaps(ipv4Connections, ipv4_fds, mapsWrapper);
				updateConnectionsFromMaps(ipv6Connections, ipv6_fds, mapsWrapper);

				std::unique_lock<std::mutex> lk{exitCtrl.m};
				exitCtrl.cv.wait_for(lk, std::chrono::seconds(exitCtrl.wait_time), [] { return !exitCtrl.running; });
			}
		};
	}

	auto log_pmap = ebpf.get_perf_map("bpf_logs");
	event_reader log_evnts;
	if (!log_pmap.pfd.empty() && !stdoutlog) {
		LOG_INFO("Starting BPF log events");
		log_evnts.start<bpf_log_event_t>(log_pmap, bpf_log_event_update);
	}

	auto ipv4_pmap = ebpf.get_perf_map("tcp_event_ipv4");
	event_reader ipv4_evnts;
	if (!ipv4_pmap.pfd.empty()) {
		LOG_INFO("Starting TCP IPv4 events");
		ipv4_evnts.start<tcp_ipv4_event_t>(ipv4_pmap, ipv4_event_update);
	}

	auto ipv6_pmap = ebpf.get_perf_map("tcp_event_ipv6");
	event_reader ipv6_evnts;
	if (!ipv6_pmap.pfd.empty()) {
		LOG_INFO("Starting TCP IPv6 events");
		ipv6_evnts.start<tcp_ipv6_event_t>(ipv6_pmap, ipv6_event_update);
	}

	std::this_thread::sleep_for(std::chrono::milliseconds(1));

	auto map_reader = std::thread{map_reading};

	if (map_reader.joinable()) {
		map_reader.join();
	};
	ipv4_evnts.stop();
	ipv6_evnts.stop();
	log_evnts.stop();

	LOG_INFO("Events stopped");

	return 0;
}
