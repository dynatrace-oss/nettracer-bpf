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
#include "bpf_loading.h"

#include "bpf_wrapper.h"
#include "errors.h"
#include "kernel_version.h"
#include "maps_loading.h"
#include "perf_sys.h"

#include <fmt/core.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <vector>
#include <llvm/ADT/StringRef.h>
#include "log.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

namespace bpf {

namespace {

constexpr auto KPROBE_NAME_PREFIX = "nt_";

class file_fd {
public:
	int fd;
	file_fd(const std::string& path) {
		fd = open(path.c_str(), O_RDONLY, 0);
		if (fd < 0)
			throw std::runtime_error{"cannot open bpf program file: " + path};
	}
	~file_fd() {
		close(fd);
	}
};

bool initialize_perf_maps(maps_config& pmaps, BPFMapsWrapper& mapsWrapper) {
	bool all_success = true;
	int page_size = getpagesize();
	constexpr int any_pid = -1;
	constexpr int any_group_fd = -1;

	for (auto& pmap : pmaps) {
		pmap.page_count = 8;
		const int pc = get_nprocs();

		if (pmap.def.type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
			continue;

		for (int cpuC = 0; cpuC < pc; ++cpuC) {
			int pfd = perf_event_open_map(any_pid, cpuC, any_group_fd, PERF_FLAG_FD_CLOEXEC);
			if (pfd < 0) {
				std::string msg{fmt::format("perf_event_open_map for pfd {:d} failed: {} ({:d})", pfd, strerror(errno), errno)};
				if (errno == EACCES || errno == EPERM) {
					throw InsufficientCapabilitiesError{msg};
				} else {
					LOG_ERROR(msg);
					all_success = false;
					continue;
				}
			}

			int mmap_size = page_size * (pmap.page_count + 1);

			void* mem = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
			if ((*(int*)mem) == -1) {
				int err = *(int*)mem;
				LOG_ERROR("mmap error: {:d}", err);
				all_success = false;
				continue;
			}

			if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
				LOG_ERROR("ioctlk error");
			}
			if (!mapsWrapper.updateElement(pmap.fd, &cpuC, &pfd)) {
				LOG_ERROR("failed to set perf map with fd: {:d}, errno: {:d} ({})", pmap.fd, errno, strerror(errno));
				all_success = false;
				continue;
			}

			pmap.pfd.push_back(pfd);
			pmap.header.push_back((perf_event_mmap_page*)mem);
		}
	}
	return all_success;
}

int config_tracepoint(int fd, int kprobeId) {
	int efd = perf_event_open_tracepoint(kprobeId, -1 /*pid*/, 0 /*cpu*/, -1 /*group_fd*/, 0);
	if (efd < 0) {
		LOG_ERROR("event {:d} fd {:d} err {}", kprobeId, efd, strerror(errno));
		return efd;
	}
	int err = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	if (err < 0) {
		LOG_ERROR("ioctl PERF_EVENT_IOC_ENABLE failed err {}", strerror(errno));
		return err;
	}
	err = ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);
	if (err < 0) {
		LOG_ERROR("ioctl PERF_EVENT_IOC_SET_BPF failed err {}", strerror(errno));
		return err;
	}

	return efd;
}

} // namespace

int bpf_subsystem::get_map_fd(const std::string& id) {
	auto it = std::find_if(maps.begin(), maps.end(), [&](const auto& it) { return it.name == id; });
	if (it != maps.end())
		return it->fd;
	else
		return -1;
}

map_data bpf_subsystem::get_perf_map(const std::string& name) {
	auto it = std::find_if(maps.begin(), maps.end(), [&](const auto& it) { return it.name == name; });
	if (it != maps.end())
		return *it;
	else
		return {};
}

int bpf_subsystem::uninstall_kprobe_fs(const std::string& cmd) {
	int flags;
	if (!cmd.empty()) {
		flags = O_WRONLY | O_APPEND;
	} else {
		flags = O_WRONLY | O_TRUNC;
	}

	int fd = open(DEBUGFS "kprobe_events", flags, 0);
	int ret = write(fd, cmd.c_str(), cmd.size());

	close(fd);
	return ret;
}

int bpf_subsystem::install_kprobe_fs(const std::string& prefix, const std::string& name, bool isKprobe, int fd) {
	std::string formatted{fmt::format("{0}:{1}{2} {2}", isKprobe ? 'p' : 'r', prefix, name)};
	int fdke = open(DEBUGFS "kprobe_events", O_WRONLY | O_APPEND);
	int ret = write(fdke, formatted.c_str(), formatted.size());
	close(fdke);
	std::string event_file = std::string(DEBUGFS) + "events/kprobes/" + prefix + name + "/id";
	std::ifstream ifs(event_file, std::ifstream::in);
	if (!ifs) {
		LOG_ERROR("failed to open event {}", name);
		return -1;
	}

	int kprobeId = 0;
	ifs >> kprobeId;
	// LOG_INFO("kprobeId {:d}", kprobeId);
	ret = config_tracepoint(fd, kprobeId);
	return ret;
}

bool bpf_subsystem::load_and_attach(kprobe& probe, const char* license, int kernVersion) {
	auto nameSepPos{probe.fname.find("/")};
	if (nameSepPos == std::string::npos) {
		LOG_ERROR("Invalid event name: " + probe.fname);
		return false;
	}
	std::string_view type{probe.fname.c_str(), nameSepPos};
	std::string_view name{probe.fname.c_str() + nameSepPos + 1};

	bool isKprobe{type == "kprobe"};
	bool isKretprobe{type == "kretprobe"};

	if (!isKprobe && !isKretprobe) {
		LOG_ERROR("Unknown event " + probe.fname);
		return false;
	}

	int insns_cnt = probe.size / sizeof(bpf_insn);
	probe.fd = bpf::loadProgram(BPF_PROG_TYPE_KPROBE, probe.insn, insns_cnt, license, debug_print, kernVersion, sysCallBPF);
	if (probe.fd < 0) {
		LOG_ERROR(fmt::format("loadProgram() failed for {} with error: {:d} ({}), logs: {}", probe.fname, errno, strerror(errno), getLogBuffer()));
		return false;
	}

	std::string name_prefix;
	if (isKretprobe) {
		name_prefix = "ret_";
	}
	name_prefix += KPROBE_NAME_PREFIX;

	if (name.empty()) {
		LOG_ERROR("Event name cannot be empty");
		return false;
	}

	probe.efd = install_kprobe_fs(name_prefix, std::string{name}, isKprobe, probe.fd);
	if (probe.efd < 0) {
		LOG_ERROR({fmt::format("Cannot write probe {}: {:d} ({})", name, errno, strerror(errno))});
		return false;
	}

	probes.push_back(probe);
	return true;
}

void bpf_subsystem::load_programs_from_sections(const BpfPrograms& bpfPrograms, int kernVersion) {
	bool allFailed = true;
    for (const auto& [name, program]: bpfPrograms) {
		LOG_DEBUG("loading {} {}", name, program.size());
		kprobe probe{.fname = name, .insn = (bpf_insn*)program.data(), .size = program.size(), .fd = -1, .efd = -1};
		allFailed &= !load_and_attach(probe, "GPL", kernVersion);
	}

	if(allFailed){
		throw InsufficientCapabilitiesError{"Failed to load all probes"};
	}
}

void bpf_subsystem::set_maps_max_entries(uint32_t map_max_entries) {
	for (auto& m : maps) {
		if (m.def.max_entries == 1024) { // only change size of maps with traffic data, not logs or configuration
			m.def.max_entries = map_max_entries;
		}
	}
}

bpf_subsystem::bpf_subsystem(const ISystemCalls& sysCalls)
	: sysCalls(sysCalls) {}

bool bpf_subsystem::load_bpf_file(const std::string& path, uint32_t map_max_entries) {

	MapsSectionLoader sectionloader(path);
	maps = sectionloader.load();
	BPFMapsWrapper mapsWrapper;
	set_maps_max_entries(map_max_entries);
	if (!loadMaps(maps, mapsWrapper)) {
		LOG_ERROR("Cannot load BPF maps");
		return false;
	}

	if (!initialize_perf_maps(maps, mapsWrapper)) {
		LOG_ERROR("Cannot initialize perf maps");
		return false;
	}

	if (!sectionloader.processReloSections(maps)) {
		LOG_ERROR("Processing relocations failed");
		return false;
	}

	auto kernelVersion{getKernelVersion(sysCalls)};
	if (!kernelVersion) {
		throw std::runtime_error{"Could not obtain current kernel version"};
	}
	if (!isKernelSupported(*kernelVersion)) {
		LOG_ERROR("Kernel version {} is not supported", kernelVersionToString(*kernelVersion));
		// don't return, see what happens
	}

	load_programs_from_sections(sectionloader.getBpfPrograms(), *kernelVersion);
	return true;
}

void bpf_subsystem::close_all_probes() {
	for (auto probe = probes.rbegin(); probe != probes.rend(); probe++) {
		if (probe->efd != -1)
			close(probe->efd);

		if (probe->fd != -1)
			close(probe->fd);

		std::string name = probe->fname;
		auto p = name.find_first_of("/");
		if (p != std::string::npos) {
			std::string cmd("-:");
			std::string type = name.substr(0, p);
			if (type == "kretprobe")
				cmd += std::string("ret_") + KPROBE_NAME_PREFIX + name.substr(p + 1) + "\n";
			else if (type == "kprobe")
				cmd += KPROBE_NAME_PREFIX + name.substr(p + 1) + "\n";

			if (!cmd.empty()) {
				uninstall_kprobe_fs(cmd);
			}
		}
	}
	probes.clear();
}

void bpf_subsystem::close_all_maps() {
	for (const auto& m : maps) {
		for (auto fd : m.pfd) {
			close(fd);
		}

		close(m.fd);
	}
	maps.clear();
}

bpf_subsystem::~bpf_subsystem() {
	close_all_maps();
	close_all_probes();
}

void bpf_subsystem::clear_all_probes() {
	uninstall_kprobe_fs("");
}

} // namespace bpf
