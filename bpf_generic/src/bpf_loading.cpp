#include "bpf_loading.h"

#include "bpf_wrapper.h"
#include "elf_utils.h"
#include "errors.h"
#include "kernel_version.h"
#include "log.h"
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
#include <gelf.h>
#include <libelf.h>
#include <stdexcept>
#include <string_view>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <vector>

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

void bpf_subsystem::load_and_attach(kprobe& probe, const char* license, int kernVersion) {
	auto nameSepPos{probe.fname.find("/")};
	if (nameSepPos == std::string::npos) {
		throw std::runtime_error{"Invalid event name: " + probe.fname};
	}
	std::string_view type{probe.fname.c_str(), nameSepPos};
	std::string_view name{probe.fname.c_str() + nameSepPos + 1};

	bool isKprobe{type == "kprobe"};
	bool isKretprobe{type == "kretprobe"};

	if (!isKprobe && !isKretprobe) {
		throw std::runtime_error{"Unknown event " + probe.fname};
	}

	int insns_cnt = probe.size / sizeof(bpf_insn);
	probe.fd = bpf::loadProgram(BPF_PROG_TYPE_KPROBE, probe.insn, insns_cnt, license, debug_print, kernVersion, sysCallBPF);
	if (probe.fd < 0) {
		throw std::runtime_error{fmt::format("loadProgram() failed for {} with error: {:d} ({}), logs: {}", probe.fname, errno, strerror(errno), getLogBuffer())};
	}

	std::string name_prefix;
	if (isKretprobe) {
		name_prefix = "ret_";
	}
	name_prefix += KPROBE_NAME_PREFIX;

	if (name.empty()) {
		throw std::runtime_error{"Event name cannot be empty"};
	}

	probe.efd = install_kprobe_fs(name_prefix, std::string{name}, isKprobe, probe.fd);
	if (probe.efd < 0) {
		throw InsufficientCapabilitiesError{fmt::format("Cannot write probe {}: {:d} ({})", name, errno, strerror(errno))};
	}

	probes.push_back(probe);
}

struct ElfFileContent {
	std::vector<elf_section> sections;
	char license[128] = {0};
	int mapsShndx = -1;
	int strtabidx = -1;
	Elf_Data* symbols = nullptr;

	bool isOk() const {
		if (sections.empty()) {
			LOG_ERROR("No sections available");
			return false;
		}
		if (*license == '\n') {
			LOG_ERROR("No license found");
			return false;
		}
		if (mapsShndx == -1) {
			LOG_ERROR("No maps section found");
			return false;
		}
		if (strtabidx == -1 || !symbols) {
			LOG_ERROR("No symbols section found");
			return false;
		}
		return true;
	}
};

ElfFileContent scanElfSections(Elf* elf, GElf_Ehdr* ehdr) {
	ElfFileContent fileContent;
	for (unsigned i = 1; i < ehdr->e_shnum; ++i) {
		elf_section sec{.indx = i};
		if (!getSection(elf, ehdr, sec))
			continue;

		LOG_DEBUG(
				"section {:2d}: {}",
				i,
				to_string(sec));

		if (sec.shname == "license") {
			sec.processed = true;
			memcpy(fileContent.license, sec.data->d_buf, sec.data->d_size);
		}
		else if (sec.shname ==  "version")  {
			sec.processed = true;
			if (sec.data->d_size != sizeof(int)) {
				throw std::runtime_error{"Invalid size of version, section: " + std::to_string(sec.data->d_size)};
			}
			// Actually disregard the kernel version from ELF section
			// Checking if the version of a probe to be loaded matches the present kernel version didn't work well as a compatibility test anyway
			// and in kernel 5 the check was removed.
			// memcpy(&fileContent.kernVersion, sec.data->d_buf, sizeof(int));
		}
		else if (sec.shname == "maps") {
			fileContent.mapsShndx = fileContent.sections.size();
		}
		else if (sec.shdr.sh_type == SHT_SYMTAB) {
			fileContent.strtabidx = sec.shdr.sh_link;
			fileContent.symbols = sec.data;
		}
		fileContent.sections.push_back(std::move(sec));
	}
	return fileContent;
}

bool processReloSections(Elf* elf, GElf_Ehdr* ehdr, std::vector<elf_section>& allSections, Elf_Data* symbols, maps_config& maps) {
	bool all_ok = true;
	for (auto& sec : allSections) {
		if (sec.processed)
			continue;

		// relocations section
		if (sec.shdr.sh_type == SHT_REL) {
			elf_section prog_scn{.indx = sec.shdr.sh_info};
			if (!getSection(elf, ehdr, prog_scn))
				continue;

			if (prog_scn.shdr.sh_type != SHT_PROGBITS || !(prog_scn.shdr.sh_flags & SHF_EXECINSTR))
				continue;

			bpf_insn* insns = (bpf_insn*)prog_scn.data->d_buf;
			sec.processed = true;

			if (!readAndApplyRelocations(sec.data, symbols, &sec.shdr, insns, maps)) {
				LOG_ERROR("Relocations for section {:d} failed", sec.indx);
				all_ok = false;
			}
		}
	}
	return all_ok;
}

void bpf_subsystem::load_programs_from_sections(std::vector<elf_section>& allSections, const char* license, int kernVersion) {
	for (auto& sec : allSections) {
		if (sec.processed)
			continue;

		if (sec.shname.compare(0, 7, "kprobe/") == 0 || sec.shname.compare(0, 10, "kretprobe/") == 0) {
			kprobe probe{.fname = sec.shname, .insn = (bpf_insn*)sec.data->d_buf, .size = sec.data->d_size, .fd = -1, .efd = -1};
			load_and_attach(probe, license, kernVersion);
			sec.processed = true;
		}
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
	if (elf_version(EV_CURRENT) == EV_NONE)
		throw std::runtime_error{"Cannot read elf version"};

	LOG_DEBUG("Loading BPF program from {}", path);
	file_fd bpf_file_fd{path};
	Elf* elf = elf_begin(bpf_file_fd.fd, ELF_C_READ, nullptr);

	if (!elf)
		throw std::runtime_error{"Cannot read elf"};

	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf, &ehdr) != &ehdr)
		throw std::runtime_error{"Cannot read elf header"};

	ElfFileContent content{scanElfSections(elf, &ehdr)};
	if (!content.isOk()) {
		LOG_ERROR("Scanning Elf sections failed");
		return false;
	}

	maps = MapsSectionLoader{content.sections[content.mapsShndx], elf, content.symbols, content.strtabidx}.load();
	BPFMapsWrapper mapsWrapper;
	set_maps_max_entries(map_max_entries);
	if (!loadMaps(maps, mapsWrapper)) {
		LOG_ERROR("Cannot load BPF maps");
		return false;
	}

	content.sections[content.mapsShndx].processed = true;

	if (!initialize_perf_maps(maps, mapsWrapper)) {
		LOG_ERROR("Cannot initialize perf maps");
		return false;
	}

	if (!processReloSections(elf, &ehdr, content.sections, content.symbols, maps)) {
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

	load_programs_from_sections(content.sections, content.license, *kernelVersion);
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
