#include "btf_loader.h"
#include "log.h"
#include "maps_def.h"

extern "C" {
#include "../../ebpf-common/bcc/libbpf-tools/btf_helpers.h"
}

namespace bpf {

bool BTFLoader::load_bpf(const std::string& a, uint32_t b){
	LOG_DEBUG("Loading BPF program.");

	{
		LIBBPF_OPTS(bpf_object_open_opts, newOpenOpts);
		openOpts = newOpenOpts;
	}

	LOG_TRACE("Fetching BTF for CO-RE.");
	if (const auto res{ensure_core_btf(&openOpts)}) {
		throw std::runtime_error("Failed to fetch necessary BTF for CO-RE: " + std::string(strerror(-res)));
	}
	coreEnsured = true;

	LOG_TRACE("Opening Discovery BPF object.");
	skel = nettracer_bpf_core__open_opts(&openOpts);
	if (skel == nullptr) {
		throw std::runtime_error("Failed to open BPF object.");
	}

	LOG_TRACE("Loading Discovery BPF program.");
	if (const auto res{nettracer_bpf_core__load(skel)}) {
		throw std::runtime_error("Failed to load BPF object: " + std::to_string(res));
	}

	LOG_TRACE("Attaching Discovery BPF program.");
	if (const auto res{nettracer_bpf_core__attach(skel)}) {
		throw std::runtime_error("Failed to attach BPF object: " + std::to_string(res));
	}

 return true;
}

void BTFLoader::clear_all_probes() {
	nettracer_bpf_core__detach(skel);
}

BTFLoader::~BTFLoader() {
	clear_all_probes();
	nettracer_bpf_core__destroy(skel);
	LOG_INFO("BPF destroyed");
}

int BTFLoader::get_map_fd(const std::string& id) {
	 if(id == "connectsock_ipv4") return bpf_map__fd(skel->maps.connectsock_ipv4);

	if( id == "nettracer_status") return bpf_map__fd(skel->maps.nettracer_status);

	if( id == "tuplepid_ipv4") return bpf_map__fd(skel->maps.tuplepid_ipv4);

	if( id == "tcp_event_ipv4") return bpf_map__fd(skel->maps.tcp_event_ipv4);

	if( id == "connectsock_ipv6") return bpf_map__fd(skel->maps.connectsock_ipv6);

	if( id == "tuplepid_ipv6") return bpf_map__fd(skel->maps.tuplepid_ipv6);

	if( id == "tcp_event_ipv6") return bpf_map__fd(skel->maps.tcp_event_ipv6);

	if( id == "map_sends") return bpf_map__fd(skel->maps.map_sends);

	if( id == "tcp_stats_ipv4") return bpf_map__fd(skel->maps.tcp_stats_ipv4);

	if( id == "tcp_stats_ipv6") return bpf_map__fd(skel->maps.tcp_stats_ipv6);

	if( id == "nettracer_config") return bpf_map__fd(skel->maps.nettracer_config);

	if( id == "bpf_logs") return bpf_map__fd(skel->maps.bpf_logs);

	if( id == "stats_ipv4") return bpf_map__fd(skel->maps.stats_ipv4);

	if( id == "stats_ipv6") return bpf_map__fd(skel->maps.stats_ipv6);

	return -1;
}

//static bpf_link* attachKprobe(bpf_program* prog, const std::string& funcName) {
//	auto link{bpf_program__attach_kprobe(prog, false, funcName.c_str())};
//	if (link == nullptr) {
//		LOG_WARN("Failed to attach kprobe for {}.", funcName);
//	}
//	return link;
//}

void BTFLoader::attachAllProbes(){
	//bool anySuccess = false;
	//anySuccess |= (skel->links.kprobeSysAccept = attachKprobe(skel->progs.kprobe__tcp_v4_connect;, SYS_PREFIX "sys_accept")) != nullptr;

}

map_data BTFLoader::get_perf_map(const std::string& name) {
	return {};
}

std::unique_ptr<Ibpf> createBTFBPF() {
	return std::make_unique<BTFLoader>();
}
}
