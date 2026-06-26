#include "btf_loader.h"
#include "log.h"
#include "maps_def.h"

extern "C" {
#include "../../ebpf-common/bcc/libbpf-tools/btf_helpers.h"
}

namespace bpf {

void BTFLoader::set_maps_max_entries(uint32_t map_max_entries) {
	bpf_map__set_max_entries(skel->maps.connectsock_ipv4, map_max_entries);
	bpf_map__set_max_entries(skel->maps.connectsock_ipv6, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tcp_stats_ipv4, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tcp_stats_ipv6, map_max_entries);
	bpf_map__set_max_entries(skel->maps.map_sends, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tuplepid_ipv4, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tuplepid_ipv6, map_max_entries);
	bpf_map__set_max_entries(skel->maps.stats_ipv4, map_max_entries);
	bpf_map__set_max_entries(skel->maps.stats_ipv6, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tcp_event_ipv4, map_max_entries);
	bpf_map__set_max_entries(skel->maps.tcp_event_ipv6, map_max_entries);
}

bool BTFLoader::load_bpf(const std::string& path, uint32_t max_entries, uint32_t kernVersion){

	openOpts = {};
	openOpts.sz = sizeof(openOpts);

	LOG_TRACE("Ensuring BTF for CO-RE.");
	if (const auto res{ensure_core_btf(&openOpts)}) {
		LOG_ERROR("Failed to fetch necessary BTF for CO-RE: {}", strerror(-res));
		return false;
	}

	LOG_TRACE("Opening BPF object.");
	skel = nettracer_bpf_core__open_opts(&openOpts);
	if (skel == nullptr) {
		LOG_ERROR("Failed to open BPF object");
		cleanup_core_btf(&openOpts);
		return false;
	}

	set_maps_max_entries(max_entries);
	LOG_TRACE("Loading BPF program");
	if (const auto res{nettracer_bpf_core__load(skel)}) {
		LOG_ERROR("Failed to load BPF object: {}", std::to_string(res));
		return false;
	}

	LOG_TRACE("Attaching BPF probes");
	if (!tryAttachProbes()) {
		LOG_ERROR("Failed to attach all BPF probes");
		return false;
	}

 return true;
}

void BTFLoader::clear_all_probes() {
	//handled by kernel at process exit
}

bool BTFLoader::needs_offset_guessing() const {
	return false;
}

BTFLoader::~BTFLoader() {
	if (skel) {
		nettracer_bpf_core__detach(skel);
		nettracer_bpf_core__destroy(skel);
		cleanup_core_btf(&openOpts);
		LOG_INFO("BPF destroyed");
	}

}

int BTFLoader::get_map_fd(const std::string& id) {
	if (id == "connectsock_ipv4") {
		return bpf_map__fd(skel->maps.connectsock_ipv4);
	}

	if (id == "tuplepid_ipv4") {
		return bpf_map__fd(skel->maps.tuplepid_ipv4);
	}

	if (id == "tcp_event_ipv4") {
		return bpf_map__fd(skel->maps.tcp_event_ipv4);
	}

	if (id == "connectsock_ipv6") {
		return bpf_map__fd(skel->maps.connectsock_ipv6);
	}

	if (id == "tuplepid_ipv6") {
		return bpf_map__fd(skel->maps.tuplepid_ipv6);
	}

	if (id == "tcp_event_ipv6") {
		return bpf_map__fd(skel->maps.tcp_event_ipv6);
	}

	if (id == "map_sends") {
		return bpf_map__fd(skel->maps.map_sends);
	}

	if (id == "tcp_stats_ipv4") {
		return bpf_map__fd(skel->maps.tcp_stats_ipv4);
	}

	if (id == "tcp_stats_ipv6") {
		return bpf_map__fd(skel->maps.tcp_stats_ipv6);
	}

	if (id == "nettracer_config") {
		return bpf_map__fd(skel->maps.nettracer_config);
	}

	if (id == "bpf_logs") {
		return bpf_map__fd(skel->maps.bpf_logs);
	}

	if (id == "stats_ipv4") {
		return bpf_map__fd(skel->maps.stats_ipv4);
	}

	if (id == "stats_ipv6") {
		return bpf_map__fd(skel->maps.stats_ipv6);
	}
	if (id == "bpf_debug_counters") {
		return bpf_map__fd(skel->maps.bpf_debug_counters);
	}

	return -1;
}

static bpf_link* attachKprobe(bpf_program* prog, const std::string& funcName) {
	auto link{bpf_program__attach_kprobe(prog, false, funcName.c_str())};
	if (link == nullptr) {
		LOG_WARN("Failed to attach kprobe for {}", funcName);
	}
	return link;
}

static bpf_link* attachKretprobe(bpf_program* prog, const std::string& funcName) {
	auto link{bpf_program__attach_kprobe(prog, true, funcName.c_str())};
	if (link == nullptr) {
		LOG_WARN("Failed to attach kretprobe for {}", funcName);
	}
	return link;
}

bool BTFLoader::tryAttachProbes() {
	bool anySuccess = false;
	anySuccess |= (skel->links.kprobe__tcp_v4_connect = attachKprobe(skel->progs.kprobe__tcp_v4_connect, "tcp_v4_connect")) != nullptr;
	anySuccess |=
			(skel->links.kretprobe__tcp_v4_connect = attachKretprobe(skel->progs.kretprobe__tcp_v4_connect, "tcp_v4_connect")) != nullptr;
	anySuccess |= (skel->links.kprobe__tcp_v6_connect = attachKprobe(skel->progs.kprobe__tcp_v6_connect, "tcp_v6_connect")) != nullptr;
	anySuccess |=
			(skel->links.kretprobe__tcp_v6_connect = attachKretprobe(skel->progs.kretprobe__tcp_v6_connect, "tcp_v6_connect")) != nullptr;
	anySuccess |= (skel->links.kretprobe__inet_csk_accept = attachKretprobe(skel->progs.kretprobe__inet_csk_accept, "inet_csk_accept")) !=
				  nullptr;
	anySuccess |= (skel->links.kprobe__tcp_close = attachKprobe(skel->progs.kprobe__tcp_close, "tcp_close")) != nullptr;
	anySuccess |= (skel->links.kprobe__tcp_sendmsg = attachKprobe(skel->progs.kprobe__tcp_sendmsg, "tcp_sendmsg")) != nullptr;
	anySuccess |= (skel->links.kretprobe__tcp_sendmsg = attachKretprobe(skel->progs.kretprobe__tcp_sendmsg, "tcp_sendmsg")) != nullptr;
	anySuccess |= (skel->links.kprobe__tcp_sendpage = attachKprobe(skel->progs.kprobe__tcp_sendpage, "tcp_sendpage")) != nullptr;
	anySuccess |=
			(skel->links.kprobe__tcp_cleanup_rbuf = attachKprobe(skel->progs.kprobe__tcp_cleanup_rbuf, "tcp_cleanup_rbuf")) != nullptr;
	anySuccess |= (skel->links.kprobe__tcp_retransmit_skb = attachKprobe(skel->progs.kprobe__tcp_retransmit_skb, "tcp_retransmit_skb")) !=
				  nullptr;
	return anySuccess;
}

map_data BTFLoader::get_perf_map(const std::string& name) {
	//not implemented
	return {};
}

std::unique_ptr<Ibpf> createBTFBPF() {
	return std::make_unique<BTFLoader>();
}
}
