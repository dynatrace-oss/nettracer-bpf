#include "elf_utils.h"

#include "log.h"
#include "maps_loading.h"

#include <algorithm>
#include <fmt/core.h>
#include <linux/bpf.h>
#include <stdexcept>

namespace bpf {

std::string to_string(const elf_section& section) {
	return fmt::format("{:35} {:5d} bytes at {:p}, link={:02d} flags={:d}",
		section.shname,
		section.data->d_size,
		section.data->d_buf,
		section.shdr.sh_link,
		section.shdr.sh_flags);
}

bool getSection(Elf* elf, GElf_Ehdr* ehdr, elf_section& section) {
	Elf_Scn* scn = elf_getscn(elf, section.indx);

	if (!scn) {
		LOG_ERROR("elf_getscn failed for section {:d}", section.indx);
		return false;
	}

	if (!gelf_getshdr(scn, &section.shdr)) {
		throw std::runtime_error(fmt::format("gelf_getshdr failed for section {:d}", section.indx));
	}

	char* shname = elf_strptr(elf, ehdr->e_shstrndx, section.shdr.sh_name);
	if (!shname || !section.shdr.sh_size) {
		LOG_ERROR("elf_strptr failed for section {:d}", section.indx);
		return false;
	}

	section.shname = std::string(shname);
	section.data = elf_getdata(scn, 0);
	if (!section.data) {
		LOG_ERROR("No data descriptors found for section {:d}", section.indx);
		return false;
	}
	if (elf_getdata(scn, section.data)) {
		LOG_ERROR("More than one data descriptor found for section {:d}", section.indx);
		return false;
	}

	return true;
}

bool readAndApplyRelocations(Elf_Data* data, Elf_Data* symbols, GElf_Shdr* shdr, bpf_insn* insn, maps_config& maps) {
	size_t relSize = shdr->sh_size / shdr->sh_entsize;
	for (size_t i = 0; i < relSize; ++i) {
		GElf_Rel rel;
		GElf_Sym sym;

		gelf_getrel(data, i, &rel);
		unsigned insn_idx = rel.r_offset / sizeof(bpf_insn);
		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
			LOG_ERROR("Invalid relo for insn[{}], code {}", insn_idx, insn[insn_idx].code);
			return false;
		}
		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

		auto it = std::find_if(maps.begin(), maps.end(), [&](auto& it) { return it.elf_offset == sym.st_value; });
		if (it != maps.end()) {
			insn[insn_idx].imm = it->fd;
		}
		else {
			LOG_ERROR("Invalid relo for insn[{:d}] - no matching map", insn_idx);
			return false;
		}
	}

	return true;
}

} // namespace bpf
