set(SOURCES
	bpf_loading.cpp
	bpf_wrapper.cpp
	elf_utils.cpp
	log.cpp
	maps_loading.cpp
)

set(HEADERS
	bpf_loading.h
	bpf_wrapper.h
	elf_utils.h
	log.h
	maps_loading.h
	perf_event.h
	perf_sys.h
)

add_library(bpf_generic STATIC ${SOURCES} ${HEADERS})

if(DEFINED CONAN_DEPS)
    target_link_libraries(bpf_generic CONAN_PKG::spdlog)
    target_link_libraries(bpf_generic CONAN_PKG::fmt)
    target_link_libraries(bpf_generic CONAN_PKG::elfutils)
else()
    target_link_libraries(nettracersrv spdlog::spdlog)
    target_link_libraries(nettracersrv fmt::fmt)
    target_link_libraries(bpf_generic /usr/lib/${ARCHITECTURE}-linux-gnu/libelf.a)
endif()
