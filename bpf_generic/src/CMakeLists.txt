set(SOURCES
	bpf_loading.cpp
	bpf_wrapper.cpp
	elf_utils.cpp
	log.cpp
	kernel_version.cpp
	maps_loading.cpp
	perf_event.cpp
	system_calls.cpp
)

set(HEADERS
	bpf_loading.h
	bpf_wrapper.h
	elf_utils.h
	errors.h
	log.h
	kernel_version.h
	maps_loading.h
	perf_event.h
	perf_sys.h
	system_calls.h
)

add_library(bpf_generic STATIC ${SOURCES} ${HEADERS})

if(DEFINED CONAN_DEPS)
    target_link_libraries(bpf_generic CONAN_PKG::spdlog)
    target_link_libraries(bpf_generic CONAN_PKG::fmt)
    target_link_libraries(bpf_generic CONAN_PKG::elfutils)
else()
    target_link_libraries(bpf_generic spdlog::spdlog)
    target_link_libraries(bpf_generic fmt::fmt)
    target_link_libraries(bpf_generic /usr/lib/${ARCHITECTURE}-linux-gnu/libelf.a)
endif()
target_link_libraries(bpf_generic -lz)
