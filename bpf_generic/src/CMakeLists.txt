set(SOURCES
	classic_loader.cpp
	btf_loader.cpp
	bpf_wrapper.cpp
	log.cpp
	maps_loading.cpp
	perf_event.cpp
)

set(HEADERS
	classic_loader.h
	btf_loader.h
	bpf_wrapper.h
	errors.h
	log.h
	maps_loading.h
	perf_event.h
	perf_sys.h
)

set(CMAKE_CXX_STANDARD 20)
add_library(bpf_generic STATIC ${SOURCES} ${HEADERS})

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
include_directories("${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../libbpf")
add_definitions(${LLVM_DEFINITIONS})

target_link_libraries(bpf_generic CONAN_PKG::spdlog)
target_link_libraries(bpf_generic CONAN_PKG::fmt)
target_link_libraries(bpf_generic "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../bpftool/bootstrap/libbpf/libbpf.a")
target_link_libraries(bpf_generic "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../lib/liblibpf-tools.a")
target_link_libraries(bpf_generic elf)
