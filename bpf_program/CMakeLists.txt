if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(BUILD_TYPE_MACRO "DEBUG")
else()
	set(BUILD_TYPE_MACRO "NDEBUG")
endif()

# BPF programs used in NetTracer runs don't need any debug information, so it is useful only for specific debugging purposes
if(DEBUG_BPF)
	set(BPF_OPTIMIZATION "-Og")
else()
	set(BPF_OPTIMIZATION "-O2")
endif()

set(ISYSTEM_KERNEL_HEADERS "")
foreach(dir ${KERNEL_HEADERS})
	list(APPEND ISYSTEM_KERNEL_HEADERS "-isystem" "${dir}")
endforeach()

set(CLANG_COMMAND clang
	-D__KERNEL__ -D__TARGET_ARCH_${ARCH}
	-D${BUILD_TYPE_MACRO}
	-fno-jump-tables -fno-builtin
	-Wall -Wpadded -Werror
	${BPF_OPTIMIZATION} -emit-llvm
	-c "${CMAKE_CURRENT_LIST_DIR}/nettracer-bpf.c"
	-nostdinc
	-I "${CMAKE_CURRENT_LIST_DIR}"
	-isystem ${LLVM_HEADERS}
	${ISYSTEM_KERNEL_HEADERS}
	-o nettracer-bpf.c.o
)

set(LLC_COMMAND llc
	nettracer-bpf.c.o
	-march=bpf -filetype=obj
	-o "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/nettracer-bpf.o"
)

set(FULL_COMMAND ${CLANG_COMMAND} && ${LLC_COMMAND})

set(SOURCES
	nettracer-bpf.c
)
PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}" ${SOURCES})

set(HEADERS
	asm_inline.h
	bpf_helpers.h
	log.h
	maps.h
	metrics_utilities.h
	nettracer-bpf.h
	offset_guessing.h
	probes/connections.h
	probes/metrics.h
	probes/other.h
	tuples_utilities.h
)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}" ${HEADERS})

add_custom_command(OUTPUT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/nettracer-bpf.o"
	COMMAND ${FULL_COMMAND}
	DEPENDS ${SOURCES_FULL} ${HEADERS_FULL}
)
add_custom_target(bpf_program
	ALL
	DEPENDS "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/nettracer-bpf.o"
)

install(FILES "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/nettracer-bpf.o"
	DESTINATION "bin"
)
