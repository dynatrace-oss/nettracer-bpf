if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(BUILD_TYPE_MACRO "DEBUG")
else()
	set(BUILD_TYPE_MACRO "NDEBUG")
endif()

set(BPF_OPTIMIZATION "-g" "-O2")

set(ISYSTEM_KERNEL_HEADERS "")
foreach(dir ${KERNEL_HEADERS})
	list(APPEND ISYSTEM_KERNEL_HEADERS "-isystem" "${dir}")
endforeach()

set(SOURCES
	nettracer-bpf.c
)

PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}" ${SOURCES})

set(HEADERS
	metrics_utilities.h
	nettracer-bpf.h
	probes/connections.h
	probes/metrics.h
	tuples_utilities.h
)

if( DEFINED LEGACY_BPF)
	list(APPEND HEADERS
		legacy/asm_inline.h
		legacy/bpf_helpers.h
		legacy/maps.h
		legacy/offset_guessing.h
		legacy/other.h
	)
	set(CLANG_COMMAND ${LLVM_BINDIR}/clang
		-D__KERNEL__ -D__TARGET_ARCH_${ARCH} -DLEGACY_BPF=1
		-D${BUILD_TYPE_MACRO}
		-fno-jump-tables -fno-builtin
		-Wall -Wpadded -Werror
		${BPF_OPTIMIZATION} -emit-llvm
		-c "${CMAKE_CURRENT_LIST_DIR}/nettracer-bpf.c"
		-nostdinc
		-I "${CMAKE_CURRENT_LIST_DIR}"
		-isystem ${LLVM_INCLUDE}
		${ISYSTEM_KERNEL_HEADERS}
		-o nettracer-bpf.c.o
	)

	set(LLC_COMMAND ${LLVM_BINDIR}/llc
		nettracer-bpf.c.o
		-march=bpf -filetype=obj
		-o "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/nettracer-bpf.o"
	)
	set(FULL_COMMAND ${CLANG_COMMAND} && ${LLC_COMMAND})
else()
	list(APPEND HEADERS
		maps.h
	)
	set(FULL_COMMAND ${LLVM_BINDIR}/clang
		-D__TARGET_ARCH_${ARCH}
		${BPF_OPTIMIZATION}
		-target bpf
		-c "${CMAKE_CURRENT_LIST_DIR}/nettracer-bpf.c"
		-I "${CMAKE_CURRENT_LIST_DIR}"
		-o nettracer-bpf.c.o
	)
endif()

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
