set(SOURCES
	bpf_loading.cpp
	bpf_wrapper.cpp
	log.cpp
	kernel_version.cpp
	maps_loading.cpp
	perf_event.cpp
	system_calls.cpp
)

set(HEADERS
	bpf_loading.h
	bpf_wrapper.h
	errors.h
	log.h
	kernel_version.h
	maps_loading.h
	perf_event.h
	perf_sys.h
	system_calls.h
)

set(CMAKE_CXX_STANDARD 20)
add_library(bpf_generic STATIC ${SOURCES} ${HEADERS})

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
target_link_libraries(bpf_generic CONAN_PKG::spdlog)
target_link_libraries(bpf_generic CONAN_PKG::fmt)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMObject.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMTextAPI.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMMCParser.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMIRReader.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMAsmParser.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMMC.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMDebugInfoCodeView.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMBitReader.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMCore.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMRemarks.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMBinaryFormat.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMTargetParser.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMBitstreamReader.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMSupport.a)
target_link_libraries(bpf_generic ${LLVM_LIBDIR}/libLLVMDemangle.a)
