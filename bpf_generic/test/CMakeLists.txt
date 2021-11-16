set(SOURCES
	kernel_version_test.cpp
)
PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${SOURCES})

set(HEADERS
	mock_system_calls.h
)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${HEADERS})

add_executable(bpf_generic_test ${SOURCES_FULL} ${HEADERS_FULL})

target_include_directories(bpf_generic_test
	PRIVATE
		"${PROJECT_SOURCE_DIR}/bpf_generic/src"
)

target_link_libraries(bpf_generic_test bpf_generic)
target_link_libraries(bpf_generic_test -lstdc++fs)

if(DEFINED CONAN_DEPS)
    target_link_libraries(bpf_generic_test CONAN_PKG::gtest)
else()
    target_link_libraries(bpf_generic_test gmock_main)
    target_link_libraries(bpf_generic_test gtest_main)
endif()

include(GoogleTest)
gtest_discover_tests(bpf_generic_test)
