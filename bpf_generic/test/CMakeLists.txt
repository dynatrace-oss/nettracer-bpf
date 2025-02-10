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

include(GoogleTest)

target_link_libraries(bpf_generic_test bpf_generic)
target_link_libraries(bpf_generic_test CONAN_PKG::gtest)
target_link_libraries(bpf_generic_test CONAN_PKG::boost)

gtest_discover_tests(bpf_generic_test)
